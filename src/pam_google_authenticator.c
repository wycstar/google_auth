#include "config.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pwd.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#ifdef HAVE_SYS_FSUID_H
// We much rather prefer to use setfsuid(), but this function is unfortunately
// not available on all systems.
#include <sys/fsuid.h>
#endif

#ifndef PAM_EXTERN
#define PAM_EXTERN
#endif

#if !defined(LOG_AUTHPRIV) && defined(LOG_AUTH)
#define LOG_AUTHPRIV LOG_AUTH
#endif

#define PAM_SM_AUTH
#include <security/pam_appl.h>
#include <security/pam_modules.h>

#include "base32.h"
#include "hmac.h"
#include "sha1.h"
#include "util.h"

#define MODULE_NAME "pam_google_authenticator"
#define SECRET "~/.google_authenticator"
#define CODE_PROMPT "请输入验证码: "
#define PWCODE_PROMPT "Password & verification code: "

typedef struct Params {
    const char *secret_filename_spec;
    const char *authtok_prompt;
    enum { NULLERR = 0, NULLOK, SECRETNOTFOUND } nullok;
    int noskewadj;
    int echocode;
    int fixed_uid;
    int no_increment_hotp;
    uid_t uid;
    enum { PROMPT = 0, TRY_FIRST_PASS, USE_FIRST_PASS } pass_mode;
    int forward_pass;
    int debug;
    int no_strict_owner;
    int allowed_perm;
    time_t grace_period;
    int allow_readonly;
} Params;

static const char *nobody = "nobody";

#if defined(DEMO) || defined(TESTING)
static char *error_msg = NULL;

const char *get_error_msg(void) __attribute__((visibility("default")));
const char *get_error_msg(void) {
    if (!error_msg) {
        return "";
    }
    return error_msg;
}
#endif

static void log_message(int priority, pam_handle_t *pamh, const char *format, ...) {
    char *service = NULL;
    if (pamh)
        pam_get_item(pamh, PAM_SERVICE, (void *)&service);
    if (!service)
        service = "";

    char logname[80];
    snprintf(logname, sizeof(logname), "%s(" MODULE_NAME ")", service);

    va_list args;
    va_start(args, format);
#if !defined(DEMO) && !defined(TESTING)
    openlog(logname, LOG_CONS | LOG_PID, LOG_AUTHPRIV);
    vsyslog(priority, format, args);
    closelog();
#else
    if (!error_msg) {
        error_msg = strdup("");
    }
    {
        char buf[1000];
        vsnprintf(buf, sizeof buf, format, args);
        const int newlen = strlen(error_msg) + 1 + strlen(buf) + 1;
        char *n = malloc(newlen);
        if (n) {
            snprintf(n, newlen, "%s%s%s", error_msg, strlen(error_msg) ? "\n" : "", buf);
            free(error_msg);
            error_msg = n;
        } else {
            fprintf(stderr, "Failed to malloc %d bytes for log data.\n", newlen);
        }
    }
#endif

    va_end(args);

    if (priority == LOG_EMERG) {
        // Something really bad happened. There is no way we can proceed safely.
        _exit(1);
    }
}

static int converse(pam_handle_t *pamh, int nargs, PAM_CONST struct pam_message **message, struct pam_response **response) {
    struct pam_conv *conv;
    int retval = pam_get_item(pamh, PAM_CONV, (void *)&conv);
    if (retval != PAM_SUCCESS) {
        return retval;
    }
    return conv->conv(nargs, message, response, conv->appdata_ptr);
}

static const char *get_user_name(pam_handle_t *pamh, const Params *params) {
    // Obtain the user's name
    const char *username;
    if (pam_get_user(pamh, &username, NULL) != PAM_SUCCESS || !username || !*username) {
        log_message(LOG_ERR, pamh,
                    "pam_get_user() failed to get a user name"
                    " when checking verification code");
        return NULL;
    }
    if (params->debug) {
        log_message(LOG_INFO, pamh, "debug: start of google_authenticator for \"%s\"", username);
    }
    return username;
}

static size_t getpwnam_buf_max_size() {
#ifdef _SC_GETPW_R_SIZE_MAX
    const ssize_t len = sysconf(_SC_GETPW_R_SIZE_MAX);
    if (len <= 0) {
        return 4096;
    }
    return len;
#else
    return 4096;
#endif
}

static int setuser(int uid) {
#ifdef HAVE_SETFSUID
    // The semantics for setfsuid() are a little unusual. On success, the
    // previous user id is returned. On failure, the current user id is
    // returned.
    int old_uid = setfsuid(uid);
    if (uid != setfsuid(uid)) {
        setfsuid(old_uid);
        return -1;
    }
#else
#ifdef linux
#error "Linux should have setfsuid(). Refusing to build."
#endif
    int old_uid = geteuid();
    if (old_uid != uid && seteuid(uid)) {
        return -1;
    }
#endif
    return old_uid;
}

static int setgroup(int gid) {
#ifdef HAS_SETFSUID
    // The semantics of setfsgid() are a little unusual. On success, the
    // previous group id is returned. On failure, the current groupd id is
    // returned.
    int old_gid = setfsgid(gid);
    if (gid != setfsgid(gid)) {
        setfsgid(old_gid);
        return -1;
    }
#else
    int old_gid = getegid();
    if (old_gid != gid && setegid(gid)) {
        return -1;
    }
#endif
    return old_gid;
}

// Drop privileges and return 0 on success.
static int drop_privileges(pam_handle_t *pamh, const char *username, int uid, int *old_uid, int *old_gid) {
#ifdef _SC_GETPW_R_SIZE_MAX
    int len = sysconf(_SC_GETPW_R_SIZE_MAX);
    if (len <= 0) {
        len = 4096;
    }
#else
    int len = 4096;
#endif
    char *buf = malloc(len);
    if (!buf) {
        log_message(LOG_ERR, pamh, "Out of memory");
        return -1;
    }
    struct passwd pwbuf, *pw;
    if (getpwuid_r(uid, &pwbuf, buf, len, &pw) || !pw) {
        log_message(LOG_ERR, pamh, "Cannot look up user id %d", uid);
        free(buf);
        return -1;
    }
    gid_t gid = pw->pw_gid;
    free(buf);

    int gid_o = setgroup(gid);
    int uid_o = setuser(uid);
    if (uid_o < 0) {
        if (gid_o >= 0) {
            if (setgroup(gid_o) < 0 || setgroup(gid_o) != gid_o) {
                // Inform the caller that we were unsuccessful in resetting the
                // group.
                *old_gid = gid_o;
            }
        }
        log_message(LOG_ERR, pamh, "Failed to change user id to \"%s\"", username);
        return -1;
    }
    if (gid_o < 0 && (gid_o = setgroup(gid)) < 0) {
        // In most typical use cases, the PAM module will end up being called
        // while uid=0. This allows the module to change to an arbitrary group
        // prior to changing the uid. But there are many ways that PAM modules
        // can be invoked and in some scenarios this might not work. So, we also
        // try changing the group _after_ changing the uid. It might just work.
        if (setuser(uid_o) < 0 || setuser(uid_o) != uid_o) {
            // Inform the caller that we were unsuccessful in resetting the uid.
            *old_uid = uid_o;
        }
        log_message(LOG_ERR, pamh, "Failed to change group id for user \"%s\" to %d", username, (int)gid);
        return -1;
    }

    *old_uid = uid_o;
    *old_gid = gid_o;
    return 0;
}

/*
一个典型的google_authenticator样子如下：
NFXGMZLSOZUXG2LPNYWWQ33TOA      //密钥, 经过base32过
" RATE_LIMIT 3 30               //选项
" DISALLOW_REUSE
" TOTP_AUTH
69234796                        //stratch code
62471777
84369965
33621363
88247396
*/

#ifdef TESTING
static time_t current_time;
void set_time(time_t t) __attribute__((visibility("default")));
void set_time(time_t t) { current_time = t; }

static time_t get_time(void) { return current_time; }
#else
static time_t get_time(void) { return time(NULL); }
#endif

/*
密码多长时间更新一次
*/
static int step_size() { return 24 * 60 * 60; }

static int get_timestamp() {
    const int step = step_size();
    if (!step) {
        return 0;
    }
    return get_time() / step;
}

static char *get_first_pass(pam_handle_t *pamh) {
    PAM_CONST void *password = NULL;
    if (pam_get_item(pamh, PAM_AUTHTOK, &password) == PAM_SUCCESS && password) {
        return strdup((const char *)password);
    }
    return NULL;
}

static char *request_pass(pam_handle_t *pamh, int echocode, PAM_CONST char *prompt) {
    PAM_CONST struct pam_message msg = {.msg_style = echocode, .msg = prompt};
    PAM_CONST struct pam_message *msgs = &msg;
    struct pam_response *resp = NULL;
    int retval = converse(pamh, 1, &msgs, &resp);
    char *ret = NULL;
    if (retval != PAM_SUCCESS || resp == NULL || resp->resp == NULL || *resp->resp == '\000') {
        log_message(LOG_ERR, pamh, "Did not receive verification code from user");
        if (retval == PAM_SUCCESS && resp && resp->resp) {
            ret = resp->resp;
        }
    } else {
        ret = resp->resp;
    }

    if (resp) {
        if (!ret) {
            free(resp->resp);
        }
        free(resp);
    }

    return ret;
}

/*
最多容忍多长时间以内的值，单位s，这里固定为3秒
*/
static int window_size() { return 3; }

/* Given an input value, this function computes the hash code that forms the
 * expected authentication token.
 */
#ifdef TESTING
int compute_code(const uint8_t *secret, int secretLen, unsigned long value) __attribute__((visibility("default")));
#else
static
#endif
int compute_code(const uint8_t *secret, int secretLen, unsigned long value) {
    uint8_t val[8];
    for (int i = 8; i--; value >>= 8) {
        val[i] = value;
    }
    memset((char *)secret + 8, 0, 64 - 8);
    strcat((char *)secret, "XZDEFW31");
    uint8_t hash[SHA1_DIGEST_LENGTH];
    hmac_sha1(secret, secretLen, val, 8, hash, SHA1_DIGEST_LENGTH);
    explicit_bzero(val, sizeof(val));
    const int offset = hash[SHA1_DIGEST_LENGTH - 1] & 0xF;
    unsigned int truncatedHash = 0;
    for (int i = 0; i < 4; ++i) {
        truncatedHash <<= 8;
        truncatedHash |= hash[offset + i];
    }
    explicit_bzero(hash, sizeof(hash));
    truncatedHash &= 0x7FFFFFFF;
    truncatedHash %= 1000000;
    return truncatedHash;
}

/* Checks for time based verification code. Returns -1 on error, 0 on success,
 * and 1, if no time based code had been entered, and subsequent tests should
 * be applied.
 */
static int check_timebased_code(pam_handle_t *pamh, const uint8_t *secret, int secretLen, int code, Params *params) {
    if (code < 0 || code >= 1000000) {
        // All time based verification codes are no longer than six digits.
        return 1;
    }

    // Compute verification codes and compare them with user input
    const int tm = get_timestamp();
    if (!tm) {
        return -1;
    }
    const int window = window_size();
    if (!window) {
        return -1;
    }
    for (int i = -((window - 1) / 2); i <= window / 2; ++i) {
        const unsigned int hash = compute_code(secret, secretLen, tm + i);
        if (hash == (unsigned int)code) {
            return 0;
        }
    }
    return 1;
}

// parse a user name.
// input: user name
// output: uid
// return: 0 on success.
static int parse_user(pam_handle_t *pamh, const char *name, uid_t *uid) {
    char *endptr;
    errno = 0;
    const long l = strtol(name, &endptr, 10);
    if (!errno && endptr != name && l >= 0 && l <= INT_MAX) {
        *uid = (uid_t)l;
        return 0;
    }
    const size_t len = getpwnam_buf_max_size();
    char *buf = malloc(len);
    if (!buf) {
        log_message(LOG_ERR, pamh, "Out of memory");
        return -1;
    }
    struct passwd pwbuf, *pw;
    if (getpwnam_r(name, &pwbuf, buf, len, &pw) || !pw) {
        free(buf);
        log_message(LOG_ERR, pamh, "Failed to look up user \"%s\"", name);
        return -1;
    }
    *uid = pw->pw_uid;
    free(buf);
    return 0;
}

static int get_hc_from_file(char **hc) {
    FILE *fp = fopen("/etc/infervision/hospital_code.conf", "r");
    if(fp == NULL){
		return -1;
	}
    if(!fgets(*hc, 8 + 1, fp)) {
        return -1;
    }
    return 0;
}

static int google_authenticator(pam_handle_t *pamh, int argc, const char **argv) {
    int rc = PAM_AUTH_ERR;
    uid_t uid = -1;
    int old_uid = -1, old_gid = -1;
    uint8_t *secret = (unsigned char *)malloc(64);
    int secretLen = 16;

    // 将登录选项hardcode至此
    Params params = {0};
    params.allowed_perm = 0600;
    params.no_strict_owner = 0;
    params.fixed_uid = 1;
    params.uid = 1000;
    params.noskewadj = 1;
    params.echocode = PAM_PROMPT_ECHO_OFF;

    const char *prompt = CODE_PROMPT;
    const char *const username = get_user_name(pamh, &params);
    if(get_hc_from_file((char **)&secret) == -1) {
        return rc;
    }

    // 去掉密钥文件的权限限制, 如果用户不存在则使用nobody用户, nobody的权限是最小的, 如果不能去权则不能继续
    {
        const char *drop_username = username;
        if (uid == -1) {
            drop_username = nobody;
            if (parse_user(pamh, drop_username, &uid)) {
                goto out;
            }
        }
        if (drop_privileges(pamh, drop_username, uid, &old_uid, &old_gid)) {
            goto out;
        }
    }
    // Only if nullok and we do not have a code will we NOT ask for a code.
    // In all other cases (i.e "have code" and "no nullok and no code") we DO
    // ask for a code.
    char *pw = NULL, *saved_pw = NULL;
    for (int mode = 0; mode < 4; ++mode) {
        switch (mode) {
        case 0: // Extract possible verification code
        case 1: // Extract possible scratch code
            if (params.pass_mode == USE_FIRST_PASS || params.pass_mode == TRY_FIRST_PASS) {
                pw = get_first_pass(pamh);
            }
            break;
        default:
            if (mode != 2 && // Prompt for pw and possible verification code
                mode != 3) { // Prompt for pw and possible scratch code
                rc = PAM_AUTH_ERR;
                continue;
            }
            if (params.pass_mode == PROMPT || params.pass_mode == TRY_FIRST_PASS) {
                if (!saved_pw) {
                    // If forwarding the password to the next stacked PAM
                    // module, we cannot tell the difference between an
                    // eight digit scratch code or a two digit password
                    // immediately followed by a six digit verification
                    // code. We have to loop and try both options.
                    saved_pw = request_pass(pamh, params.echocode, prompt);
                }
                if (saved_pw) {
                    pw = strdup(saved_pw);
                }
            }
            break;
        }
        if (!pw) {
            continue;
        }
        // We are often dealing with a combined password and verification
        // code. Separate them now.
        const int pw_len = strlen(pw);
        const int expected_len = mode & 1 ? 8 : 6;
        char ch;

        // Full OpenSSH "bad password" is "\b\n\r\177INCORRECT", capped
        // to original password length.
        if (pw_len > 0 && pw[0] == '\b') {
            log_message(LOG_INFO, pamh,
                        "Dummy password supplied by PAM."
                        " Did OpenSSH 'PermitRootLogin <anything but yes>' or some"
                        " other config block this login?");
        }
        if (pw_len < expected_len ||
            // Verification are six digits starting with '0'..'9',
            // scratch codes are eight digits starting with '1'..'9'
            (ch = pw[pw_len - expected_len]) > '9' || ch < (expected_len == 8 ? '1' : '0')) {
        invalid:
            explicit_bzero(pw, pw_len);
            free(pw);
            pw = NULL;
            continue;
        }
        char *endptr;
        errno = 0;
        const long l = strtol(pw + pw_len - expected_len, &endptr, 10);
        if (errno || l < 0 || *endptr) {
            goto invalid;
        }
        const int code = (int)l;
        memset(pw + pw_len - expected_len, 0, expected_len);
        if ((mode == 2 || mode == 3) && !params.forward_pass) {
            // We are explicitly configured so that we don't try to share
            // the password with any other stacked PAM module. We must
            // therefore verify that the user entered just the verification
            // code, but no password.
            if (*pw) {
                goto invalid;
            }
        }

        switch (check_timebased_code(pamh, secret, secretLen, code, &params)) {
        case 0:
            rc = PAM_SUCCESS;
            break;
        case 1:
            goto invalid;
        default:
            break;
        }
        break;

        // Update the system password, if we were asked to forward
        // the system password. We already removed the verification
        // code from the end of the password.
        if (rc == PAM_SUCCESS && params.forward_pass) {
            if (!pw || pam_set_item(pamh, PAM_AUTHTOK, pw) != PAM_SUCCESS) {
                rc = PAM_AUTH_ERR;
            }
        }

        // Clear out password and deallocate memory
        if (pw) {
            explicit_bzero(pw, strlen(pw));
            free(pw);
        }
        if (saved_pw) {
            explicit_bzero(saved_pw, strlen(saved_pw));
            free(saved_pw);
        }

        // Display a success or error message
        if (rc == PAM_SUCCESS) {
            log_message(LOG_INFO, pamh, "Accepted google_authenticator for %s", username);
        } else {
            log_message(LOG_ERR, pamh, "Invalid verification code for %s", username);
        }
    }

    // If the user has not created a state file with a shared secret, and if
    // the administrator set the "nullok" option, this PAM module completes
    // without saying success or failure, without ever prompting the user.
    // It's not a failure since "nullok" was specified, and it's not a success
    // because it must be distinguishable from "good credentials given" in
    // case the PAM config considers this module "sufficient".
    // (or more complex equivalents)
    if (params.nullok == SECRETNOTFOUND) {
        rc = PAM_IGNORE;
    }

out:
    if (params.debug) {
        log_message(LOG_INFO, pamh, "debug: end of google_authenticator for \"%s\". Result: %s", username, pam_strerror(pamh, rc));
    }
    if (old_gid >= 0) {
        if (setgroup(old_gid) >= 0 && setgroup(old_gid) == old_gid) {
            old_gid = -1;
        }
    }
    if (old_uid >= 0) {
        if (setuser(old_uid) < 0 || setuser(old_uid) != old_uid) {
            log_message(LOG_EMERG, pamh,
                        "We switched users from %d to %d, "
                        "but can't switch back",
                        old_uid, uid);
        }
    }
    return rc;
}

#ifndef UNUSED_ATTR
#if __GNUC__ >= 3 || (__GNUC__ == 2 && __GNUC_MINOR__ >= 7)
#define UNUSED_ATTR __attribute__((__unused__))
#else
#define UNUSED_ATTR
#endif
#endif

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags UNUSED_ATTR, int argc, const char **argv) {
    return google_authenticator(pamh, argc, argv);
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh UNUSED_ATTR, int flags UNUSED_ATTR, int argc UNUSED_ATTR, const char **argv UNUSED_ATTR) {
    return PAM_SUCCESS;
}

#ifdef PAM_STATIC
struct pam_module _pam_listfile_modstruct = {MODULE_NAME, pam_sm_authenticate, pam_sm_setcred, NULL, NULL, NULL, NULL};
#endif
