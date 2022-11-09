/*
 * pam_single_kcm_cache module
 *
 * Written Konrad Bucheli 2022-09-22
 * Inspired by Dave Kinchlea <kinch@kinch.ark.com>, who also supplied the
 * template for this file (via pam_env)
 */


#include "config.h"

#include <ctype.h>
#include <errno.h>
#include <krb5.h>
#include <pwd.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <sys/time.h>
#include <unistd.h>

#include <security/pam_modules.h>
#include <security/pam_modutil.h>
#include <security/_pam_macros.h>
#include <security/pam_ext.h>

#define PAM_DEBUG_ARG                   0x01

/* inspiration: https://github.com/Perl/perl5/blob/v5.22.0/util.c#L4488 */
void seed() {
    struct timeval when;
    unsigned int seed;

    gettimeofday(&when, NULL);

    seed = 1000003 * when.tv_sec + 3 * when.tv_usec;
    seed += 269 * getpid();
    seed += 26107 * (unsigned int) (unsigned long long) &when;
    srand(seed);
}

static int
pam_parse (const pam_handle_t *pamh, int argc, const char **argv, char **cc_suffix)
{
    int ctrl=0;

    *cc_suffix = NULL;

    char option_suffix[] = "suffix=";
    size_t option_suffix_len = sizeof(option_suffix)-1;

    /* step through arguments */
    for (; argc-- > 0; ++argv) {

        /* generic options */
        if (!strcmp(*argv, "debug"))
            ctrl |= PAM_DEBUG_ARG;

        /* random credential cache name */
        else if (!strcmp(*argv, "random")) {
            static const int a = 'a',  z= 'z';
            char key[11];
            seed();
            for(unsigned int i = 0; i < sizeof key - 1; i++) {
                key[i] = (char) (rand() % (z - a + 1) + a);
            }
            key[sizeof key - 1] = '\0';
            *cc_suffix = strdup(key);
        }
        /* fixed credential cache name */
        else if (strncmp(*argv, option_suffix, option_suffix_len) == 0) {
            const char *str = *argv + option_suffix_len;
            if (str[0] == '\0') {
                pam_syslog(pamh, LOG_ERR, "suffix= specification missing argument - ignored");
            }
            else {
                *cc_suffix = strdup(str);
            }
        }
    }

    return ctrl;
}

/** start copy from krb5 source code **/

/* Some data comparison and conversion functions.  */
static inline int
data_eq(krb5_data d1, krb5_data d2)
{
    return (d1.length == d2.length
        && (d1.length == 0 || !memcmp(d1.data, d2.data, d1.length)));
}

static inline int
data_eq_string (krb5_data d, const char *s)
{
    return (d.length == strlen(s)
        && (d.length == 0 || !memcmp(d.data, s, d.length)));
}

/* Return true if a comes after b. */
static inline krb5_boolean
ts_after(krb5_timestamp a, krb5_timestamp b)
{
    return (uint32_t)a > (uint32_t)b;
}


/* Return true if princ is the local krbtgt principal for local_realm. */
static krb5_boolean
is_local_tgt(krb5_principal princ, krb5_data *realm)
{
    return princ->length == 2
        && data_eq(princ->realm, *realm)
        && data_eq_string(princ->data[0], KRB5_TGS_NAME)
        && data_eq(princ->data[1], *realm);
}

/** end copy from krb5 source code **/


/* returns TGT */
static krb5_boolean
get_ccache_tgt(krb5_context context, krb5_ccache cache, krb5_creds *tgt)
{
    krb5_error_code ret;
    krb5_cc_cursor cur;
    krb5_creds creds;
    krb5_principal princ;

    if (krb5_cc_get_principal(context, cache, &princ) != 0)
        return FALSE;
    if (krb5_cc_start_seq_get(context, cache, &cur) != 0)
        return FALSE;
    while ((ret = krb5_cc_next_cred(context, cache, &cur, &creds)) == 0) {
        if (is_local_tgt(creds.server, &princ->realm)) {
            *tgt = creds;
            break;
        }
        else {
            krb5_free_cred_contents(context, &creds);
        }
    }
    krb5_free_principal(context, princ);
    if (krb5_cc_end_seq_get(context, cache, &cur) != 0)
        return FALSE;

    return TRUE;
}


/*
 *    TGT delegation (ssh) stores the new delegated TGT in a new cache KCM:$UID:$RANDOM_NUMBER
 *    new TGTs (after password authentication) end up in whatever (possibly old, could also be new)
 *    cache the KCM selects (and that seems rather random)
 *    iterates through all credential caches and checkes
 *    - if the TGT belongs to the the user ("$username@REALM")
 *    - and that it is not expired
 *    - and it is younger than 10s
 *    => and of them the youngest TGT wins
 *
 *    source_cache parameter will be updated with the winner, to be freed with krb5_cc_close after use
 *    source_cache will be unchanged where there is no match, still the function reports PAM_SUCCESS
 *
 *    source_cache_name is treated similary, it will be updated with the name of the winner cache,
 *    to be freed with krb5_free_string after use
 *    similarly source_cache_name will be unchanged where there is no match
 */
static int
get_best_source_ccache (pam_handle_t *pamh, krb5_context context, const char *username, uid_t uid, krb5_ccache *source_cache, krb5_creds *source_tgt)
{
    krb5_error_code error;
    size_t username_length = strlen(username);

    /* iterate over all credential caches */
    krb5_cccol_cursor cursor;
    error = krb5_cccol_cursor_new(context, &cursor);
    if (error) {
        const char *msg;
        msg = krb5_get_error_message(context, error);
        pam_syslog(pamh, LOG_ERR, "%s while listing ccache collection", msg);
        krb5_free_error_message(context, msg);
        return PAM_SESSION_ERR;
    }

    krb5_ccache cache;
    krb5_ccache overall_youngest_cache = NULL;
    krb5_creds overall_youngest_tgt;
    memset(&overall_youngest_tgt, 0, sizeof(overall_youngest_tgt)); /* https://web.mit.edu/kerberos/krb5-devel/doc/appdev/init_creds.html */
    krb5_timestamp overall_youngest_tgt_ts = 0;
    krb5_timestamp now = time(NULL);
    krb5_timestamp not_older = now - 10;

    while ((error = krb5_cccol_cursor_next(context, cursor, &cache)) == 0 &&
        cache != NULL) {

        /* is the TGT assinged to current user? */
        krb5_principal princ = NULL;
        char *princname = NULL;

        error = krb5_cc_get_principal(context, cache, &princ);
        if (error)  {
            const char *msg;
            msg = krb5_get_error_message(context, error);
            pam_syslog(pamh, LOG_WARNING, "%s while reading principal of credential cache", msg);
            krb5_free_error_message(context, msg);
            krb5_cc_close(context, cache);
            continue;
        }

        error = krb5_unparse_name(context, princ, &princname);
        if (error)  {
            const char *msg;
            msg = krb5_get_error_message(context, error);
            pam_syslog(pamh, LOG_WARNING, "%s while creating principal string", msg);
            krb5_free_error_message(context, msg);
            krb5_free_principal(context, princ);
            krb5_cc_close(context, cache);
            continue;
        }
        krb5_free_principal(context, princ);

        size_t princname_length = strlen(princname);
        if (princname_length <= username_length                     /* principal name has to be longer */
            && strncmp(username, princname, username_length) != 0   /* start with user name */
            && princname[username_length] != '@'                    /* followed by a "@REALM", but we just check the "@" */
        ) {
            krb5_free_unparsed_name(context, princname);
            krb5_cc_close(context, cache);
            continue;
        }
        krb5_free_unparsed_name(context, princname);

        krb5_creds tgt;
        memset(&tgt, 0, sizeof(tgt)); /* https://web.mit.edu/kerberos/krb5-devel/doc/appdev/init_creds.html */
        if (get_ccache_tgt(context, cache, &tgt)) {
            /* check creation and expiration */
            krb5_timestamp tgt_expiration = tgt.times.endtime;
            krb5_timestamp tgt_init = tgt.times.starttime ? tgt.times.starttime : tgt.times.authtime;
            if (ts_after(tgt_expiration, now)
                && ts_after(tgt_init, overall_youngest_tgt_ts)
                && ts_after(tgt_init, not_older)) {

                /* all fine, so lets keep the cache name and expiration */
                if (overall_youngest_cache) {
                    krb5_free_cred_contents(context, &overall_youngest_tgt);
                    krb5_cc_close(context, overall_youngest_cache);
                }
                overall_youngest_cache = cache;
                overall_youngest_tgt = tgt;
                overall_youngest_tgt_ts = tgt_init;
            }
            else {
                krb5_free_cred_contents(context, &tgt);
                krb5_cc_close(context, cache);
            }
        }
        else {
            krb5_free_cred_contents(context, &tgt);
            krb5_cc_close(context, cache);
        }
    }
    if (error) {
        const char *msg;
        msg = krb5_get_error_message(context, error);
        pam_syslog(pamh, LOG_ERR, "%s while reading ccache collection", msg);
        krb5_free_error_message(context, msg);
        if (overall_youngest_cache) {
            krb5_free_cred_contents(context, &overall_youngest_tgt);
            krb5_cc_close(context, overall_youngest_cache);
        }
        krb5_cccol_cursor_free(context, &cursor);
        return PAM_SESSION_ERR;
    }
    krb5_cccol_cursor_free(context, &cursor);

    if (overall_youngest_cache) {
        *source_cache = overall_youngest_cache;
        *source_tgt = overall_youngest_tgt;
    }
    return PAM_SUCCESS;
}

/*
  try to create the predefined cache in Kerberos/KCM
  copy over tickets from newest normal cache
*/
static int
prepare_ccache (pam_handle_t *pamh, const char *cache_name, const char *username, uid_t uid)
{
    int retval = PAM_IGNORE;

    krb5_context context = NULL;
    krb5_error_code error;
    const char *error_msg = NULL;
    krb5_ccache source_cache = NULL;
    krb5_creds source_tgt;
    memset(&source_tgt, 0, sizeof(source_tgt)); /* https://web.mit.edu/kerberos/krb5-devel/doc/appdev/init_creds.html */
    char *source_cache_name = NULL;
    krb5_principal princ = NULL;
    krb5_ccache fixed_cache = NULL;
    krb5_principal test_princ = NULL;
    char *krb5ccname = getenv("KRB5CCNAME");

    /* ensure that we are iterating all KCM */
    if (setenv("KRB5CCNAME", "KCM:", 1) != 0) {
        pam_syslog(pamh, LOG_ERR, "Could not set environemnt variable KRB5CCNAME=KCM: because of %s", strerror(errno));
        retval = PAM_IGNORE;
        goto exit;
    }

    /* initalize Kerberos library */
    error = krb5_init_context(&context);
    if (error) {
        error_msg = krb5_get_error_message(context, error);
        pam_syslog(pamh, LOG_ERR, "%s while initializing krb5", error_msg);
        retval = PAM_IGNORE;
        goto exit;
    }

    /* get current best cache to be able to copy over the delegated credentials */

    retval = get_best_source_ccache(pamh, context, username, uid, &source_cache, &source_tgt);
    if (retval) {
        goto exit; /* let get_best_source_ccache() log the error */
    }

    /* did we by chance hit the cache we actually want? */
    if (source_cache != NULL) {
        error = krb5_cc_get_full_name(context, source_cache, &source_cache_name);
        if (error) {
            error_msg = krb5_get_error_message(context, error);
            pam_syslog(pamh, LOG_WARNING, "%s while reading source cache name", error_msg);
            retval = PAM_IGNORE;
            goto exit;
        }

        if (strcmp(source_cache_name, cache_name) == 0) {
            retval = PAM_SUCCESS;
            goto exit;
        }
    }
    else {
        pam_syslog(pamh, LOG_INFO, "no suitable source cache found");
    }

    /* lets get the principal before we start with a (new?) cache */
    if (source_cache == NULL || krb5_cc_get_principal(context, source_cache, &princ) != 0) {
        /* create the principal from user name if there is no one in the source cache */
        error = krb5_parse_name_flags(context, username, 0, &princ);
        if (error) {
            error_msg = krb5_get_error_message(context, error);
            pam_syslog(pamh, LOG_ERR, "%s while creating principal", error_msg);
            retval = PAM_IGNORE;
            goto exit;
        }
    }

    /* create fixed credential cache */
    error = krb5_cc_resolve(context, cache_name, &fixed_cache);
    if (error) {
        error_msg = krb5_get_error_message(context, error);
        pam_syslog(pamh, LOG_ERR, "%s while getting ccache", error_msg);
        retval = PAM_IGNORE;
        goto exit;
    }

    /* is it already initialized? */
    error = krb5_cc_get_principal(context, fixed_cache, &test_princ);
    if (error)  {
        /* initialize if not */
        error = krb5_cc_initialize(context, fixed_cache, princ);
        if (error) {
            error_msg = krb5_get_error_message(context, error);
            pam_syslog(pamh, LOG_ERR, "%s while initializing credential cache", error_msg);
            retval = PAM_IGNORE;
            goto exit;
        }
    }

    /* insert TGT from source cache (when available) to the fixed cache */
    if (source_cache) {
        error = krb5_cc_store_cred(context, fixed_cache, &source_tgt);
        if (error) {
            error_msg = krb5_get_error_message(context, error);
            pam_syslog(pamh, LOG_ERR, "%s while copying TGT from credential cache '%s' to fixed credential cache '%s'", error_msg, source_cache_name, cache_name);
            retval = PAM_IGNORE;
            goto exit;
        }
        pam_syslog(pamh, LOG_INFO, "Copied TGT from credential cache '%s' to fixed credential cache '%s'", source_cache_name, cache_name);
    }

    retval = PAM_SUCCESS;

exit:
    if (test_princ) krb5_free_principal(context, test_princ);
    if (princ) krb5_free_principal(context, princ);
    if (fixed_cache) krb5_cc_close(context, fixed_cache);
    if (source_cache) krb5_cc_close(context, source_cache);
    krb5_free_cred_contents(context, &source_tgt);
    if (source_cache_name) krb5_free_string(context, source_cache_name);
    if (error_msg) krb5_free_error_message(context, error_msg);
    if (context) krb5_free_context(context);
    if (krb5ccname) setenv("KRB5CCNAME", krb5ccname, 1);
    return retval;
}

static int
set_ideal_kerberos_cc_env (pam_handle_t *pamh, int argc, const char **argv)
{
    char *cc_suffix;
    pam_parse(pamh, argc, argv, &cc_suffix);

    if (!cc_suffix) {
        pam_syslog(pamh, LOG_ERR, "select 'random' or 'suffix=whatever'");
        return PAM_IGNORE;
    }

    /* get some user information */
    const char *username = NULL;
    if (pam_get_item(pamh, PAM_USER, (const void**) &username) != PAM_SUCCESS) {
        free(cc_suffix);
        return PAM_IGNORE;     /* let pam_get_item() log the error */
    }

    struct passwd *user_entry = NULL;
    if (username)
        user_entry = pam_modutil_getpwnam (pamh, username);
    if (!user_entry) {
        pam_syslog(pamh, LOG_ERR, "No such user '%s'!?", username);
        free(cc_suffix);
        return PAM_IGNORE;
    }

    char *target_cache = NULL;
    if (asprintf(&target_cache, "KCM:%d:%s", user_entry->pw_uid, cc_suffix) < 0) {
        pam_syslog(pamh, LOG_CRIT, "Out of memory");
        free(cc_suffix);
        return PAM_BUF_ERR;
    }
    free(cc_suffix);

    pam_syslog(pamh, LOG_INFO, "Using fixed credential cache '%s'", target_cache);

    /* become the user */
    uid_t pam_uid = geteuid();
    if (seteuid(user_entry->pw_uid) != 0) {
        pam_syslog(pamh, LOG_ERR, "Could not change to user '%s': %s", username, strerror(errno));
        free(target_cache);
        return PAM_IGNORE;
    }

    /* ensure that the given credential cache exists at the end
       and whatever has been set up already is copied over  */
    int retval = prepare_ccache(pamh, target_cache, username, user_entry->pw_uid);

    /* go back to root */
    if (seteuid(pam_uid) != 0) {
        pam_syslog(pamh, LOG_ERR, "Could not change back to user root: %s", strerror(errno));
        free(target_cache);
        return PAM_IGNORE;
    }

    if (retval != PAM_SUCCESS) {
        free(target_cache);
        return retval; /* let prepare_ccache() log the error */
    }
    /* set KRB5CCNAME environment variable */
    char *env_entry = NULL;
    if (asprintf(&env_entry, "KRB5CCNAME=%s", target_cache) < 0) {
        pam_syslog(pamh, LOG_CRIT, "Out of memory");
        free(target_cache);
        return PAM_BUF_ERR;
    }
    free(target_cache);

    retval = pam_putenv(pamh, env_entry);
    if (retval != PAM_SUCCESS) {
        pam_syslog(pamh, LOG_ERR, "could not set environment variable %s", env_entry);
    }
    free(env_entry);
    return retval;
}

/* inspiration: https://github.com/linux-pam/linux-pam/blob/v1.5.2/modules/pam_env/pam_env.c#L854 */
/* --- PAM functions (only) --- */

int
pam_sm_authenticate (pam_handle_t *pamh UNUSED, int flags UNUSED,
                     int argc UNUSED, const char **argv UNUSED)
{
    return PAM_IGNORE;
}

int
pam_sm_acct_mgmt (pam_handle_t *pamh, int flags UNUSED,
                  int argc UNUSED, const char **argv UNUSED)
{
    pam_syslog(pamh, LOG_NOTICE, "pam_sm_acct_mgmt called inappropriately");
    return PAM_IGNORE;
}

int
pam_sm_setcred (pam_handle_t *pamh, int flags UNUSED,
                int argc, const char **argv)
{
    return set_ideal_kerberos_cc_env(pamh, argc, argv);
}

int
pam_sm_open_session (pam_handle_t *pamh, int flags UNUSED,
                     int argc, const char **argv)
{
    return set_ideal_kerberos_cc_env(pamh, argc, argv);
}

int
pam_sm_close_session (pam_handle_t *pamh UNUSED, int flags UNUSED,
                      int argc UNUSED, const char **argv UNUSED)
{
    return PAM_SUCCESS;
}

int
pam_sm_chauthtok (pam_handle_t *pamh, int flags UNUSED,
                  int argc UNUSED, const char **argv UNUSED)
{
    pam_syslog(pamh, LOG_NOTICE, "pam_sm_chauthtok called inappropriately");
    return PAM_IGNORE;
}
