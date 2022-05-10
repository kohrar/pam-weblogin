#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

#include <security/pam_appl.h>
#include <security/pam_modules.h>

#include <json.h>

#include "utils.h"
#include "config.h"
#include "http.h"

/* expected hook */
PAM_EXTERN int pam_sm_setcred(UNUSED pam_handle_t *pamh, UNUSED int flags, UNUSED int argc, UNUSED const char *argv[])
{
	// printf("Setcred\n");
	return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_acct_mgmt(UNUSED pam_handle_t *pamh, UNUSED int flags, UNUSED int argc, UNUSED const char *argv[])
{
	// printf("Acct mgmt\n");
	return PAM_SUCCESS;
}

/* expected hook, this is where custom stuff happens */
PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, UNUSED int flags, int argc, const char *argv[])
{
	log_message(LOG_INFO, pamh, "Start of pam_websso");

	// Read username
	const char *username;
	if (pam_get_user(pamh, &username, "Username: ") != PAM_SUCCESS)
	{
		log_message(LOG_ERR, pamh, "Error getting user");
		return PAM_SYSTEM_ERR;
	}

	// Read configuration file
	Config *cfg = NULL;
	if (!(cfg = getConfig(pamh, (argc > 0) ? argv[0] : "/etc/pam-websso.conf")))
	{
		conv_info(pamh, "Error reading conf");
		return PAM_SYSTEM_ERR;
	}
	/*
		log_message(LOG_INFO, pamh, "cfg->url: '%s'\n", cfg->url);
		log_message(LOG_INFO, pamh, "cfg->token: '%s'\n", cfg->token);
		log_message(LOG_INFO, pamh, "cfg->attribute: '%s'\n", cfg->attribute);
		log_message(LOG_INFO, pamh, "cfg->cache_duration: '%s'\n", cfg->cache_duration);
		log_message(LOG_INFO, pamh, "cfg->retries: '%d'\n", cfg->retries);
	*/
	// Prepare full req url...
	char *url = NULL;
	asprintf(&url, "%s/start", cfg->url);

	// Prepare req input data...
	char *data = NULL;
	asprintf(&data, "{\"user\":\"%s\",\"attribute\":\"%s\",\"cache_duration\":\"%d\"}",
			 username, cfg->attribute, cfg->cache_duration);

	// Request auth session_id/challenge
	char *req = NULL;
	int rc = postURL(url, cfg->token, data, &req);
	free(url);
	free(data);

	if (!rc)
	{
		log_message(LOG_ERR, pamh, "Error making request");
		conv_info(pamh, "Could not contact auth server");
		freeConfig(cfg);
		return PAM_SYSTEM_ERR;
	}

	log_message(LOG_INFO, pamh, "req: %s", req);

	// Parse response
	json_char *json = (json_char *)req;
	json_value *value = json_parse(json, strlen(json));
	free(req);

	char *session_id = getString(value, "session_id");
	char *challenge = getString(value, "challenge");
	bool cached = getBool(value, "cached");
	free(value);
	/*
		log_message(LOG_INFO, pamh, "session_id: %s\n", session_id);
		log_message(LOG_INFO, pamh, "challenge: %s\n", challenge);
		log_message(LOG_INFO, pamh, "cached: %s\n", cached ? "true" : "false");
	*/
	if (cached)
	{
		conv_info(pamh, "You were cached!");
		freeConfig(cfg);
		free(session_id);
		free(challenge);
		return PAM_SUCCESS;
	}

	/* Pin challenge Conversation */
	conv_info(pamh, challenge);
	free(challenge);

	int retval = PAM_AUTH_ERR;
	bool timeout = false;

	for (unsigned retry = 0; (retry < cfg->retries) &&
							 (retval != PAM_SUCCESS) &&
							 !timeout;
		 ++retry)
	{
		char *rpin = conv_read(pamh, "Pin: ", PAM_PROMPT_ECHO_OFF);

		/* Prepare URL... */
		asprintf(&url, "%s/check-pin", cfg->url);

		/* Prepare auth input data... */
		asprintf(&data, "{\"session_id\":\"%s\",\"rpin\":\"%s\"}", session_id, rpin);
		free(rpin);

		/* Request auth result */
		char *auth = NULL;
		rc = postURL(url, cfg->token, data, &auth);
		free(url);
		free(data);

		if (!rc)
		{
			log_message(LOG_ERR, pamh, "Error making request");
			conv_info(pamh, "Could not contact auth server");
			retval = PAM_SYSTEM_ERR;
			break;
		}

		log_message(LOG_INFO, pamh, "auth: %s\n", auth);

		/* Parse auth result */
		json = (json_char *)auth;
		value = json_parse(json, strlen(json));
		free(auth);

		char *auth_result = getString(value, "result");
		char *auth_msg = getString(value, "msg");
		free(value);

		conv_info(pamh, auth_msg);

		log_message(LOG_INFO, pamh, "auth_result: %s\n", auth_result);
		log_message(LOG_INFO, pamh, "auth_msg: %s\n", auth_msg);

		if (auth_result)
		{
			retval = !strcmp(auth_result, "SUCCESS") ? PAM_SUCCESS : PAM_AUTH_ERR;
			timeout = !strcmp(auth_result, "TIMEOUT");
		}

		free(auth_result);
		free(auth_msg);
	}

	free(session_id);
	freeConfig(cfg);
	return retval;
}
