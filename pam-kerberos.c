// vim: set filetype=c syntax=c autoindent noexpandtab sts=2 ts=2 sw=2:
// vim: foldmethod=marker foldmarker=[[[,]]]:

// The MIT License
//
// Copyright (C) 2022 by jgoguen
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.


#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>
#include <security/pam_modules.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "pam-kerberos.h"

#define _(s) s

// Helper functions
void free_password(pam_handle_t *ph, void *password, int pam_status) {
	volatile char *vpassword;
	size_t passwd_len;

	if (!password) {
		return;
	}

	// Optimization defeating
	passwd_len = strlen(password);
	memset(password, 0xAA, passwd_len);
	memset(password, 0xFF, passwd_len);
	vpassword = (volatile char *)password;
	while (*vpassword) {
		*(vpassword++) = 0xBB;
	}

	free(password);
}

int store_password(pam_handle_t *ph, const char *password) {
	if (pam_set_data(ph, PAMKERB_DATA_HANDLE, strdup(password), free_password) != PAM_SUCCESS) {
		syslog(LOG_ERROR, "pam-kerberos: error storing password");
		return PAM_AUTHTOK_RECOVER_ERR;
	}

	return PAM_SUCCESS;
}

int do_kinit(pam_handle_t *ph, const char *password) {
	if (password == NULL) {
		return PAM_AUTH_ERR;
	}

	pid_t waitval;
	int fd[2];
	pipe(fd);

	pid_t forkpid = fork();
	if (forkpid == 0) {
		// Child process
		struct passwd *pwd;
		const char *username;
		pam_get_user(ph, &username, NULL);
		pwd = getpwnam(username);

		close(fd[1]);
		dup2(fd[0], 0);

		syslog(LOG_INFORMATION, "pam-kerberos: dropping privs to %s", username);
		setgid(pwd->pw_gid);
		setuid(pwd->pw_uid);
		setegid(pwd->pw_gid);
		seteuid(pwd->pw_uid);

		execlp("kinit", "kinit", NULL);
	} else if (forkpid == -1) {
		perror("error calling fork()");
	} else {
		// Parent/this process
		close(fd[0]);
		write(fd[1], password, (strlen(password)+1));
		close(fd[1]);
		syslog(LOG_INFORMATION, "waiting for kinit");
		waitval = wait(NULL);
		syslog(LOG_INFORMATION, "kinit done");

		if (waitval == -1) {
			syslog(LOG_WARN, "pam-kerberos: kinit failed");
			return PAM_AUTHINFO_UNAVAIL;
		}
	}

	return PAM_SUCCESS;
}


// PAM functions
PAM_EXTERN int
pam_sm_authenticate(pam_handle_t *ph, int flags, int argc, const char **argv) {
	const char *password;
	int retval;

	// Look up the password
	retval = pam_get_item(ph, PAM_AUTHTOK, (const void **)&password);
	if (retval != PAM_SUCCESS || password == NULL) {
		if (retval == PAM_SUCCESS) {
			syslog(LOG_WARN, "pam-kerberos: no password is available");
		} else {
			syslog(LOG_WARN, "pam-kerberos: no password is available: %s", pam_strerror(ph, retval));
		}

		return PAM_SUCCESS;
	}

	retval = do_kinit(ph, password);
	if (retval != PAM_SUCCESS) {
		// If kinit failed, store the password. That will be our signal to retry
		// when the session is opened.
		retval = store_password(ph, password);
		if (retval == PAM_SUCCESS) {
			syslog(LOG_INFORMATION, "pam-kerberos: stored password for session use");
		}
	}

	return PAM_SUCCESS;
}

PAM_EXTERN int
pam_sm_open_session(pam_handle_t *ph, int flags, int argc, const char **argv) {
	const char *password = NULL;

	// Try to get the password
	if (pam_get_data(ph, PAMKERB_DATA_HANDLE, (const void **)&password) != PAM_SUCCESS) {
		password = NULL;
	}

	if (password != NULL) {
		// If the password isn't NULL, kinit failed during auth and we should try
		// again in the session.
		syslog(LOG_INFORMATION, "pam-kerberos: retrieved password");
		do_kinit(ph, password);
	}

	if (password && store_password(ph, NULL) != PAM_SUCCESS) {
		syslog(LOG_ERROR, "pam-kerberos: error destroying the password");
	} else {
		syslog(LOG_INFORMATION, "pam-kerberos: password destroyed");
	}

	return PAM_SUCCESS;
}

PAM_EXTERN int
pam_sm_setcred (pam_handle_t * ph, int flags, int argc, const char **argv)
{
	return PAM_SUCCESS;
}

PAM_EXTERN int
pam_sm_close_session (pam_handle_t *ph, int flags, int argc, const char **argv)
{
	/* Nothing to do, but we have to have this function exported */
	return PAM_SUCCESS;
}
