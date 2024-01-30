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

#ifndef PAMKERBEROS_H_
#define PAMKERBEROS_H_

#include <syslog.h>

#ifndef PAMKERB_DATA_HANDLE
#define PAMKERB_DATA_HANDLE "pamkerb_system_authtok"
#endif

#ifndef PAM_EXTERN
#ifdef PAM_STATIC
#define PAM_EXTERN static
#else
#define PAM_EXTERN extern
#endif
#endif

#ifndef LOG_AUTHPRIV
#define LOG_AUTHPRIV LOG_AUTH
#endif

#define LOG_ERROR (LOG_ERR | LOG_AUTHPRIV)
#define LOG_WARN (LOG_WARNING | LOG_AUTHPRIV)
#define LOG_INFORMATION (LOG_INFO | LOG_AUTHPRIV)

void free_password(pam_handle_t *ph, void *password, int pam_status);
int store_password(pam_handle_t *ph, const char *password);
int do_kinit(pam_handle_t *ph, const char *password);

PAM_EXTERN int
pam_sm_authenticate(pam_handle_t *ph, int flags, int argc, const char **argv);

PAM_EXTERN int
pam_sm_open_session(pam_handle_t *ph, int flags, int argc, const char **argv);

PAM_EXTERN int
pam_sm_setcred (pam_handle_t * ph, int flags, int argc, const char **argv);

PAM_EXTERN int
pam_sm_close_session (pam_handle_t *ph, int flags, int argc, const char **argv);

#endif
