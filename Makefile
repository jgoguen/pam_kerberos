all:
	$(CC) -Wall -Werror -fpic -lpam -shared -o pam_kerberos.so pam-kerberos.c

install: all
	mv pam_kerberos.so /lib64/security/pam_kerberos.so
