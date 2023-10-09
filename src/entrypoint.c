#include <stdlib.h>
#include <stdio.h>

#include "http/http.h"
#include "../res/resource.h"

/* TODO: Remove the DEBUG_LOG function and replace with a more neuteral function like printf_log which has optional debugging features */
/* TODO: Add a proper way to search for a specific certificate in the store */
/* TODO: Lookup how a HTTPS Authentication is supposed to he handled */
int main(int argc, char **argv)
{
	struct http_instance server;
	server.port = "443";
	server.address = "127.0.0.1";
	server.queue = 1;

	struct http_certificate cert;
	cert.location = "My";
	cert.subject = "growtopia1.com";
	cert.issuer = "growtopia1.com";

	if (http_server_initialize(&server) == 0) {
		printf("server\n");
		return 0;
	}

	if (http_certificate_initialize(&server, &cert) == 0) {
		printf("cert\n");
		return 0;
	}

	while (TRUE) {
		if (http_server_listen(&server) == 0) {
		printf("listen\n");
			return 0;
		}

		if (http_server_accept(&server) == 0) {
		printf("accept\n");
			return 0;
		}

		printf("A connection has been established, attempting to authenticate...\n");
		if (http_server_authenticate(&server) == 0) {
		printf("auth\n");
			return 0;
		}

		printf("Authentication successfull\n");
		while (TRUE) {

		}
	}

	return 0;

	(void) argc;
	(void) argv;
}