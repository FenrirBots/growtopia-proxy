#include <stdlib.h>
#include <stdio.h>

#include "log.h"
#include "http/http.h"
#include "../res/resource.h"

/* Log Template: "[%i:%s]: %s", __LINE__, __FILE__ */

/* DONE: Remove the DEBUG_LOG function and replace with a more neuteral function like printf_log which has optional debugging features */
/* TODO: Add macros for log functions (ie. log_error, log_warning, log_message) and improve logging */
/* TODO: Add a proper way to search for a specific certificate in the store */
/* TODO: Lookup how a HTTPS Authentication is supposed to he handled */
/* TODO: Check for administrator privilages and request raised privilages if missing */
int main(int argc, char **argv) {
	struct http_instance server;
	struct http_certificate cert;

	server.port = "443";
	server.address = "127.0.0.1";
	server.queue = 1;
	cert.location = "My";
	cert.subject = "growtopia1.com";
	cert.issuer = "growtopia1.com";

	/* Something simple to show that the application is running (Stole this from yuhkil)*/
	printf("Anubis Proxy 1.0.0 (tags/v1.0.0:beta)\n");
  	printf("Type 'help', 'copyright', 'credits' or 'license' for more information\n");

	if (http_server_initialize(&server) == 0) {
		return 0;
	}

	if (http_certificate_initialize(&server, &cert) == 0) {
		return 0;
	}

	printf("Server initialized\n");
	while (TRUE) {
		if (http_server_listen(&server) == 0) {
			return 0;
		}

		printf("Waiting for a connection...\n");
		if (http_server_accept(&server) == 0) {
			return 0;
		}

		printf("Connection recieved, Attempting to authenticate...\n");
		if (http_server_authenticate(&server) == 0) {
			return 0;
		}

		while (TRUE) {

		}
	}

	return 0;

	(void) argc;
	(void) argv;
}