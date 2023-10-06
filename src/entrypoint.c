#include <stdlib.h>
#include <stdio.h>

#include "http/http.h"
#include "../res/resource.h"


int main(int argc, char **argv)
{
	struct http_instance server;
	server.port = "443";
	server.address = "127.0.0.1";
	server.queue = 1;

	if (http_server_initialize(&server) == 0) {
		return 0;
	}

	while (TRUE) {
		if (http_server_listen(&server) == 0) {
			return 0;
		}

		if (http_server_accept(&server) == 0) {
			return 0;
		}

		printf("A connection has been established, attempting to authenticate...\n");
		if (http_server_authenticate(&server) == 0) {
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