@ECHO OFF
	SETLOCAL
		SET CFLAGS=-pthread -lpthread -I./src
		SET CLIBS=-lwininet -lws2_32 -lsecur32 -lcrypt32

		:: Server Data
		GCC %CFLAGS% -c -std=c99 src/tests/server_data.c -o bin/int/tests/server_data.o
		GCC -o bin/out/tests/server_data.exe bin/int/tests/server_data.o %CLIBS%

		:: Main Application
		@REM LD -r -b binary -o bin/int/growtopia_certificate.o res/growtopia_certificate.crt res/growtopia_certificate.pem
		WINDRES -i res/resource.rc -o bin/int/resources.o
		GCC %CFLAGS% -c -std=c99 src/entrypoint.c -o bin/int/entrypoint.o
		GCC %CFLAGS% -c -std=c99 src/http/http_server.c -o bin/int/http_server.o
		GCC %CFLAGS% -c -std=c99 src/http/http_certificate.c -o bin/int/http_certificate.o
		GCC -o bin/out/proxy.exe bin/int/entrypoint.o bin/int/http_server.o bin/int/http_certificate.o bin/int/resources.o %CLIBS%
	ENDLOCAL
:EOF