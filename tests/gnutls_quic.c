#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#if defined(_WIN32)

int main(void)
{
	exit(77);
}

#else

#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <errno.h>

#include "cert-common.h"
#include "utils.h"

#ifndef IPPROTO_QUIC
#define IPPROTO_QUIC	261
#endif

#define MAX_BUF 1024
#define MSG "Hello world!"

static pid_t child;

static void ch_handler(int sig)
{
}

static void server_log_func(int level, const char *str)
{
	fprintf(stderr, "server|<%d>| %s", level, str);
}

static void client_log_func(int level, const char *str)
{
	fprintf(stderr, "client|<%d>| %s", level, str);
}

static void client(int fd, const char *prio)
{
	gnutls_certificate_credentials_t x509_cred;
	gnutls_session_t session;
	char buffer[MAX_BUF + 1];
	int ret;

	global_init();

	if (debug) {
		gnutls_global_set_log_function(client_log_func);
		gnutls_global_set_log_level(7);
	}

	gnutls_certificate_allocate_credentials(&x509_cred);

	gnutls_init(&session, GNUTLS_CLIENT);
	gnutls_handshake_set_timeout(session, 0);

	assert(gnutls_priority_set_direct(session, prio, NULL) >= 0);

	gnutls_credentials_set(session, GNUTLS_CRD_CERTIFICATE, x509_cred);

	gnutls_transport_set_int(session, fd);

	ret = gnutls_quic_handshake(session);
	if (ret < 0)
		fail("client: Handshake has failed (%s)\n", gnutls_strerror(ret));

	if (debug)
		success("client: Handshake was completed\n");

	ret = recv(fd, buffer, sizeof(buffer), 0);
	if (ret < 0)
		fail("client: data sending has failed (%s)\n", strerror(errno));

	if (strncmp(buffer, MSG, ret))
		fail("client: Message doesn't match\n");

	if (debug)
		success("client: messages received\n");

	close(fd);

	gnutls_deinit(session);

	gnutls_certificate_free_credentials(x509_cred);

	gnutls_global_deinit();
}

static void server(int fd, const char *prio)
{
	gnutls_certificate_credentials_t x509_cred;
	gnutls_session_t session;
	int ret;

	global_init();

	if (debug) {
		gnutls_global_set_log_function(server_log_func);
		gnutls_global_set_log_level(7);
	}

	gnutls_certificate_allocate_credentials(&x509_cred);
	gnutls_certificate_set_x509_key_mem(x509_cred, &server_cert, &server_key,
					    GNUTLS_X509_FMT_PEM);

	gnutls_init(&session, GNUTLS_SERVER);
	gnutls_handshake_set_timeout(session, 0);

	assert(gnutls_priority_set_direct(session, prio, NULL) >= 0);

	gnutls_credentials_set(session, GNUTLS_CRD_CERTIFICATE, x509_cred);

	gnutls_transport_set_int(session, fd);

	ret = gnutls_quic_handshake(session);
	if (ret < 0)
		fail("server: Handshake has failed (%s)\n", gnutls_strerror(ret));

	if (debug)
		success("server: Handshake was completed\n");

	ret = send(fd, MSG, sizeof(MSG), MSG_SYN | MSG_FIN);
	if (ret < 0)
		fail("server: data sending has failed (%s)\n", strerror(errno));
	recv(fd, NULL, 0, 0);

	close(fd);

	gnutls_deinit(session);

	gnutls_certificate_free_credentials(x509_cred);

	gnutls_global_deinit();

	if (debug)
		success("server: finished\n");
}

static void create_quic_socket_pair(int *client_fd, int *listen_fd)
{
	int client, listener, ret;
	struct sockaddr_in saddr;
	socklen_t addrlen;

	listener = socket(AF_INET, SOCK_STREAM, IPPROTO_QUIC);
	if (listener == -1)
		fail("error in listener(): %s\n", strerror(errno));

	memset(&saddr, 0, sizeof(saddr));
	saddr.sin_family = AF_INET;
	saddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	saddr.sin_port = 0;

	ret = bind(listener, (struct sockaddr *)&saddr, sizeof(saddr));
	if (ret == -1)
		fail("error in bind(): %s\n", strerror(errno));

	addrlen = sizeof(saddr);
	ret = getsockname(listener, (struct sockaddr *)&saddr, &addrlen);
	if (ret == -1)
		fail("error in getsockname(): %s\n", strerror(errno));

	ret = listen(listener, 1);
	if (ret == -1)
		fail("error in listen(): %s\n", strerror(errno));

	client = socket(AF_INET, SOCK_STREAM, IPPROTO_QUIC);
	if (client < 0)
		fail("error in socket(): %s\n", strerror(errno));

	ret = connect(client, (struct sockaddr *)&saddr, addrlen);
	if (ret < 0)
		fail("error in connect(): %s\n", strerror(errno));

	*client_fd = client;
	*listen_fd = listener;
}

static void run(const char *prio)
{
	int client_fd, listen_fd;

	success("running quic test with %s\n", prio);

	signal(SIGCHLD, ch_handler);
	signal(SIGPIPE, SIG_IGN);

	create_quic_socket_pair(&client_fd, &listen_fd);

	child = fork();
	if (child < 0)
		fail("error in fork(): %s\n", strerror(errno));

	if (child) {
		/* parent */
		int server_fd, status;

		close(client_fd);

		server_fd = accept(listen_fd, NULL, NULL);
		if (server_fd < 0)
			fail("server: error in accept(): %s\n", strerror(errno));

		server(server_fd, prio);

		wait(&status);
		check_wait_status(status);
	} else {
		close(listen_fd);

		client(client_fd, prio);

		exit(0);
	}
}

void doit(void)
{
	run("NORMAL:-VERS-ALL:+VERS-TLS1.3:-CIPHER-ALL:+AES-128-GCM:%DISABLE_TLS13_COMPAT_MODE");
	run("NORMAL:-VERS-ALL:+VERS-TLS1.3:-CIPHER-ALL:+AES-256-GCM:%DISABLE_TLS13_COMPAT_MODE");
	if (!gnutls_fips140_mode_enabled())
		run("NORMAL:-VERS-ALL:+VERS-TLS1.3:-CIPHER-ALL:+CHACHA20-POLY1305:%DISABLE_TLS13_COMPAT_MODE");
#if defined(__linux__)
	run("NORMAL:-VERS-ALL:+VERS-TLS1.3:-CIPHER-ALL:+AES-128-CCM:%DISABLE_TLS13_COMPAT_MODE");
#endif
}

#endif /* _WIN32 */
