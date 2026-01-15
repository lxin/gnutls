#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#if defined(_WIN32)

int main(void)
{
	exit(77);
}

#else

#include <linux/quic.h>
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

#ifndef SOL_QUIC
#define SOL_QUIC	288
#endif

#define SESSIONS 3
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

struct storage_st {
	gnutls_datum_t entries[SESSIONS];
	size_t num_entries;
};

static int storage_add(void *ptr, time_t expires, const gnutls_datum_t *key,
		       const gnutls_datum_t *value)
{
	struct storage_st *storage = ptr;
	gnutls_datum_t *datum;
	size_t i;

	for (i = 0; i < storage->num_entries; i++) {
		if (key->size == storage->entries[i].size &&
		    memcmp(storage->entries[i].data, key->data, key->size) ==
			    0) {
			return GNUTLS_E_DB_ENTRY_EXISTS;
		}
	}

	/* If the maximum number of ClientHello exceeded, reject early
	 * data until next time.
	 */
	if (storage->num_entries == SESSIONS)
		return GNUTLS_E_DB_ERROR;

	datum = &storage->entries[storage->num_entries];
	datum->data = gnutls_malloc(key->size);
	if (!datum->data)
		return GNUTLS_E_MEMORY_ERROR;
	memcpy(datum->data, key->data, key->size);
	datum->size = key->size;

	storage->num_entries++;

	return 0;
}

static void storage_clear(struct storage_st *storage)
{
	size_t i;

	for (i = 0; i < storage->num_entries; i++)
		gnutls_free(storage->entries[i].data);
	storage->num_entries = 0;
}

static void client(int fds[], const char *prio)
{
	gnutls_certificate_credentials_t x509_cred;
	gnutls_datum_t session_data, tp_param;
	struct quic_transport_param param;
	gnutls_session_t session;
	char buffer[MAX_BUF + 1];
	unsigned int len;
	int fd, t, ret;

	param.remote = 1;
	tp_param.data = (unsigned char *)&param;
	tp_param.size = sizeof(param);

	global_init();

	if (debug) {
		gnutls_global_set_log_function(client_log_func);
		gnutls_global_set_log_level(7);
	}

	gnutls_certificate_allocate_credentials(&x509_cred);

	for (t = 0; t < SESSIONS; t++) {
		fd = fds[t];

		gnutls_init(&session, GNUTLS_CLIENT | GNUTLS_ENABLE_EARLY_DATA);
		gnutls_handshake_set_timeout(session, 0);

		assert(gnutls_priority_set_direct(session, prio, NULL) >= 0);

		gnutls_credentials_set(session, GNUTLS_CRD_CERTIFICATE, x509_cred);

		gnutls_transport_set_int(session, fd);

		if (t > 0) {
			/* Set session ticket and QUIC transport parameter. */
			gnutls_session_set_data(session, session_data.data, session_data.size);

			ret = setsockopt(fd, SOL_QUIC, QUIC_SOCKOPT_TRANSPORT_PARAM,
					 tp_param.data, tp_param.size);
			if (ret)
				fail("client: Setting TP param failed\n");

			/* Send stream data as early data. */
			ret = send(fd, MSG, sizeof(MSG), MSG_SYN | MSG_FIN);
			if (ret < 0)
				fail("client: data sending has failed (%s)\n", strerror(errno));
		}

		ret = gnutls_quic_handshake(session);
		if (ret < 0)
			fail("client: Handshake has failed (%s)\n", gnutls_strerror(ret));

		if (debug)
			success("client: Handshake was completed\n");

		if (t == 0) {
			/* Send stream data. */
			ret = send(fd, MSG, sizeof(MSG), MSG_SYN | MSG_FIN);
			if (ret < 0)
				fail("client: data sending has failed (%s)\n", strerror(errno));
			recv(fd, NULL, 0, 0);

			/* Get session ticket and QUIC transport parameter. */
			len = sizeof(buffer);
			ret = getsockopt(fd, SOL_QUIC, QUIC_SOCKOPT_SESSION_TICKET, buffer, &len);
			if (ret || !len)
				fail("client: Receiving New Session Ticket Msg failed %d\n", len);

			ret = gnutls_handshake_write(session, GNUTLS_ENCRYPTION_LEVEL_APPLICATION,
						     buffer, len);
			if (ret)
				fail("client: Parsing New Session Ticket Msg failed\n");

			ret = gnutls_session_get_data2(session, &session_data);
			if (ret)
				fail("client: Getting resume data failed\n");

			ret = getsockopt(fd, SOL_QUIC, QUIC_SOCKOPT_TRANSPORT_PARAM,
					 tp_param.data, &tp_param.size);
			if (ret)
				fail("client: Getting TP param failed\n");
		}

		recv(fd, NULL, 0, 0);

		close(fd);

		gnutls_deinit(session);
	}

	gnutls_certificate_free_credentials(x509_cred);

	gnutls_global_deinit();
}

static void server(int fds[], const char *prio)
{
	gnutls_certificate_credentials_t x509_cred;
	gnutls_datum_t session_ticket_key = {};
	gnutls_anti_replay_t anti_replay;
	struct storage_st storage = {};
	gnutls_session_t session;
	char buffer[MAX_BUF + 1];
	int fd, t, ret;

	global_init();

	if (debug) {
		gnutls_global_set_log_function(server_log_func);
		gnutls_global_set_log_level(7);
	}

	gnutls_certificate_allocate_credentials(&x509_cred);
	gnutls_certificate_set_x509_key_mem(x509_cred, &server_cert, &server_key,
					    GNUTLS_X509_FMT_PEM);

	gnutls_session_ticket_key_generate(&session_ticket_key);

	ret = gnutls_anti_replay_init(&anti_replay);
	if (ret < 0)
		fail("server: failed to initialize anti-replay\n");

	gnutls_anti_replay_set_add_function(anti_replay, storage_add);
	gnutls_anti_replay_set_ptr(anti_replay, &storage);

	for (t = 0; t < SESSIONS; t++) {
		fd = accept(fds[t], NULL, NULL);
		if (fd < 0)
			fail("server: error in accept(): %s\n", strerror(errno));
		close(fds[t]);

		gnutls_init(&session, GNUTLS_SERVER | GNUTLS_ENABLE_EARLY_DATA);
		gnutls_handshake_set_timeout(session, 0);

		assert(gnutls_priority_set_direct(session, prio, NULL) >= 0);

		gnutls_credentials_set(session, GNUTLS_CRD_CERTIFICATE, x509_cred);

		gnutls_session_ticket_enable_server(session, &session_ticket_key);

		gnutls_anti_replay_enable(session, anti_replay);

		gnutls_record_set_max_early_data_size(session, MAX_BUF);

		gnutls_transport_set_int(session, fd);

		ret = gnutls_quic_handshake(session);
		if (ret < 0)
			fail("server: Handshake has failed (%s)\n", gnutls_strerror(ret));

		if (debug)
			success("server: Handshake was completed\n");

		ret = recv(fd, buffer, sizeof(buffer), 0);
		if (ret < 0)
			fail("server: data receiving has failed (%s)\n", strerror(errno));

		if (strncmp(buffer, MSG, ret))
			fail("server: Message doesn't match\n");

		if (debug)
			success("server: messages received\n");

		close(fd);

		gnutls_deinit(session);
	}

	gnutls_anti_replay_deinit(anti_replay);

	storage_clear(&storage);

	gnutls_free(session_ticket_key.data);

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
	int client_fd[SESSIONS], listen_fd[SESSIONS], i;

	success("running quic test with %s\n", prio);

	signal(SIGCHLD, ch_handler);
	signal(SIGPIPE, SIG_IGN);

	for (i = 0; i < SESSIONS; i++)
		create_quic_socket_pair(&client_fd[i], &listen_fd[i]);

	child = fork();
	if (child < 0)
		fail("error in fork(): %s\n", strerror(errno));

	if (child) {
		/* parent */
		int status;

		for (i = 0; i < SESSIONS; i++)
			close(client_fd[i]);

		server(listen_fd, prio);

		wait(&status);
		check_wait_status(status);
	} else {
		for (i = 0; i < SESSIONS; i++)
			close(listen_fd[i]);

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
