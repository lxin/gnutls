/*
 * Copyright (C) 2026 Red Hat, Inc.
 *
 * Author: Xin Long
 *
 * This file is part of GnuTLS.
 *
 * The GnuTLS is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * as published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>
 *
 */

/* Functions that relate to the QUIC handshake procedure.
 */

#include "config.h"

#ifdef ENABLE_QUIC

#include <linux/quic.h>
#include <linux/tls.h>
#include <errno.h>

#include "record.h"

#ifndef SOL_QUIC
#define SOL_QUIC		288
#endif

#ifndef IPPROTO_QUIC
#define IPPROTO_QUIC		261
#endif

#define QUIC_TLSEXT_TP_PARAM	0x39u
#define QUIC_TLSEXT_TP_MAXLEN	256

static const gnutls_record_encryption_level_t gnutls_quic_to_crypto_levels[QUIC_CRYPTO_MAX] = {
	[QUIC_CRYPTO_APP]	= GNUTLS_ENCRYPTION_LEVEL_APPLICATION,
	[QUIC_CRYPTO_INITIAL]	= GNUTLS_ENCRYPTION_LEVEL_INITIAL,
	[QUIC_CRYPTO_HANDSHAKE]	= GNUTLS_ENCRYPTION_LEVEL_HANDSHAKE,
	[QUIC_CRYPTO_EARLY]	= GNUTLS_ENCRYPTION_LEVEL_EARLY,
};

static const uint8_t gnutls_quic_from_crypto_levels[GNUTLS_ENCRYPTION_LEVEL_APPLICATION + 1] = {
	[GNUTLS_ENCRYPTION_LEVEL_INITIAL]	= QUIC_CRYPTO_INITIAL,
	[GNUTLS_ENCRYPTION_LEVEL_EARLY]		= QUIC_CRYPTO_EARLY,
	[GNUTLS_ENCRYPTION_LEVEL_HANDSHAKE]	= QUIC_CRYPTO_HANDSHAKE,
	[GNUTLS_ENCRYPTION_LEVEL_APPLICATION]	= QUIC_CRYPTO_APP,
};

static uint32_t gnutls_quic_from_cipher_type(gnutls_cipher_algorithm_t cipher)
{
	switch (cipher) {
	case GNUTLS_CIPHER_AES_128_GCM:
		return TLS_CIPHER_AES_GCM_128;
	case GNUTLS_CIPHER_AES_128_CCM:
		return TLS_CIPHER_AES_CCM_128;
	case GNUTLS_CIPHER_AES_256_GCM:
		return TLS_CIPHER_AES_GCM_256;
	case GNUTLS_CIPHER_CHACHA20_POLY1305:
		return TLS_CIPHER_CHACHA20_POLY1305;
	default:
		return gnutls_assert_val(0);
	}
}

static int gnutls_quic_tp_recv(gnutls_session_t session, const uint8_t *buf, size_t len)
{
	int sockfd = gnutls_transport_get_int(session);

	if (setsockopt(sockfd, SOL_QUIC, QUIC_SOCKOPT_TRANSPORT_PARAM_EXT, buf, len))
		return gnutls_assert_val(GNUTLS_E_INTERNAL_ERROR);

	return GNUTLS_E_SUCCESS;
}

static int gnutls_quic_tp_send(gnutls_session_t session, gnutls_buffer_t extdata)
{
	int sockfd = gnutls_transport_get_int(session);
	uint8_t buf[QUIC_TLSEXT_TP_MAXLEN];
	unsigned int len;

	len = sizeof(buf);
	if (getsockopt(sockfd, SOL_QUIC, QUIC_SOCKOPT_TRANSPORT_PARAM_EXT, buf, &len))
		return gnutls_assert_val(GNUTLS_E_INTERNAL_ERROR);

	return gnutls_buffer_append_data(extdata, buf, len);
}

static int gnutls_quic_secret_set(gnutls_session_t session, gnutls_record_encryption_level_t level,
				  const void *rx_secret, const void *tx_secret, size_t secretlen)
{
	gnutls_cipher_algorithm_t type  = gnutls_cipher_get(session);
	struct quic_crypto_secret secret = {};
	int sockfd, ret, len = sizeof(secret);

	if (secretlen > QUIC_CRYPTO_SECRET_BUFFER_SIZE)
		return gnutls_assert_val(GNUTLS_E_UNEXPECTED_PACKET_LENGTH);

	if (level == GNUTLS_ENCRYPTION_LEVEL_EARLY)
		type = gnutls_early_cipher_get(session);

	sockfd = gnutls_transport_get_int(session);
	secret.level = gnutls_quic_from_crypto_levels[level];
	secret.type = gnutls_quic_from_cipher_type(type);
	if (tx_secret) {
		secret.send = 1;
		memcpy(secret.secret, tx_secret, secretlen);
		ret = setsockopt(sockfd, SOL_QUIC, QUIC_SOCKOPT_CRYPTO_SECRET, &secret, len);
		gnutls_memset(secret.secret, 0, secretlen);
		if (ret)
			return gnutls_assert_val(GNUTLS_E_INTERNAL_ERROR);
	}
	if (rx_secret) {
		secret.send = 0;
		memcpy(secret.secret, rx_secret, secretlen);
		ret = setsockopt(sockfd, SOL_QUIC, QUIC_SOCKOPT_CRYPTO_SECRET, &secret, len);
		gnutls_memset(secret.secret, 0, secretlen);
		if (ret)
			return gnutls_assert_val(GNUTLS_E_INTERNAL_ERROR);
	}

	return GNUTLS_E_SUCCESS;
}

static int gnutls_quic_msg_read(gnutls_session_t session, gnutls_record_encryption_level_t level,
				gnutls_handshake_description_t htype, const void *data, size_t len)
{
	char outcmsg[CMSG_SPACE(sizeof(struct quic_handshake_info))];
	int flags, sockfd = gnutls_transport_get_int(session);
	struct quic_handshake_info *info;
	struct msghdr outmsg;
	struct cmsghdr *cmsg;
	struct iovec iov;
	ssize_t ret;

	flags = session->internals.handshake_send_buffer.byte_length > len ? MSG_MORE : 0;
	while (len) {
		iov.iov_base = (void *)data;
		iov.iov_len  = len;

		memset(&outmsg, 0, sizeof(outmsg));
		outmsg.msg_iov = &iov;
		outmsg.msg_iovlen = 1;
		outmsg.msg_control = outcmsg;
		outmsg.msg_controllen = sizeof(outcmsg);

		cmsg = CMSG_FIRSTHDR(&outmsg);
		cmsg->cmsg_level = SOL_QUIC;
		cmsg->cmsg_type  = QUIC_HANDSHAKE_INFO;
		cmsg->cmsg_len   = CMSG_LEN(sizeof(*info));

		info = (struct quic_handshake_info *)CMSG_DATA(cmsg);
		info->crypto_level = gnutls_quic_from_crypto_levels[level];
		ret = sendmsg(sockfd, &outmsg, flags);
		if (ret <= 0) {
			switch (errno) {
			case EINTR:
				ret = GNUTLS_E_INTERRUPTED;
				break;
			case EAGAIN:
				ret = GNUTLS_E_AGAIN;
				break;
			default:
				ret = gnutls_assert_val(GNUTLS_E_INTERNAL_ERROR);
				break;
			}
			return ret;
		}
		len -= ret;
	}

	return GNUTLS_E_SUCCESS;
}

static int gnutls_quic_handshake_process(gnutls_session_t session, uint8_t level,
					 void *data, ssize_t len)
{
	int ret;

	if (data) {
		ret = gnutls_handshake_write(session, gnutls_quic_to_crypto_levels[level],
					     data, len);
		if (ret != GNUTLS_E_SUCCESS) {
			if (!gnutls_error_is_fatal(ret))
				return GNUTLS_E_SUCCESS;
			return ret;
		}
	}

	ret = gnutls_handshake(session);
	if (ret != GNUTLS_E_SUCCESS) {
		if (!gnutls_error_is_fatal(ret))
			return GNUTLS_E_SUCCESS;
	}
	return ret;
}

static int gnutls_quic_handshake_run(gnutls_session_t session)
{
	char incmsg[CMSG_SPACE(sizeof(struct quic_handshake_info))];
	ssize_t ret, len = max_record_recv_size(session);
	int sockfd = gnutls_transport_get_int(session);
	struct quic_handshake_info *info;
	struct cmsghdr *cmsg;
	struct msghdr inmsg;
	struct iovec iov;
	void *data;

	if (session->internals.handshake_in_progress) {
		if (session->internals.handshake_send_buffer.byte_length > 0) {
			ret = _gnutls_handshake_io_write_flush(session);
			if (ret != GNUTLS_E_SUCCESS)
				return ret;
		}
	} else if (!IS_SERVER(session)) {
		ret = gnutls_quic_handshake_process(session, 0, NULL, 0);
		if (ret != GNUTLS_E_SUCCESS)
			return ret;
	}

	data = gnutls_malloc(len);
	if (!data)
		return gnutls_assert_val(GNUTLS_E_MEMORY_ERROR);

	do {
		iov.iov_base = data;
		iov.iov_len = len;

		memset(&inmsg, 0, sizeof(inmsg));
		inmsg.msg_iov = &iov;
		inmsg.msg_iovlen = 1;
		inmsg.msg_control = incmsg;
		inmsg.msg_controllen = sizeof(incmsg);

		ret = recvmsg(sockfd, &inmsg, 0);
		if (ret <= 0) {
			switch (errno) {
			case EINTR:
				ret = GNUTLS_E_INTERRUPTED;
				break;
			case EAGAIN:
				ret = GNUTLS_E_AGAIN;
				break;
			default:
				ret = gnutls_assert_val(GNUTLS_E_INTERNAL_ERROR);
				break;
			}
			break;
		}

		cmsg = CMSG_FIRSTHDR(&inmsg);
		if (!cmsg || cmsg->cmsg_level != SOL_QUIC ||
		    cmsg->cmsg_type != QUIC_HANDSHAKE_INFO) {
			ret = gnutls_assert_val(GNUTLS_E_INTERNAL_ERROR);
			break;
		}

		info = (struct quic_handshake_info *)CMSG_DATA(cmsg);
		ret = gnutls_quic_handshake_process(session, info->crypto_level, data, ret);
		if (ret != GNUTLS_E_SUCCESS)
			break;
	} while (!session->internals.initial_negotiation_completed);

	gnutls_free(data);
	return ret;
}

/**
 * gnutls_quic_handshake:
 * @session: a #gnutls_session_t initialized for QUIC transport.
 *
 * Perform a TLS 1.3 handshake over a QUIC transport.
 *
 * This function integrates GnuTLS with a kernel QUIC stack. The TLS session provided by
 * @session is used to configure TLS-level parameters and to drive the handshake logic in
 * userspace.
 *
 * During the handshake, this function:
 *
 * - Registers the TLS QUIC Transport Parameters extension and exchanges transport
 *   parameters with the kernel.
 *
 * - Exchanges raw TLS handshake messages with the kernel using sendmsg() and recvmsg(),
 *   carrying QUIC-specific ancillary data that indicates the corresponding QUIC encryption
 *   level.
 *
 * - Provisions QUIC traffic secrets for the different crypto levels to the kernel as
 *   they become available.
 *
 * The QUIC socket file descriptor MUST be associated with @session prior to calling this
 * function (e.g., via gnutls_transport_set_int()).
 *
 * On successful completion, the TLS handshake is complete and all keys required by the
 * QUIC stack have been installed in the kernel. Further QUIC packet processing and data
 * transfer are handled by the kernel.
 *
 * Example usage (client/server):
 *
 * .nf
 * \&    Client                                     Server
 * \&  ----------------------------------------------------------------------------------
 * \&  sockfd = socket(IPPROTO_QUIC)              listenfd = socket(IPPROTO_QUIC)
 * \&  bind(sockfd)                               bind(listenfd)
 * \&                                             listen(listenfd)
 * \&  connect(sockfd)
 *
 * \&  gnutls_init(&session, GNUTLS_CLIENT) ...
 * \&  gnutls_transport_set_int(session, sockfd)
 * \&  gnutls_quic_handshake(session)
 * \&                                             sockfd = accept(listenfd)
 *
 * \&                                             gnutls_init(&session, GNUTLS_SERVER) ...
 * \&                                             gnutls_transport_set_int(session, sockfd)
 * \&                                             gnutls_quic_handshake(session)
 *
 * \&  sendmsg(sockfd)                            recvmsg(sockfd)
 * \&  close(sockfd)                              close(sockfd)
 * \&                                             close(listenfd)
 * .fi
 *
 * For the full specification of QUIC socket APIs, refer to:
 *
 * - https://datatracker.ietf.org/doc/html/draft-lxin-quic-socket-apis
 *
 * Returns: %GNUTLS_E_SUCCESS on a successful handshake, otherwise a negative error code.
 **/
int gnutls_quic_handshake(gnutls_session_t session)
{
	int ret;

	ret = gnutls_session_ext_register(
		session, "QUIC Transport Parameters", QUIC_TLSEXT_TP_PARAM,
		GNUTLS_EXT_TLS, gnutls_quic_tp_recv, gnutls_quic_tp_send, NULL, NULL, NULL,
		GNUTLS_EXT_FLAG_TLS | GNUTLS_EXT_FLAG_CLIENT_HELLO | GNUTLS_EXT_FLAG_EE |
		GNUTLS_EXT_FLAG_OVERRIDE_INTERNAL);
	if (ret != GNUTLS_E_SUCCESS)
		return ret;

	gnutls_handshake_set_secret_function(session, gnutls_quic_secret_set);
	gnutls_handshake_set_read_function(session, gnutls_quic_msg_read);

	return gnutls_quic_handshake_run(session);
}
#endif
