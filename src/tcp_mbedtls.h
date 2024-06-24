#ifndef LWIPR_MBEDTLS_H
#define LWIPR_MBEDTLS_H

#if ASYNC_TCP_SSL_ENABLED

#include "mbedtls/platform.h"
#include "mbedtls/net.h"
#include "mbedtls/debug.h"
#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/error.h"

#ifdef __cplusplus
extern "C" {
#endif

#define ERR_TCP_SSL_INVALID_SSL           -101
#define ERR_TCP_SSL_INVALID_TCP           -102
#define ERR_TCP_SSL_INVALID_CLIENTFD      -103
#define ERR_TCP_SSL_INVALID_CLIENTFD_DATA -104
#define ERR_TCP_SSL_INVALID_DATA          -105

struct tcp_pcb;
struct pbuf;
struct tcp_ssl_pcb;

typedef void (* tcp_ssl_data_cb_t)(void *arg, struct tcp_pcb *tcp, uint8_t * data, size_t len);
typedef void (* tcp_ssl_handshake_cb_t)(void *arg, struct tcp_pcb *tcp, struct tcp_ssl_pcb* ssl);
typedef void (* tcp_ssl_error_cb_t)(void *arg, struct tcp_pcb *tcp, int8_t error);

uint8_t tcp_ssl_has_client();
int tcp_ssl_new_client(struct tcp_pcb *tcp, void *arg, const char* hostname, const char* root_ca, const size_t root_ca_len,
                       const char* cli_cert, const size_t cli_cert_len, const char* cli_key, const size_t cli_key_len);
int tcp_ssl_new_server(struct tcp_pcb *tcp, void *arg, const char *cert, const size_t cert_len, const char *private_key, const size_t private_key_len, const char *password);
int tcp_ssl_new_server_client(struct tcp_pcb *tcp, void *arg, struct tcp_pcb *server_tcp);
int tcp_ssl_new_psk_client(struct tcp_pcb *tcp, void *arg, const char* psk_ident, const char* psk);
int tcp_ssl_write(struct tcp_pcb *tcp, uint8_t *data, size_t len);
int tcp_ssl_read(struct tcp_pcb *tcp, struct pbuf *p);
int tcp_ssl_handshake_step(struct tcp_pcb *tcp);
int tcp_ssl_free(struct tcp_pcb *tcp);
bool tcp_ssl_has(struct tcp_pcb *tcp);
void tcp_ssl_arg(struct tcp_pcb *tcp, void * arg);
void tcp_ssl_data(struct tcp_pcb *tcp, tcp_ssl_data_cb_t arg);
void tcp_ssl_handshake(struct tcp_pcb *tcp, tcp_ssl_handshake_cb_t ssl_handshake_cb);
void tcp_ssl_err(struct tcp_pcb *tcp, tcp_ssl_error_cb_t arg);

#ifdef __cplusplus
}
#endif


#endif // LWIPR_MBEDTLS_H
#endif // ASYNC_TCP_SSL_ENABLED
