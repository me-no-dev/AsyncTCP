#if ASYNC_TCP_SSL_ENABLED

#include "tcp_mbedtls.h"
#include "lwip/tcp.h"
#include "mbedtls/debug.h"
#include "mbedtls/esp_debug.h"
#include <string.h>

// stubs to call LwIP's tcp functions on the LwIP thread itself, implemented in AsyncTCP.cpp
extern esp_err_t _tcp_output4ssl(struct tcp_pcb * pcb, void* client);
extern esp_err_t _tcp_write4ssl(struct tcp_pcb * pcb, const char* data, size_t size, uint8_t apiflags, void* client);

#if 1
#define TCP_SSL_DEBUG(...) do { ets_printf("T %s- ", pcTaskGetTaskName(xTaskGetCurrentTaskHandle())); ets_printf(__VA_ARGS__); } while(0)
#else
#define TCP_SSL_DEBUG(...)
#endif

static const char pers[] = "esp32-tls";

static int handle_error(int err) {
    if(err == -30848){
        return err;
    }
#ifdef MBEDTLS_ERROR_C
    char error_buf[100];
    mbedtls_strerror(err, error_buf, 100);
    TCP_SSL_DEBUG("%s\n", error_buf);
#endif
    TCP_SSL_DEBUG("MbedTLS message code: %d\n", err);
    return err;
}

/**
 * Certificate verification callback for mbed TLS
 * Here we only use it to display information on each cert in the chain
 */
// static int my_verify(void *data, mbedtls_x509_crt *crt, int depth, uint32_t *flags) {
//     const uint32_t buf_size = 1024;
//     char buf[buf_size];
//     (void) data;

//     mbedtls_printf("\nVerifying certificate at depth %d:\n", depth);
//     mbedtls_x509_crt_info(buf, buf_size - 1, "  ", crt);
//     mbedtls_printf("%s", buf);

//     if (*flags == 0)
//         mbedtls_printf("No verification issue for this certificate\n");
//     else
//     {
//         mbedtls_x509_crt_verify_info(buf, buf_size, "  ! ", *flags);
//         mbedtls_printf("%s\n", buf);
//     }

//     return 0;
// }

static uint8_t _tcp_ssl_has_client = 0;

struct tcp_ssl_pcb {
  struct tcp_pcb *tcp;
  int fd;
  mbedtls_ssl_context ssl_ctx;
  mbedtls_ssl_config ssl_conf;
  mbedtls_x509_crt ca_cert;
  bool has_ca_cert;
  mbedtls_x509_crt client_cert;
  bool has_client_cert;
  mbedtls_pk_context client_key;
  mbedtls_ctr_drbg_context drbg_ctx;
  mbedtls_entropy_context entropy_ctx;
  uint8_t type;
  // int handshake;
  void* arg;
  tcp_ssl_data_cb_t on_data;
  tcp_ssl_handshake_cb_t on_handshake;
  void* on_handshake_arg;
  tcp_ssl_error_cb_t on_error;
  size_t last_wr;
  struct pbuf *tcp_pbuf;
  int pbuf_offset;
  struct tcp_ssl_pcb* next;
};

typedef struct tcp_ssl_pcb tcp_ssl_t;

static tcp_ssl_t * tcp_ssl_array = NULL;
static int tcp_ssl_next_fd = 0;

// tcp_ssl_recv attempts to read up to len bytes into buf from data already received.
// It is called by mbedtls.
int tcp_ssl_recv(void *ctx, unsigned char *buf, size_t len) {
  TCP_SSL_DEBUG("tcp_ssl_recv: ctx: 0x%X, buf: 0x%X, len: %d\n", ctx, buf, len);
  tcp_ssl_t *tcp_ssl = (tcp_ssl_t*)ctx;
  u16_t recv_len = 0;

  if(tcp_ssl->tcp_pbuf == NULL || tcp_ssl->tcp_pbuf->tot_len == 0) {
    TCP_SSL_DEBUG("tcp_ssl_recv: not yet ready to read: tcp_pbuf: 0x%X.\n", tcp_ssl->tcp_pbuf);
    return MBEDTLS_ERR_SSL_WANT_READ;
  }

  recv_len = pbuf_copy_partial(tcp_ssl->tcp_pbuf, buf, len, tcp_ssl->pbuf_offset);
  TCP_SSL_DEBUG("tcp_ssl_recv: len: %d, recv_len: %d, pbuf_offset: %d, tcp_pbuf len: %d.\n",
      len, recv_len, tcp_ssl->pbuf_offset, tcp_ssl->tcp_pbuf->len);
  tcp_ssl->pbuf_offset += recv_len;

  if(recv_len == 0) {
    return MBEDTLS_ERR_SSL_WANT_READ;
  }
  return recv_len;
}

// tcp_ssl_send attempts to send len bytes from buf.
// It is called by mbedtls.
int tcp_ssl_send(void *ctx, const unsigned char *buf, size_t len) {
  TCP_SSL_DEBUG("tcp_ssl_send: ctx: 0x%X, buf: 0x%X, len: %d\n", ctx, buf, len);

  if(ctx == NULL) {
    TCP_SSL_DEBUG("tcp_ssl_send: no context set\n");
    return -1;
  }

  if(buf == NULL) {
    TCP_SSL_DEBUG("tcp_ssl_send: buf not set\n");
    return -1;
  }

  tcp_ssl_t *tcp_ssl = (tcp_ssl_t*)ctx;
  size_t tcp_len = 0;
  int err = ERR_OK;

  if (tcp_sndbuf(tcp_ssl->tcp) < len) {
    tcp_len = tcp_sndbuf(tcp_ssl->tcp);
    if(tcp_len == 0) {
      TCP_SSL_DEBUG("tcp_ssl_send: tcp_sndbuf is zero: %d\n", len);
      return ERR_MEM;
    }
  } else {
    tcp_len = len;
  }

  if (tcp_len > 2 * tcp_ssl->tcp->mss) {
    tcp_len = 2 * tcp_ssl->tcp->mss;
  }

  TCP_SSL_DEBUG("tcp_ssl_send: tcp_write(%x, %x, %d, %x)\n", tcp_ssl->tcp, (char *)buf, tcp_len, tcp_ssl->arg);
  err = _tcp_write4ssl(tcp_ssl->tcp, (char *)buf, tcp_len, TCP_WRITE_FLAG_COPY, tcp_ssl->arg);
  if(err < ERR_OK) {
    if (err == ERR_MEM) {
      TCP_SSL_DEBUG("tcp_ssl_send: No memory %d (%d)\n", tcp_len, len);
      return err;
    }
    TCP_SSL_DEBUG("tcp_ssl_send: tcp_write error: %d\n", err);
    return err;
  } else if (err == ERR_OK) {
    TCP_SSL_DEBUG("tcp_ssl_send: tcp_output: %d / %d\n", tcp_len, len);
    err = _tcp_output4ssl(tcp_ssl->tcp, tcp_ssl->arg);
    if(err != ERR_OK) {
      TCP_SSL_DEBUG("tcp_ssl_send: tcp_output err: %d\n", err);
      return err;
    }
  }

  tcp_ssl->last_wr += tcp_len;

  return tcp_len;
}

uint8_t tcp_ssl_has_client() {
  return _tcp_ssl_has_client;
}

tcp_ssl_t * tcp_ssl_new(struct tcp_pcb *tcp, void* arg) {

  if(tcp_ssl_next_fd < 0){
    tcp_ssl_next_fd = 0;//overflow
  }

  tcp_ssl_t * new_item = (tcp_ssl_t*)malloc(sizeof(tcp_ssl_t));
  if(!new_item){
    TCP_SSL_DEBUG("tcp_ssl_new: failed to allocate tcp_ssl\n");
    return NULL;
  }

  new_item->tcp = tcp;
  new_item->arg = arg;
  new_item->on_data = NULL;
  new_item->on_handshake = NULL;
  new_item->on_error = NULL;
  new_item->tcp_pbuf = NULL;
  new_item->pbuf_offset = 0;
  new_item->next = NULL;
  new_item->has_ca_cert = false;
  new_item->has_client_cert = false;

  if(tcp_ssl_array == NULL){
    tcp_ssl_array = new_item;
  } else {
    tcp_ssl_t * item = tcp_ssl_array;
    while(item->next != NULL)
      item = item->next;
    item->next = new_item;
  }

  return new_item;
}

tcp_ssl_t* tcp_ssl_get(struct tcp_pcb *tcp) {
  if(tcp == NULL) {
    return NULL;
  }
  tcp_ssl_t * item = tcp_ssl_array;
  while(item && item->tcp != tcp){
    item = item->next;
  }
  return item;
}

int tcp_ssl_new_client(struct tcp_pcb *tcp, void *arg, const char* hostname, const char* root_ca, const size_t root_ca_len,
                       const char* cli_cert, const size_t cli_cert_len, const char* cli_key, const size_t cli_key_len) {
  tcp_ssl_t* tcp_ssl;

  if(tcp == NULL) {
    return -1;
  }

  if(tcp_ssl_get(tcp) != NULL){
    return -1;
  }

  tcp_ssl = tcp_ssl_new(tcp, arg);
  if(tcp_ssl == NULL){
    return -1;
  }

  mbedtls_entropy_init(&tcp_ssl->entropy_ctx);
  mbedtls_ctr_drbg_init(&tcp_ssl->drbg_ctx);
  mbedtls_ssl_init(&tcp_ssl->ssl_ctx);
  mbedtls_ssl_config_init(&tcp_ssl->ssl_conf);
  if(root_ca != NULL) {
    mbedtls_x509_crt_init(&tcp_ssl->ca_cert);
    tcp_ssl->has_ca_cert = true;
  }
  if (cli_cert != NULL && cli_key != NULL) {
    mbedtls_x509_crt_init(&tcp_ssl->client_cert);
    mbedtls_pk_init(&tcp_ssl->client_key);
    tcp_ssl->has_client_cert = true;
  }

  mbedtls_ctr_drbg_seed(&tcp_ssl->drbg_ctx, mbedtls_entropy_func,
                        &tcp_ssl->entropy_ctx, (const unsigned char*)pers, sizeof(pers));

  if(mbedtls_ssl_config_defaults(&tcp_ssl->ssl_conf,
    MBEDTLS_SSL_IS_CLIENT,
    MBEDTLS_SSL_TRANSPORT_STREAM,
    MBEDTLS_SSL_PRESET_DEFAULT)) {
    TCP_SSL_DEBUG("error setting SSL config.\n");

    tcp_ssl_free(tcp);
    return -1;
  }

  int ret = 0;

  if(tcp_ssl->has_ca_cert) {
    TCP_SSL_DEBUG("setting the root ca.\n");

    mbedtls_x509_crt_init(&tcp_ssl->ca_cert);

    mbedtls_ssl_conf_authmode(&tcp_ssl->ssl_conf, MBEDTLS_SSL_VERIFY_REQUIRED);

    ret = mbedtls_x509_crt_parse(&tcp_ssl->ca_cert, (const unsigned char *)root_ca, root_ca_len);
    if( ret < 0 ){
      TCP_SSL_DEBUG(" failed\n  !  mbedtls_x509_crt_parse returned -0x%x\n\n", -ret);
      tcp_ssl_free(tcp);
      return handle_error(ret);
    }

    mbedtls_ssl_conf_ca_chain(&tcp_ssl->ssl_conf, &tcp_ssl->ca_cert, NULL);
  } else {
    mbedtls_ssl_conf_authmode(&tcp_ssl->ssl_conf, MBEDTLS_SSL_VERIFY_OPTIONAL);
  }

  if (tcp_ssl->has_client_cert) {
    TCP_SSL_DEBUG("loading client cert");
    ret = mbedtls_x509_crt_parse(&tcp_ssl->client_cert, (const unsigned char *) cli_cert, cli_cert_len);
    if (ret < 0) {
      tcp_ssl_free(tcp);
      return handle_error(ret);
    } 
    TCP_SSL_DEBUG("loading private key");
    ret = mbedtls_pk_parse_key(&tcp_ssl->client_key, (const unsigned char *) cli_key, cli_key_len, NULL, 0);
    if (ret != 0) {
      tcp_ssl_free(tcp);
      return handle_error(ret);
    }
    mbedtls_ssl_conf_own_cert(&tcp_ssl->ssl_conf, &tcp_ssl->client_cert, &tcp_ssl->client_key);
  }

  if(hostname != NULL) {
    TCP_SSL_DEBUG("setting the hostname: %s\n", hostname);
    if((ret = mbedtls_ssl_set_hostname(&tcp_ssl->ssl_ctx, hostname)) != 0){
      tcp_ssl_free(tcp);

      return handle_error(ret);
    }
  }

  mbedtls_ssl_conf_rng(&tcp_ssl->ssl_conf, mbedtls_ctr_drbg_random, &tcp_ssl->drbg_ctx);

  if ((ret = mbedtls_ssl_setup(&tcp_ssl->ssl_ctx, &tcp_ssl->ssl_conf)) != 0) {
    tcp_ssl_free(tcp);

    return handle_error(ret);
  }

  mbedtls_ssl_set_bio(&tcp_ssl->ssl_ctx, (void*)tcp_ssl, tcp_ssl_send, tcp_ssl_recv, NULL);

  // Start handshake.
  ret = mbedtls_ssl_handshake(&tcp_ssl->ssl_ctx);
  if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
    TCP_SSL_DEBUG("handshake error!\n");
    tcp_ssl_free(tcp);
    return handle_error(ret);
  }

  return ERR_OK;
}

int tcp_ssl_new_server(struct tcp_pcb *tcp, void *arg, const char *cert, const size_t cert_len, const char *private_key, const size_t private_key_len, const char *password) {
  tcp_ssl_t* tcp_ssl;

  if(tcp == NULL) {
    return -1;
  }

  if(tcp_ssl_get(tcp) != NULL){
    return -1;
  }

  tcp_ssl = tcp_ssl_new(tcp, arg);
  if(tcp_ssl == NULL){
    return -1;
  }

  int ret;
  mbedtls_ssl_init( &tcp_ssl->ssl_ctx );
  mbedtls_ssl_config_init( &tcp_ssl->ssl_conf );
  mbedtls_x509_crt_init( &tcp_ssl->ca_cert );
  mbedtls_pk_init( &tcp_ssl->client_key );
  mbedtls_entropy_init( &tcp_ssl->entropy_ctx );
  mbedtls_ctr_drbg_init( &tcp_ssl->drbg_ctx );

  /*
    * 1. Load the certificates and private RSA key
    */
  TCP_SSL_DEBUG("Loading the server cert\n");
  ret = mbedtls_x509_crt_parse(&tcp_ssl->ca_cert, (const unsigned char *) cert, cert_len);
  if (ret != 0) {
      TCP_SSL_DEBUG("failed loading server cert, returned %d\n", ret);
      tcp_ssl_free(tcp);
      return handle_error(ret);
  }

  TCP_SSL_DEBUG("Loading the server key\n");
  ret = mbedtls_pk_parse_key(&tcp_ssl->client_key, (const unsigned char *) private_key, private_key_len, NULL, 0);
  if (ret != 0) {
      TCP_SSL_DEBUG("failed loading server private key, returned %d\n", ret); 
      tcp_ssl_free(tcp);
      return handle_error(ret);
  }

  /*
    * 3. Seed the RNG
    */
  TCP_SSL_DEBUG("Seeding the random number generator...\n" );
  ret = mbedtls_ctr_drbg_seed(&tcp_ssl->drbg_ctx, mbedtls_entropy_func, &tcp_ssl->entropy_ctx,
                              (const unsigned char *) pers,
                              strlen(pers));
  if (ret != 0) {
      TCP_SSL_DEBUG("failed seeding the random number generator, returned %d\n", ret);
      tcp_ssl_free(tcp);
      return handle_error(ret);
  }

  /*
    * 4. Setup stuff
    */
  TCP_SSL_DEBUG("Setting up the SSL data...\n" );
  ret = mbedtls_ssl_config_defaults( &tcp_ssl->ssl_conf,
                  MBEDTLS_SSL_IS_SERVER,
                  MBEDTLS_SSL_TRANSPORT_STREAM,
                  MBEDTLS_SSL_PRESET_DEFAULT );
  if (ret != 0) {
      TCP_SSL_DEBUG("failed mbedtls_ssl_config_defaults returned %d\n", ret);
      tcp_ssl_free(tcp);
      return handle_error(ret);
  }

  mbedtls_ssl_conf_rng(&tcp_ssl->ssl_conf, mbedtls_ctr_drbg_random, &tcp_ssl->drbg_ctx);


  mbedtls_ssl_conf_ca_chain(&tcp_ssl->ssl_conf, tcp_ssl->ca_cert.next, NULL);
  ret = mbedtls_ssl_conf_own_cert(&tcp_ssl->ssl_conf, &tcp_ssl->ca_cert, &tcp_ssl->client_key);
  if (ret != 0) {
      TCP_SSL_DEBUG("failed mbedtls_ssl_conf_own_cert returned %d\n", ret);
      tcp_ssl_free(tcp);
      return handle_error(ret);
  }

  ret = mbedtls_ssl_setup(&tcp_ssl->ssl_ctx, &tcp_ssl->ssl_conf);
  if (ret != 0) {
      TCP_SSL_DEBUG("failed mbedtls_ssl_setup returned %d\n", ret);
      tcp_ssl_free(tcp);
      return handle_error(ret);
  }

  TCP_SSL_DEBUG("tcp_ssl_new_server completed succesfully\n");

  return ERR_OK;
}

int tcp_ssl_new_server_client(struct tcp_pcb *tcp, void *arg, struct tcp_pcb *server_tcp) {
  tcp_ssl_t* tcp_ssl;
  tcp_ssl_t* server_tcp_ssl;

  if(tcp == NULL || server_tcp == NULL) {
    return -1;
  }

  if(tcp_ssl_get(tcp) != NULL){
    return -1;
  }

  server_tcp_ssl = tcp_ssl_get(server_tcp);
  if (server_tcp_ssl == NULL) {
    return -1;
  }

  tcp_ssl = tcp_ssl_new(tcp, arg);
  if(tcp_ssl == NULL){
    return -1;
  }

  int ret;

  mbedtls_ssl_init(&tcp_ssl->ssl_ctx);
  ret = mbedtls_ssl_setup(&tcp_ssl->ssl_ctx, &server_tcp_ssl->ssl_conf);
  if (ret != 0) {
    TCP_SSL_DEBUG("failed: mbedtls_ssl_setup returned -0x%04x\n", -ret );
    return handle_error(ret);
  }

  mbedtls_ssl_set_bio(&tcp_ssl->ssl_ctx, (void*)tcp_ssl, tcp_ssl_send, tcp_ssl_recv, NULL);

  return ERR_OK;
}

// Open an SSL connection using a PSK (pre-shared-key) cipher suite.
int tcp_ssl_new_psk_client(struct tcp_pcb *tcp, void *arg, const char* psk_ident, const char* pskey) {
  tcp_ssl_t* tcp_ssl;

  if (pskey == NULL || psk_ident == NULL) {
    TCP_SSL_DEBUG(" failed\n  !  pre-shared key or identity is NULL\n\n");
    return -1;
  }

  if(tcp == NULL) return -1;
  if(tcp_ssl_get(tcp) != NULL) return -1;

  int pskey_len = strnlen(pskey, 2*MBEDTLS_PSK_MAX_LEN+1);
  if ((pskey_len > 2*MBEDTLS_PSK_MAX_LEN) || (pskey_len & 1) != 0) {
      TCP_SSL_DEBUG(" failed\n  !  pre-shared key not valid hex or too long\n\n");
      return -1;
  }

  tcp_ssl = tcp_ssl_new(tcp, arg);
  if(tcp_ssl == NULL) return -1;

  mbedtls_entropy_init(&tcp_ssl->entropy_ctx);
  mbedtls_ctr_drbg_init(&tcp_ssl->drbg_ctx);
  mbedtls_ssl_init(&tcp_ssl->ssl_ctx);
  mbedtls_ssl_config_init(&tcp_ssl->ssl_conf);

  mbedtls_ctr_drbg_seed(&tcp_ssl->drbg_ctx, mbedtls_entropy_func,
                        &tcp_ssl->entropy_ctx, (const uint8_t*)pers, sizeof(pers));

  if(mbedtls_ssl_config_defaults(&tcp_ssl->ssl_conf,
    MBEDTLS_SSL_IS_CLIENT,
    MBEDTLS_SSL_TRANSPORT_STREAM,
    MBEDTLS_SSL_PRESET_DEFAULT)) {
    TCP_SSL_DEBUG("error setting SSL config.\n");

    tcp_ssl_free(tcp);
    return -1;
  }

  //mbedtls_esp_enable_debug_log(&tcp_ssl->ssl_conf, 4); // 4=verbose

  int ret = 0;

  TCP_SSL_DEBUG("setting the pre-shared key.\n");
  // convert PSK from hex string to binary
  unsigned char psk[MBEDTLS_PSK_MAX_LEN];
  size_t psk_len = pskey_len/2;
  for (int j=0; j<pskey_len; j+= 2) {
      char c = pskey[j];
      if (c >= '0' && c <= '9') c -= '0';
      else if (c >= 'A' && c <= 'F') c -= 'A' - 10;
      else if (c >= 'a' && c <= 'f') c -= 'a' - 10;
      else return -1;
      psk[j/2] = c<<4;
      c = pskey[j+1];
      if (c >= '0' && c <= '9') c -= '0';
      else if (c >= 'A' && c <= 'F') c -= 'A' - 10;
      else if (c >= 'a' && c <= 'f') c -= 'a' - 10;
      else return -1;
      psk[j/2] |= c;
  }
  // set mbedtls config
  ret = mbedtls_ssl_conf_psk(&tcp_ssl->ssl_conf, psk, psk_len,
           (const unsigned char *)psk_ident, strnlen(psk_ident, 64));
  if (ret != 0) {
      TCP_SSL_DEBUG("  failed\n  !  mbedtls_ssl_conf_psk returned -0x%x\n\n", -ret);
      return handle_error(ret);
  }

  mbedtls_ssl_conf_rng(&tcp_ssl->ssl_conf, mbedtls_ctr_drbg_random, &tcp_ssl->drbg_ctx);

  if ((ret = mbedtls_ssl_setup(&tcp_ssl->ssl_ctx, &tcp_ssl->ssl_conf)) != 0) {
    tcp_ssl_free(tcp);

    return handle_error(ret);
  }

  mbedtls_ssl_set_bio(&tcp_ssl->ssl_ctx, (void*)tcp_ssl, tcp_ssl_send, tcp_ssl_recv, NULL);

  // Start handshake.
  ret = mbedtls_ssl_handshake(&tcp_ssl->ssl_ctx);
  if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
    TCP_SSL_DEBUG("handshake error!\n");
    return handle_error(ret);
  }

  return ERR_OK;
}

// tcp_ssl_write writes len bytes from data into the TLS connection. I.e., data is plaintext, gets
// encrypted, and then transmitted on the TCP connection.
int tcp_ssl_write(struct tcp_pcb *tcp, uint8_t *data, size_t len) {
  TCP_SSL_DEBUG("tcp_ssl_write(%x, %x, len=%d)\n", tcp, data, len);
  if(tcp == NULL) {
    return -1;
  }

  tcp_ssl_t * tcp_ssl = tcp_ssl_get(tcp);

  if(tcp_ssl == NULL){
    return 0;
  }

  tcp_ssl->last_wr = 0;

  int rc = mbedtls_ssl_write(&tcp_ssl->ssl_ctx, data, len);

  if (rc < 0){
    if (rc != MBEDTLS_ERR_SSL_WANT_READ && rc != MBEDTLS_ERR_SSL_WANT_WRITE) {
      TCP_SSL_DEBUG("about to call mbedtls_ssl_write\n");
      return handle_error(rc);
    }
    if(rc != MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) {
      TCP_SSL_DEBUG("tcp_ssl_write error: %d\r\n", rc);
    }
    return rc;
  }

  return tcp_ssl->last_wr;
}

// tcp_ssl_read is a callback that reads from the TLS connection, i.e., it calls mbedtls, which then
// tries to read from the TCP connection and decrypts it, tcp_ssl_read then calls the application's
// onData callback with the decrypted data.
int tcp_ssl_read(struct tcp_pcb *tcp, struct pbuf *p) {
  TCP_SSL_DEBUG("tcp_ssl_read(%x, %x)\n", tcp, p);
  if(tcp == NULL) {
    return -1;
  }

  int read_bytes = 0;
  int total_bytes = 0;
  static const size_t read_buf_size = 1024;
  uint8_t read_buf[read_buf_size];

  tcp_ssl_t *tcp_ssl = tcp_ssl_get(tcp);
  if(tcp_ssl == NULL) {
    return ERR_TCP_SSL_INVALID_CLIENTFD_DATA;
  }

  if(p == NULL) {
    return ERR_TCP_SSL_INVALID_DATA;
  }

  // TCP_SSL_DEBUG("READY TO READ SOME DATA\n");

  tcp_ssl->tcp_pbuf = p;
  tcp_ssl->pbuf_offset = 0;

  do {
    if(tcp_ssl->ssl_ctx.state != MBEDTLS_SSL_HANDSHAKE_OVER) {
      TCP_SSL_DEBUG("start handshake: %d\n", tcp_ssl->ssl_ctx.state);
      int ret = mbedtls_ssl_handshake(&tcp_ssl->ssl_ctx);
      //handle_error(ret);
      if(ret == 0) {
        TCP_SSL_DEBUG("Protocol is %s Ciphersuite is %s\n", mbedtls_ssl_get_version(&tcp_ssl->ssl_ctx), mbedtls_ssl_get_ciphersuite(&tcp_ssl->ssl_ctx));

        TCP_SSL_DEBUG("Verifying peer X.509 certificate...");
        if ((mbedtls_ssl_get_verify_result(&tcp_ssl->ssl_ctx)) != 0) {
          TCP_SSL_DEBUG("handshake error: %d\n", ret);
          handle_error(ret);
          if(tcp_ssl->on_error)
            tcp_ssl->on_error(tcp_ssl->arg, tcp_ssl->tcp, ret);
        } else {
          TCP_SSL_DEBUG("Certificate verified.");
        }

        if(tcp_ssl->on_handshake)
          tcp_ssl->on_handshake(tcp_ssl->on_handshake_arg, tcp_ssl->tcp, tcp_ssl);
      } else if(ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
        TCP_SSL_DEBUG("handshake error: %d\n", ret);
        handle_error(ret);

        if(tcp_ssl->on_error)
          tcp_ssl->on_error(tcp_ssl->arg, tcp_ssl->tcp, ret);

        break;
      }
    } else {
      read_bytes = mbedtls_ssl_read(&tcp_ssl->ssl_ctx, (unsigned char *)&read_buf, read_buf_size);
      TCP_SSL_DEBUG("tcp_ssl_read: read_bytes: %d, total_bytes: %d, tot_len: %d, pbuf_offset: %d\r\n", read_bytes, total_bytes, p->tot_len, tcp_ssl->pbuf_offset);
      if(read_bytes < 0) { // SSL_OK
        if(read_bytes == MBEDTLS_ERR_SSL_WANT_READ) {
          break;
        } else if(read_bytes != MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) {
          TCP_SSL_DEBUG("tcp_ssl_read: read error: %d\n", read_bytes);
        }
        total_bytes = read_bytes;
        break;
      } else if(read_bytes > 0){
        if(tcp_ssl->on_data){
          tcp_ssl->on_data(tcp_ssl->arg, tcp, read_buf, read_bytes);
        }
        total_bytes+= read_bytes;
      }
    }
  } while (p->tot_len - tcp_ssl->pbuf_offset > 0 || read_bytes > 0);

  tcp_ssl->tcp_pbuf = NULL;

  TCP_SSL_DEBUG("tcp_ssl_read: return total_bytes: %d\r\n", total_bytes >= 0 ? 0 : total_bytes);
  return total_bytes >= 0 ? 0 : total_bytes; // return error code
}

int tcp_ssl_handshake_step(struct tcp_pcb *tcp) {
  TCP_SSL_DEBUG("tcp_ssl_handshake_step(%x)\n", tcp);
  if(tcp == NULL) {
    return -1;
  }

  tcp_ssl_t * tcp_ssl = tcp_ssl_get(tcp);
  if(tcp_ssl == NULL){
    return 0;
  }

  return ERR_OK;
}

int tcp_ssl_free(struct tcp_pcb *tcp) {
  TCP_SSL_DEBUG("tcp_ssl_free(%x)\n", tcp);
  return -1;
  if(tcp == NULL) {
    return -1;
  }
  tcp_ssl_t * item = tcp_ssl_array;
  if(item->tcp == tcp){
    tcp_ssl_array = tcp_ssl_array->next;
    if(item->tcp_pbuf != NULL) {
      pbuf_free(item->tcp_pbuf);
    }
    mbedtls_ssl_free(&item->ssl_ctx);
    mbedtls_ssl_config_free(&item->ssl_conf);
    mbedtls_ctr_drbg_free(&item->drbg_ctx);
    mbedtls_entropy_free(&item->entropy_ctx);
    if(item->has_ca_cert) {
      mbedtls_x509_crt_free(&item->ca_cert);
    }
    if (item->has_client_cert) {
      mbedtls_x509_crt_free(&item->client_cert);
      mbedtls_pk_free(&item->client_key);
    }
    free(item);
    return 0;
  }

  while(item->next && item->next->tcp != tcp)
    item = item->next;

  if(item->next == NULL){
    return ERR_TCP_SSL_INVALID_CLIENTFD_DATA;//item not found
  }
  tcp_ssl_t * i = item->next;
  item->next = i->next;
  if(i->tcp_pbuf != NULL){
    pbuf_free(i->tcp_pbuf);
  }
  mbedtls_ssl_free(&i->ssl_ctx);
  mbedtls_ssl_config_free(&i->ssl_conf);
  mbedtls_ctr_drbg_free(&i->drbg_ctx);
  mbedtls_entropy_free(&i->entropy_ctx);
  free(i);

  return 0;
}

bool tcp_ssl_has(struct tcp_pcb *tcp) {
  return tcp_ssl_get(tcp) != NULL;
}

void tcp_ssl_arg(struct tcp_pcb *tcp, void * arg) {
  tcp_ssl_t * item = tcp_ssl_get(tcp);
  if(item) {
    item->arg = arg;
  }
}

void tcp_ssl_data(struct tcp_pcb *tcp, tcp_ssl_data_cb_t arg){
  tcp_ssl_t * item = tcp_ssl_get(tcp);
  if(item) {
    item->on_data = arg;
  }
}

void tcp_ssl_handshake(struct tcp_pcb *tcp, void *arg, tcp_ssl_handshake_cb_t ssl_handshake_cb){
  tcp_ssl_t * item = tcp_ssl_get(tcp);
  if(item) {
    item->on_handshake = ssl_handshake_cb;
    item->on_handshake_arg = arg;
  }
}

void tcp_ssl_err(struct tcp_pcb *tcp, tcp_ssl_error_cb_t arg){
  tcp_ssl_t * item = tcp_ssl_get(tcp);
  if(item) {
    item->on_error = arg;
  }
}

#endif // ASYNC_TCP_SSL_ENABLED
