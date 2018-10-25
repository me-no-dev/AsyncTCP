#define DEBUG true
#define CONFIG_MBEDTLS_DEBUG true
#define DEBUG_LEVEL 4

#include "tcp_mbedtls.h"
#include "lwip/tcp.h"
#include "mbedtls/debug.h"
#include "mbedtls/esp_debug.h"
#include <string.h>

#include "mbedtls/debug.h"

// #define TCP_SSL_DEBUG(...) ets_printf(__VA_ARGS__)
#define TCP_SSL_DEBUG(...) 

static const char pers[] = "esp32-tls";

static int handle_error(int err)
{
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

static void my_debug(void *ctx, int level, const char *file, int line,
                         const char *str)
    {
        const char *p, *basename;
        (void) ctx;

        /* Extract basename from file */
        for(p = basename = file; *p != '\0'; p++) {
            if(*p == '/' || *p == '\\') {
                basename = p + 1;
            }
        }

        mbedtls_printf("%s:%04d: |%d| %s", basename, line, level, str);
    }

    /**
     * Certificate verification callback for mbed TLS
     * Here we only use it to display information on each cert in the chain
     */
    static int my_verify(void *data, mbedtls_x509_crt *crt, int depth, uint32_t *flags)
    {
        const uint32_t buf_size = 1024;
        //char *buf = new char[buf_size];
        char buf[buf_size];
        (void) data;

        mbedtls_printf("\nVerifying certificate at depth %d:\n", depth);
        mbedtls_x509_crt_info(buf, buf_size - 1, "  ", crt);
        mbedtls_printf("%s", buf);

        if (*flags == 0)
            mbedtls_printf("No verification issue for this certificate\n");
        else
        {
            mbedtls_x509_crt_verify_info(buf, buf_size, "  ! ", *flags);
            mbedtls_printf("%s\n", buf);
        }

        //delete[] buf;
        return 0;
    }

static uint8_t _tcp_ssl_has_client = 0;

struct tcp_ssl_pcb {
  struct tcp_pcb *tcp;
  int fd;
  mbedtls_ssl_context ssl_ctx;
  mbedtls_ssl_config ssl_conf;
  mbedtls_ctr_drbg_context drbg_ctx;
  mbedtls_entropy_context entropy_ctx;
  uint8_t type;
  // int handshake;
  void* arg;
  tcp_ssl_data_cb_t on_data;
  tcp_ssl_handshake_cb_t on_handshake;
  tcp_ssl_error_cb_t on_error;
  size_t last_wr;
  struct pbuf *tcp_pbuf;
  int pbuf_offset;
  struct tcp_ssl_pcb* next;
};

typedef struct tcp_ssl_pcb tcp_ssl_t;

static tcp_ssl_t * tcp_ssl_array = NULL;
static int tcp_ssl_next_fd = 0;

int tcp_ssl_recv(void *ctx, unsigned char *buf, size_t len) {
  tcp_ssl_t *tcp_ssl = (tcp_ssl_t*)ctx;
  uint8_t *read_buf = NULL;
  uint8_t *pread_buf = NULL;
  u16_t recv_len = 0;

  TCP_SSL_DEBUG("tcp_ssl_recv: ctx: 0x%X, buf: 0x%X, len: %d\n", ctx, buf, len);

  if(tcp_ssl->tcp_pbuf == NULL || tcp_ssl->tcp_pbuf->tot_len == 0) {
    TCP_SSL_DEBUG("tcp_ssl_recv: not yet ready to read: tcp_pbuf: 0x%X.\n", tcp_ssl->tcp_pbuf);
    return MBEDTLS_ERR_SSL_WANT_READ;
  }

  read_buf =(uint8_t*)calloc(tcp_ssl->tcp_pbuf->len + 1, sizeof(uint8_t));
  pread_buf = read_buf;
  if (pread_buf != NULL){
    recv_len = pbuf_copy_partial(tcp_ssl->tcp_pbuf, read_buf, len, tcp_ssl->pbuf_offset);
    tcp_ssl->pbuf_offset += recv_len;
  }

  if (recv_len != 0) {
    memcpy(buf, read_buf, recv_len);
  }

  if(len < recv_len) {
    TCP_SSL_DEBUG("tcp_ssl_recv: got %d bytes more than expected\n", recv_len - len);
  }

  free(pread_buf);
  pread_buf = NULL;

  return recv_len;
}

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
      TCP_SSL_DEBUG("ax_port_write: tcp_sndbuf is zero: %d\n", len);
      return ERR_MEM;
    }
  } else {
    tcp_len = len;
  }
  
  if (tcp_len > 2 * tcp_ssl->tcp->mss) {
    tcp_len = 2 * tcp_ssl->tcp->mss;
  }

  err = tcp_write(tcp_ssl->tcp, buf, tcp_len, TCP_WRITE_FLAG_COPY);
  if(err < ERR_OK) {
    if (err == ERR_MEM) {
      TCP_SSL_DEBUG("ax_port_write: No memory %d (%d)\n", tcp_len, len);
      return err;
    }
    TCP_SSL_DEBUG("ax_port_write: tcp_write error: %d\n", err);
    return err;
  } else if (err == ERR_OK) {
    //TCP_SSL_DEBUG("ax_port_write: tcp_output: %d / %d\n", tcp_len, len);
    err = tcp_output(tcp_ssl->tcp);
    if(err != ERR_OK) {
      TCP_SSL_DEBUG("ax_port_write: tcp_output err: %d\n", err);
      return err;
    }
  }

  tcp_ssl->last_wr += tcp_len;

  return tcp_len;
}

uint8_t tcp_ssl_has_client() {
  return _tcp_ssl_has_client;
}

tcp_ssl_t * tcp_ssl_new(struct tcp_pcb *tcp) {

  if(tcp_ssl_next_fd < 0){
    tcp_ssl_next_fd = 0;//overflow
  }

  tcp_ssl_t * new_item = (tcp_ssl_t*)malloc(sizeof(tcp_ssl_t));
  if(!new_item){
    TCP_SSL_DEBUG("tcp_ssl_new: failed to allocate tcp_ssl\n");
    return NULL;
  }

  new_item->tcp = tcp;
  new_item->arg = NULL;
  new_item->on_data = NULL;
  new_item->on_handshake = NULL;
  new_item->on_error = NULL;
  new_item->tcp_pbuf = NULL;
  new_item->pbuf_offset = 0;
  new_item->next = NULL;
  // new_item->fd = tcp_ssl_next_fd++;

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

int tcp_ssl_new_client(struct tcp_pcb *tcp, const char* hostname) {
  tcp_ssl_t* tcp_ssl;

  TCP_SSL_DEBUG("tcp_ssl_new_client\n");

  if(tcp == NULL) {
    return -1;
  }

  if(tcp_ssl_get(tcp) != NULL){
    return -1;
  }

  tcp_ssl = tcp_ssl_new(tcp);
  if(tcp_ssl == NULL){
    return -1;
  }

  mbedtls_entropy_init(&tcp_ssl->entropy_ctx);
  mbedtls_ctr_drbg_init(&tcp_ssl->drbg_ctx);
  mbedtls_ssl_init(&tcp_ssl->ssl_ctx);
  mbedtls_ssl_config_init(&tcp_ssl->ssl_conf);

  mbedtls_ctr_drbg_seed(&tcp_ssl->drbg_ctx, mbedtls_entropy_func,
                        &tcp_ssl->entropy_ctx, (const unsigned char*)pers, strlen(pers));

  if(mbedtls_ssl_config_defaults(&tcp_ssl->ssl_conf,
    MBEDTLS_SSL_IS_CLIENT,
    MBEDTLS_SSL_TRANSPORT_STREAM,
    MBEDTLS_SSL_PRESET_DEFAULT)) {
    TCP_SSL_DEBUG("error setting SSL config.\n");
    
    tcp_ssl_free(tcp);
    return -1;
  }

  // @ToDo: allow setting a root CA, for now just not verify.
  mbedtls_ssl_conf_authmode(&tcp_ssl->ssl_conf, MBEDTLS_SSL_VERIFY_NONE);
  // mbedtls_ssl_conf_authmode(&tcp_ssl->ssl_conf, MBEDTLS_SSL_VERIFY_OPTIONAL);
  
  int ret = 0;

  // @ToDo: required?
  if(hostname != NULL) {
    TCP_SSL_DEBUG("setting the hostname: %s\n", hostname);
    if((ret = mbedtls_ssl_set_hostname(&tcp_ssl->ssl_ctx, hostname)) != 0){
      tcp_ssl_free(tcp);

      return handle_error(ret);
    }
  }

  mbedtls_ssl_conf_rng(&tcp_ssl->ssl_conf, mbedtls_ctr_drbg_random, &tcp_ssl->drbg_ctx);
 
  mbedtls_ssl_conf_verify(&tcp_ssl->ssl_conf, my_verify, NULL);
  mbedtls_ssl_conf_dbg(&tcp_ssl->ssl_conf, my_debug, NULL);
  //mbedtls_debug_set_threshold(2);

  if ((ret = mbedtls_ssl_setup(&tcp_ssl->ssl_ctx, &tcp_ssl->ssl_conf)) != 0) {
    tcp_ssl_free(tcp);
    
    return handle_error(ret);
  }

  mbedtls_ssl_set_bio(&tcp_ssl->ssl_ctx, (void*)tcp_ssl, tcp_ssl_send, tcp_ssl_recv, NULL);
  // mbedtls_ssl_set_bio(&tcp_ssl->ssl_ctx, &tcp_ssl->fd, mbedtls_net_send, mbedtls_net_recv, NULL );

  // Start handshake.
  ret = mbedtls_ssl_handshake(&tcp_ssl->ssl_ctx);
  if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
    TCP_SSL_DEBUG("handshake error!\n");
    return handle_error(ret);
  }

  // @ToDo: don't need the fd?
  return ERR_OK;
}

int tcp_ssl_write(struct tcp_pcb *tcp, uint8_t *data, size_t len) {
  if(tcp == NULL) {
    return -1;
  }
  
  tcp_ssl_t * tcp_ssl = tcp_ssl_get(tcp);

  TCP_SSL_DEBUG("tcp_ssl_write %x, state: %d\n", tcp_ssl, tcp->state);

  if(tcp_ssl == NULL){
    TCP_SSL_DEBUG("tcp_ssl_write: tcp_ssl is NULL\n");
    return 0;
  }

  tcp_ssl->last_wr = 0;

  TCP_SSL_DEBUG("about to call mbedtls_ssl_write\n");
  int rc = mbedtls_ssl_write(&tcp_ssl->ssl_ctx, data, len);

  TCP_SSL_DEBUG("tcp_ssl_write: %u -> %d (%d)\r\n", len, tcp_ssl->last_wr, rc);

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

int tcp_ssl_read(struct tcp_pcb *tcp, struct pbuf *p) {
  TCP_SSL_DEBUG("tcp_ssl_ssl_read\n");

  if(tcp == NULL) {
    return -1;
  }
  tcp_ssl_t* tcp_ssl = NULL;

  int read_bytes = 0;
  int total_bytes = 0;
  static const size_t read_buf_size = 1024;
  uint8_t read_buf[read_buf_size];

  tcp_ssl = tcp_ssl_get(tcp);
  if(tcp_ssl == NULL) {
    TCP_SSL_DEBUG("tcp_ssl_read: tcp_ssl is NULL\n");
    return ERR_TCP_SSL_INVALID_CLIENTFD_DATA;
  }

  if(p == NULL) {
    TCP_SSL_DEBUG("tcp_ssl_read:p == NULL\n");
    return ERR_TCP_SSL_INVALID_DATA;
  }

  TCP_SSL_DEBUG("READY TO READ SOME DATA\n");

  tcp_ssl->tcp_pbuf = p;
  tcp_ssl->pbuf_offset = 0;
  
  do {
    if(tcp_ssl->ssl_ctx.state != MBEDTLS_SSL_HANDSHAKE_OVER) {
      TCP_SSL_DEBUG("start handshake: %d\n", tcp_ssl->ssl_ctx.state);
      int ret = mbedtls_ssl_handshake(&tcp_ssl->ssl_ctx);
      handle_error(ret);
      if(ret == 0) {
        TCP_SSL_DEBUG("Protocol is %s Ciphersuite is %s\n", mbedtls_ssl_get_version(&tcp_ssl->ssl_ctx), mbedtls_ssl_get_ciphersuite(&tcp_ssl->ssl_ctx));

        if(tcp_ssl->on_handshake)
          tcp_ssl->on_handshake(tcp_ssl->arg, tcp_ssl->tcp, tcp_ssl);
      } else if(ret != MBEDTLS_ERR_SSL_WANT_READ || ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
        // if(fd_data->on_error)
        //   fd_data->on_error(fd_data->arg, fd_data->tcp, ret);
        TCP_SSL_DEBUG("handshake error: %d\n", ret);
        // return ret;
        return 0;
      }
    } else {
      read_bytes = mbedtls_ssl_read(&tcp_ssl->ssl_ctx, &read_buf, read_buf_size);
      TCP_SSL_DEBUG("tcp_ssl_read: read_bytes: %d\n", read_bytes);
      if(read_bytes < 0) { // SSL_OK
        // MBEDTLS_ERR_SSL_CONN_EOF
        if(read_bytes != MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) {
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
  } while (p->tot_len - tcp_ssl->pbuf_offset > 0);

  tcp_recved(tcp, p->tot_len);
  tcp_ssl->tcp_pbuf = NULL;
  pbuf_free(p);

  TCP_SSL_DEBUG("tcp_ssl_read: eof: %d\n", total_bytes);

  return total_bytes;
}

int tcp_ssl_free(struct tcp_pcb *tcp) {
  if(tcp == NULL) {
    return -1;
  }
  tcp_ssl_t * item = tcp_ssl_array;
  if(item->tcp == tcp){
    tcp_ssl_array = tcp_ssl_array->next;
    if(item->tcp_pbuf != NULL) {
      pbuf_free(item->tcp_pbuf);
    }
    TCP_SSL_DEBUG("tcp_ssl_free: %x\n", item);
    mbedtls_ssl_free(&item->ssl_ctx);
    mbedtls_ssl_config_free(&item->ssl_conf);
    mbedtls_ctr_drbg_free(&item->drbg_ctx);
    mbedtls_entropy_free(&item->entropy_ctx);
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

void tcp_ssl_handshake(struct tcp_pcb *tcp, tcp_ssl_handshake_cb_t arg){
  tcp_ssl_t * item = tcp_ssl_get(tcp);
  if(item) {
    item->on_handshake = arg;
  }
}

void tcp_ssl_err(struct tcp_pcb *tcp, tcp_ssl_error_cb_t arg){
  tcp_ssl_t * item = tcp_ssl_get(tcp);
  if(item) {
    item->on_error = arg;
  }
}
