#include "tcp_mbedtls.h"
#include "lwip/tcp.h"
#include "mbedtls/debug.h"
#include <string.h>

#define TCP_SSL_DEBUG(...) ets_printf(__VA_ARGS__)

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
  int last_wr;
  struct pbuf *tcp_pbuf;
  int pbuf_offset;
  struct tcp_ssl_pcb* next;
};

typedef struct tcp_ssl_pcb tcp_ssl_t;

static tcp_ssl_t * tcp_ssl_array = NULL;
static int tcp_ssl_next_fd = 0;

int tcp_ssl_recv(void *ctx, unsigned char *buf, size_t len) {
  tcp_ssl_t *fd_data = (tcp_ssl_t*)ctx;
  uint8_t *read_buf = NULL;
  uint8_t *pread_buf = NULL;
  u16_t recv_len = 0;

  if(fd_data->tcp_pbuf == NULL || fd_data->tcp_pbuf->tot_len == 0) {
    return 0;
  }

  read_buf =(uint8_t*)calloc(fd_data->tcp_pbuf->len + 1, sizeof(uint8_t));
  pread_buf = read_buf;
  if (pread_buf != NULL){
    recv_len = pbuf_copy_partial(fd_data->tcp_pbuf, read_buf, len, fd_data->pbuf_offset);
    fd_data->pbuf_offset += recv_len;
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

int tcp_ssl_send(void *ctx, const unsigned char *buf, size_t size) {
  if(ctx == NULL) {
    TCP_SSL_DEBUG("tcp_ssl_send: no context set\n");
    return -1;
  }

  if(buf == NULL) {
    TCP_SSL_DEBUG("tcp_ssl_send: buf not set\n");
    return -1;
  }

  tcp_ssl_t *tcp = (tcp_ssl_t*)ctx;
  
  size_t room = tcp_sndbuf(tcp->tcp);
  size_t will_send = (room < size) ? room : size;

  TCP_SSL_DEBUG("len: %d, has space? %d\n", size, room);

  int8_t ret = tcp_write(tcp->tcp, buf, will_send, 0);
  if(ret == ERR_OK) {
    TCP_SSL_DEBUG("oki!\n");
  }

  return will_send;
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
  // new_item->ssl_ctx = NULL;
  // new_item->ssl = NULL;
  new_item->fd = tcp_ssl_next_fd++;

  if(tcp_ssl_array == NULL){
    tcp_ssl_array = new_item;
  } else {
    tcp_ssl_t * item = tcp_ssl_array;
    while(item->next != NULL)
      item = item->next;
    item->next = new_item;
  }

  TCP_SSL_DEBUG("tcp_ssl_new: %d: 0x%x\n", new_item->fd, tcp);
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

int tcp_ssl_new_client(struct tcp_pcb *tcp) {
  tcp_ssl_t* tcp_ssl;

  TCP_SSL_DEBUG("tcp_ssl_new_client\n");

  if(tcp == NULL) {
    return -1;
  }

  if(tcp_ssl_get(tcp) != NULL){
    TCP_SSL_DEBUG("tcp_ssl_new_client: tcp_ssl already exists\n");
    return -1;
  }

  tcp_ssl = tcp_ssl_new(tcp);
  if(tcp_ssl == NULL){
    return -1;
  }

  // 
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
    
    // tcp_ssl_free(tcp);
    return -1;
  }

  mbedtls_ssl_conf_authmode(&tcp_ssl->ssl_conf, MBEDTLS_SSL_VERIFY_NONE);
  int ret = 0;

  // @ToDo: there's no hostname at this stage, set it later.
  // if((ret = mbedtls_ssl_set_hostname(&ctx->ssl_ctx, host)) != 0){
  //   return handle_error(ret);
  // }

  mbedtls_ssl_conf_rng(&tcp_ssl->ssl_conf, mbedtls_ctr_drbg_random, &tcp_ssl->drbg_ctx);
 
  if ((ret = mbedtls_ssl_setup(&tcp_ssl->ssl_ctx, &tcp_ssl->ssl_conf)) != 0) {
    // tcp_ssl_free(tcp);
    return handle_error(ret);
  }

  // mbedtls_ssl_set_bio(&tcp_ssl->ssl_ctx, (void*)tcp_ssl, tcp_ssl_send, tcp_ssl_recv, NULL );
  mbedtls_ssl_set_bio(&tcp_ssl->ssl_ctx, (void*)tcp_ssl, tcp_ssl_send, tcp_ssl_recv, NULL);
  // mbedtls_ssl_set_bio(&tcp_ssl->ssl_ctx, &tcp_ssl->fd, mbedtls_net_send, mbedtls_net_recv, NULL );

  // @ToDo: do we need this here?
  ret = mbedtls_ssl_handshake(&tcp_ssl->ssl_ctx);
  handle_error(ret);
  TCP_SSL_DEBUG("ret mbedtls_ssl_handshake: %d, want read: %d, write: %d\n", ret, MBEDTLS_ERR_SSL_WANT_READ, MBEDTLS_ERR_SSL_WANT_WRITE);
  // if (ret != 0 && ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
  //   TCP_SSL_DEBUG("tcp_ssl_new_client: mbedtls_ssl_handshake: %d.\n", ret);
  //   // if(tcp_ssl->on_error)
  //   //   tcp_ssl->on_error(tcp_ssl->arg, tcp_ssl->tcp, ret);
  // }

  TCP_SSL_DEBUG("end tcp_ssl_new_client %d.\n", tcp_ssl->fd);

  return tcp_ssl->fd;
}

int tcp_ssl_write(struct tcp_pcb *tcp, uint8_t *data, size_t len) {
  if(tcp == NULL) {
    return -1;
  }
  
  tcp_ssl_t * tcp_ssl = tcp_ssl_get(tcp);

  TCP_SSL_DEBUG("tcp_ssl_write %x\n, state: %d\n", tcp_ssl, tcp->state);

  if(tcp_ssl == NULL){
    TCP_SSL_DEBUG("tcp_ssl_write: tcp_ssl is NULL\n");
    return 0;
  }

  tcp_ssl->last_wr = 0;

  TCP_SSL_DEBUG("about to call mbedtls_ssl_write\n");
  int rc = mbedtls_ssl_write(&tcp_ssl->ssl_ctx, data, len);

  TCP_SSL_DEBUG("tcp_ssl_write: %u -> %d (%d)\r\n", len, tcp_ssl->last_wr, rc);

  if (rc < 0){
    // @ToDO: ???
    // if(rc != MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) {
      TCP_SSL_DEBUG("tcp_ssl_write error: %d\r\n", rc);
    // }
    return rc;
  }

  return tcp_ssl->last_wr;
}

int tcp_ssl_read(struct tcp_pcb *tcp, struct pbuf *p) {
  TCP_SSL_DEBUG("tcp_ssl_ssl_read\n");

  if(tcp == NULL) {
    return -1;
  }
  tcp_ssl_t* fd_data = NULL;

  int read_bytes = 0;
  int total_bytes = 0;
  uint8_t *read_buf;

  fd_data = tcp_ssl_get(tcp);
  if(fd_data == NULL) {
    TCP_SSL_DEBUG("tcp_ssl_read: tcp_ssl is NULL\n");
    return ERR_TCP_SSL_INVALID_CLIENTFD_DATA;
  }

  if(p == NULL) {
    TCP_SSL_DEBUG("tcp_ssl_read:p == NULL\n");
    return ERR_TCP_SSL_INVALID_DATA;
  }

  TCP_SSL_DEBUG("READY TO READ SOME DATA\n");

  fd_data->tcp_pbuf = p;
  fd_data->pbuf_offset = 0;

  do {    
    if(fd_data->ssl_ctx.state != MBEDTLS_SSL_HANDSHAKE_OVER) {
      TCP_SSL_DEBUG("start handshake: %d\n", fd_data->ssl_ctx.state);
      int ret = mbedtls_ssl_handshake(&fd_data->ssl_ctx);
      if(ret == 0) {
        if(fd_data->on_handshake)
          fd_data->on_handshake(fd_data->arg, fd_data->tcp, fd_data);
      } else if(ret != MBEDTLS_ERR_SSL_WANT_READ || ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
        // if(fd_data->on_error)
        //   fd_data->on_error(fd_data->arg, fd_data->tcp, ret);
        
        TCP_SSL_DEBUG("handshake error: %d\n", ret);
        // return ret;
        //return 0;
      }
    } else {
      uint8_t readb[1024];
      read_bytes = mbedtls_ssl_read(&fd_data->ssl_ctx, &readb, 1024);
      TCP_SSL_DEBUG("start read: %d.\n", read_bytes);
      if(read_bytes < 0) {
        handle_error(read_bytes);
        if(read_bytes != MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) {
          TCP_SSL_DEBUG("tcp_ssl_read: read error: %d\n", read_bytes);
        }
        total_bytes = read_bytes;
        break;
      } else if(read_bytes > 0) {
        if(fd_data->on_data){
          fd_data->on_data(fd_data->arg, tcp, &readb, read_bytes);
        }
        total_bytes+= read_bytes;
      }
    }
    //   if(fd_data->ssl_ctx.state != MBEDTLS_SSL_HANDSHAKE_OVER) {
    //     TCP_SSL_DEBUG("start handshake.\n");
    //     int ret = mbedtls_ssl_handshake(&fd_data->ssl_ctx);
    //     if(ret == 0) {
    //       if(fd_data->on_handshake)
    //         fd_data->on_handshake(fd_data->arg, fd_data->tcp, fd_data);
    //     } else if(ret != MBEDTLS_ERR_SSL_WANT_READ || ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
    //       if(fd_data->on_error)
    //         fd_data->on_error(fd_data->arg, fd_data->tcp, ret);
    //       return ret;
    //     }
    //   } 
    // // @TODO: FIX!
    // read_bytes = mbedtls_ssl_read(&fd_data->ssl_ctx, &read_buf, 0);
    // TCP_SSL_DEBUG("tcp_ssl_ssl_read: read_bytes: %d (%d)\n", read_bytes, MBEDTLS_SSL_HANDSHAKE_OVER);
    // if(read_bytes < 0) {
    //   handle_error(read_bytes);
    //   if(read_bytes != MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) {
    //     TCP_SSL_DEBUG("tcp_ssl_read: read error: %d\n", read_bytes);
    //   }
    //   total_bytes = read_bytes;
    //   break;
    // } else if(read_bytes > 0){
    //   if(fd_data->on_data){
    //     fd_data->on_data(fd_data->arg, tcp, read_buf, read_bytes);
    //   }
    //   total_bytes+= read_bytes;
    // } else {
    //   TCP_SSL_DEBUG("start handshake? %d.\n", fd_data->ssl_ctx.state);
    //   if(fd_data->ssl_ctx.state != MBEDTLS_SSL_HANDSHAKE_OVER) {
    //     TCP_SSL_DEBUG("start handshake.\n");
    //     int ret = mbedtls_ssl_handshake(&fd_data->ssl_ctx);
    //     if(ret == 0) {
    //       if(fd_data->on_handshake)
    //         fd_data->on_handshake(fd_data->arg, fd_data->tcp, fd_data);
    //     } else if(ret != MBEDTLS_ERR_SSL_WANT_READ || ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
    //       if(fd_data->on_error)
    //         fd_data->on_error(fd_data->arg, fd_data->tcp, ret);
    //       return ret;
    //     }
    //   } 
    // }
  } while (p->tot_len - fd_data->pbuf_offset > 0);
     
  // OLD     
  // if(fd_data->handshake != MBEDTLS_SSL_HANDSHAKE_OVER) {
  //   fd_data->handshake = mbedtls_ssl_handshake(&fd_data->ssl_ctx);
  //   if(fd_data->handshake == 0){
  //     TCP_SSL_DEBUG("tcp_ssl_read: handshake OK\n");
  //     if(fd_data->on_handshake)
  //       fd_data->on_handshake(fd_data->arg, fd_data->tcp, fd_data);
  //   } else if(fd_data->handshake != 0){
  //     TCP_SSL_DEBUG("tcp_ssl_read: handshake error: %d\n", fd_data->handshake);
  //     if(fd_data->on_error)
  //       fd_data->on_error(fd_data->arg, fd_data->tcp, fd_data->handshake);
  //     return fd_data->handshake;
  //   }
  // }

  tcp_recved(tcp, p->tot_len);
  fd_data->tcp_pbuf = NULL;
  pbuf_free(p);

  TCP_SSL_DEBUG("tcp_ssl_read: eof: %d\n", total_bytes);

  return total_bytes;
}

int tcp_ssl_free(struct tcp_pcb *tcp) {
  TCP_SSL_DEBUG("tcp_ssl_free: 1\n");
  if(tcp == NULL) {
    return -1;
  }
  TCP_SSL_DEBUG("tcp_ssl_free: 2\n");
  tcp_ssl_t * item = tcp_ssl_array;
  TCP_SSL_DEBUG("tcp_ssl_free: 2a 0x%x\n", item);
  if(item->tcp == tcp){
    TCP_SSL_DEBUG("tcp_ssl_free: 3\n");
    tcp_ssl_array = tcp_ssl_array->next;
    if(item->tcp_pbuf != NULL) {
      pbuf_free(item->tcp_pbuf);
    }
    TCP_SSL_DEBUG("tcp_ssl_free: %d\n", item->fd);
    mbedtls_ssl_free(&item->ssl_ctx);
    mbedtls_ssl_config_free(&item->ssl_conf);
    mbedtls_ctr_drbg_free(&item->drbg_ctx);
    mbedtls_entropy_free(&item->entropy_ctx);
    free(item);
    return 0;
  }

  TCP_SSL_DEBUG("tcp_ssl_free: 4\n");
  while(item->next && item->next->tcp != tcp)
    item = item->next;

  TCP_SSL_DEBUG("tcp_ssl_free: 5\n");
  if(item->next == NULL){
    return ERR_TCP_SSL_INVALID_CLIENTFD_DATA;//item not found
  }
  TCP_SSL_DEBUG("tcp_ssl_free: 6\n");
  tcp_ssl_t * i = item->next;
  item->next = i->next;
  if(i->tcp_pbuf != NULL){
    pbuf_free(i->tcp_pbuf);
  }
  TCP_SSL_DEBUG("tcp_ssl_free: %d\n", i->fd);
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
