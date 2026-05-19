#include <netdb.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <errno.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

#include "wgetx.h"

static SSL_CTX *create_context() {
  const SSL_METHOD *method;
  SSL_CTX *ctx;

  method = TLS_client_method();

  ctx = SSL_CTX_new(method);
  if (ctx == NULL) {
    perror("Unable to create SSL context");
    ERR_print_errors_fp(stderr);
    exit(EXIT_FAILURE);
  }

  return ctx;
}

static void configure_client_context(SSL_CTX *ctx) {
  /*
   * Configure the client to abort the handshake if certificate verification
   * fails
   */
  SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
  /*
   * In a real application you would probably just use the default system
   * certificate trust store and call:
   *     SSL_CTX_set_default_verify_paths(ctx);SSL_CTX_load_verify_locations(ctx,
   * "cert.pem", NULL) In this demo though we are using a self-signed
   * certificate, so the client must trust it directly.
   */
  if (!SSL_CTX_set_default_verify_paths(ctx)) {
    ERR_print_errors_fp(stderr);
    exit(EXIT_FAILURE);
  }
}

void parse_url(char *url, unsigned long length, wgetx_url_info_t *url_info) {
  assert(!url[length] && length == strnlen(url, length + 1));

  if (length > 7 && memcmp(url, "http://", 7) == 0) {
    url_info->is_secure = 0;
    url_info->host = url + 7;
    url_info->path_len = url_info->host_len = length - 7;
  } else if (length > 8 && memcmp(url, "https://", 8) == 0) {
    url_info->is_secure = 1;
    url_info->host = url + 8;
    url_info->path_len = url_info->host_len = length - 8;
  } else {
    url_info->is_secure = 1;
    url_info->host = url;
    url_info->path_len = url_info->host_len = length;
  }

  url_info->path = url_info->host;

  while (*url_info->path && *url_info->path != '/') {
    url_info->path++;
    url_info->path_len--;
  }

  url_info->host_len -= url_info->path_len;

  if (*url_info->path) {
    *url_info->path = 0;
    url_info->path++;
    url_info->path_len--;
  }
}

int save_file(FILE *file, char *data, ssize_t length, uint8_t is_chunked,
              ssize_t *chunk_remaining) {

  if (!length)
    return 0;

  if (is_chunked) {
    if (*chunk_remaining) {
      if (length >= *chunk_remaining + 2) {
        if (data[*chunk_remaining] == '\r' &&
            data[*chunk_remaining + 1] == '\n') {
          if (fwrite(data, *chunk_remaining, 1, file) != 1) {
            fprintf(stderr, "Error when writting %s\n", strerror(errno));
            return -1;
          }
          length = length - *chunk_remaining - 2;
          data += *chunk_remaining +2;
          *chunk_remaining = 0;
          return save_file(file, data, length, is_chunked, chunk_remaining);
        }
        else {
          fprintf(stderr, "Chunk format error\n");
          return -1;
        }
      } else {
        if (fwrite(data, length, 1, file) != 1) {
          fprintf(stderr, "Error when writting %s\n", strerror(errno));
          return -1;
        }
        *chunk_remaining -= length;
        return 0;
      }
    }
    if (length == 5 && strncmp(data, "0\r\n\r\n", 5))
      return 1;
    if (length < 6)
      return -1;
    char *cur;
    *chunk_remaining = strtol(data, &cur, 16);
    if (cur[0] != '\r' || cur[1] != '\n' || length < 2 + data - cur) {
      fprintf(stderr, "Chunk format error\n");
      return -1;
    }
    cur += 2;
    return save_file(file, cur, length - (cur - data), is_chunked,
                     chunk_remaining);
  }

  if (fwrite(data, length, 1, file) != 1) {
    fprintf(stderr, "Error when writting %s\n", strerror(errno));
    return -1;
  }

  return 0;
}

int parse_header_line(char **header, char **data) {

  if ((*header)[0] == '\r' && (*header)[1] == '\n') {
    *header += 2;
    return 0;
  }

  char *field_name = *header;
  char *field_end, *field_data;

  for (field_end = field_name;
       *field_end && !(field_end[0] == ':' && field_end[1] == ' ');
       field_end++) {
    if (field_end[0] == '\r' && field_end[1] == '\n')
      return -1;
  }
  if (!*field_end) {
    return -1;
  }

  field_data = field_end;
  for (field_end += 2;
       *field_end && !(field_end[0] == '\r' && field_end[1] == '\n');
       field_end++) {
  }
  if (!*field_end)
    return -1;

  *field_end = 0;
  field_end += 2;
  *field_data = 0;
  field_data += 2;
  *header = field_end;

  if (strnlen(field_name, 9) == 8 && !memcmp(field_name, "Location", 9)) {
    *data = field_data;
    return 3;
  }
  if (strnlen(field_name, 18) == 17 &&
      !memcmp(field_name, "Transfer-Encoding", 18)) {
    *data = (void *)(long)strncmp(field_data, "chunked", 8);
    return 2;
  }
  return 1;
}

long parse_http_response(char *recv_data, ssize_t rcv_len, void *data,
                         ssize_t *data_len, uint8_t *is_chunked) {
  char *cur;
  char *rep_code;
  long code;
  int header_line;
  char *header_data;

  if (memcmp(recv_data, "HTTP", 4)) {
    return 1;
  }

  for (cur = recv_data; *cur != ' ' && *cur; cur++)
    ;
  if (!*cur) {
    return 1;
  }

  rep_code = ++cur;
  for (; *cur != ' ' && *cur != '\r' && *cur; cur++)
    ;
  *cur = 0;
  if (strnlen(rep_code, 4) != 3) {
    return 1;
  }

  code = strtol(rep_code, &cur, 10);

  cur++;

  for (; *cur != '\n' && *cur; cur++) {
  }
  if (!*cur) {
    return 1;
  }

  cur++;

  while ((header_line = parse_header_line(&cur, &header_data))) {
    switch (header_line) {
    case -1:
      return 1;
    case 2:
      *is_chunked = !(uint8_t)(long)header_data;
      break;
    case 3:
      if (code / 100 != 3)
        break;
      *(wgetx_url_info_t **)data = calloc(1, sizeof(wgetx_url_info_t));
      parse_url(header_data, strlen(header_data), *(wgetx_url_info_t **)data);
      *data_len = sizeof(wgetx_url_info_t);
      return 306;
    default:;
    }
  }
  *(char **)data = cur;
  *data_len = rcv_len - (cur - recv_data);
  return code;
}

int http_get_request(wgetx_url_info_t *urlinfo, char *buf) {
  return snprintf(buf, REQUEST_MAX_LEN - 1,
                  "GET /%s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n",
                  urlinfo->path, urlinfo->host);
}

int download_page_s(wgetx_url_info_t *url_info, char *root_path) {
  int ret;
  struct addrinfo *addrinfo = NULL;
  int request_len;
  ssize_t answer_len;
  long code;
  uint8_t is_chunked = 0;
  ssize_t chunk_remaining = 0;

  SSL_CTX *ssl_ctx = create_context();
  SSL *ssl = NULL;

  int fd = -1;
  FILE *file = NULL;

  configure_client_context(ssl_ctx);

  ssl = SSL_new(ssl_ctx);

  char *file_path = calloc(
      strnlen(root_path, MAX_PATH_LEN) + url_info->path_len, sizeof(char));
  char *request = calloc(REQUEST_MAX_LEN, sizeof(char));
  char *answer = calloc(PACKET_MAX_LEN, sizeof(char));
  char *answer_ptr = answer;

  if (!file_path || !request || !answer) {
    fprintf(stderr, "Allocation error\n");
    return 1;
  }

  if ((ret = getaddrinfo(url_info->host, url_info->is_secure ? "https" : "http",
                         NULL, &addrinfo) != 0)) {
    fprintf(stderr, "Name resolution error : %s\n",
            ret != -1 ? gai_strerror(ret) : strerror(errno));
    ret = 1;
    goto end;
  }

  if ((request_len = http_get_request(url_info, request)) < 0) {
    fprintf(stderr, "Request formation error : %d\n", ret);
    ret = 1;
    goto end;
  }

  strncpy(file_path, root_path, strnlen(root_path, MAX_PATH_LEN));

  if (url_info->path_len) {
    memcpy(file_path + strlen(file_path), url_info->path,
           MIN(strlen(file_path), MAX_PATH_LEN - strlen(root_path)));
  } else {
    memcpy(file_path + strlen(file_path), "index.html",
           MIN(11, MAX_PATH_LEN - strlen(file_path)));
  }

  if ((file = fopen(file_path, "w")) == NULL) {
    fprintf(stderr, "Error while openning %s : %s\n", file_path,
            strerror(errno));
    ret = 1;
    goto end;
  }

  if ((fd = socket(addrinfo->ai_family, SOCK_STREAM, 0)) < 0) {
    fprintf(stderr, "Invalid socket creation : %s\n", strerror(errno));
    ret = 1;
    goto end;
  };

  if ((ret = connect(fd, addrinfo->ai_addr, addrinfo->ai_addrlen)) != 0) {
    fprintf(stderr, "Impossible  to connect to remote host : %s\n",
            strerror(errno));
    ret = 1;
    goto end;
  }

  if (!SSL_set_fd(ssl, fd)) {
    ERR_print_errors_fp(stderr);
    ret = 1;
    goto end;
  }
  /* Set hostname for SNI */
  SSL_set_tlsext_host_name(ssl, url_info->host);
  /* Configure server hostname check */
  if (!SSL_set1_host(ssl, url_info->host)) {
    ERR_print_errors_fp(stderr);
    ret = 1;
    goto end;
  }

  SSL_connect(ssl);

  SSL_write(ssl, request, request_len);

  if ((answer_len = SSL_read(ssl, answer, PACKET_MAX_LEN)) > 0) {
    switch ((code = parse_http_response(answer, answer_len, &answer,
                                        &answer_len, &is_chunked)) /
            100) {
    case 1:
    case 3:
      if (code == 306) {
        SSL_shutdown(ssl);
        SSL_free(ssl);
        SSL_CTX_free(ssl_ctx);
        free(request);
        free(file_path);
        close(fd);
        fclose(file);
        freeaddrinfo(addrinfo);
        ret = ((wgetx_url_info_t *)answer)->is_secure
                  ? download_page_s((wgetx_url_info_t *)answer, root_path)
                  : download_page((wgetx_url_info_t *)answer, root_path);
        free(answer_ptr);
        return ret;
      }
    case 4:
    case 5:
      // pb
    case 2:
      // good
      break;
    default:
      ret = 1;
      goto end;
    }
  } else if (answer_len < 0) {
    fprintf(stderr, "Error while receiving data : %s\n", strerror(errno));
    ret = 1;
    goto end;
  }

  while (answer_len > 0 && save_file(file, answer, answer_len, is_chunked,
                                     &chunk_remaining) == 0) {
    answer_len = SSL_read(ssl, answer, PACKET_MAX_LEN);
  }

  if (answer_len < 0) {
    fprintf(stderr, "Error while receiving data : %s\n", strerror(errno));
    ret = 1;
    goto end;
  }

end:
  if (ssl) {
    SSL_shutdown(ssl);
    SSL_free(ssl);
  }
  SSL_CTX_free(ssl_ctx);
  free(answer_ptr);
  free(request);
  free(file_path);
  if (fd != -1)
    close(fd);
  if (file)
    fclose(file);
  if (addrinfo)
    freeaddrinfo(addrinfo);
  return ret;
}

int download_page(wgetx_url_info_t *url_info, char *root_path) {
  int ret;
  struct addrinfo *addrinfo = NULL;
  int request_len;
  ssize_t answer_len;
  long code;
  uint8_t is_chunked = 0;
  ssize_t chunk_remaining = 0;

  int fd = -1;
  FILE *file = NULL;

  char *file_path = calloc(
      strnlen(root_path, MAX_PATH_LEN) + url_info->path_len, sizeof(char));
  char *request = calloc(REQUEST_MAX_LEN, sizeof(char));
  char *answer = calloc(PACKET_MAX_LEN, sizeof(char));
  char *answer_ptr = answer;

  if (!file_path || !request || !answer) {
    fprintf(stderr, "Allocation error\n");
    return 1;
  }

  if ((ret = getaddrinfo(url_info->host, url_info->is_secure ? "https" : "http",
                         NULL, &addrinfo) != 0)) {
    fprintf(stderr, "Name resolution error : %s\n",
            ret != -1 ? gai_strerror(ret) : strerror(errno));
    ret = 1;
    goto end;
  }

  if ((request_len = http_get_request(url_info, request)) < 0) {
    fprintf(stderr, "Request formation error : %d\n", ret);
    ret = 1;
    goto end;
  }

  strncpy(file_path, root_path, strnlen(root_path, MAX_PATH_LEN));

  if (url_info->path_len) {
    memcpy(file_path + strlen(file_path), url_info->path,
           MIN(strlen(file_path), MAX_PATH_LEN - strlen(root_path)));
  } else {
    memcpy(file_path + strlen(file_path), "index.html",
           MIN(11, MAX_PATH_LEN - strlen(file_path)));
  }

  if ((file = fopen(file_path, "w")) == NULL) {
    fprintf(stderr, "Error while openning %s : %s\n", file_path,
            strerror(errno));
    ret = 1;
    goto end;
  }

  if ((fd = socket(addrinfo->ai_family, SOCK_STREAM, 0)) < 0) {
    fprintf(stderr, "Invalid socket creation : %s\n", strerror(errno));
    ret = 1;
    goto end;
  };

  if ((ret = connect(fd, addrinfo->ai_addr, addrinfo->ai_addrlen)) != 0) {
    fprintf(stderr, "Impossible  to connect to remote host : %s\n",
            strerror(errno));
    ret = 1;
    goto end;
  }

  if (send(fd, request, request_len, 0) < 0) {
    fprintf(stderr, "Impossible to send request : %s\n", strerror(errno));
    ret = 1;
    goto end;
  };

  if ((answer_len = recv(fd, answer, PACKET_MAX_LEN, 0)) > 0) {
    switch ((code = parse_http_response(answer, answer_len, &answer,
                                        &answer_len, &is_chunked)) /
            100) {
    case 1:
    case 3:
      if (code == 306) {
        free(request);
        free(file_path);
        close(fd);
        fclose(file);
        freeaddrinfo(addrinfo);
        ret = ((wgetx_url_info_t *)answer)->is_secure
                  ? download_page_s((wgetx_url_info_t *)answer, root_path)
                  : download_page((wgetx_url_info_t *)answer, root_path);
        free(answer_ptr);
        return ret;
      }
    case 4:
    case 5:
      // pb
    case 2:
      // good
      break;
    default:
      ret = 1;
      goto end;
    }
  } else if (answer_len < 0) {
    fprintf(stderr, "Error while receiving data : %s\n", strerror(errno));
    ret = 1;
    goto end;
  }

  while (answer_len > 0 && save_file(file, answer, answer_len, is_chunked,
                                     &chunk_remaining) == 0) {
    answer_len = recv(fd, answer, PACKET_MAX_LEN, 0);
  }

  if (answer_len < 0) {
    fprintf(stderr, "Error while receiving data : %s\n", strerror(errno));
    ret = 1;
    goto end;
  }

end:
  free(answer_ptr);
  free(request);
  free(file_path);
  if (fd != -1)
    close(fd);
  if (file)
    fclose(file);
  if (addrinfo)
    freeaddrinfo(addrinfo);
  return ret;
}

int main(int argc, char **argv) {

  if (argc != 2) {
    fprintf(stderr, "Usage: %s url\n", argv[0]);
    return 1;
  }

  char url[1024];
  memset(url, 0, 1024);
  strncpy(url, argv[1], 1023);

  wgetx_url_info_t url_info;
  parse_url(url, strlen(url), &url_info);

  return url_info.is_secure ? download_page_s(&url_info, "./")
                            : download_page(&url_info, "./");
}