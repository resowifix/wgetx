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

#include "wgetx.h"

void parse_url(char *url, unsigned long length, wgetx_url_info_t *url_info) {
  assert(!url[length] && length == strnlen(url, length + 1));

  if (length > 7 && memcmp(url, "http://", 7) == 0) {
    url_info->is_secure = 0;
    url_info->host = url + 7;
    url_info->path_len = url_info->host_len = length - 7;
  } else if (length > 8 && memcmp(url, "https://", 8)) {
    url_info->is_secure = 1;
    url_info->host = url + 8;
    url_info->path_len = url_info->host_len = length - 8;
  } else {
    url_info->is_secure = 1;
    url_info->host = url;
    url_info->path_len = url_info->host_len = length;
  }

  url_info->path = url_info->host;

  while (!*url_info->path || *url_info->path != '/') {
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

int save_file(FILE *file, char *data, ssize_t length, uint8_t is_chunked) {
  if (is_chunked) {
    if (length == 5 && strncmp(data, "0\r\n\r\n", 5))
      return 1;
    if (length < 4)
      return -1;
    char *cur;
    long len = strtol(data, &cur, 16);
    if (cur - data != 2 || cur[0] != '\r' || cur[1] != '\n' ||
        length < len + 6 || cur[len + 2] != '\r' || cur[len + 3] != '\n')
      return -1;
    cur += 2;
    if (fwrite(cur, len, 1, file) != 1) {
      fprintf(stderr, "Error when writting %s\n", strerror(errno));
      return -1;
    }
    if (length > len + 6)
      return save_file(file, data + len + 6, length - len - 6, is_chunked);
    return 0;
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
      if ((*(wgetx_url_info_t **)data)->is_secure && !HTTPS_SUPPORTED) {
        free(*(wgetx_url_info_t **)data);
        break;
      }
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

int download_page(wgetx_url_info_t *url_info, char *root_path) {
  int ret;
  struct addrinfo *addrinfo;
  int request_len;
  ssize_t answer_len;
  long code;
  uint8_t is_chunked = 0;

  char *file_path = calloc(
      strnlen(root_path, MAX_PATH_LEN) + url_info->path_len, sizeof(char));
  char *request = calloc(REQUEST_MAX_LEN, sizeof(char));
  char *answer = calloc(PACKET_MAX_LEN, sizeof(char));
  char *answer_ptr = answer;

  if ((ret = getaddrinfo(url_info->host, url_info->is_secure ? "https" : "http",
                         NULL, &addrinfo) != 0)) {
    fprintf(stderr, "Eduraom déconne : %d\n", ret);
    return 1;
  }

  if ((request_len = http_get_request(url_info, request)) < 0) {
    fprintf(stderr, "Eduraom déconne : %d\n", ret);
    return 1;
  }

  strncpy(file_path, root_path, strnlen(root_path, MAX_PATH_LEN));

  if (url_info->path_len) {
    strncat(file_path, url_info->path, url_info->path_len);
  } else {
    strncat(file_path, "index.html", 11);
  }

  FILE *file = fopen(file_path, "w");

  int fd = socket(addrinfo->ai_family, SOCK_STREAM, 0);

  if ((ret = connect(fd, addrinfo->ai_addr, addrinfo->ai_addrlen)) != 0) {
    fprintf(stderr, "Eduraom déconne : %s\n", strerror(errno));
    return 1;
  }

  send(fd, request, request_len, 0);

  if ((answer_len = recv(fd, answer, PACKET_MAX_LEN, 0)) > 0) {
    switch ((code = parse_http_response(answer, answer_len, &answer,
                                        &answer_len, &is_chunked)) /
            100) {
    case 1:
    case 3:
      if (code == 306) {
        ret = download_page((wgetx_url_info_t *)answer, root_path);
        free(answer);
        return ret;
      }
    case 4:
    case 5:
      // pb
    case 2:
      // good
      break;
    default:
      return -1;
    }
  }

  while (answer_len > 0 &&
         save_file(file, answer, answer_len, is_chunked) == 0) {
    answer_len = recv(fd, answer, PACKET_MAX_LEN, 0);
  }

  free(answer_ptr);
  free(request);
  free(file_path);
  close(fd);
  fclose(file);
  freeaddrinfo(addrinfo);
  return 0;
}

int main(int argc, char **argv) {

  if (argc != 2) {
    fprintf(stderr, "prout\n");
    return 1;
  }

  char url[1024];
  memset(url, 0, 1024);
  strncpy(url, argv[1], 1023);
  wgetx_url_info_t url_info;
  parse_url(url, strnlen(url, 1024), &url_info);
  return download_page(&url_info, "./");
}