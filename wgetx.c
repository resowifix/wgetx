#include <netdb.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

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

  while (!url_info->path || *url_info->path != '/') {
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

  char *file_path = calloc(
      strnlen(root_path, MAX_PATH_LEN) + url_info->path_len, sizeof(char));
  char *request = calloc(REQUEST_MAX_LEN, sizeof(char));
  char *answer = calloc(PACKET_MAX_LEN, sizeof(char));

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

  int fd = socket(AF_INET, SOCK_STREAM, 0);

  if ((ret = connect(fd, addrinfo->ai_addr, addrinfo->ai_addrlen) != 0)) {
    fprintf(stderr, "Eduraom déconne : %d\n", ret);
    return 1;
  }

  send(fd, request, request_len, 0);

  while (1) {
    if ((answer_len = recv(fd, answer, PACKET_MAX_LEN, 0)) <= 0)
      break;

    size_t nbr = fwrite(answer, answer_len, 1, file);
    if (nbr != 1) {
      printf("Error when writting %d\n", (int)nbr);
    }
  }

  close(fd);
  fclose(file);
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