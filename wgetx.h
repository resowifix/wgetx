#ifndef WGETX_H
#define WGETX_H

#include <stdint.h>
#include <stdio.h>

#define REQUEST_MAX_LEN 8000
#define PACKET_MAX_LEN  65535
#define MAX_PATH_LEN    8000
#define MAX_URL_LEN     8000

#define URL_CHAR                                                                            \
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!*'();:@&=+$,/?#[]%_.~-"

#define MAX(x, y) ((x) < (y) ? (y) : (x))
#define MIN(x, y) ((x) < (y) ? (x) : (y))

typedef struct st_wgetx_url_info_t {
    char host[MAX_URL_LEN];
    unsigned long host_len;
    char path[MAX_PATH_LEN];
    unsigned long path_len;
    uint8_t is_secure;
} wgetx_url_info_t;

typedef struct st_wgetx_cnx_ctx_t {
    char file_path[MAX_PATH_LEN];
    char *answer;
    char *answer_ptr;
    FILE *file;
    char *request;
    int request_len;
    int fd;
} wgetx_cnx_ctx_t;

typedef int (*wgetx_data_processor_t)(const void *, size_t, FILE *, void *);

int wgetx_is_url_char(char c);

void wgetx_create_local_path(char *root_path, char *path, int path_len, char *local_path);

wgetx_url_info_t *wgetx_parse_url(char *url, unsigned long length);

int wgetx_download_page_s(wgetx_url_info_t *url_info, char *root_path,
        wgetx_data_processor_t processor, void *processor_arg);

int wgetx_download_page(wgetx_url_info_t *url_info, char *root_path,
        wgetx_data_processor_t processor, void *processor_arg);

#endif // WGETX_H
