#include <netdb.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

#include "wgetx.h"

int wgetx_save_data(const void *data, size_t length, FILE *f, void *null)
{
    return fwrite(data, length, 1, f) == 1;
}

int main(int argc, char **argv)
{
    if (argc != 2) {
        fprintf(stderr, "Usage: %s url\n", argv[0]);
        return 1;
    }

    char url[MAX_URL_LEN];
    memset(url, 0, MAX_URL_LEN);
    strncpy(url, argv[1], MAX_URL_LEN);

    wgetx_url_info_t *url_info = wgetx_parse_url(url, strlen(url));

    return url_info->is_secure ? wgetx_download_page_s(url_info, "./", &wgetx_save_data, NULL)
                               : wgetx_download_page(url_info, "./", &wgetx_save_data, NULL);
}
