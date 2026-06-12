#include <netdb.h>
#include <openssl/cryptoerr_legacy.h>
#include <sched.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

#include "wgetx.h"
#include "setx.h"

typedef struct st_wgetx_page_to_be_downloaded_t wgetx_page_to_be_downloaded_t;

struct st_wgetx_page_to_be_downloaded_t {
    wgetx_url_info_t *url_info;
    int recursive_level;
    wgetx_page_to_be_downloaded_t *next;
};

typedef struct st_wgetx_downloader_args_t {
    wgetx_url_info_t *url_info;
    wgetx_page_to_be_downloaded_t *pages;
    char *root_path;
    int *thread_number;
    int recursive_level;
} wgetx_downloader_args_t;

typedef struct st_wgetx_processor_args_t {
    wgetx_page_to_be_downloaded_t *pages;
    char *root_path;
    int recursive_level;
    int len_buffered;
    char split_buffer[MAX_URL_LEN];
} wgetx_processor_args_t;

pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;

int wgetx_parse_href_url(char *byte, const char *last_byte, wgetx_page_to_be_downloaded_t **page,
        char **end)
{
    if ((*page = calloc(1, sizeof(wgetx_page_to_be_downloaded_t))) == NULL) {
        return -1;
    }

    for (*end = byte; *end < last_byte; (*end)++) {
        if (**end == '"') {
            **end = 0;
            if (((*page)->url_info = wgetx_parse_url(byte, *end - byte)) == NULL) {
                free(*page);
                return -1;
            }
            **end = '"';
            return 0;
        }
        if (!wgetx_is_url_char(**end) || *end - byte > MAX_URL_LEN) {
            free(*page);
            return -1;
        }
    }
    free(*page);
    return 1;
}

void wgetx_insert_page(wgetx_page_to_be_downloaded_t *pages, wgetx_page_to_be_downloaded_t *page)
{
    if (pages->next == NULL) {
        pages->next = page;
        page->next = NULL;
    } else {
        page->next = pages->next;
        pages->next = page;
    }
}

wgetx_downloader_args_t *wgetx_pop_page(wgetx_page_to_be_downloaded_t *pages)
{
    wgetx_downloader_args_t *downloader_args = NULL;
    if ((downloader_args = calloc(1, sizeof(wgetx_downloader_args_t))) == NULL)
        return NULL;

    downloader_args->url_info = pages->next->url_info;
    downloader_args->recursive_level = pages->next->recursive_level;
    downloader_args->pages = pages;

    wgetx_page_to_be_downloaded_t *next = pages->next->next;
    free(pages->next);
    pages->next = next;

    return downloader_args;
}

int wgetx_process_data(const void *data, size_t length, FILE *f, void *args)
{
    wgetx_processor_args_t *processor_arg = args;

    const char *segment_start = data;
    wgetx_page_to_be_downloaded_t *page;
    char local_path[MAX_PATH_LEN];
    int ret;
    char *end, *cur;
    char *last_byte = (char *)data + length;

    memcpy(processor_arg->split_buffer + processor_arg->len_buffered, data,
            MIN(MAX_URL_LEN - processor_arg->len_buffered, length));
    
    for (cur = processor_arg->split_buffer; cur < processor_arg->split_buffer + processor_arg->len_buffered; cur++) {
        switch (*cur) {
            case 'h':
                if (!memcmp(cur, "href=\"", 6)) {
                    page = NULL;

                    if (!(ret = wgetx_parse_href_url(cur + 6, data + length, &page, &end))) {
                        page->recursive_level = processor_arg->recursive_level + 1;

                        pthread_mutex_lock(&lock);
                        wgetx_insert_page(processor_arg->pages, page);
                        wgetx_create_local_path(processor_arg->root_path, page->url_info->path,
                                page->url_info->path_len, local_path);
                        pthread_mutex_unlock(&lock);

                        fwrite(segment_start, cur - segment_start + 6, 1, f);
                        fwrite(local_path, strlen(local_path), 1, f);
                        segment_start = cur = end;
                    } else if (ret == 1) {
                        memcpy(processor_arg->split_buffer, cur, last_byte - cur);
                        processor_arg->len_buffered = last_byte - cur;
                        ret = fwrite(segment_start, last_byte - segment_start, 1, f) == 1;
                        return ret && !fseek(f, cur - last_byte, SEEK_CUR);
                    } else if (ret == -1) {
                        continue;
                    }
                }
            default:
                break;
        }
    }

    for (char *cur = (char *)data; cur < last_byte - 5; cur++) {
        switch (*cur) {
            case 'h':
                if (!memcmp(cur, "href=\"", 6)) {
                    page = NULL;

                    if (!(ret = wgetx_parse_href_url(cur + 6, data + length, &page, &end))) {
                        page->recursive_level = processor_arg->recursive_level + 1;

                        pthread_mutex_lock(&lock);
                        wgetx_insert_page(processor_arg->pages, page);
                        wgetx_create_local_path(processor_arg->root_path, page->url_info->path,
                                page->url_info->path_len, local_path);
                        pthread_mutex_unlock(&lock);

                        fwrite(segment_start, cur - segment_start + 6, 1, f);
                        fwrite(local_path, strlen(local_path), 1, f);
                        segment_start = cur = end;
                    } else if (ret == 1) {
                        memcpy(processor_arg->split_buffer, cur, last_byte - cur);
                        processor_arg->len_buffered = last_byte - cur;
                        ret = fwrite(segment_start, last_byte - segment_start, 1, f) == 1;
                        return ret && !fseek(f, cur - last_byte, SEEK_CUR);
                    } else if (ret == -1) {
                        continue;
                    }
                }
            default:
                break;
        }
    }
    memcpy(processor_arg->split_buffer, last_byte - 5, 5);
    processor_arg->len_buffered = 5;
    ret = fwrite(segment_start, last_byte - segment_start, 1, f) == 1;
    return ret && !fseek(f, -5, SEEK_CUR);
}

void *wgetx_downloader(void *args)
{
    wgetx_downloader_args_t *downloader_args = (wgetx_downloader_args_t *)args;

    wgetx_processor_args_t processor_arg = {.pages = downloader_args->pages,
            .root_path = downloader_args->root_path,
            .recursive_level = downloader_args->recursive_level,
            .len_buffered = 0};

    downloader_args->url_info->is_secure
            ? wgetx_download_page_s(downloader_args->url_info, downloader_args->root_path,
                      &wgetx_process_data, &processor_arg)
            : wgetx_download_page(downloader_args->url_info, downloader_args->root_path,
                      &wgetx_process_data, &processor_arg);

    pthread_mutex_lock(&lock);
    (*downloader_args->thread_number)--;
    pthread_mutex_unlock(&lock);
    return NULL;
}

int main(int argc, char **argv)
{
    wgetx_page_to_be_downloaded_t pages = {.url_info = NULL, .recursive_level = -1, .next = NULL};
    int nb_running_threads = 0;
    pthread_t t;
    wgetx_downloader_args_t *downloader_args;

    char root_path[] = "./";

    if (argc != 2) {
        fprintf(stderr, "Usage: %s url\n", argv[0]);
        return 1;
    }

    char url[MAX_URL_LEN];
    memset(url, 0, MAX_URL_LEN);
    strncpy(url, argv[1], MAX_URL_LEN);

    pages.next = malloc(sizeof(wgetx_page_to_be_downloaded_t));
    pages.next->url_info = wgetx_parse_url(url, strlen(url));
    pages.next->recursive_level = 0;
    pages.next->next = NULL;

    while (1) {
        pthread_mutex_lock(&lock);
        if (!nb_running_threads && !pages.next)
            break;

        if (nb_running_threads < 10 && pages.next
                && (downloader_args = wgetx_pop_page(&pages)) != NULL) {
            pthread_mutex_unlock(&lock);

            downloader_args->root_path = root_path;
            downloader_args->thread_number = &nb_running_threads;
            pthread_create(&t, NULL, wgetx_downloader, downloader_args);

            pthread_mutex_lock(&lock);
            nb_running_threads++;
        }
        pthread_mutex_unlock(&lock);
    }
    pthread_mutex_unlock(&lock);
}
