#define REQUEST_MAX_LEN 2048
#define PACKET_MAX_LEN 65535
#define MAX_PATH_LEN 1024
#define MAX_URL_LEN 1024

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
  int request_len;
  char *request;
  char *file_path;
  char *answer;
  char *answer_ptr;
  FILE *file;
  int fd;
} wgetx_cnx_ctx_t;

int wgetx_download_page(wgetx_url_info_t *url_info, char *root_path);