#include <stdint.h>

#define REQUEST_MAX_LEN 2048
#define PACKET_MAX_LEN 65535
#define MAX_PATH_LEN 1024

typedef struct st_wgetx_url_info_t {
  char *host;
  unsigned long host_len;
  char *path;
  unsigned long path_len;
  uint8_t is_secure;
} wgetx_url_info_t;