#ifndef SETX_H
#define SETX_H

#include <stdint.h>
#include <unistd.h>

#define MAX(x, y) ((x) < (y) ? (y) : (x))
#define MIN(x, y) ((x) < (y) ? (x) : (y))

#define MAX_MASK SIZE_MAX >> 1

typedef struct st_xset_elem_t {
    uint64_t hash;
    char *value;
    size_t len;
} xset_elem_t;

typedef struct st_xset_line_t {
    size_t n_elem;
    size_t n_slots;
    xset_elem_t *elems;
} xset_line_t;

typedef struct st_xset_t {
    size_t n_elem;
    size_t mask;
    xset_line_t *lines;
} xset_t;

xset_t *xset_init();

void xset_free(xset_t *set);

int xset_find(xset_t *set, char *value, size_t len);

void xset_pop(xset_t *set, char *value, size_t len);

int xset_add(xset_t *set, char *value, size_t len);

#endif /* SETX_H */
