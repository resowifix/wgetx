#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#include "setx.h"

static uint64_t xset_FNV1a_hash(uint8_t *byte, size_t len) {
  uint64_t hash = 0xcbf29ce484222325;

  for (size_t i = 0; i < len; i++) {
    hash ^= byte[i];
    hash *= 0x100000001b3;
  }

  return hash;
}

xset_t *xset_init() {
  xset_t *set = malloc(sizeof(xset_t));

  set->n_elem = 0;
  set->mask = 0x0f;
  set->lines = calloc(0x10, sizeof(xset_line_t));

  return set;
}

void xset_free(xset_t *set) {
  if (!set)
    return;

  if (!set->lines) {
    free(set);
    return;
  }

  for (size_t i = 0; i <= set->mask; i++) {
    if (!set->lines[i].elems)
      continue;

    for (size_t j = 0; j < set->lines[i].n_elem; j++)
      if (set->lines[i].elems[j].value)
        free(set->lines[i].elems[j].value);

    free(set->lines[i].elems);
  }
  free(set->lines);
}

int xset_find(xset_t *set, char *value, size_t len) {
  uint64_t hash = xset_FNV1a_hash((uint8_t *)value, len);
  uint64_t i = hash & set->mask;

  for (size_t j = 0; j <= set->lines[i].n_elem; j++)
    if (hash == set->lines[i].elems[j].hash &&
        !strncmp(set->lines[i].elems[j].value, value,
                 MIN(set->lines[i].elems[j].len, len)))
      return 1;

  return 0;
}

void xset_pop(xset_t *set, char *value, size_t len) {
  uint64_t hash = xset_FNV1a_hash((uint8_t *)value, len);
  uint64_t i = hash & set->mask;

  for (size_t j = 0; j < set->lines[i].n_elem; j++)
    if (hash == set->lines[i].elems[j].hash &&
        !strncmp(set->lines[i].elems[j].value, value,
                 MIN(set->lines[i].elems[j].len, len))) {
      free(set->lines[i].elems[j].value);
      if (set->lines[i].n_elem-- > 1) {
        set->lines[i].elems[j].hash =
            set->lines[i].elems[set->lines[i].n_elem].hash;
        set->lines[i].elems[j].value =
            set->lines[i].elems[set->lines[i].n_elem].value;
        set->lines[i].elems[j].len =
            set->lines[i].elems[set->lines[i].n_elem].len;
      }
      set->n_elem--;
      return;
    }
}

static int xset_add_to_line(xset_line_t *line, xset_elem_t elem) {
  if (line->n_elem >= line->n_slots) {
    if (line->n_slots == SIZE_MAX)
      return 1;

    xset_elem_t *new_elems;
    size_t new_n_slots = !line->n_slots       ? 2
                         : line->n_slots << 1 ? line->n_slots << 1
                                              : ULONG_MAX;

    if ((new_elems = calloc(new_n_slots, sizeof(xset_elem_t))) == NULL)
      return 1;

    memcpy(new_elems, line->elems, line->n_elem * sizeof(xset_elem_t));

    free(line->elems);
    line->elems = new_elems;
    line->n_slots = new_n_slots;
  }

  line->elems[line->n_elem].hash = elem.hash;
  line->elems[line->n_elem].value = elem.value;
  line->elems[line->n_elem].len = elem.len;

  line->n_elem++;
  return 0;
}

static int xset_resize(xset_t *set) {
  if (set->mask == MAX_MASK)
    return 0;

  size_t new_mask = (set->mask << 1) + 1;

  xset_line_t *new_lines = calloc(new_mask + 1, sizeof(xset_line_t));

  for (size_t i = 0; i <= set->mask; i++) {
    for (size_t j = 0; j < set->lines[i].n_elem; j++)
      if (xset_add_to_line(&new_lines[set->lines[i].elems[j].hash & new_mask],
                           set->lines[i].elems[j]))
        return 1;

    free(set->lines[i].elems);
  }

  free(set->lines);
  set->lines = new_lines;
  set->mask = new_mask;
  return 0;
}

int xset_add(xset_t *set, char *value, size_t len) {
  if (set->mask < set->n_elem + set->n_elem / 2 && xset_resize(set))
    return 1;

  uint64_t hash = xset_FNV1a_hash((uint8_t *)value, len);
  uint64_t i = hash & set->mask;

  for (ssize_t j = 0; j < set->lines[i].n_elem; j++)
    if (!strncmp(set->lines[i].elems[j].value, value,
                 MIN(set->lines[i].elems[j].len, len)))
      return 0;

  xset_elem_t elem = {hash, value, len};
  set->n_elem++;
  return xset_add_to_line(&set->lines[i], elem);
}
