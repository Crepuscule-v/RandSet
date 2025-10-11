/*
   american fuzzy lop++ - queue relates routines
   ---------------------------------------------

   Originally written by Michal Zalewski

   Now maintained by Marc Heuse <mh@mh-sec.de>,
                        Heiko Eißfeldt <heiko.eissfeldt@hexco.de> and
                        Andrea Fioraldi <andreafioraldi@gmail.com>

   Copyright 2016, 2017 Google Inc. All rights reserved.
   Copyright 2019-2024 AFLplusplus Project. All rights reserved.
   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     https://www.apache.org/licenses/LICENSE-2.0

   This is the real deal: the program takes an instrumented binary and
   attempts a variety of basic fuzzing tricks, paying close attention to
   how they affect the execution path.

 */

#include "afl-fuzz.h"
#include <limits.h>
#include <ctype.h>
#include <math.h>

#ifdef _STANDALONE_MODULE
void minimize_bits(afl_state_t *afl, u8 *dst, u8 *src) {

  return;

}

void run_afl_custom_queue_new_entry(afl_state_t *afl, struct queue_entry *q,
                                    u8 *a, u8 *b) {

  return;

}

#endif

/* select next queue entry based on alias algo - fast! */

inline u32 select_next_queue_entry(afl_state_t *afl) {

  u32    s = rand_below(afl, afl->queued_items);
  double p = rand_next_percent(afl);

  /*
  fprintf(stderr, "select: p=%f s=%u ... p < prob[s]=%f ? s=%u : alias[%u]=%u"
  " ==> %u\n", p, s, afl->alias_probability[s], s, s, afl->alias_table[s], p <
  afl->alias_probability[s] ? s : afl->alias_table[s]);
  */

  return (p < afl->alias_probability[s] ? s : afl->alias_table[s]);

}

double compute_weight(afl_state_t *afl, struct queue_entry *q,
                      double avg_exec_us, double avg_bitmap_size,
                      double avg_top_size) {

  double weight = 1.0;

  if (likely(afl->schedule >= FAST && afl->schedule <= RARE)) {

    u32 hits = afl->n_fuzz[q->n_fuzz_entry];
    if (likely(hits)) { weight /= (log10(hits) + 1); }

  }

  if (likely(afl->schedule < RARE)) { weight *= (avg_exec_us / q->exec_us); }
  weight *= (log(q->bitmap_size) / avg_bitmap_size);
  weight *= (1 + (q->tc_ref / avg_top_size));

  if (unlikely(weight < 0.1)) { weight = 0.1; }
  if (unlikely(q->favored)) { weight *= 5; }
  if (unlikely(!q->was_fuzzed)) { weight *= 2; }
  if (unlikely(q->fs_redundant)) { weight *= 0.8; }

  return weight;

}

/* create the alias table that allows weighted random selection - expensive */

void create_alias_table(afl_state_t *afl) {

  u32    n = afl->queued_items, i = 0, nSmall = 0, nLarge = n - 1;
  double sum = 0;

  double *P = (double *)afl_realloc(AFL_BUF_PARAM(out), n * sizeof(double));
  u32 *Small = (int *)afl_realloc(AFL_BUF_PARAM(out_scratch), n * sizeof(u32));
  u32 *Large = (int *)afl_realloc(AFL_BUF_PARAM(in_scratch), n * sizeof(u32));

  afl->alias_table =
      (u32 *)afl_realloc((void **)&afl->alias_table, n * sizeof(u32));
  afl->alias_probability = (double *)afl_realloc(
      (void **)&afl->alias_probability, n * sizeof(double));

  if (!P || !Small || !Large || !afl->alias_table || !afl->alias_probability) {

    FATAL("could not acquire memory for alias table");

  }

  memset((void *)afl->alias_probability, 0, n * sizeof(double));
  memset((void *)afl->alias_table, 0, n * sizeof(u32));
  memset((void *)Small, 0, n * sizeof(u32));
  memset((void *)Large, 0, n * sizeof(u32));

  if (likely(afl->schedule < RARE)) {

    double avg_exec_us = 0.0;
    double avg_bitmap_size = 0.0;
    double avg_top_size = 0.0;
    u32    active = 0;

    for (i = 0; i < n; i++) {

      struct queue_entry *q = afl->queue_buf[i];

      // disabled entries might have timings and bitmap values
      if (likely(!q->disabled)) {

        avg_exec_us += q->exec_us;
        avg_bitmap_size += log(q->bitmap_size);
        avg_top_size += q->tc_ref;
        ++active;

      }

    }

    avg_exec_us /= active;
    avg_bitmap_size /= active;
    avg_top_size /= active;

    for (i = 0; i < n; i++) {

      struct queue_entry *q = afl->queue_buf[i];

      if (likely(!q->disabled)) {

        q->weight =
            compute_weight(afl, q, avg_exec_us, avg_bitmap_size, avg_top_size);
        q->perf_score = calculate_score(afl, q);
        sum += q->weight;

      }

    }

    if (unlikely(afl->schedule == MMOPT) && afl->queued_discovered) {

      u32 cnt = afl->queued_discovered >= 5 ? 5 : afl->queued_discovered;

      for (i = n - cnt; i < n; i++) {

        struct queue_entry *q = afl->queue_buf[i];

        if (likely(!q->disabled)) { q->weight *= 2.0; }

      }

    }

    for (i = 0; i < n; i++) {

      // weight is always 0 for disabled entries
      if (unlikely(afl->queue_buf[i]->disabled)) {

        P[i] = 0;

      } else {

        P[i] = (afl->queue_buf[i]->weight * n) / sum;

      }

    }

  } else {

    for (i = 0; i < n; i++) {

      struct queue_entry *q = afl->queue_buf[i];

      if (likely(!q->disabled)) {

        q->perf_score = calculate_score(afl, q);
        sum += q->perf_score;

      }

    }

    for (i = 0; i < n; i++) {

      // perf_score is always 0 for disabled entries
      if (unlikely(afl->queue_buf[i]->disabled)) {

        P[i] = 0;

      } else {

        P[i] = (afl->queue_buf[i]->perf_score * n) / sum;

      }

    }

  }

  // Done collecting weightings in P, now create the arrays.

  for (s32 j = (s32)(n - 1); j >= 0; j--) {

    if (P[j] < 1) {

      Small[nSmall++] = (u32)j;

    } else {

      Large[nLarge--] = (u32)j;

    }

  }

  while (nSmall && nLarge != n - 1) {

    u32 small = Small[--nSmall];
    u32 large = Large[++nLarge];

    afl->alias_probability[small] = P[small];
    afl->alias_table[small] = large;

    P[large] = P[large] - (1 - P[small]);

    if (P[large] < 1) {

      Small[nSmall++] = large;

    } else {

      Large[nLarge--] = large;

    }

  }

  while (nSmall) {

    afl->alias_probability[Small[--nSmall]] = 1;

  }

  while (nLarge != n - 1) {

    afl->alias_probability[Large[++nLarge]] = 1;

  }

  afl->reinit_table = 0;

  /*
  #ifdef INTROSPECTION
    u8 fn[PATH_MAX];
    snprintf(fn, PATH_MAX, "%s/introspection_corpus.txt", afl->out_dir);
    FILE *f = fopen(fn, "a");
    if (f) {

      for (i = 0; i < n; i++) {

        struct queue_entry *q = afl->queue_buf[i];
        fprintf(
            f,
            "entry=%u name=%s favored=%s variable=%s disabled=%s len=%u "
            "exec_us=%u "
            "bitmap_size=%u bitsmap_size=%u tops=%u weight=%f perf_score=%f\n",
            i, q->fname, q->favored ? "true" : "false",
            q->var_behavior ? "true" : "false", q->disabled ? "true" : "false",
            q->len, (u32)q->exec_us, q->bitmap_size, q->bitsmap_size, q->tc_ref,
            q->weight, q->perf_score);

      }

      fprintf(f, "\n");
      fclose(f);

    }

  #endif
  */
  /*
  fprintf(stderr, "  entry  alias  probability  perf_score   weight
  filename\n"); for (i = 0; i < n; ++i) fprintf(stderr, "  %5u  %5u  %11u
  %0.9f  %0.9f  %s\n", i, afl->alias_table[i], afl->alias_probability[i],
  afl->queue_buf[i]->perf_score, afl->queue_buf[i]->weight,
            afl->queue_buf[i]->fname);
  */

}

/* Mark deterministic checks as done for a particular queue entry. We use the
   .state file to avoid repeating deterministic fuzzing when resuming aborted
   scans. */

void mark_as_det_done(afl_state_t *afl, struct queue_entry *q) {

  char fn[PATH_MAX];
  s32  fd;

  snprintf(fn, PATH_MAX, "%s/queue/.state/deterministic_done/%s", afl->out_dir,
           strrchr((char *)q->fname, '/') + 1);

  fd = open(fn, O_WRONLY | O_CREAT | O_EXCL, DEFAULT_PERMISSION);
  if (fd < 0) { PFATAL("Unable to create '%s'", fn); }
  close(fd);

  q->passed_det = 1;

}

/* Mark as variable. Create symlinks if possible to make it easier to examine
   the files. */

void mark_as_variable(afl_state_t *afl, struct queue_entry *q) {

  char fn[PATH_MAX];
  char ldest[PATH_MAX];

  char *fn_name = strrchr((char *)q->fname, '/') + 1;

  sprintf(ldest, "../../%s", fn_name);
  sprintf(fn, "%s/queue/.state/variable_behavior/%s", afl->out_dir, fn_name);

  if (symlink(ldest, fn)) {

    s32 fd = open(fn, O_WRONLY | O_CREAT | O_EXCL, DEFAULT_PERMISSION);
    if (fd < 0) { PFATAL("Unable to create '%s'", fn); }
    close(fd);

  }

  q->var_behavior = 1;

}

/* Mark / unmark as redundant (edge-only). This is not used for restoring state,
   but may be useful for post-processing datasets. */

void mark_as_redundant(afl_state_t *afl, struct queue_entry *q, u8 state) {

  if (likely(state == q->fs_redundant)) { return; }

  char fn[PATH_MAX];

  q->fs_redundant = state;

  sprintf(fn, "%s/queue/.state/redundant_edges/%s", afl->out_dir,
          strrchr((char *)q->fname, '/') + 1);

  if (state) {

    s32 fd;

    fd = open(fn, O_WRONLY | O_CREAT | O_EXCL, DEFAULT_PERMISSION);
    if (fd < 0) { PFATAL("Unable to create '%s'", fn); }
    close(fd);

  } else {

    if (unlink(fn)) { PFATAL("Unable to remove '%s'", fn); }

  }

}

/* check if pointer is ascii or UTF-8 */

u8 check_if_text_buf(u8 *buf, u32 len) {

  u32 offset = 0, ascii = 0, utf8 = 0;

  while (offset < len) {

    // ASCII: <= 0x7F to allow ASCII control characters
    if ((buf[offset + 0] == 0x09 || buf[offset + 0] == 0x0A ||
         buf[offset + 0] == 0x0D ||
         (0x20 <= buf[offset + 0] && buf[offset + 0] <= 0x7E))) {

      offset++;
      utf8++;
      ascii++;
      continue;

    }

    if (isascii((int)buf[offset]) || isprint((int)buf[offset])) {

      ascii++;
      // we continue though as it can also be a valid utf8

    }

    // non-overlong 2-byte
    if (len - offset > 1 &&
        ((0xC2 <= buf[offset + 0] && buf[offset + 0] <= 0xDF) &&
         (0x80 <= buf[offset + 1] && buf[offset + 1] <= 0xBF))) {

      offset += 2;
      utf8++;
      continue;

    }

    // excluding overlongs
    if ((len - offset > 2) &&
        ((buf[offset + 0] == 0xE0 &&
          (0xA0 <= buf[offset + 1] && buf[offset + 1] <= 0xBF) &&
          (0x80 <= buf[offset + 2] &&
           buf[offset + 2] <= 0xBF)) ||  // straight 3-byte
         (((0xE1 <= buf[offset + 0] && buf[offset + 0] <= 0xEC) ||
           buf[offset + 0] == 0xEE || buf[offset + 0] == 0xEF) &&
          (0x80 <= buf[offset + 1] && buf[offset + 1] <= 0xBF) &&
          (0x80 <= buf[offset + 2] &&
           buf[offset + 2] <= 0xBF)) ||  // excluding surrogates
         (buf[offset + 0] == 0xED &&
          (0x80 <= buf[offset + 1] && buf[offset + 1] <= 0x9F) &&
          (0x80 <= buf[offset + 2] && buf[offset + 2] <= 0xBF)))) {

      offset += 3;
      utf8++;
      continue;

    }

    // planes 1-3
    if ((len - offset > 3) &&
        ((buf[offset + 0] == 0xF0 &&
          (0x90 <= buf[offset + 1] && buf[offset + 1] <= 0xBF) &&
          (0x80 <= buf[offset + 2] && buf[offset + 2] <= 0xBF) &&
          (0x80 <= buf[offset + 3] &&
           buf[offset + 3] <= 0xBF)) ||  // planes 4-15
         ((0xF1 <= buf[offset + 0] && buf[offset + 0] <= 0xF3) &&
          (0x80 <= buf[offset + 1] && buf[offset + 1] <= 0xBF) &&
          (0x80 <= buf[offset + 2] && buf[offset + 2] <= 0xBF) &&
          (0x80 <= buf[offset + 3] && buf[offset + 3] <= 0xBF)) ||  // plane 16
         (buf[offset + 0] == 0xF4 &&
          (0x80 <= buf[offset + 1] && buf[offset + 1] <= 0x8F) &&
          (0x80 <= buf[offset + 2] && buf[offset + 2] <= 0xBF) &&
          (0x80 <= buf[offset + 3] && buf[offset + 3] <= 0xBF)))) {

      offset += 4;
      utf8++;
      continue;

    }

    offset++;

  }

  return (utf8 > ascii ? utf8 : ascii);

}

/* check if queue entry is ascii or UTF-8 */

static u8 check_if_text(afl_state_t *afl, struct queue_entry *q) {

  if (q->len < AFL_TXT_MIN_LEN || q->len < AFL_TXT_MAX_LEN) return 0;

  u8     *buf;
  int     fd;
  u32     len = q->len, offset = 0, ascii = 0, utf8 = 0;
  ssize_t comp;

  if (len >= MAX_FILE) len = MAX_FILE - 1;
  if ((fd = open((char *)q->fname, O_RDONLY)) < 0) return 0;
  buf = (u8 *)afl_realloc(AFL_BUF_PARAM(in_scratch), len + 1);
  comp = read(fd, buf, len);
  close(fd);
  if (comp != (ssize_t)len) return 0;
  buf[len] = 0;

  while (offset < len) {

    // ASCII: <= 0x7F to allow ASCII control characters
    if ((buf[offset + 0] == 0x09 || buf[offset + 0] == 0x0A ||
         buf[offset + 0] == 0x0D ||
         (0x20 <= buf[offset + 0] && buf[offset + 0] <= 0x7E))) {

      offset++;
      utf8++;
      ascii++;
      continue;

    }

    if (isascii((int)buf[offset]) || isprint((int)buf[offset])) {

      ascii++;
      // we continue though as it can also be a valid utf8

    }

    // non-overlong 2-byte
    if (len - offset > 1 &&
        ((0xC2 <= buf[offset + 0] && buf[offset + 0] <= 0xDF) &&
         (0x80 <= buf[offset + 1] && buf[offset + 1] <= 0xBF))) {

      offset += 2;
      utf8++;
      comp--;
      continue;

    }

    // excluding overlongs
    if ((len - offset > 2) &&
        ((buf[offset + 0] == 0xE0 &&
          (0xA0 <= buf[offset + 1] && buf[offset + 1] <= 0xBF) &&
          (0x80 <= buf[offset + 2] &&
           buf[offset + 2] <= 0xBF)) ||  // straight 3-byte
         (((0xE1 <= buf[offset + 0] && buf[offset + 0] <= 0xEC) ||
           buf[offset + 0] == 0xEE || buf[offset + 0] == 0xEF) &&
          (0x80 <= buf[offset + 1] && buf[offset + 1] <= 0xBF) &&
          (0x80 <= buf[offset + 2] &&
           buf[offset + 2] <= 0xBF)) ||  // excluding surrogates
         (buf[offset + 0] == 0xED &&
          (0x80 <= buf[offset + 1] && buf[offset + 1] <= 0x9F) &&
          (0x80 <= buf[offset + 2] && buf[offset + 2] <= 0xBF)))) {

      offset += 3;
      utf8++;
      comp -= 2;
      continue;

    }

    // planes 1-3
    if ((len - offset > 3) &&
        ((buf[offset + 0] == 0xF0 &&
          (0x90 <= buf[offset + 1] && buf[offset + 1] <= 0xBF) &&
          (0x80 <= buf[offset + 2] && buf[offset + 2] <= 0xBF) &&
          (0x80 <= buf[offset + 3] &&
           buf[offset + 3] <= 0xBF)) ||  // planes 4-15
         ((0xF1 <= buf[offset + 0] && buf[offset + 0] <= 0xF3) &&
          (0x80 <= buf[offset + 1] && buf[offset + 1] <= 0xBF) &&
          (0x80 <= buf[offset + 2] && buf[offset + 2] <= 0xBF) &&
          (0x80 <= buf[offset + 3] && buf[offset + 3] <= 0xBF)) ||  // plane 16
         (buf[offset + 0] == 0xF4 &&
          (0x80 <= buf[offset + 1] && buf[offset + 1] <= 0x8F) &&
          (0x80 <= buf[offset + 2] && buf[offset + 2] <= 0xBF) &&
          (0x80 <= buf[offset + 3] && buf[offset + 3] <= 0xBF)))) {

      offset += 4;
      utf8++;
      comp -= 3;
      continue;

    }

    offset++;

  }

  u32 percent_utf8 = (utf8 * 100) / comp;
  u32 percent_ascii = (ascii * 100) / len;

  if (percent_utf8 >= percent_ascii && percent_utf8 >= AFL_TXT_MIN_PERCENT)
    return 2;
  if (percent_ascii >= AFL_TXT_MIN_PERCENT) return 1;
  return 0;

}

/* Append new test case to the queue. */

void add_to_queue(afl_state_t *afl, u8 *fname, u32 len, u8 passed_det) {

  struct queue_entry *q =
      (struct queue_entry *)ck_alloc(sizeof(struct queue_entry));

  q->fname = fname;
  q->len = len;
  q->depth = afl->cur_depth + 1;
  q->passed_det = passed_det;
  q->trace_mini = NULL;
  q->testcase_buf = NULL;
  q->mother = afl->queue_cur;

#ifdef INTROSPECTION
  q->bitsmap_size = afl->bitsmap_size;
#endif

  if (q->depth > afl->max_depth) { afl->max_depth = q->depth; }

  if (afl->queue_top) {

    afl->queue_top = q;

  } else {

    afl->queue = afl->queue_top = q;

  }

  if (likely(q->len > 4)) { ++afl->ready_for_splicing_count; }

  ++afl->queued_items;
  ++afl->active_items;
  ++afl->pending_not_fuzzed;

  afl->cycles_wo_finds = 0;

  struct queue_entry **queue_buf = (struct queue_entry **)afl_realloc(
      AFL_BUF_PARAM(queue), afl->queued_items * sizeof(struct queue_entry *));
  if (unlikely(!queue_buf)) { PFATAL("alloc"); }
  queue_buf[afl->queued_items - 1] = q;
  q->id = afl->queued_items - 1;



  u64 cur_time = get_cur_time();

  if (likely(afl->start_time) &&
      unlikely(afl->longest_find_time < cur_time - afl->last_find_time)) {

    if (unlikely(!afl->last_find_time)) {

      afl->longest_find_time = cur_time - afl->start_time;

    } else {

      afl->longest_find_time = cur_time - afl->last_find_time;

    }

  }

  afl->last_find_time = cur_time;

  if (afl->custom_mutators_count) {

    /* At the initialization stage, queue_cur is NULL */
    if (afl->queue_cur && !afl->syncing_party) {

      run_afl_custom_queue_new_entry(afl, q, fname, afl->queue_cur->fname);

    }

  }

  /* only redqueen currently uses is_ascii */
  if (unlikely(afl->shm.cmplog_mode && !q->is_ascii)) {

    q->is_ascii = check_if_text(afl, q);

  }

  q->skipdet_e = (struct skipdet_entry *)ck_alloc(sizeof(struct skipdet_entry));

}

/* Destroy the entire queue. */

void destroy_queue(afl_state_t *afl) {

  u32 i;

  for (i = 0; i < afl->queued_items; i++) {

    struct queue_entry *q;

    q = afl->queue_buf[i];
    ck_free(q->fname);
    ck_free(q->trace_mini);
    ck_free(q->frontier_node_bitmap);
    ck_free(q->covered_frontier_node_list);
    if (q->skipdet_e) {

      if (q->skipdet_e->done_inf_map) ck_free(q->skipdet_e->done_inf_map);
      if (q->skipdet_e->skip_eff_map) ck_free(q->skipdet_e->skip_eff_map);

      ck_free(q->skipdet_e);

    }

    ck_free(q);

  }

}

/* When we bump into a new path, we call this to see if the path appears
   more "favorable" than any of the existing ones. The purpose of the
   "favorables" is to have a minimal set of paths that trigger all the bits
   seen in the bitmap so far, and focus on fuzzing them at the expense of
   the rest.

   The first step of the process is to maintain a list of afl->top_rated[]
   entries for every byte in the bitmap. We win that slot if there is no
   previous contender, or if the contender has a more favorable speed x size
   factor. */

void update_bitmap_score(afl_state_t *afl, struct queue_entry *q) {
  

  u32 i;
  u64 fav_factor;
  u64 fuzz_p2;

  if (likely(afl->schedule >= FAST && afl->schedule < RARE)) {

    fuzz_p2 = 0;  // Skip the fuzz_p2 comparison

  } else if (unlikely(afl->schedule == RARE)) {

    fuzz_p2 = next_pow2(afl->n_fuzz[q->n_fuzz_entry]);

  } else {

    fuzz_p2 = q->fuzz_level;

  }

  if (unlikely(afl->schedule >= RARE) || unlikely(afl->fixed_seed)) {

    fav_factor = q->len << 2;

  } else {

    fav_factor = q->exec_us * q->len;

  }

  if (afl->use_set_cover_scheduling) {
    // q->frontier_node_bitmap = ck_alloc((afl->fsrv.real_map_size >> 3) + 1);
    q->covered_frontier_node_list = ck_alloc(MAX_NODES_PER_SEED * sizeof(u32));  
    q->covered_frontier_nodes_count = 0;    
  }

  /* For every byte set in afl->fsrv.trace_bits[], see if there is a previous
     winner, and how it compares to us. */
  for (i = 0; i < afl->fsrv.map_size; ++i) {

    if (afl->fsrv.trace_bits[i]) {

      u32 edge_id = i;

       
      if (true) {
        
          // time_t current_time = time(NULL); 
          
          // BITMAP_SET(q->frontier_node_bitmap,edge_id);

          if (q->covered_frontier_nodes_count < MAX_NODES_PER_SEED) {
            q->covered_frontier_node_list[q->covered_frontier_nodes_count++] = edge_id;
          } else {
              WARNF("Exceeded MAX_NODES_PER_SEED limit!");
          }
       
          if (!BITMAP_CHECK(afl->global_frontier_bitmap, edge_id)) {

              BITMAP_SET(afl->global_frontier_bitmap, edge_id);
              afl->global_covered_frontier_nodes_count++;
              // global_updated = true;
          }

      }


      if (afl->top_rated[i]) {

        /* Faster-executing or smaller test cases are favored. */
        u64 top_rated_fav_factor;
        u64 top_rated_fuzz_p2;

        if (likely(afl->schedule >= FAST && afl->schedule < RARE)) {

          top_rated_fuzz_p2 = 0;  // Skip the fuzz_p2 comparison

        } else if (unlikely(afl->schedule == RARE)) {

          top_rated_fuzz_p2 =
              next_pow2(afl->n_fuzz[afl->top_rated[i]->n_fuzz_entry]);

        } else {

          top_rated_fuzz_p2 = afl->top_rated[i]->fuzz_level;

        }

        if (unlikely(afl->schedule >= RARE) || unlikely(afl->fixed_seed)) {

          top_rated_fav_factor = afl->top_rated[i]->len << 2;

        } else {

          top_rated_fav_factor =
              afl->top_rated[i]->exec_us * afl->top_rated[i]->len;

        }

        if (likely(fuzz_p2 > top_rated_fuzz_p2)) { continue; }

        if (likely(fav_factor > top_rated_fav_factor)) { continue; }

        /* Looks like we're going to win. Decrease ref count for the
           previous winner, discard its afl->fsrv.trace_bits[] if necessary. */

        if (!--afl->top_rated[i]->tc_ref) {

          ck_free(afl->top_rated[i]->trace_mini);
          afl->top_rated[i]->trace_mini = 0;

        }

      }

      /* Insert ourselves as the new winner. */

      afl->top_rated[i] = q;
      ++q->tc_ref;

      if (!q->trace_mini) {

        u32 len = (afl->fsrv.map_size >> 3);
        q->trace_mini = (u8 *)ck_alloc(len);
        minimize_bits(afl, q->trace_mini, afl->fsrv.trace_bits);

      }

      afl->score_changed = 1;

    }

  }
  // printf("seed: %d cover fronieter_nodes_count: %d\n", q->id, q->covered_frontier_nodes_count);

}

/* The second part of the mechanism discussed above is a routine that
   goes over afl->top_rated[] entries, and then sequentially grabs winners for
   previously-unseen bytes (temp_v) and marks them as favored, at least
   until the next run. The favored entries are given more air time during
   all fuzzing steps. */

void cull_queue(afl_state_t *afl) {



  if (likely(!afl->score_changed || afl->non_instrumented_mode)) { return; }

  u32 len = (afl->fsrv.map_size >> 3);
  u32 i;
  u8 *temp_v = afl->map_tmp_buf;

  afl->score_changed = 0;

  memset(temp_v, 255, len);

  afl->queued_favored = 0;
  afl->pending_favored = 0;

  for (i = 0; i < afl->queued_items; i++) {

    afl->queue_buf[i]->favored = 0;

  }

  /* Let's see if anything in the bitmap isn't captured in temp_v.
     If yes, and if it has a afl->top_rated[] contender, let's use it. */

  afl->smallest_favored = -1;

  for (i = 0; i < afl->fsrv.map_size; ++i) {

    if (afl->top_rated[i] && (temp_v[i >> 3] & (1 << (i & 7)))) {

      u32 j = len;

      /* Remove all bits belonging to the current entry from temp_v. */

      while (j--) {

        if (afl->top_rated[i]->trace_mini[j]) {

          temp_v[j] &= ~afl->top_rated[i]->trace_mini[j];

        }

      }

      if (!afl->top_rated[i]->favored) {

        afl->top_rated[i]->favored = 1;
        ++afl->queued_favored;

        if (!afl->top_rated[i]->was_fuzzed) {

          ++afl->pending_favored;
          if (unlikely(afl->smallest_favored < 0)) {

            afl->smallest_favored = (s64)afl->top_rated[i]->id;

          }

        }

      }

    }

  }

  for (i = 0; i < afl->queued_items; i++) {

    if (likely(!afl->queue_buf[i]->disabled)) {

      mark_as_redundant(afl, afl->queue_buf[i], !afl->queue_buf[i]->favored);

    }

  }

  afl->reinit_table = 1;

}


void cull_queue_new(afl_state_t *afl) {
    
    // printf("------------1 . 开始调用cull_queue_new------------------\n");
    // Step 1: 检查前沿节点的变化
    // afl->cull_queue_new_call_nums++;
    // if (detect_frontier_changes(afl)) {
    //   afl->detect_frontier_changes_nums++;
    //     // printf("前沿节点整体上有数量变化\n");
    //     if (afl->new_frontier_found) {
    //         // printf("set_cover_reduction active\n");
    //         // printf("Set cover 执行前 set_favored_id= %ld before set_cover_reduction active\n",afl->set_favored_id);
    //         // 如果有新增的前沿节点，执行 Set Cover Reduction
    //         afl->set_cover_call_nums++;
    //         set_cover_reduction_v3(afl);
    //         // printf("Set cover 执行后 set_favored_id= %ld after set_cover_reduction active\n",afl->set_favored_id);
    //     }
    //     else{
    //         // printf("set_cover_reduction is not active"); 
    //         // printf("set_favored_id= %ld before use_previous_set_cover\n",afl->set_favored_id);
    //         afl->use_previou_call_nums++;
    //         use_previous_set_cover(afl);// frontier node 减少太多
    //         // printf("set_favored_id= %ld after use_previous_set_cover\n",afl->set_favored_id);
    //     }
    // } else{
    //   // printf("set_favored_id= %ld before use_previous_set_cover\n",afl->set_favored_id);
    //   afl->use_previou_call_nums++;
    //   use_previous_set_cover(afl);// frontier node 减少太多
    //   // printf("set_favored_id= %ld after use_previous_set_cover\n",afl->set_favored_id);
    // }
    // detect_frontier_changes(afl);
    set_cover_reduction_final(afl);

}


void add_frontier_nodes_to_seed(struct queue_entry *q, afl_state_t *afl) {
    q->covered_frontier_nodes_count = 0;  // 初始化计数
    bool global_updated = false;  // 记录是否有全局位图更新
    
    // 遍历该种子的 trace_mini，找到该种子覆盖的边
    for (u32 i = 0; i < afl->fsrv.map_size >> 3; i++) {
        if (q->trace_mini[i]) {
            for (u8 bit = 0; bit < 8; bit++) {
                if (q->trace_mini[i] & (1 << bit)) {
                    u32 edge_id = (i << 3) + bit;

                    // 检查这个边是否是前沿节点
                    if (is_frontier_node_inner(afl, edge_id)) {
                        // 增加该种子覆盖的前沿节点
                        BITMAP_SET(q->frontier_node_bitmap,edge_id);
                        q->covered_frontier_nodes_count++;
                        // 检查全局位图是否已有该前沿节点标记
                        if (!BITMAP_CHECK(afl->global_frontier_bitmap, edge_id)) {
                            // 将该节点标记为新的前沿节点
                            BITMAP_SET(afl->global_frontier_bitmap, edge_id);
                            global_updated = true;
                        }
                    } else {
                        // 如果该边不再是前沿节点，且在全局位图中已标记
                        if (BITMAP_CHECK(afl->global_frontier_bitmap, edge_id)) {
                            // 清除全局位图中该边的标记
                            BITMAP_CLEAR(afl->global_frontier_bitmap, edge_id);
                            global_updated = true;
                        }
                    }
                }
            }
        }
    }

    // 如果 global_frontier_bitmap 发生变化，标记变化
    if (global_updated) {
        afl->global_frontier_updated = true;
    }
    // 更新种子覆盖的前沿节点数量（通过硬件指令统计位图中为1的位）
    // q->covered_frontier_nodes_count = BITMAP_COUNT(q->frontier_node_bitmap, MAP_SIZE >> 3);
}

bool detect_frontier_changes(afl_state_t *afl) {
  // printf("------------2 . 开始调用detect_frontier_changes------------------\n");
  // if (!afl->global_frontier_updated) return false;  // 如果没有更新全局位图，跳过检测

  bool new_frontier_found = false;
  bool removed_frontier_found = false;
  // time_t current_time = time(NULL);  // 获取当前时间

  for (u32 i = 0; i < (afl->fsrv.real_map_size >> 3) + 1; i++) {
    u8 current = afl->global_frontier_bitmap[i];
    u8 initial = afl->initial_frontier_bitmap[i];
    u8 diff = current ^ initial;

    if (diff) {
      if (diff & current) {
        new_frontier_found = true; 
        // 找到具体的 edge_id 并打印
        for (u8 bit = 0; bit < 8; bit++) {
            if (diff & (1 << bit) && current & (1 << bit)) {

                u32 edge_id = (i << 3) + bit;  // 计算 edge_id

                // if (afl->frontier_discovery_time[edge_id] == 0xFFFFFFFF) {
                //   afl->frontier_discovery_time[edge_id] = current_time;  // 记录发现时间
                //   // printf("New frontier node discovered: edge_id = %u at time %ld\n", edge_id, current_time);
                // }

                if (afl->recent_frontier_count < RECENT_FRONTIER_LIMIT) {

                  afl->recent_frontier_nodes[afl->recent_frontier_count++] = edge_id;

                } else {
                    // 如果超出限制，采用 FIFO 替换策略
                  memmove(afl->recent_frontier_nodes, afl->recent_frontier_nodes + 1,
                          (RECENT_FRONTIER_LIMIT - 1) * sizeof(u32));
                  afl->recent_frontier_nodes[RECENT_FRONTIER_LIMIT - 1] = edge_id;

                }
                // printf("New frontier found: edge_id = %u\n", edge_id);
            }
        }
        // break;
      }
      if (diff & initial) {
        removed_frontier_found = true;
        // 找到被移除的 edge_id 并打印
        // for (u8 bit = 0; bit < 8; bit++) {
        //     if (diff & (1 << bit) && initial & (1 << bit)) {
        //         u32 edge_id = (i << 3) + bit;  // 计算 edge_id
        //         printf("Removed frontier found: edge_id = %u\n", edge_id);
        //     }
        // }
      }
    }
  }
  memcpy(afl->initial_frontier_bitmap, afl->global_frontier_bitmap, (afl->fsrv.real_map_size >> 3) + 1);
  
  afl->new_frontier_found = new_frontier_found;
  afl->removed_frontier_found = removed_frontier_found;
  // printf("new_frontier_found: %d, removed_frontier_found: %d\n", new_frontier_found, removed_frontier_found);
  return new_frontier_found || removed_frontier_found;
}



void update_global_frontier_nodes(struct queue_entry *q, afl_state_t *afl) {
  // printf("---------4 . 开始调用update_global_frontier_nodes函数--------------\n");

    // if (!afl->global_frontier_updated) return;  // 如果全局位图未更新，跳过该函数

    u32 updated_coverage_count = 0;  // 临时存储已覆盖的前沿节点数量
    q -> set_covered = 0;

    u32 init_count = q -> covered_frontier_nodes_count;
    u32 count = 0;
    for (u32 i = 0; i < (afl->fsrv.real_map_size >> 3) + 1; i++) {
        u8 current = q->frontier_node_bitmap[i];  // 当前种子的前沿节点位图

        if (current == 0) continue;  // 如果当前字节为空，跳过检查
        
        for (u8 bit = 0; bit < 8; bit++) {
            u32 edge_id = (i << 3) + bit;

            if (edge_id < (i << 3)) {
              FATAL("edge_id溢出");
            }
            if (current & (1 << bit)) {
                if (edge_id >= afl->fsrv.map_size) {
                    FATAL("Edge ID %d 超出 trace_bits 范围，跳过该边\n", edge_id);
                }   
                if (!is_frontier_node_outer(afl, edge_id)) { 
                    count++;
            
                    if(BITMAP_CHECK(afl->global_frontier_bitmap, edge_id)) {
                      BITMAP_CLEAR(afl->global_frontier_bitmap, edge_id);
                      afl->global_covered_frontier_nodes_count--;
                    }
                    
                    // 如果不再是前沿节点，从位图中清除该边
                    current &= ~(1 << bit);
                }
            }
        }
        // 更新位图到种子
        q->frontier_node_bitmap[i] = current;

        // 更新种子覆盖的前沿节点数量
        updated_coverage_count+= __builtin_popcount(current);
    }
    q->covered_frontier_nodes_count = updated_coverage_count;
    
    
}

void write_trace_bits_info(struct afl_state *afl) {
  // 构造输出文件路径
  u8 *trace_bits_info_path = alloc_printf("%s/trace_bits_info", afl->out_dir);
  
  // 打开文件，追加写入
  FILE *f = fopen(trace_bits_info_path, "a+");
  if (!f) {
    perror("Unable to open file for writing trace bits information");
    ck_free(trace_bits_info_path);
    return;
  }
  ck_free(trace_bits_info_path);

  // 写入 trace_bits 的信息
  fprintf(f, "=== Trace Bits Information ===\n");
  for (u32 i = 0; i < afl->fsrv.map_size; i++) {
    if (afl->fsrv.trace_bits[i]) {
      fprintf(f, "Edge ID: %u, Value: %u\n", i, afl->fsrv.trace_bits[i]);
    }
  }
  fprintf(f, "==============================\n");

  fclose(f);
}



void use_previous_set_cover(afl_state_t *afl){
  // printf("------------开始调用use_previous_set_cover函数----------------\n");
  
  struct queue_entry *best_seed = NULL;
  // u32 max_coverage = 0;
  // 如果已经选择了一个种子，验证其贡献，计算剩余未覆盖节点


  // for (u32 i = 0; i < afl->queued_items; i++){
  //   // if (afl->queue_buf[i]->id != afl->set_favored_id){
  //     if (afl->queue_buf[i]->covered_frontier_nodes_count > max_coverage) {
  //       max_coverage = afl->queue_buf[i]->covered_frontier_nodes_count;
  //       best_seed = afl->queue_buf[i];
  //     }
  //   // }
  // }

  for (u32 i = 0; i < afl->queued_items; i++){

    u32 random_index = rand() % afl->queued_items;

    
    best_seed = afl->queue_buf[random_index];

    if (!best_seed){
       ACTF("random_index:%u,queued_items:%u",random_index, afl->queued_items);
    }

    if (best_seed ->covered_frontier_nodes_count > 0 && !best_seed->set_favored) break;

  }

  if (!best_seed) {
    afl -> use_previou_call_and_random++;
    // srand(time(NULL));

    u32 random_index = rand() % afl->queued_items;
    // 随机选择一个队列中的种子作为 fallback（可以根据需要优化选择策略）
    
    afl->set_favored_id = random_index;
    afl->queue_buf[afl->set_favored_id]->set_favored = 1;
    
    return;
    
  } else {
    best_seed->set_favored = 1;  // 标记为 favored
    afl->set_favored_id = best_seed->id;
  }
}


double calculate_newest_frontier_node_score(afl_state_t *afl, struct queue_entry *q) {
    double score = 0.0;
    time_t current_time = time(NULL);

    for (u32 i = 0; i < afl->recent_frontier_count; i++) {

        u32 frontier_node = afl->recent_frontier_nodes[i];
        if (BITMAP_CHECK(q->frontier_node_bitmap,frontier_node)) {
            time_t discovery_time = afl->frontier_discovery_time[frontier_node];
            if (discovery_time != 0xFFFFFFFF) {
              // 时间权重：越新发现的节点，得分越高
              double time_weight = 1.0 / (1.0 + difftime(current_time, discovery_time));
              score += time_weight;
            }
        }
    }

    return score;
}

double calculate_latest_frontier_node_found_time(afl_state_t *afl, struct queue_entry *q) {
    double score = 0.0;
    time_t current_time = time(NULL);

    for (u32 i = 0; i < afl->recent_frontier_count; i++) {

        u32 frontier_node = afl->recent_frontier_nodes[i];
        if (BITMAP_CHECK(q->frontier_node_bitmap,frontier_node)) {
            time_t discovery_time = afl->frontier_discovery_time[frontier_node];
            if (discovery_time != 0xFFFFFFFF) {
              // 时间权重：越新发现的节点，得分越高
              double time_weight = 1.0 / (1.0 + difftime(current_time, discovery_time));
              score += time_weight;
            }
        }
    }

    return score;
}

u32 select_seed_covering_latest_frontier_node(afl_state_t *afl, u32 *set_covered_seed_list) {
    srand(time(NULL));

    // 找出最新发现的 frontier node 及其发现时间
    // time_t latest_discovery_time = 0;
    u32 latest_frontier_node = 0;
    int recent_frontier_count_tmp = afl->recent_frontier_count - 1;

    // if (recent_frontier_count_tmp >= 0) {
    //   latest_frontier_node = afl->recent_frontier_nodes[recent_frontier_count_tmp];
    // }

    // for (u32 i = 0; i < afl->recent_frontier_count; i++) {
    //     u32 frontier_node = afl->recent_frontier_nodes[i];
    //     time_t discovery_time = afl->frontier_discovery_time[frontier_node];

    //     if (discovery_time > latest_discovery_time) {
    //         latest_discovery_time = discovery_time;
    //         latest_frontier_node = frontier_node;
    //     }
    // }

    // 遍历种子集合，找到覆盖最新 frontier node 的最佳种子
    u32 random_index = rand() % afl->covered_seed_list_counter;
    u32 best_seed_id = set_covered_seed_list[random_index];

    double best_priority_score = 0;
    double priority_score = 0;
    u32  best_latest_find_frontier_node = 0;
    
    int all_favored = 1;

    for (u32 i = 0; i < afl->covered_seed_list_counter; i++) {

        struct queue_entry *q = afl->queue_buf[set_covered_seed_list[i]];
        recent_frontier_count_tmp = afl->recent_frontier_count - 1;

        if (!q->set_favored) {
            all_favored = 0;
            // 检查是否覆盖最新 frontier node
            while(recent_frontier_count_tmp >= 0){

              if (BITMAP_CHECK(q->frontier_node_bitmap, latest_frontier_node)) break;

              latest_frontier_node =  afl->recent_frontier_nodes[recent_frontier_count_tmp];
              recent_frontier_count_tmp--;

            }

            if (latest_frontier_node > best_latest_find_frontier_node) {

              best_latest_find_frontier_node = latest_frontier_node;
              best_seed_id = q->id;

            }
            
            if (latest_frontier_node == best_latest_find_frontier_node) {

              priority_score = 100.0 / (q->exec_us + 1);  // 次级指标：执行速度

              if (priority_score > best_priority_score) {

                best_priority_score = priority_score;
                best_seed_id = q->id;

              }
            }
        }
    }

    // 如果所有种子都被标记为 favored，则随机选择一个
    if (all_favored) {
        for (u32 i = 0; i < afl->covered_seed_list_counter; i++) {
            struct queue_entry *q = afl->queue_buf[set_covered_seed_list[i]];
            q->set_favored = 0;
        }
        
    }

    // 标记选择的种子为 favored
    afl->queue_buf[best_seed_id]->set_favored = 1;
    return best_seed_id;
}

/* 新增函数：从Set Cover集合中选择优先级最高的种子 */
u32 select_seed_with_priority(afl_state_t *afl, u32 *set_covered_seed_list) {
    srand(time(NULL));

    u32 best_seed_id = set_covered_seed_list[0];
    double best_priority_score = -1;
    int all_favored = 1;  
    for (u32 i = 0; i < afl->covered_seed_list_counter; i++) {
        struct queue_entry *q = afl->queue_buf[set_covered_seed_list[i]];

        // u32 newest_frontier_count = 0;
        // for (u32 j = 0; j < afl->recent_frontier_count; j++) {
        //   u32 recent_frontier_node = afl->recent_frontier_nodes[j];
          
        //   if(BITMAP_CHECK(q->frontier_node_bitmap,recent_frontier_node)){
        //     newest_frontier_count++;
        //   }
        // }
        // q->newest_frontier_node_count = newest_frontier_count;

        
        if (!q -> set_favored) {
          double frontier_score = calculate_newest_frontier_node_score(afl, q);
          double priority_score = frontier_score / (q->exec_us + 1);
          // double priority_score = q->newest_frontier_node_count;
          // double priority_score = frontier_score;
          all_favored = 0;
          if (priority_score > best_priority_score) {
              best_priority_score = priority_score;
              best_seed_id = q->id;
          }
        }
    }
    if (all_favored) {
       for (u32 i = 0; i < afl->covered_seed_list_counter; i++) {
        struct queue_entry *q = afl->queue_buf[set_covered_seed_list[i]];
        q -> set_favored = 0;
       }
      u32 random_index = rand() % afl->covered_seed_list_counter;
      best_seed_id = random_index;
    } 

    afl->queue_buf[best_seed_id]->set_favored = 1;
    return best_seed_id; 
}

/* 轻量化版本：在 Set Cover 集合中选择最新加入的种子 */
u32 select_latest_seed(afl_state_t *afl, u32 *set_covered_seed_list) {
    srand(time(NULL));
    u32 latest_seed_id = set_covered_seed_list[0];
    int all_favored = 1;  
    for (u32 i = 1; i < afl->covered_seed_list_counter; i++) {
        
        struct queue_entry *q = afl->queue_buf[set_covered_seed_list[i]];
        if (!q -> set_favored) {
        // 找到 ID 最大的种子
          if (q->id > latest_seed_id) {
              latest_seed_id = q->id;
          }
          all_favored = 0;
        }
      if (all_favored) {
        for (u32 i = 0; i < afl->covered_seed_list_counter; i++) {
          struct queue_entry *q = afl->queue_buf[set_covered_seed_list[i]];
          q -> set_favored = 0;
        }
        u32 random_index = rand() % afl->covered_seed_list_counter;
        latest_seed_id = random_index;
      }
    }
     afl->queue_buf[latest_seed_id]->set_favored = 1;
    return latest_seed_id;
}

u32 select_fastest_seed(afl_state_t *afl, u32 *set_covered_seed_list) {
    srand(time(NULL));
    u32 latest_seed_id = set_covered_seed_list[0];
    int all_favored = 1;  
    for (u32 i = 1; i < afl->covered_seed_list_counter; i++) {
        
        struct queue_entry *q = afl->queue_buf[set_covered_seed_list[i]];
        if (!q -> set_favored) {
        // 找到 ID 最大的种子
          if (q->id > latest_seed_id) {
              latest_seed_id = q->id;
          }
          all_favored = 0;
        }
      if (all_favored) {
        for (u32 i = 0; i < afl->covered_seed_list_counter; i++) {
          struct queue_entry *q = afl->queue_buf[set_covered_seed_list[i]];
          q -> set_favored = 0;
        }
        u32 random_index = rand() % afl->covered_seed_list_counter;
        latest_seed_id = random_index;
      }
    }
     afl->queue_buf[latest_seed_id]->set_favored = 1;
    return latest_seed_id;
}


void set_cover_reduction_final(afl_state_t *afl) {


  // srand(time(NULL));

  // for (u32 j = 0; j < (afl->fsrv.real_map_size >> 3) + 1; j++) {
    
  //   for (u8 bit = 0; bit < 8; bit++) {

  //     u32 edge_id = (j << 3) + bit;

  //     if (BITMAP_CHECK(afl->global_frontier_bitmap,edge_id)){

  //       if (!is_frontier_node_outer(afl, edge_id)){
  //         BITMAP_CLEAR(afl->global_frontier_bitmap,edge_id);
  //         afl->global_covered_frontier_nodes_count--;
  //       }
  //     }
  //   }
    
  // }

  memset((void *)afl->local_covered, 0, (afl->fsrv.real_map_size >> 3) + 1);
  memcpy(afl->global_frontier_bitmap_temp, afl->global_frontier_bitmap, (afl->fsrv.real_map_size >> 3) + 1);

  u8 fast_seed_exist = 0;
  u8 no_searched_frontier_exist = 0;
  u32 set_covered_seed_list[MAX_NODES_PER_SEED] = {0};
  u32 set_covered_fast_seed_list[MAX_NODES_PER_SEED] = {0};
  // u32 set_covered_favored_seed_list[MAX_NODES_PER_SEED] = {0};
  // 初始化未选种子数组
  u32 *unselected_seeds = ck_alloc(afl->queued_items * sizeof(u32));
  u32 unselected_seeds_count = 0;
  u32 setcover_finish_try_times = 0;
  u32 random_index = 0;

  

  afl->covered_seed_list_counter = 0;
  afl->covered_fast_seed_list_counter = 0;
  afl->covered_favored_seed_list_counter = 0;



  for (u32 i = 0; i < afl->queued_items; i++) {

    struct queue_entry *q = afl->queue_buf[i];



    q->set_covered = 0;  // 初始化 set_covered 标志

    if (q->covered_frontier_nodes_count > 0) { 
      unselected_seeds[unselected_seeds_count++] = i;
    }
  }

  // // 使用 Fisher-Yates Shuffle 进行随机打乱
  // for (u32 i = unselected_seeds_count - 1; i > 0; i--) {
  //   u32 j = rand() % (i + 1);
  //   SWAP(unselected_seeds[i], unselected_seeds[j]);  // 交换两个元素
  // }

  // // 生成一个随机索引列表
  // u32 *random_indices = ck_alloc(unselected_seeds_count * sizeof(u32));
  // for (u32 i = 0; i < unselected_seeds_count; i++) {
  //     random_indices[i] = i;
  // }

  // // Fisher-Yates Shuffle 打乱索引
  // for (u32 i = unselected_seeds_count - 1; i > 0; i--) {
  //     u32 j = rand() % (i + 1);
  //     SWAP(random_indices[i], random_indices[j]);
  // }

  
  // mean_exec_us = (total_exec_us - max_exec_us ) / (afl->queued_items - 1);

  // 计算均值和标准差
  // mean_exec_us = total_exec_us / unselected_seeds_count;
  // stddev_exec_us = sqrt((total_exec_us_sq / unselected_seeds_count) - (mean_exec_us * mean_exec_us));

  if (!unselected_seeds_count) {

    random_index = rand() % afl->queued_items;
    afl->set_favored_id = afl->queue_buf[random_index]->id;
    
  } else {

    u32 global_frontier_nodes = afl->global_covered_frontier_nodes_count;
    u32 covered_frontier_count = 0;

    u32 index = 0;  // 从打乱后的 `unselected_seeds` 数组中按顺序选取种子

    while (1) {
      no_searched_frontier_exist = 0;
      setcover_finish_try_times++;

      int best_seed_idx = -1;
      u32 max_gain = 0;

      for (u32 i = 0; i < unselected_seeds_count; i++) {
        u32 seed_index = unselected_seeds[i];
        struct queue_entry *seed = afl->queue_buf[seed_index];
        u32 gain = 0;
    
        for (u32 k = 0; k < seed->covered_frontier_nodes_count; k++) {
          u32 edge_id = seed->covered_frontier_node_list[k];
          if (BITMAP_CHECK(afl->global_frontier_bitmap_temp, edge_id)) {
            gain++;
          }
        }
    
        if (gain > max_gain) {
          max_gain = gain;
          best_seed_idx = i;
        }
      }
      
      // 获取选中的种子
      u32 seed_index = unselected_seeds[best_seed_idx];
      struct queue_entry *reduction_seed = afl->queue_buf[seed_index];

 
      // // 检查是否已覆盖所有前沿节点
      // int all_covered = 0;
      // 如果该种子没有带来新的覆盖，跳过
      u32 local_covered_intersection_num = 0;
      u64 builtin_start_time = get_cur_time();

      for (u32 k = 0; k < reduction_seed->covered_frontier_nodes_count; k++) {
        u32 edge_id = reduction_seed->covered_frontier_node_list[k];

        if (BITMAP_CHECK(afl->global_frontier_bitmap_temp, edge_id)) {
          local_covered_intersection_num++;
          BITMAP_CLEAR(afl->global_frontier_bitmap_temp, edge_id);
        }

      }
      if (local_covered_intersection_num){

        unselected_seeds[best_seed_idx] = unselected_seeds[--unselected_seeds_count];

        covered_frontier_count += local_covered_intersection_num;
        // 记录该种子到 set cover 集合中，并标记为已选择

        
        set_covered_seed_list[afl->covered_seed_list_counter++] = reduction_seed->id;
        reduction_seed->set_covered = 1;

      }

      u64 builtin_end_time = get_cur_time();
      afl->setcover_cost_time += (builtin_start_time - builtin_end_time);


      if (covered_frontier_count == global_frontier_nodes) {
        fprintf(afl->fsrv.set_cover_analysis, "setcover_finish_try_times : %u\n",setcover_finish_try_times);
        break;
      }
    }
    if (covered_frontier_count != global_frontier_nodes){
      fprintf(afl->fsrv.set_cover_analysis, "setcover_not_finish_and_exit! :%u, %u\n", covered_frontier_count, global_frontier_nodes);
    }
    
  }

  

  if (afl->covered_seed_list_counter > MAX_NODES_PER_SEED) {
      FATAL("Too many seeds selected in set cover reduction.");
  }


  // 释放动态分配的内存
  free(unselected_seeds);
  
}

void set_cover_reduction_v2(afl_state_t *afl) {

    u64 time_start = get_cur_time();

    // srand(time(NULL));

    memset((void *)afl->local_covered, 0, (afl->fsrv.real_map_size >> 3) + 1);

    u8 fast_seed_exist = 0;
    u32 set_covered_seed_list[MAX_NODES_PER_SEED] = {0};
    u32 set_covered_fast_seed_list[MAX_NODES_PER_SEED] = {0};
    // 初始化未选种子数组
    u32 *unselected_seeds = ck_alloc(afl->queued_items * sizeof(u32));
    u32 unselected_seeds_count = 0;
    u32 setcover_finish_try_times = 0;

    // if (unselected_seeds) {
    //   memset(unselected_seeds, 0, afl->queued_items * sizeof(u32));
    // } 

    afl->covered_seed_list_counter = 0;
    afl->covered_fast_seed_list_counter = 0;

    double total_exec_us = 0.0;
    double total_exec_us_sq = 0.0;
    double max_exec_us = 0.0;
    double mean_exec_us = 0.0;
    double stddev_exec_us = 0.0;

    for (u32 i = 0; i < afl->queued_items; i++) {

      struct queue_entry *q = afl->queue_buf[i];

      // update_global_frontier_nodes(q, afl);

      total_exec_us += q->exec_us;
      total_exec_us_sq += q->exec_us * q->exec_us;
      max_exec_us = MAX(max_exec_us, q->exec_us);

      if (q->covered_frontier_nodes_count > 0) { 
        unselected_seeds[unselected_seeds_count++] = i;
      }

    }
    
    mean_exec_us = (total_exec_us - max_exec_us ) / (afl->queued_items - 1);

    // 计算均值和标准差
    mean_exec_us = total_exec_us / afl->queued_items;
    stddev_exec_us = sqrt((total_exec_us_sq / afl->queued_items) - (mean_exec_us * mean_exec_us));

    if (!unselected_seeds_count) {

      u32 random_index = rand() % afl->queued_items;
      afl->set_favored_id = afl->queue_buf[random_index]->id;
      
    } else {

      while (unselected_seeds_count > 0) {
        setcover_finish_try_times++;
        // 从未选种子数组中随机选择一个种子
        u64 random_start_time = get_cur_time();
        u32 random_index = rand() % unselected_seeds_count;
        u64 random_end_time = get_cur_time();
        afl->random_cost_time += random_end_time - random_start_time;
        u32 seed_index = unselected_seeds[random_index];
        
        // 获取选中的种子
        struct queue_entry *reduction_seed = afl->queue_buf[seed_index];

        // 将最后一个元素移动到被选中的位置，缩减数组大小
        unselected_seeds[random_index] = unselected_seeds[unselected_seeds_count - 1];
        unselected_seeds_count--;

        // 检查是否已覆盖所有前沿节点
        int all_covered = 1;
        // 如果该种子没有带来新的覆盖，跳过
        int local_covered_intersection_num = 0;
        u64 builtin_start_time = get_cur_time();
        for (u32 j = 0; j < (afl->fsrv.real_map_size >> 3) + 1; j++) {
            u8 previous = afl->local_covered[j];
            afl->local_covered[j] |= reduction_seed->frontier_node_bitmap[j];
            
            local_covered_intersection_num += __builtin_popcount(afl->local_covered[j] & ~previous);
            
            // 如果更新的local_covered与全局前沿节点有交集，则说明没有完全覆盖，all_covered置为0，从此无需再进入该分支重复赋值
            if (~afl->local_covered[j] & afl->global_frontier_bitmap[j] & all_covered) {
                //注意不要break，一旦进入该分支说明还没有完全覆盖global_frontier_bitmap,所以local_covered要更新完，
                // 否则影响后面的种子继续判断是否完全覆盖global_frontier_bitmap
                all_covered = 0;
            }

        }
        u64 builtin_end_time = get_cur_time();
        afl->setcover_cost_time += builtin_start_time - builtin_end_time;
        if (!local_covered_intersection_num) continue;

        // 记录该种子到 set cover 集合中，并标记为已选择
        set_covered_seed_list[afl->covered_seed_list_counter++] = reduction_seed->id;

        if (afl->queue_buf[reduction_seed->id] -> exec_us < mean_exec_us + stddev_exec_us) {
          set_covered_fast_seed_list[afl->covered_fast_seed_list_counter++] = reduction_seed->id;
          fast_seed_exist = 1;
        }
        // reduction_seed->set_covered = 1;

        // 检查是否已覆盖所有前沿节点
        // int all_covered = 1;
        // for (u32 j = 0; j < (afl->fsrv.real_map_size >> 3) + 1; j++) {
        //     if (~afl->local_covered[j] & afl->global_frontier_bitmap[j]) {
        //         all_covered = 0;
        //         break;
        //     }
        // }

        if (all_covered) {
          fprintf(afl->fsrv.set_cover_analysis, "setcover_finish_try_times : %u\n",setcover_finish_try_times);
          // 已生成完成的Set Cover集合，现在基于优先级进行种子选择
          // afl->set_favored_id = select_seed_covering_latest_frontier_node(afl, set_covered_seed_list);
          if (fast_seed_exist) {
            
            u32 random_index = rand() % afl->covered_fast_seed_list_counter;
            
            afl->set_favored_id = set_covered_fast_seed_list[random_index];

            // fprintf(afl->fsrv.set_cover_analysis, "random_index from covered_fast_seed_list_counter : %u %u \n",random_index, afl->set_favored_id );
          
          } else {

            u32 random_index = rand() % afl->covered_seed_list_counter;
            afl->set_favored_id = set_covered_seed_list[random_index];
            // fprintf(afl->fsrv.set_cover_analysis, "random_index from covered_seed_list_counter :%u %u\n", random_index, afl->set_favored_id );

          }
          
          break;
        }

      }
    }

    

    if (afl->covered_seed_list_counter > MAX_NODES_PER_SEED) {
        FATAL("Too many seeds selected in set cover reduction.");
    }

    // 释放动态分配的内存
    free(unselected_seeds);
    u64 time_end = get_cur_time();
    u64 diff_time = time_end - time_start;
    afl->setcover_global_cull_queue_time += diff_time;
}

inline bool is_frontier_node_inner(afl_state_t *afl, u32 id) {

    int num_successors = afl->fsrv.successor_count[id];
    if (num_successors <= 1) {
        return 0;  // 该路径没有或只有一个后继节点，不是前沿节点
    }
    // printf("该路径有%d个后继节点，是前沿节点\n", num_successors);    
    int not_visited = 0;
    // printf("正在判断edge: %d 是否 frontier node\n",id);
    for (int i = 0; i < num_successors; i++) {
        u32 succ_id = afl->fsrv.successor_map[id][i];
        u8 current_status = afl->fsrv.trace_bits[succ_id];
        u8 virgin_status = afl->virgin_bits[succ_id];
        
        if(virgin_status == 0xFF && current_status == 0x00){
          not_visited =1;
          break;
        }
    }

    return not_visited;
}

inline bool is_frontier_node_outer(afl_state_t *afl, u32 id) {

    int num_successors = afl->fsrv.successor_count[id];
    if (num_successors <= 1) {
        return 0;  // 该路径没有或只有一个后继节点，不是前沿节点
    }
    // printf("该路径有%d个后继节点，是前沿节点\n", num_successors);    
    int not_visited = 0;
    // printf("正在判断edge: %d 是否 frontier node\n",id);
    for (int i = 0; i < num_successors; i++) {
        u32 succ_id = afl->fsrv.successor_map[id][i];
        u8 succ_status = afl->virgin_bits[succ_id];

        if (succ_status == 0xFF) {
            not_visited = 1;
            break;
        }
    }

    return not_visited;
}

void set_cover_reduction_v1(afl_state_t *afl) {
  
  srand(time(NULL));
  // printf("------------3. 开始调用set_cover_reduction函数----------------\n");
    // 更新所有种子的前沿节点状态
  for (u32 i = 0; i < afl->queued_items; i++) {
      struct queue_entry *q = afl->queue_buf[i];
      update_global_frontier_nodes(q, afl);
  }

  u8 local_covered[MAP_SIZE >> 3] = {0};  // 用位图记录已经覆盖的前沿节点
  u32 set_covered_seed_list[MAX_NODES_PER_SEED] = {0};

  struct queue_entry* reduction_seed = NULL;

  while (1) {
      // printf("Select represented seed using set cover 第 %d 轮\n", set_cover_rounds++);
    
      reduction_seed = NULL;
      // best_coverage = 0;
      u32 random_index = rand() % afl->queued_items;

      reduction_seed = afl->queue_buf[random_index];

      if (reduction_seed -> set_favored || !reduction_seed -> covered_frontier_nodes_count) continue;
      // printf("---这一轮 best_seed_id: %d and best_coverage: %d----\n", reduction_seed->id, best_coverage);
      // 如果没有更多的种子可以选择，跳出循环
      if (!reduction_seed) {
        // reduction_seed = afl->queue_buf[afl->set_favored_id];
        FATAL("No more seeds to choose from!\n");
        printf("No more seeds to choose from! use previous seed\n");
        break;
      }
      
      if(afl->covered_seed_list_counter >= afl->queued_items){
        printf("afl->covered_seed_list_counter: %d, afl->queued_items: %d", afl->covered_seed_list_counter, afl->queued_items);
        FATAL("!!!!!!!!!!!!!!!!!Fatal Error！!!!!!!!!!!!!!!!!!!!!!!!!!");
      }

      if (afl->covered_seed_list_counter > MAX_NODES_PER_SEED){
        break;
      }

      // 更新已覆盖的前沿节点位图
      int local_covered_intersection_num = 0;
      // int total_covered_intersection_num = 0;
      for (u32 j = 0; j < (MAP_SIZE >> 3); j++) {
          u8 previous = local_covered[j];  // 保存合并之前的状态
          local_covered[j] |= reduction_seed->frontier_node_bitmap[j];  // 合并覆盖的前沿节点
          //total_covered_intersection_num += __builtin_popcount(local_covered[j]);
          local_covered_intersection_num += __builtin_popcount(local_covered[j] & ~previous);
      }

      if (!local_covered_intersection_num) continue;

      set_covered_seed_list[afl->covered_seed_list_counter++] = reduction_seed->id;
      reduction_seed -> set_favored = 1;

      if(afl->global_covered_frontier_nodes_count == 0) break;
      // printf("----------经过这一轮set cover, best_seed 覆盖了 : %d gloabl_frontier_nodes\n", local_covered_intersection_num);
      // printf("----------经过这一轮set cover, all best_seeds 一共覆盖了: %d gloabl_frontier_nodes \n", total_covered_intersection_num);
      // printf("++++++++++此时全局frontier node的数量为: %d \n", afl->global_covered_frontier_nodes_count);
      // 检查是否所有前沿节点都已覆盖 

      

      int all_covered = 1;
      for (u32 j = 0; j < (MAP_SIZE >> 3); j++) {
          if (~local_covered[j] & afl->global_frontier_bitmap[j]) {  // 如果有未覆盖的前沿节点
              // printf("set cover 集合中的种子还没有覆盖率所有 frontier node!!!!!!!!\n");
              all_covered = 0;
              break;
          }
      }
      // printf("当前一共选出的set cover 集合数量 afl->covered_seed_list_counter  : %d\n",afl->covered_seed_list_counter );
      // 如果所有前沿节点都已覆盖，跳出循环
      if (all_covered) {
        ACTF("afl->covered_seed_list_counter: %u", afl->covered_seed_list_counter);

       
        // if(afl->use_set_cover_scheduling) {
        //   FILE *f = fopen("setcover.txt", "a+");
        //   if (!f) {
        //     perror("Unable to open file for writing frontier node information");
        //     return;
        //   }

        //   fprintf(f, "afl->covered_seed_list_counter %u  | global_covered_frontier_nodes_count %u | selected seed id %u\n" , afl->covered_seed_list_counter, afl->global_covered_frontier_nodes_count,random_index);

        // fclose(f);
        // }
        
        // srand(time(NULL));
        u32 random_index = rand() % afl->covered_seed_list_counter;
        // printf("random_index: %d ", random_index);
        afl->set_favored_id = set_covered_seed_list[random_index];
        // printf("set_favored_id: %ld\n",afl->set_favored_id);
        break;
      };
  }
  // printf("++++++++++++++++++结束调用set_cover_reduction函数++++++++++++++++++\n");
}

// void set_cover_reduction_v5(afl_state_t *afl) {
//     // 更新所有种子的前沿节点状态
//     for (u32 i = 0; i < afl->queued_items; i++) {
//         struct queue_entry *q = afl->queue_buf[i];
//         update_global_frontier_nodes(q, afl);
//     }

//     // 全局位图，记录尚未覆盖的前沿节点
//     u8 remaining_frontier_bitmap[MAP_SIZE >> 3];
//     memcpy(remaining_frontier_bitmap, afl->global_frontier_bitmap, sizeof(remaining_frontier_bitmap));

//     // 优先队列，按种子覆盖的前沿节点数量进行排序
//     struct priority_queue pq[afl->queued_items];
//     int pq_size = 0;

//     // 初始化优先队列，计算每个种子对剩余前沿节点的贡献
//     for (u32 i = 0; i < afl->queued_items; i++) {
//         struct queue_entry *q = afl->queue_buf[i];
//         int coverage = 0;

//         // 仅统计还未被覆盖的前沿节点
//         for (u32 j = 0; j < (MAP_SIZE >> 3); j++) {
//             u8 uncovered_bits = q->frontier_node_bitmap[j] & remaining_frontier_bitmap[j];
//             coverage += __builtin_popcount(uncovered_bits);
//         }

//         // 将种子加入优先队列，按覆盖量排序
//         if (coverage > 0) {
//             pq[pq_size].q = q;
//             pq[pq_size].coverage = coverage;
//             pq_size++;
//         }
//     }

//     // 按覆盖量对种子排序，使用优先队列来选择种子
//     qsort(pq, pq_size, sizeof(struct priority_queue), compare_coverage);

//     int total_selected_seeds = 0;

//     // 选择种子并更新全局位图
//     while (pq_size > 0) {
//         struct queue_entry* best_seed = pq[0].q;  // 选择覆盖最多前沿节点的种子
//         best_seed->set_favored = 1;  // 标记为 favored
//         total_selected_seeds++;

//         // 更新已覆盖的前沿节点
//         for (u32 j = 0; j < (MAP_SIZE >> 3); j++) {
//             remaining_frontier_bitmap[j] &= ~best_seed->frontier_node_bitmap[j];  // 移除已覆盖的前沿节点
//         }

//         // 重新计算剩余种子对尚未覆盖前沿节点的贡献
//         int new_pq_size = 0;
//         for (int i = 1; i < pq_size; i++) {  // 跳过已经选中的种子
//             struct queue_entry *q = pq[i].q;
//             int coverage = 0;

//             for (u32 j = 0; j < (MAP_SIZE >> 3); j++) {
//                 u8 uncovered_bits = q->frontier_node_bitmap[j] & remaining_frontier_bitmap[j];
//                 coverage += __builtin_popcount(uncovered_bits);
//             }

//             if (coverage > 0) {
//                 pq[new_pq_size].q = q;
//                 pq[new_pq_size].coverage = coverage;
//                 new_pq_size++;
//             }
//         }

//         pq_size = new_pq_size;

//         // 重新排序剩余种子，保证选择覆盖最多的种子
//         qsort(pq, pq_size, sizeof(struct priority_queue), compare_coverage);

//         // 如果没有剩余的前沿节点可以覆盖，提前结束
//         if (memcmp(remaining_frontier_bitmap, afl->global_frontier_bitmap, sizeof(remaining_frontier_bitmap)) == 0) {
//             break;
//         }
//     }
// }

void set_cover_reduction_v4(afl_state_t *afl) { 
    u8 remaining_frontier_bitmap[MAP_SIZE >> 3];
    memcpy(remaining_frontier_bitmap, afl->global_frontier_bitmap, sizeof(remaining_frontier_bitmap));

    while (true) {
        struct queue_entry *best_seed = NULL;
        int best_coverage = 0;

        // 1. 首先使用 q->covered_frontier_nodes_count 进行预估排序
        for (u32 i = 0; i < afl->queued_items; i++) {
            struct queue_entry *q = afl->queue_buf[i];
            if (q->set_covered) continue;  // 跳过已标记种子

            int estimated_coverage = q->covered_frontier_nodes_count;

            // 如果未覆盖节点已经少于 estimated_coverage，继续用剩余位图计算
            if (best_coverage < estimated_coverage) {
                best_coverage = estimated_coverage;
                best_seed = q;
            }
        }

        // 如果已经选择了一个种子，验证其贡献，计算剩余未覆盖节点
        if (best_seed) {
            int actual_coverage = 0;

            // 只在必要时计算实际覆盖的未覆盖节点
            for (u32 j = 0; j < (MAP_SIZE >> 3); j++) {
                u8 q_bitmap = best_seed->frontier_node_bitmap[j];
                u8 remaining_bits = q_bitmap & remaining_frontier_bitmap[j];
                actual_coverage += __builtin_popcount(remaining_bits);
            }

            // 确定实际的最佳种子
            if (actual_coverage > best_coverage) {
                best_coverage = actual_coverage;
            }

            best_seed->set_favored = 1;  // 标记为 favored
            // 更新 remaining_frontier_bitmap
            for (u32 j = 0; j < (MAP_SIZE >> 3); j++) {
                remaining_frontier_bitmap[j] &= ~best_seed->frontier_node_bitmap[j];
            }
        } else {
            break;  // 如果没有种子可选，退出循环
        }

        // 检查是否所有前沿节点都已覆盖
        bool all_covered = true;
        for (u32 j = 0; j < (MAP_SIZE >> 3); j++) {
            if (remaining_frontier_bitmap[j] != 0) {
                all_covered = false;
                break;
            }
        }
        if (all_covered) break;
    }
}

void set_cover_reduction_v3(afl_state_t *afl) {

    for (u32 i = 0; i < afl->queued_items; i++) {
        struct queue_entry *q = afl->queue_buf[i];
        if (q -> covered_frontier_nodes_count) {
          update_global_frontier_nodes(q, afl);
        }
        
    }

    // u8 remaining_frontier_bitmap[MAP_SIZE >> 3];
    // memcpy(remaining_frontier_bitmap, afl->global_frontier_bitmap, sizeof(remaining_frontier_bitmap));

    struct queue_entry *best_seed = NULL;
    u32 max_coverage = 0;
    // 如果已经选择了一个种子，验证其贡献，计算剩余未覆盖节点
    

    for (u32 i = 0; i < afl->queued_items; i++){
      // if (!afl->queue_buf[i]->set_favored) {
        if (afl->queue_buf[i]->covered_frontier_nodes_count > max_coverage ) {
          max_coverage = afl->queue_buf[i]->covered_frontier_nodes_count;
          best_seed = afl->queue_buf[i];
        }
      // }
    }
    
    if (!best_seed) {
      u32 random_index = rand() % afl->queued_items;
        // 随机选择一个队列中的种子作为 fallback（可以根据需要优化选择策略）
      afl->set_favored_id = random_index;
      // afl->queue_buf[afl->set_favored_id]->set_favored = 1;
    } else {
      afl->set_favored_id = best_seed->id;
      best_seed->set_favored = 1;  // 标记为 favored
    }

    
    
    
    // 更新 remaining_frontier_bitmap
}

void set_cover_reduction(afl_state_t *afl) {
  
  // srand(time(NULL));
  // printf("------------3. 开始调用set_cover_reduction函数----------------\n");
    // 更新所有种子的前沿节点状态
    for (u32 i = 0; i < afl->queued_items; i++) {
        struct queue_entry *q = afl->queue_buf[i];
        update_global_frontier_nodes(q, afl);
    }

    u8 local_covered[MAP_SIZE >> 3] = {0};  // 用位图记录已经覆盖的前沿节点
    u32 set_covered_seed_list[MAX_NODES_PER_SEED] = {0};

    struct queue_entry* best_seed = NULL;
    int best_coverage = 0;
    
    
    // int set_cover_rounds = 0;
    while (1) {
        // printf("Select represented seed using set cover 第 %d 轮\n", set_cover_rounds++);
      
        best_seed = NULL;
        best_coverage = 0;

        // 找到覆盖最多前沿节点的种子
        for (u32 i = 0; i < afl->queued_items; i++) {
            struct queue_entry *q = afl->queue_buf[i];
            // if (q->set_favored) continue;  // 跳过已标记的种子
            // printf("current seed id: %d,afl->set_favored_id: %ld \n", q->id,afl->set_favored_id);

            int coverage = 0;
            // printf("当前种子: %d 覆盖的frontier_nodes_count: %d\n",q->id,q->covered_frontier_nodes_count);
            // int flag = 0;
            // 计算当前种子对未覆盖前沿节点的贡献
            for (u32 j = 0; j < (MAP_SIZE >> 3); j++) {
                u8 q_bitmap = q->frontier_node_bitmap[j];  // 获取该种子的前沿节点位图字节
                
                if (q_bitmap == 0) continue;

                // flag = 1;
                u8 covered_bitmap = local_covered[j];      // 已覆盖的前沿节点位图字节

                // 通过按位与和取反操作，找到当前种子新覆盖的前沿节点
                u8 new_coverage = q_bitmap & ~covered_bitmap;

                // 统计新覆盖的前沿节点数量
                coverage += __builtin_popcount(new_coverage);
                // if (new_coverage != 0 && coverage != 0) {
                //     // 更新已覆盖的前沿节点位图
                //     printf("当前种子存在新的与全局frontier node交集 new_coverage: %d and coverage : %d ---------\n", new_coverage, coverage);
                // }
                
            }
            // if (!flag){
            //   printf("***********当前种子没有新的与全局frontier node交集,frontier_node_bitmap全部为0！！！！！！\n");
            // }
            // if (coverage != 0){
            //   printf("当前种子: %d, 覆盖的global_frontier_bitmap数量（交集）: %d\n", q->id, coverage);
            // }
            

            // 找到覆盖前沿节点最多的种子
            if (coverage >= best_coverage) {
                best_coverage = coverage;
                best_seed = q;
            }
        }
        // printf("---这一轮 best_seed_id: %d and best_coverage: %d----\n", best_seed->id, best_coverage);
        // 如果没有更多的种子可以选择，跳出循环
        if (!best_seed) {
          // best_seed = afl->queue_buf[afl->set_favored_id];
          FATAL("No more seeds to choose from!\n");
          printf("No more seeds to choose from! use previous seed\n");
          break;
        }
        
        if(afl->covered_seed_list_counter >= afl->queued_items){
          FATAL("!!!!!!!!!!!!!!!!!严重错误！!!!!!!!!!!!!!!!!!!!!!!!!!");
        }
        if (afl->covered_seed_list_counter < MAX_NODES_PER_SEED){
          set_covered_seed_list[afl->covered_seed_list_counter++] = best_seed->id;
        }

        // 更新已覆盖的前沿节点位图
        // int local_covered_intersection_num = 0;
        // int total_covered_intersection_num = 0;
        for (u32 j = 0; j < (MAP_SIZE >> 3); j++) {
            // u8 previous = local_covered[j];  // 保存合并之前的状态
            local_covered[j] |= best_seed->frontier_node_bitmap[j];  // 合并覆盖的前沿节点
            // total_covered_intersection_num += __builtin_popcount(local_covered[j]);
            // local_covered_intersection_num += __builtin_popcount(local_covered[j] & ~previous);
        }
        // printf("----------经过这一轮set cover, best_seed 覆盖了 : %d gloabl_frontier_nodes\n", local_covered_intersection_num);
        // printf("----------经过这一轮set cover, all best_seeds 一共覆盖了: %d gloabl_frontier_nodes \n", total_covered_intersection_num);
        // printf("++++++++++此时全局frontier node的数量为: %d \n", afl->global_covered_frontier_nodes_count);
        // 检查是否所有前沿节点都已覆盖 
        int all_covered = 1;
        for (u32 j = 0; j < (MAP_SIZE >> 3); j++) {
            if (~local_covered[j] & afl->global_frontier_bitmap[j]) {  // 如果有未覆盖的前沿节点
                // printf("set cover 集合中的种子还没有覆盖率所有 frontier node!!!!!!!!\n");
                all_covered = 0;
                break;
            }
        }
        // printf("当前一共选出的set cover 集合数量 afl->covered_seed_list_counter  : %d\n",afl->covered_seed_list_counter );
        // 如果所有前沿节点都已覆盖，跳出循环
        if (all_covered) {
          u32 random_index = rand() % afl->covered_seed_list_counter;
          // printf("random_index: %d", random_index);
          afl->set_favored_id = set_covered_seed_list[random_index];
          // FILE *f = fopen("setcover.txt", "a+");
          // if (!f) {
          //   perror("Unable to open file for writing frontier node information");
          //   return;
          // }

          // fprintf(f, "afl->covered_seed_list_counter %u  | global_covered_frontier_nodes_count %u | selected seed id %u\n" , afl->covered_seed_list_counter, afl->global_covered_frontier_nodes_count,random_index);

          // fclose(f);
          // printf("set_favored_id: %ld",afl->set_favored_id);
          break;
        };
    }
}

// 定义比较函数，用于按照覆盖量排序
int compare_coverage(const void *a, const void *b) {
    const struct priority_queue *pa = (const struct priority_queue *)a;
    const struct priority_queue *pb = (const struct priority_queue *)b;

    // 按照覆盖量降序排列
    if (pa->coverage > pb->coverage) {
        return -1;  // 覆盖量大的优先
    } else if (pa->coverage < pb->coverage) {
        return 1;   // 覆盖量小的排后
    } else {
        return 0;   // 覆盖量相等
    }
}

void write_frontier_node_info(struct afl_state *afl) {

  u8 *frontier_node_info_analysis_tmp = alloc_printf("%s/frontier_node_info", afl->out_dir);
  FILE *f = fopen(frontier_node_info_analysis_tmp, "a+");
  if (!f) {
    perror("Unable to open file for writing frontier node information");
    return;
  }
  ck_free(frontier_node_info_analysis_tmp);


  for (u32 i = 0; i < afl->queued_items; i++) {
    struct queue_entry *q = afl->queue_buf[i];
    fprintf(f, "Seed %u covers %u frontier nodes\n", q->id, q->covered_frontier_nodes_count);
  }

  fclose(f);
  // if (!afl->use_set_cover_scheduling) {
  //   fprintf(afl->fsrv.set_cover_analysis, "%u\n",afl->baseline_global_cull_queue_time);
  // } else{
  //   fprintf(afl->fsrv.set_cover_analysis, "%u\n",afl->setcover_global_cull_queue_time);
  // }
  fprintf(afl->fsrv.set_cover_analysis, "baseline: %llu\n",afl->baseline_global_cull_queue_time);
  fprintf(afl->fsrv.set_cover_analysis, "setcover: %llu\n",afl->setcover_global_cull_queue_time);
  fprintf(afl->fsrv.set_cover_analysis, "random_cost_time: %llu\n",afl->random_cost_time);
  fprintf(afl->fsrv.set_cover_analysis, "setcover_cost_time: %llu\n",afl->setcover_cost_time);
}

void write_seeds_exec_time_distribution(struct afl_state *afl) {

  u8 *seeds_exec_time_analysis_tmp = alloc_printf("%s/seeds_exec_time_info", afl->out_dir);
  FILE *f = fopen(seeds_exec_time_analysis_tmp, "a+");
  if (!f) {
    perror("Unable to open file for writing frontier node information");
    return;
  }
  ck_free(seeds_exec_time_analysis_tmp);


  for (u32 i = 0; i < afl->queued_items; i++) {
    struct queue_entry *q = afl->queue_buf[i];
    fprintf(f, "Seed %u exec time is %llu \n", q->id, q->exec_us);
  }

  fclose(f);
}



/* Calculate case desirability score to adjust the length of havoc fuzzing.
   A helper function for fuzz_one(). Maybe some of these constants should
   go into config.h. */

u32 calculate_score(afl_state_t *afl, struct queue_entry *q) {

  u32 cal_cycles = afl->total_cal_cycles;
  u32 bitmap_entries = afl->total_bitmap_entries;

  if (unlikely(!cal_cycles)) { cal_cycles = 1; }
  if (unlikely(!bitmap_entries)) { bitmap_entries = 1; }

  u32 avg_exec_us = afl->total_cal_us / cal_cycles;
  u32 avg_bitmap_size = afl->total_bitmap_size / bitmap_entries;
  u32 perf_score = 100;

  /* Adjust score based on execution speed of this path, compared to the
     global average. Multiplier ranges from 0.1x to 3x. Fast inputs are
     less expensive to fuzz, so we're giving them more air time. */

  // TODO BUG FIXME: is this really a good idea?
  // This sounds like looking for lost keys under a street light just because
  // the light is better there.
  // Longer execution time means longer work on the input, the deeper in
  // coverage, the better the fuzzing, right? -mh

  if (likely(afl->schedule < RARE) && likely(!afl->fixed_seed)) {

    if (q->exec_us * 0.1 > avg_exec_us) {

      perf_score = 10;

    } else if (q->exec_us * 0.25 > avg_exec_us) {

      perf_score = 25;

    } else if (q->exec_us * 0.5 > avg_exec_us) {

      perf_score = 50;

    } else if (q->exec_us * 0.75 > avg_exec_us) {

      perf_score = 75;

    } else if (q->exec_us * 4 < avg_exec_us) {

      perf_score = 300;

    } else if (q->exec_us * 3 < avg_exec_us) {

      perf_score = 200;

    } else if (q->exec_us * 2 < avg_exec_us) {

      perf_score = 150;

    }

  }

  /* Adjust score based on bitmap size. The working theory is that better
     coverage translates to better targets. Multiplier from 0.25x to 3x. */

  if (q->bitmap_size * 0.3 > avg_bitmap_size) {

    perf_score *= 3;

  } else if (q->bitmap_size * 0.5 > avg_bitmap_size) {

    perf_score *= 2;

  } else if (q->bitmap_size * 0.75 > avg_bitmap_size) {

    perf_score *= 1.5;

  } else if (q->bitmap_size * 3 < avg_bitmap_size) {

    perf_score *= 0.25;

  } else if (q->bitmap_size * 2 < avg_bitmap_size) {

    perf_score *= 0.5;

  } else if (q->bitmap_size * 1.5 < avg_bitmap_size) {

    perf_score *= 0.75;

  }

  /* Adjust score based on handicap. Handicap is proportional to how late
     in the game we learned about this path. Latecomers are allowed to run
     for a bit longer until they catch up with the rest. */

  if (q->handicap >= 4) {

    perf_score *= 4;
    q->handicap -= 4;

  } else if (q->handicap) {

    perf_score *= 2;
    --q->handicap;

  }

  /* Final adjustment based on input depth, under the assumption that fuzzing
     deeper test cases is more likely to reveal stuff that can't be
     discovered with traditional fuzzers. */

  switch (q->depth) {

    case 0 ... 3:
      break;
    case 4 ... 7:
      perf_score *= 2;
      break;
    case 8 ... 13:
      perf_score *= 3;
      break;
    case 14 ... 25:
      perf_score *= 4;
      break;
    default:
      perf_score *= 5;

  }

  u32         n_items;
  double      factor = 1.0;
  long double fuzz_mu;

  switch (afl->schedule) {

    case EXPLORE:
      break;

    case SEEK:
      break;

    case EXPLOIT:
      factor = MAX_FACTOR;
      break;

    case COE:
      fuzz_mu = 0.0;
      n_items = 0;

      // Don't modify perf_score for unfuzzed seeds
      if (!q->fuzz_level) break;

      u32 i;
      for (i = 0; i < afl->queued_items; i++) {

        if (likely(!afl->queue_buf[i]->disabled)) {

          fuzz_mu += log2(afl->n_fuzz[afl->queue_buf[i]->n_fuzz_entry]);
          n_items++;

        }

      }

      if (unlikely(!n_items)) { FATAL("Queue state corrupt"); }

      fuzz_mu = fuzz_mu / n_items;

      if (log2(afl->n_fuzz[q->n_fuzz_entry]) > fuzz_mu) {

        /* Never skip favourites */
        if (!q->favored) factor = 0;

        break;

      }

    // Fall through
    case FAST:

      // Don't modify unfuzzed seeds
      if (!q->fuzz_level) break;

      switch ((u32)log2(afl->n_fuzz[q->n_fuzz_entry])) {

        case 0 ... 1:
          factor = 4;
          break;

        case 2 ... 3:
          factor = 3;
          break;

        case 4:
          factor = 2;
          break;

        case 5:
          break;

        case 6:
          if (!q->favored) factor = 0.8;
          break;

        case 7:
          if (!q->favored) factor = 0.6;
          break;

        default:
          if (!q->favored) factor = 0.4;
          break;

      }

      if (q->favored) factor *= 1.15;

      break;

    case LIN:
      // Don't modify perf_score for unfuzzed seeds
      if (!q->fuzz_level) break;

      factor = q->fuzz_level / (afl->n_fuzz[q->n_fuzz_entry] + 1);
      break;

    case QUAD:
      // Don't modify perf_score for unfuzzed seeds
      if (!q->fuzz_level) break;

      factor =
          q->fuzz_level * q->fuzz_level / (afl->n_fuzz[q->n_fuzz_entry] + 1);
      break;

    case MMOPT:
      /* -- this was a more complex setup, which is good, but competed with
         -- rare. the simpler algo however is good when rare is not.
        // the newer the entry, the higher the pref_score
        perf_score *= (1 + (double)((double)q->depth /
        (double)afl->queued_items));
        // with special focus on the last 8 entries
        if (afl->max_depth - q->depth < 8) perf_score *= (1 + ((8 -
        (afl->max_depth - q->depth)) / 5));
      */
      // put focus on the last 5 entries
      if (afl->max_depth - q->depth < 5) { perf_score *= 2; }

      break;

    case RARE:

      // increase the score for every bitmap byte for which this entry
      // is the top contender
      perf_score += (q->tc_ref * 10);
      // the more often fuzz result paths are equal to this queue entry,
      // reduce its value
      perf_score *= (1 - (double)((double)afl->n_fuzz[q->n_fuzz_entry] /
                                  (double)afl->fsrv.total_execs));

      break;

    default:
      PFATAL("Unknown Power Schedule");

  }

  if (unlikely(afl->schedule >= EXPLOIT && afl->schedule <= QUAD)) {

    if (factor > MAX_FACTOR) { factor = MAX_FACTOR; }
    perf_score *= factor / POWER_BETA;

  }

  // MOpt mode
  if (afl->limit_time_sig != 0 && afl->max_depth - q->depth < 3) {

    perf_score *= 2;

  } else if (afl->schedule != COE && perf_score < 1) {

    // Add a lower bound to AFLFast's energy assignment strategies
    perf_score = 1;

  }

  /* Make sure that we don't go over limit. */

  if (perf_score > afl->havoc_max_mult * 100) {

    perf_score = afl->havoc_max_mult * 100;

  }

  return perf_score;

}

/* after a custom trim we need to reload the testcase from disk */

inline void queue_testcase_retake(afl_state_t *afl, struct queue_entry *q,
                                  u32 old_len) {

  if (likely(q->testcase_buf)) {

    u32 len = q->len;

    if (len != old_len) {

      afl->q_testcase_cache_size = afl->q_testcase_cache_size + len - old_len;
      q->testcase_buf = (u8 *)realloc(q->testcase_buf, len);

      if (unlikely(!q->testcase_buf)) {

        PFATAL("Unable to malloc '%s' with len %u", (char *)q->fname, len);

      }

    }

    int fd = open((char *)q->fname, O_RDONLY);

    if (unlikely(fd < 0)) { PFATAL("Unable to open '%s'", (char *)q->fname); }

    ck_read(fd, q->testcase_buf, len, q->fname);
    close(fd);

  }

}

/* after a normal trim we need to replace the testcase with the new data */

inline void queue_testcase_retake_mem(afl_state_t *afl, struct queue_entry *q,
                                      u8 *in, u32 len, u32 old_len) {

  if (likely(q->testcase_buf)) {

    u32 is_same = in == q->testcase_buf;

    if (likely(len != old_len)) {

      u8 *ptr = (u8 *)realloc(q->testcase_buf, len);

      if (likely(ptr)) {

        q->testcase_buf = ptr;
        afl->q_testcase_cache_size = afl->q_testcase_cache_size + len - old_len;

      }

    }

    if (unlikely(!is_same)) { memcpy(q->testcase_buf, in, len); }

  }

}

/* Returns the testcase buf from the file behind this queue entry.
  Increases the refcount. */

inline u8 *queue_testcase_get(afl_state_t *afl, struct queue_entry *q) {

  u32 len = q->len;

  /* first handle if no testcase cache is configured */

  if (unlikely(!afl->q_testcase_max_cache_size)) {

    u8 *buf;

    if (unlikely(q == afl->queue_cur)) {

      buf = (u8 *)afl_realloc((void **)&afl->testcase_buf, len);

    } else {

      buf = (u8 *)afl_realloc((void **)&afl->splicecase_buf, len);

    }

    if (unlikely(!buf)) {

      PFATAL("Unable to malloc '%s' with len %u", (char *)q->fname, len);

    }

    int fd = open((char *)q->fname, O_RDONLY);

    if (unlikely(fd < 0)) { PFATAL("Unable to open '%s'", (char *)q->fname); }

    ck_read(fd, buf, len, q->fname);
    close(fd);
    return buf;

  }

  /* now handle the testcase cache */

  if (unlikely(!q->testcase_buf)) {

    /* Buf not cached, let's load it */
    u32        tid = afl->q_testcase_max_cache_count;
    static u32 do_once = 0;  // because even threaded we would want this. WIP

    while (unlikely(
        afl->q_testcase_cache_size + len >= afl->q_testcase_max_cache_size ||
        afl->q_testcase_cache_count >= afl->q_testcase_max_cache_entries - 1)) {

      /* We want a max number of entries to the cache that we learn.
         Very simple: once the cache is filled by size - that is the max. */

      if (unlikely(afl->q_testcase_cache_size + len >=
                       afl->q_testcase_max_cache_size &&
                   (afl->q_testcase_cache_count <
                        afl->q_testcase_max_cache_entries &&
                    afl->q_testcase_max_cache_count <
                        afl->q_testcase_max_cache_entries) &&
                   !do_once)) {

        if (afl->q_testcase_max_cache_count > afl->q_testcase_cache_count) {

          afl->q_testcase_max_cache_entries =
              afl->q_testcase_max_cache_count + 1;

        } else {

          afl->q_testcase_max_cache_entries = afl->q_testcase_cache_count + 1;

        }

        do_once = 1;
        // release unneeded memory
        afl->q_testcase_cache = (struct queue_entry **)ck_realloc(
            afl->q_testcase_cache,
            (afl->q_testcase_max_cache_entries + 1) * sizeof(size_t));

      }

      /* Cache full. We neet to evict one or more to map one.
         Get a random one which is not in use */

      do {

        // if the cache (MB) is not enough for the queue then this gets
        // undesirable because q_testcase_max_cache_count grows sometimes
        // although the number of items in the cache will not change hence
        // more and more loops
        tid = rand_below(afl, afl->q_testcase_max_cache_count);

      } while (afl->q_testcase_cache[tid] == NULL ||

               afl->q_testcase_cache[tid] == afl->queue_cur);

      struct queue_entry *old_cached = afl->q_testcase_cache[tid];
      free(old_cached->testcase_buf);
      old_cached->testcase_buf = NULL;
      afl->q_testcase_cache_size -= old_cached->len;
      afl->q_testcase_cache[tid] = NULL;
      --afl->q_testcase_cache_count;
      ++afl->q_testcase_evictions;
      if (tid < afl->q_testcase_smallest_free)
        afl->q_testcase_smallest_free = tid;

    }

    if (unlikely(tid >= afl->q_testcase_max_cache_entries)) {

      // uh we were full, so now we have to search from start
      tid = afl->q_testcase_smallest_free;

    }

    // we need this while loop in case there were ever previous evictions but
    // not in this call.
    while (unlikely(afl->q_testcase_cache[tid] != NULL))
      ++tid;

    /* Map the test case into memory. */

    int fd = open((char *)q->fname, O_RDONLY);

    if (unlikely(fd < 0)) { PFATAL("Unable to open '%s'", (char *)q->fname); }

    q->testcase_buf = (u8 *)malloc(len);

    if (unlikely(!q->testcase_buf)) {

      PFATAL("Unable to malloc '%s' with len %u", (char *)q->fname, len);

    }

    ck_read(fd, q->testcase_buf, len, q->fname);
    close(fd);

    /* Register testcase as cached */
    afl->q_testcase_cache[tid] = q;
    afl->q_testcase_cache_size += len;
    ++afl->q_testcase_cache_count;
    if (likely(tid >= afl->q_testcase_max_cache_count)) {

      afl->q_testcase_max_cache_count = tid + 1;

    } else if (unlikely(tid == afl->q_testcase_smallest_free)) {

      afl->q_testcase_smallest_free = tid + 1;

    }

  }

  return q->testcase_buf;

}

/* Adds the new queue entry to the cache. */

inline void queue_testcase_store_mem(afl_state_t *afl, struct queue_entry *q,
                                     u8 *mem) {

  u32 len = q->len;

  if (unlikely(afl->q_testcase_cache_size + len >=
                   afl->q_testcase_max_cache_size ||
               afl->q_testcase_cache_count >=
                   afl->q_testcase_max_cache_entries - 1)) {

    // no space? will be loaded regularly later.
    return;

  }

  u32 tid;

  if (unlikely(afl->q_testcase_max_cache_count >=
               afl->q_testcase_max_cache_entries)) {

    // uh we were full, so now we have to search from start
    tid = afl->q_testcase_smallest_free;

  } else {

    tid = afl->q_testcase_max_cache_count;

  }

  while (unlikely(afl->q_testcase_cache[tid] != NULL))
    ++tid;

  /* Map the test case into memory. */

  q->testcase_buf = (u8 *)malloc(len);

  if (unlikely(!q->testcase_buf)) {

    PFATAL("Unable to malloc '%s' with len %u", (char *)q->fname, len);

  }

  memcpy(q->testcase_buf, mem, len);

  /* Register testcase as cached */
  afl->q_testcase_cache[tid] = q;
  afl->q_testcase_cache_size += len;
  ++afl->q_testcase_cache_count;

  if (likely(tid >= afl->q_testcase_max_cache_count)) {

    afl->q_testcase_max_cache_count = tid + 1;

  } else if (unlikely(tid == afl->q_testcase_smallest_free)) {

    afl->q_testcase_smallest_free = tid + 1;

  }

}

