#define _GNU_SOURCE
#include "afl-fuzz.h"
#include "hash.h"

#include <unistd.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <time.h>
#include "alloc-inl.h"

#define SCHED_CMIN_INTERVAL_SEC 300 

// use to pass the environment variables to child process
extern char **environ;

static u8  g_cmin_inited  = 0;
static u8  g_cmin_running = 0;
static u64 g_cmin_last_ms = 0;

static inline u64 now_ms(void) {
  struct timeval tv;
  gettimeofday(&tv, NULL);
  return (u64)tv.tv_sec * 1000ULL + (u64)(tv.tv_usec / 1000);
}

static int is_casefile_name(const char *name) {
#ifndef SIMPLE_FILES
  const char *prefix = "id:";
#else
  const char *prefix = "id_";
#endif
  return strncmp(name, prefix, strlen(prefix)) == 0;
}

static int mkdirs(const char *p, mode_t m) {
  char buf[PATH_MAX]; snprintf(buf, sizeof(buf), "%s", p);
  for (char *q = buf + 1; *q; ++q) {
    if (*q == '/') { *q = 0; mkdir(buf, m); *q = '/'; }
  }
  return mkdir(buf, m) && errno == EEXIST ? 0 : 0;
}

static void extract_fixed_target_name(const char *argv0, char *out, size_t out_sz) {
  const char *prefix = "/workspace/target_final/";
  size_t plen = strlen(prefix);
  const char *p = argv0 ? argv0 : "";
  const char *q = NULL;

  if (!strncmp(p, prefix, plen)) {
    q = p + plen; 
  } else {
    q = p;
    if (*q == '/') q++;
  }

  size_t i = 0;
  while (q[i] && q[i] != '/' && i < out_sz - 1) {
    char c = q[i];
    if ((c >= 'A' && c <= 'Z') ||
        (c >= 'a' && c <= 'z') ||
        (c >= '0' && c <= '9') ||
        c == '_' || c == '-' || c == '.') {
      out[i] = c;
    } else {
      out[i] = '_';
    }
    i++;
  }
  out[i] = 0;

  if (i == 0) {
    strncpy(out, "target", out_sz - 1);
    out[out_sz - 1] = 0;
  }
}

static int read_entire_file(const char *p, u8 **out, u32 *len) {
  int fd = open(p, O_RDONLY);
  if (fd < 0) return -1;
  struct stat st;
  if (fstat(fd, &st) || st.st_size < 0) { close(fd); return -1; }
  u32 size = (u32)st.st_size;
  u8 *buf = ck_alloc(size ? size : 1);
  u32 off = 0;
  while (off < size) {
    ssize_t r = read(fd, buf + off, size - off);
    if (r <= 0) { ck_free(buf); close(fd); return -1; }
    off += (u32)r;
  }
  close(fd);
  *out = buf; *len = size;
  return 0;
}

static int copy_file_and_hash(const char *src_path, const char *dst_dir, u64 *out_hash) {
  const char *base = strrchr(src_path, '/'); base = base ? base + 1 : src_path;
  char dst_path[PATH_MAX]; snprintf(dst_path, sizeof(dst_path), "%s/%s", dst_dir, base);

  u8 *buf = NULL; u32 len = 0;
  if (read_entire_file(src_path, &buf, &len)) return -1;

  int fd = open(dst_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
  if (fd < 0) { ck_free(buf); return -1; }
  u32 off = 0;
  while (off < len) {
    ssize_t w = write(fd, buf + off, len - off);
    if (w <= 0) { close(fd); ck_free(buf); return -1; }
    off += (u32)w;
  }
  close(fd);

  *out_hash = hash64(buf, len, 0xa5b357ULL);
  ck_free(buf);
  return 0;
}

typedef struct cmin_snapshot {
  struct queue_entry **entries;
  u64 *hashes;              
  u32 count;
  u32 cap;
} cmin_snapshot_t;

static void snap_init(cmin_snapshot_t *s) {
  s->entries = NULL; s->hashes = NULL; s->count = 0; s->cap = 0;
}

static void snap_free(cmin_snapshot_t *s) {
  if (s->entries) ck_free(s->entries);
  if (s->hashes) ck_free(s->hashes);
  s->entries = NULL; s->hashes = NULL; s->count = s->cap = 0;
}

static void snap_push(cmin_snapshot_t *s, struct queue_entry *q, u64 h) {
  if (s->count == s->cap) {
    s->cap = s->cap ? (s->cap << 1) : 1024;
    s->entries = ck_realloc(s->entries, s->cap * sizeof(*s->entries));
    s->hashes  = ck_realloc(s->hashes,  s->cap * sizeof(*s->hashes));
  }
  s->entries[s->count] = q;
  s->hashes[s->count]  = h;
  s->count++;
}

static const char *k_fix_prefix = "/workspace/target_final/";

static char *replace_prefix_before_ellipsis(const char *in_path) {
  if (!in_path) return NULL;
  const char *p = strstr(in_path, "...");
  if (!p) return NULL;  

  const char *tail = p + 3;
  while (*tail == '/') ++tail; 

  size_t na = strlen(k_fix_prefix), nb = strlen(tail);
  int need_slash = (na > 0 && k_fix_prefix[na - 1] != '/' && nb > 0 && tail[0] != '/');
  size_t n = na + (need_slash ? 1 : 0) + nb + 1;

  char *out = (char *)malloc(n);
  if (!out) return NULL;
  memcpy(out, k_fix_prefix, na);
  size_t pos = na;
  if (need_slash) out[pos++] = '/';
  memcpy(out + pos, tail, nb);
  out[pos + nb] = '\0';
  return out;
}

static int snapshot_queue_copy(afl_state_t *afl, const char *tmp_in, cmin_snapshot_t *snap) {
  snap_init(snap);
  u32 cnt = 0;

  for (u32 i = 0; i < afl->queued_items; ++i) {
    struct queue_entry *q = afl->queue_buf[i];
    if (!q) continue;
    if (q->disabled) continue; 

    const char *fname = (const char *)q->fname;
    const char *base = strrchr(fname, '/'); base = base ? base + 1 : fname;
    if (!is_casefile_name(base)) continue;

    u64 h = 0;
    if (copy_file_and_hash(fname, tmp_in, &h) == 0) {
      snap_push(snap, q, h);
      ++cnt;
    }
  }

  return (int)cnt;
}

static int argv_has_atat(char **argv) {
  for (u32 i = 0; argv[i]; ++i) if (strstr(argv[i], "@@")) return 1;
  return 0;
}

static int spawn_afl_cmin_and_wait(afl_state_t *afl,
                                   const char *in_dir,
                                   const char *out_dir) {
  char mem_str[32], to_str[32];
  if (afl->fsrv.mem_limit == 0) snprintf(mem_str, sizeof(mem_str), "none");
  else snprintf(mem_str, sizeof(mem_str), "%u", (u32)afl->fsrv.mem_limit);
  snprintf(to_str, sizeof(to_str), "%u", afl->fsrv.exec_tmout);

  u32 targ_cnt = 0; while (afl->argv[targ_cnt]) ++targ_cnt;

  for (u32 i = 0; i < targ_cnt; ++i) SAYF("target_argv[%u] = <%s>\n", i, afl->argv[i]);

  bool has_atat = argv_has_atat(afl->argv);

  int idx_stdin_dash = -1;
  for (u32 i = 0; i < targ_cnt; ++i) {
    if (afl->argv[i] && strcmp(afl->argv[i], "-") == 0) { idx_stdin_dash = (int)i; break; }
  }

  int idx_fixed_path = -1;
  const char *fixed_path = NULL;
  const char *cfg_out_file = afl->fsrv.out_file;

  for (u32 i = 0; i < targ_cnt; ++i) {
    const char *arg = afl->argv[i];
    if (!arg) continue;
    if (strcmp(arg, "-") == 0) continue;
    if (strstr(arg, "@@")) continue; 
    if (cfg_out_file && strcmp(arg, cfg_out_file) == 0) {
      idx_fixed_path = (int)i;
      fixed_path = arg;
      break;
    }
    if (strstr(arg, ".cur_input") != NULL) {
      idx_fixed_path = (int)i;
      fixed_path = arg;
      if (cfg_out_file == NULL) break;
    }
  }

  enum { MODE_ATAT, MODE_FILE_FIXED, MODE_STDIN_EXISTING, MODE_STDIN_FORCED } mode;
  if (has_atat) mode = MODE_ATAT;
  else if (idx_fixed_path != -1) mode = MODE_FILE_FIXED;
  else if (idx_stdin_dash != -1) mode = MODE_STDIN_EXISTING;
  else mode = MODE_STDIN_FORCED;

  u32 cap = 64 + targ_cnt + 6;
  char **argv = ck_alloc(cap * sizeof(char *));
  u32 k = 0;

  argv[k++] = "afl-cmin";
  argv[k++] = "-i"; argv[k++] = (char *)in_dir;
  argv[k++] = "-o"; argv[k++] = (char *)out_dir;
  argv[k++] = "-m"; argv[k++] = mem_str;
  argv[k++] = "-t"; argv[k++] = to_str;

  if (afl->fsrv.frida_mode)      argv[k++] = "-O";
  else if (afl->fsrv.qemu_mode)  argv[k++] = "-Q";
  else if (afl->unicorn_mode)    argv[k++] = "-U";
#ifdef NYX_MODE
  else if (afl->fsrv.cs_mode)    argv[k++] = "-X";
#endif
#ifdef USE_WINE
  else if (afl->fsrv.use_wine)   argv[k++] = "-W";
#endif

  if (mode == MODE_FILE_FIXED) {
    if (!fixed_path) FATAL("MODE_FILE_FIXED without fixed_path");
    argv[k++] = "-f";
    argv[k++] = (char *)fixed_path;
    SAYF("[sched-cmin] using -f '%s' (file-arg mode)\n", fixed_path);
  }

  argv[k++] = "--";

  for (u32 i = 0; i < targ_cnt; ++i) {
    const char *src = afl->argv[i];
    if (!src) continue;

    if ((mode == MODE_ATAT || mode == MODE_FILE_FIXED) && strcmp(src, "-") == 0) {
      SAYF("[sched-cmin] removed '-' from target argv to avoid mixing with file mode\n");
      continue;
    }

    char *fixed = replace_prefix_before_ellipsis(src);
    if (fixed) {
      SAYF("[sched-cmin] replaced '...' path: '%s' -> '%s'\n", src, fixed);
    }
    argv[k++] = fixed ? fixed : src;
  }

  if (mode == MODE_STDIN_FORCED) {
    argv[k++] = "-";
    SAYF("[sched-cmin] appended '-' for stdin mode\n");
  }

  argv[k++] = NULL;

  char mapsz[32]; snprintf(mapsz, sizeof(mapsz), "%u", afl->fsrv.map_size);
  setenv("AFL_NO_UI", "1", 1);
  setenv("AFL_MAP_SIZE", mapsz, 1);

  if (getenv("ASAN_OPTIONS") == NULL)
    setenv("ASAN_OPTIONS", "abort_on_error=1:detect_leaks=0:symbolize=0", 0);
  if (getenv("UBSAN_OPTIONS") == NULL)
    setenv("UBSAN_OPTIONS", "print_stacktrace=1", 0);

  SAYF("[sched-cmin] AFL_MAP_SIZE=%s\n", mapsz);
  SAYF("[sched-cmin] exec argv:\n");
  for (u32 i = 0; argv[i]; ++i) SAYF("  argv[%u] = %s\n", i, argv[i]);

  pid_t pid = fork();
  if (pid < 0) PFATAL("fork() for afl-cmin");
  if (pid == 0) {

    execve("/workspace/AFLplusplus_new_cmin_5_mins/afl-cmin", argv, environ);

    fprintf(stderr, "execve(afl-cmin) failed: %s\n", strerror(errno));
    _exit(127);
  }

  int st = 0;
  if (waitpid(pid, &st, 0) < 0) PFATAL("waitpid afl-cmin");

  ck_free(argv);

  if (!WIFEXITED(st) || WEXITSTATUS(st) != 0) {
    WARNF("afl-cmin exited abnormally (status=%d)", st);
    return -1;
  }
  return 0;
}





static int cmpu64(const void *a, const void *b) {
  u64 x = *(const u64 *)a, y = *(const u64 *)b;
  return x < y ? -1 : (x > y ? 1 : 0);
}

static int collect_keep_hashes(const char *out_dir, u64 **out_arr, u32 *out_n) {
  DIR *d = opendir(out_dir);
  if (!d) return -1;
  u32 cap = 1024, n = 0;
  u64 *arr = ck_alloc(cap * sizeof(u64));
  struct dirent *de;
  while ((de = readdir(d))) {
    if (de->d_name[0] == '.') continue;
    if (!is_casefile_name(de->d_name)) continue;
    char p[PATH_MAX]; snprintf(p, sizeof(p), "%s/%s", out_dir, de->d_name);
    u8 *buf = NULL; u32 len = 0;
    if (read_entire_file(p, &buf, &len)) continue;
    u64 h = hash64(buf, len, 0xa5b357ULL);
    ck_free(buf);
    if (!h) continue;
    if (n == cap) { cap <<= 1; arr = ck_realloc(arr, cap * sizeof(u64)); }
    arr[n++] = h;
  }
  closedir(d);
  qsort(arr, n, sizeof(u64), cmpu64);
  u32 m = 0;
  for (u32 i = 0; i < n; ++i) {
    if (i == 0 || arr[i] != arr[i - 1]) arr[m++] = arr[i];
  }
  *out_arr = arr; *out_n = m;
  return 0;
}

static inline int keep_index(const u64 *arr, u32 n, u64 key) {
  u32 lo = 0, hi = n;
  while (lo < hi) {
    u32 mid = lo + ((hi - lo) >> 1);
    if (arr[mid] < key) lo = mid + 1;
    else hi = mid;
  }
  if (lo < n && arr[lo] == key) return (int)lo;
  return -1;
}

static void apply_filter_to_snapshot(afl_state_t *afl,
                                     const cmin_snapshot_t *snap,
                                     const u64 *keep, u32 keep_n) {
  if (snap->count == 0) return;


  u8 *keep_used = NULL;
  if (keep_n) {
    keep_used = ck_alloc(keep_n);
    memset(keep_used, 0, keep_n);
  }

  u32 dis_idx_cap = snap->count ? snap->count : 1;
  u32 dis_idx_cnt = 0;
  u32 *dis_idx = ck_alloc(dis_idx_cap * sizeof(u32));

  u32 kept = 0, disabled = 0;
  for (u32 i = 0; i < snap->count; ++i) {
    struct queue_entry *q = snap->entries[i];
    u64 h = snap->hashes[i];

    int idx = keep_index(keep, keep_n, h);
    if (idx >= 0 && keep_used && keep_used[idx] == 0) {
      keep_used[idx] = 1;
      q->disabled = 0;
      ++kept;
    } else {
      q->disabled = 1;
      if (dis_idx_cnt == dis_idx_cap) {
        dis_idx_cap <<= 1;
        dis_idx = ck_realloc(dis_idx, dis_idx_cap * sizeof(u32));
      }
      dis_idx[dis_idx_cnt++] = i;
      ++disabled;
    }
  }

  cull_queue(afl);
  afl->reinit_table = 1;

  u32 pnf = 0, pf = 0;
  for (u32 i = 0; i < afl->queued_items; ++i) {
    struct queue_entry *qq = afl->queue_buf[i];
    if (!qq) continue;
    if (qq->disabled) continue;
    if (!qq->was_fuzzed) ++pnf;
    if (qq->favored && !qq->was_fuzzed) ++pf;
  }
  afl->pending_not_fuzzed = pnf;
  afl->pending_favored    = pf;

  const u32 kMaxShow = 200;
  SAYF("[sched-cmin] kept=%u disabled=%u (applied to current active set)\n", kept, disabled);

  fprintf(afl->fsrv.plot_file, "Total corpus size : [%u]  |  Corpus size after cmin :  [%u]\n",  afl->queued_items, kept);
  fflush(afl->fsrv.plot_file);


  if (keep_used) ck_free(keep_used);
  if (dis_idx) ck_free(dis_idx);
}


static void run_cmin_once_blocking(afl_state_t *afl) {
  char tname[64] = {0};
  extract_fixed_target_name(afl->argv[0], tname, sizeof(tname));
  pid_t pid = getpid();

  char tmp_in[PATH_MAX];
  char tmp_out[PATH_MAX];
  snprintf(tmp_in,  sizeof(tmp_in),  "/tmp/afl-cmin_5_mins.%s.%d.in.XXXXXX",  tname, (int)pid);
  snprintf(tmp_out, sizeof(tmp_out), "/tmp/afl-cmin_5_mins.%s.%d.out.XXXXXX", tname, (int)pid);

  if (!mkdtemp(tmp_in) || !mkdtemp(tmp_out)) {
    WARNF("[sched-cmin] mkdtemp failed: in='%s' out='%s'", tmp_in, tmp_out);
    return;
  }

  cmin_snapshot_t snap;
  int snap_cnt = snapshot_queue_copy(afl, tmp_in, &snap);
  if (snap_cnt <= 0) {
    SAYF("[sched-cmin] nothing to snapshot (active=%d)\n", snap_cnt);
    goto cleanup_free;
  }

  SAYF("[sched-cmin] running afl-cmin on %d seeds (target=%s pid=%d)\n",
       snap_cnt, tname, (int)pid);

  if (spawn_afl_cmin_and_wait(afl, tmp_in, tmp_out) == 0) {
    u64 *keep = NULL; u32 keep_n = 0;
    if (collect_keep_hashes(tmp_out, &keep, &keep_n) == 0) {
      apply_filter_to_snapshot(afl, &snap, keep, keep_n);
      ck_free(keep);
    } else {
      WARNF("[sched-cmin] failed to collect keep set; skip applying filter");
    }
  } else {
    WARNF("[sched-cmin] afl-cmin failed; skip applying filter");
  }

cleanup_free:
  snap_free(&snap);
  char cmd[PATH_MAX * 2];
  snprintf(cmd, sizeof(cmd), "rm -rf '%s' '%s'", tmp_in, tmp_out);
  system(cmd);
}

void sched_cmin_maybe_run(afl_state_t *afl) {
  if (!g_cmin_inited) {
    g_cmin_inited  = 1;
    g_cmin_last_ms = now_ms();
    return;
  }
  if (g_cmin_running) return;

  u64 now = now_ms();
  if (now - g_cmin_last_ms < (u64)SCHED_CMIN_INTERVAL_SEC * 1000ULL) return;

  g_cmin_running = 1;
  SAYF("[sched-cmin] interval reached (%u s). Pausing fuzzing.\n", (unsigned)SCHED_CMIN_INTERVAL_SEC);
  run_cmin_once_blocking(afl);
  g_cmin_last_ms = now_ms();
  g_cmin_running = 0;
  SAYF("[sched-cmin] resume fuzzing.\n");
}