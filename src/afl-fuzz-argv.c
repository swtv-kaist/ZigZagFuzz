#include <float.h>
#include <limits.h>
#include <string.h>

#include "afl-fuzz.h"
#include "cmplog.h"

static inline u32 choose_block_len_small(afl_state_t *afl, u32 limit);
static void       write_shrink_log_after(afl_state_t *afl);

void init_argv_buf(afl_state_t *afl) {
  afl->num_argvs = 0;
  afl->argv_buf_size = 512;
  afl->argv_buf = (u8 **)malloc(afl->argv_buf_size * sizeof(u8 *));
  afl->argv_len_buf = (u32 *)malloc(afl->argv_buf_size * sizeof(u32));

  afl->argv_to_queue = (u32 **)calloc(afl->argv_buf_size, sizeof(u32 *));
  afl->argv_to_queue_cnt = (u32 *)calloc(afl->argv_buf_size, sizeof(u32));
  afl->argv_to_queue_size = (u32 *)calloc(afl->argv_buf_size, sizeof(u32));
  afl->argv_num_mut = (u64 *)calloc(afl->argv_buf_size, sizeof(u64));
  afl->argv_num_finds = (u32 *)calloc(afl->argv_buf_size, sizeof(u32));
  afl->argv_num_file_mut = (u64 *)calloc(afl->argv_buf_size, sizeof(u64));
  afl->argv_num_file_finds = (u32 *)calloc(afl->argv_buf_size, sizeof(u32));

  afl->file_to_queue_size_size = 512;
  afl->file_to_queue =
      (u32 **)calloc(afl->file_to_queue_size_size, sizeof(u32 *));
  afl->file_to_queue_cnt =
      (u32 *)calloc(afl->file_to_queue_size_size, sizeof(u32));
  afl->file_to_queue_size =
      (u32 *)calloc(afl->file_to_queue_size_size, sizeof(u32));
  afl->num_unique_files = 0;
  afl->file_num_mut = (u64 *)calloc(afl->file_to_queue_size_size, sizeof(u64));
  afl->file_num_finds =
      (u32 *)calloc(afl->file_to_queue_size_size, sizeof(u32));
  afl->file_num_argv_mut =
      (u64 *)calloc(afl->file_to_queue_size_size, sizeof(u64));
  afl->file_num_argv_finds =
      (u32 *)calloc(afl->file_to_queue_size_size, sizeof(u32));

  u8 file_fn[PATH_MAX];
  snprintf(file_fn, PATH_MAX, "%s/shrink_log", afl->out_dir);
  afl->shrink_log_f = fopen(file_fn, "w");
  if (!afl->shrink_log_f) { PFATAL("Unable to create '%s'", file_fn); }
  return;
}

void free_argv_bufs(afl_state_t *afl) {
  u32 idx1;
  for (idx1 = 0; idx1 < afl->num_argvs; idx1++) {
    free(afl->argv_buf[idx1]);
    free(afl->argv_to_queue[idx1]);
  }
  free(afl->argv_buf);
  free(afl->argv_to_queue);
  free(afl->argv_len_buf);
  free(afl->argv_to_queue_cnt);
  free(afl->argv_to_queue_size);
  free(afl->argv_num_mut);
  free(afl->argv_num_finds);
  free(afl->argv_num_file_mut);
  free(afl->argv_num_file_finds);

  for (idx1 = 0; idx1 < afl->num_unique_files; idx1++) {
    free(afl->file_to_queue[idx1]);
  }
  free(afl->file_to_queue);
  free(afl->file_to_queue_cnt);
  free(afl->file_to_queue_size);
  free(afl->file_num_finds);
  free(afl->file_num_mut);
  free(afl->file_num_argv_mut);
  free(afl->file_num_argv_finds);
  return;
}

void read_argv_keywords(afl_state_t *afl) {
  if (afl->keyword_fn == NULL) { PFATAL("No keyword file specified (-a)"); }

  FILE *f = fopen(afl->keyword_fn, "r");
  if (!f) { PFATAL("Unable to open '%s'", afl->keyword_fn); }

  u32 dict_size = 128;
  afl->argv_dict = malloc(dict_size * sizeof(u8 *));
  u32 num_dict_keywords = 0;

  u8 buffer[MAX_KEYWORD_LEN];
  while (fgets(buffer, MAX_KEYWORD_LEN, f)) {
    // remove '\n'
    buffer[strlen(buffer) - 1] = 0;
    afl->argv_dict[num_dict_keywords++] = strdup(buffer);

    if (num_dict_keywords == dict_size) {
      dict_size *= 2;
      afl->argv_dict = realloc(afl->argv_dict, dict_size * sizeof(u8 *));
    }
  }

  fclose(f);
  afl->argv_dict_cnt = num_dict_keywords;

  afl->extras =
      afl_realloc((void **)&afl->extras, (afl->extras_cnt + num_dict_keywords) *
                                             sizeof(struct extra_data));
  if (unlikely(!afl->extras)) { PFATAL("alloc"); }

  u32 idx1;
  for (idx1 = 0; idx1 < num_dict_keywords; idx1++) {
    u8 *keyword = afl->argv_dict[idx1];
    afl->extras[afl->extras_cnt].data = strdup(keyword);
    afl->extras[afl->extras_cnt].len = strlen(keyword);
    afl->extras[afl->extras_cnt].hit_cnt = 0;
    afl->extras_cnt++;
  }
}

u32 get_argv_id(afl_state_t *afl, struct queue_entry *q) {
  u32 idx1;

  u32 num_argvs = afl->num_argvs;

  u8 *new_argv = q->argv;
  u32 new_argv_len = q->argv_len;

  for (idx1 = 0; idx1 < num_argvs; idx1++) {
    u8 *argv1 = afl->argv_buf[idx1];
    u32 argv1_len = afl->argv_len_buf[idx1];

    if (argv1_len != new_argv_len) { continue; }
    if (memcmp(argv1, new_argv, new_argv_len) != 0) { continue; }
    break;
  }

  if (idx1 != num_argvs) {
    // existing argv
    if (unlikely(afl->argv_to_queue_cnt[idx1] ==
                 afl->argv_to_queue_size[idx1])) {
      afl->argv_to_queue_size[idx1] *= 2;
      afl->argv_to_queue[idx1] =
          (u32 *)realloc(afl->argv_to_queue[idx1],
                         afl->argv_to_queue_size[idx1] * sizeof(u32));
    }

    afl->argv_to_queue[idx1][afl->argv_to_queue_cnt[idx1]] = afl->queued_items;
    afl->argv_to_queue_cnt[idx1]++;

    return idx1;
  }

  // new argv

  if (unlikely(num_argvs == afl->argv_buf_size)) {
    afl->argv_buf_size *= 2;
    afl->argv_buf =
        (u8 **)realloc(afl->argv_buf, afl->argv_buf_size * sizeof(u8 *));
    afl->argv_len_buf =
        (u32 *)realloc(afl->argv_len_buf, afl->argv_buf_size * sizeof(u32));

    afl->argv_to_queue =
        (u32 **)realloc(afl->argv_to_queue, afl->argv_buf_size * sizeof(u32 *));
    afl->argv_to_queue_cnt = (u32 *)realloc(afl->argv_to_queue_cnt,
                                            afl->argv_buf_size * sizeof(u32));
    afl->argv_to_queue_size = (u32 *)realloc(afl->argv_to_queue_size,
                                             afl->argv_buf_size * sizeof(u32));

    afl->argv_num_mut =
        (u64 *)realloc(afl->argv_num_mut, afl->argv_buf_size * sizeof(u64));
    afl->argv_num_finds =
        (u32 *)realloc(afl->argv_num_finds, afl->argv_buf_size * sizeof(u32));
    afl->argv_num_file_mut = (u64 *)realloc(afl->argv_num_file_mut,
                                            afl->argv_buf_size * sizeof(u64));
    afl->argv_num_file_finds = (u32 *)realloc(afl->argv_num_file_finds,
                                              afl->argv_buf_size * sizeof(u32));
  }

  afl->argv_buf[num_argvs] = (u8 *)malloc(new_argv_len);
  afl->argv_len_buf[num_argvs] = new_argv_len;
  memcpy(afl->argv_buf[num_argvs], new_argv, new_argv_len);

  afl->num_argvs++;

  afl->argv_to_queue_size[num_argvs] = 16;
  afl->argv_to_queue[num_argvs] =
      (u32 *)malloc(afl->argv_to_queue_size[num_argvs] * sizeof(u32));
  afl->argv_to_queue[num_argvs][0] = afl->queued_items;
  afl->argv_to_queue_cnt[num_argvs] = 1;
  afl->argv_num_mut[num_argvs] = 0;
  afl->argv_num_finds[num_argvs] = 0;
  afl->argv_num_file_mut[num_argvs] = 0;
  afl->argv_num_file_finds[num_argvs] = 0;
  return num_argvs;
}

u32 get_file_id(afl_state_t *afl) {
  u32 file_id;
  if (afl->mut_file_only) {
    file_id = afl->num_unique_files++;
    if (unlikely(afl->file_to_queue_size_size == file_id)) {
      afl->file_to_queue_size_size *= 2;
      afl->file_to_queue = (u32 **)realloc(
          afl->file_to_queue, sizeof(u32 *) * afl->file_to_queue_size_size);
      afl->file_to_queue_cnt = (u32 *)realloc(
          afl->file_to_queue_cnt, sizeof(u32) * afl->file_to_queue_size_size);
      afl->file_to_queue_size = (u32 *)realloc(
          afl->file_to_queue_size, sizeof(u32) * afl->file_to_queue_size_size);
      afl->file_num_mut = (u64 *)realloc(
          afl->file_num_mut, afl->file_to_queue_size_size * sizeof(u64));
      afl->file_num_finds = (u32 *)realloc(
          afl->file_num_finds, sizeof(u32) * afl->file_to_queue_size_size);
      afl->file_num_argv_mut = (u64 *)realloc(
          afl->file_num_argv_mut, afl->file_to_queue_size_size * sizeof(u64));
      afl->file_num_argv_finds = (u32 *)realloc(
          afl->file_num_argv_finds, sizeof(u32) * afl->file_to_queue_size_size);
    }

    afl->file_to_queue[file_id] = (u32 *)malloc(sizeof(u32) * 8);
    afl->file_to_queue[file_id][0] = afl->queued_items;
    afl->file_to_queue_cnt[file_id] = 1;
    afl->file_to_queue_size[file_id] = 8;
    afl->file_num_mut[file_id] = 0;
    afl->file_num_finds[file_id] = 0;
    afl->file_num_argv_mut[file_id] = 0;
    afl->file_num_argv_finds[file_id] = 0;
  } else {
    file_id = afl->queue_buf[afl->current_entry]->file_id;
    if (unlikely(afl->file_to_queue_cnt[file_id] ==
                 afl->file_to_queue_size[file_id])) {
      afl->file_to_queue_size[file_id] *= 2;
      afl->file_to_queue[file_id] =
          (u32 *)realloc(afl->file_to_queue[file_id],
                         sizeof(u32) * afl->file_to_queue_size[file_id]);
    }
    afl->file_to_queue[file_id][afl->file_to_queue_cnt[file_id]++] =
        afl->queued_items;
  }

  return file_id;
}

void write_shrink_log(afl_state_t *afl) {
  static u32          shrink_log_index = 0;
  u32                 idx1, num_queue, num_active, queue_idx;
  struct queue_entry *q;

  fprintf(afl->shrink_log_f, "Shrink #%u\n", shrink_log_index++);

  for (idx1 = 0; idx1 < afl->num_argvs; idx1++) {
    num_queue = afl->argv_to_queue_cnt[idx1];

    num_active = 0;
    for (queue_idx = 0; queue_idx < num_queue; queue_idx++) {
      q = afl->queue_buf[afl->argv_to_queue[idx1][queue_idx]];
      num_active += !q->disabled;
    }

    fprintf(afl->shrink_log_f, "SHRINK res1: Argv #%u : %u/%u active\n", idx1,
            num_active, num_queue);
  }

  for (idx1 = 0; idx1 < afl->num_unique_files; idx1++) {
    num_queue = afl->file_to_queue_cnt[idx1];

    num_active = 0;
    for (queue_idx = 0; queue_idx < num_queue; queue_idx++) {
      q = afl->queue_buf[afl->file_to_queue[idx1][queue_idx]];
      num_active += !q->disabled;
    }

    fprintf(afl->shrink_log_f, "SHRINK res2: File #%u : %u/%u active\n", idx1,
            num_active, num_queue);
  }

  fprintf(afl->shrink_log_f, "finish1\n");
  fflush(afl->shrink_log_f);
}

void update_all_bitmap_score(afl_state_t *afl) {
  u32                 idx1;
  struct queue_entry *q;
  u8                 *in_buf;

  for (idx1 = 0; idx1 < afl->queued_items; idx1++) {
    q = afl->queue_buf[idx1];
    if (q->disabled) { continue; }

    in_buf = queue_testcase_get(afl, q);
    write_argv_file(afl, q->argv, q->argv_len);
    (void)write_to_testcase(afl, (void **)&in_buf, q->len, 1);
    (void)fuzz_run_target(afl, &afl->fsrv, afl->fsrv.exec_tmout);

    update_bitmap_score(afl, q);
  }
}

u8 fuzz_one_argv(afl_state_t *afl) {
  u32 len, temp_len, file_len;
  u32 i;
  u8 *in_buf, *out_buf, *orig_in, *file_buf;
  u64 havoc_queued = 0, orig_hit_cnt, new_hit_cnt = 0;
  u32 splice_cycle = 0, perf_score = 100, orig_perf;

  u8 ret_val = 1, doing_det = 0;

  if (unlikely(afl->not_on_tty)) {
    ACTF(
        "Fuzzing test case #%u argv (%u total, %llu crashes saved, "
        "perf_score=%0.0f, exec_us=%llu, hits=%u, map=%u, ascii=%u)...",
        afl->current_entry, afl->queued_items, afl->saved_crashes,
        afl->queue_cur->perf_score, afl->queue_cur->exec_us,
        likely(afl->n_fuzz) ? afl->n_fuzz[afl->queue_cur->n_fuzz_entry] : 0,
        afl->queue_cur->bitmap_size, afl->queue_cur->is_ascii);
    fflush(stdout);
  }

  file_buf = queue_testcase_get(afl, afl->queue_cur);
  file_len = afl->queue_cur->len;

  orig_in = in_buf = afl->queue_cur->argv;
  len = afl->queue_cur->argv_len;

  out_buf = afl_realloc(AFL_BUF_PARAM(out), len);
  if (unlikely(!out_buf)) { PFATAL("alloc"); }

  afl->subseq_tmouts = 0;

  afl->cur_depth = afl->queue_cur->depth;

  /*******************************************
   * CALIBRATION (only if failed earlier on) *
   *******************************************/

  if (unlikely(afl->queue_cur->cal_failed)) {
    u8 res = FSRV_RUN_TMOUT;

    if (afl->queue_cur->cal_failed < CAL_CHANCES) {
      afl->queue_cur->exec_cksum = 0;

      res = calibrate_case(afl, afl->queue_cur, file_buf, afl->queue_cycle - 1,
                           0);

      if (unlikely(res == FSRV_RUN_ERROR)) {
        FATAL("Unable to execute target application");
      }
    }

    if (unlikely(afl->stop_soon) || res != afl->crash_mode) {
      ++afl->cur_skipped_items;
      goto abandon_entry;
    }
  }

  memcpy(out_buf, in_buf, len);

  /*********************
   * PERFORMANCE SCORE *
   *********************/

  if (likely(!afl->old_seed_selection))
    orig_perf = perf_score = afl->queue_cur->perf_score;
  else
    afl->queue_cur->perf_score = orig_perf = perf_score =
        calculate_score(afl, afl->queue_cur);

  if (unlikely(perf_score <= 0 && afl->active_items > 1)) {
    goto abandon_entry;
  }

  if (unlikely(afl->shm.cmplog_mode &&
               afl->queue_cur->colorized < afl->cmplog_lvl &&
               (u32)len <= afl->cmplog_max_filesize)) {
    if (unlikely(len < 4)) {
      afl->queue_cur->colorized = CMPLOG_LVL_MAX;

    } else {
      if (afl->cmplog_lvl == 3 ||
          (afl->cmplog_lvl == 2 && afl->queue_cur->tc_ref) ||
          afl->queue_cur->favored ||
          !(afl->fsrv.total_execs % afl->queued_items) ||
          get_cur_time() - afl->last_find_time > 300000) {  // 300 seconds

        if (input_to_state_stage(afl, in_buf, out_buf, len)) {
          goto abandon_entry;
        }
      }
    }
  }

  afl->stage_cur_byte = -1;

havoc_stage:

  /* The havoc stage mutation code is also invoked when splicing files; if the
     splice_cycle variable is set, generate different descriptions and such. */

  if (!splice_cycle) {
    afl->stage_name = "havoc_argv";
    afl->stage_short = "havoc_argv";
    afl->stage_max = (doing_det ? HAVOC_CYCLES_INIT : HAVOC_CYCLES) *
                     perf_score / afl->havoc_div / 100;

  } else {
    perf_score = orig_perf;

    snprintf(afl->stage_name_buf, STAGE_BUF_SIZE, "splice %u", splice_cycle);
    afl->stage_name = afl->stage_name_buf;
    afl->stage_short = "splice_argv";
    afl->stage_max = SPLICE_HAVOC * perf_score / afl->havoc_div / 100;
  }

  if (afl->stage_max < HAVOC_MIN) { afl->stage_max = HAVOC_MIN; }

  temp_len = len;

  orig_hit_cnt = afl->queued_items + afl->saved_crashes;

  havoc_queued = afl->queued_items;

  /* We essentially just do several thousand runs (depending on perf_score)
     where we take the input file and make random stacked tweaks. */

#define MAX_HAVOC_ENTRY 64
#define MUTATE_ASCII_DICT 64

  u32 r_max, r;

  r_max = (MAX_HAVOC_ENTRY + 1) + (afl->extras_cnt ? 4 : 0) +
          (afl->a_extras_cnt
               ? (unlikely(afl->cmplog_binary && afl->queue_cur->is_ascii)
                      ? MUTATE_ASCII_DICT
                      : 4)
               : 0);

  if (unlikely(afl->expand_havoc && afl->ready_for_splicing_count > 1)) {
    /* add expensive havoc cases here, they are activated after a full
       cycle without finds happened */

    r_max += 4;
  }

  if (unlikely(get_cur_time() - afl->last_find_time > 5000 /* 5 seconds */ &&
               afl->ready_for_splicing_count > 1)) {
    /* add expensive havoc cases here if there is no findings in the last 5s */

    r_max += 4;
  }

#define FLIP_BIT(_ar, _b)                     \
  do {                                        \
    u8 *_arf = (u8 *)(_ar);                   \
    u32 _bf = (_b);                           \
    _arf[(_bf) >> 3] ^= (128 >> ((_bf) & 7)); \
                                              \
  } while (0)

  for (afl->stage_cur = 0; afl->stage_cur < afl->stage_max; ++afl->stage_cur) {
    u32 use_stacking = 1 << (1 + rand_below(afl, afl->havoc_stack_pow2));

    afl->stage_cur_val = use_stacking;

    for (i = 0; i < use_stacking; ++i) {
      switch ((r = rand_below(afl, r_max))) {
        case 0 ... 3: {
          /* Flip a single bit somewhere. Spooky! */
          FLIP_BIT(out_buf, rand_below(afl, temp_len << 3));
          break;
        }

        case 4 ... 7: {
          /* Set byte to interesting value. */
          out_buf[rand_below(afl, temp_len)] =
              interesting_8[rand_below(afl, sizeof(interesting_8))];
          break;
        }

        case 8 ... 9: {
          /* Set word to interesting value, little endian. */

          if (temp_len < 2) { break; }

          *(u16 *)(out_buf + rand_below(afl, temp_len - 1)) =
              interesting_16[rand_below(afl, sizeof(interesting_16) >> 1)];

          break;
        }

        case 10 ... 11: {
          /* Set word to interesting value, big endian. */

          if (temp_len < 2) { break; }

          *(u16 *)(out_buf + rand_below(afl, temp_len - 1)) = SWAP16(
              interesting_16[rand_below(afl, sizeof(interesting_16) >> 1)]);

          break;
        }

        case 12 ... 13: {
          /* Set dword to interesting value, little endian. */

          if (temp_len < 4) { break; }

          *(u32 *)(out_buf + rand_below(afl, temp_len - 3)) =
              interesting_32[rand_below(afl, sizeof(interesting_32) >> 2)];

          break;
        }

        case 14 ... 15: {
          /* Set dword to interesting value, big endian. */

          if (temp_len < 4) { break; }

          *(u32 *)(out_buf + rand_below(afl, temp_len - 3)) = SWAP32(
              interesting_32[rand_below(afl, sizeof(interesting_32) >> 2)]);

          break;
        }

        case 16 ... 19: {
          /* Randomly subtract from byte. */

          out_buf[rand_below(afl, temp_len)] -= 1 + rand_below(afl, ARITH_MAX);
          break;
        }

        case 20 ... 23: {
          /* Randomly add to byte. */

          out_buf[rand_below(afl, temp_len)] += 1 + rand_below(afl, ARITH_MAX);
          break;
        }

        case 24 ... 25: {
          /* Randomly subtract from word, little endian. */

          if (temp_len < 2) { break; }

          u32 pos = rand_below(afl, temp_len - 1);

          *(u16 *)(out_buf + pos) -= 1 + rand_below(afl, ARITH_MAX);
          break;
        }

        case 26 ... 27: {
          /* Randomly subtract from word, big endian. */

          if (temp_len < 2) { break; }

          u32 pos = rand_below(afl, temp_len - 1);
          u16 num = 1 + rand_below(afl, ARITH_MAX);

          *(u16 *)(out_buf + pos) =
              SWAP16(SWAP16(*(u16 *)(out_buf + pos)) - num);

          break;
        }

        case 28 ... 29: {
          /* Randomly add to word, little endian. */

          if (temp_len < 2) { break; }

          u32 pos = rand_below(afl, temp_len - 1);

          *(u16 *)(out_buf + pos) += 1 + rand_below(afl, ARITH_MAX);

          break;
        }

        case 30 ... 31: {
          /* Randomly add to word, big endian. */

          if (temp_len < 2) { break; }

          u32 pos = rand_below(afl, temp_len - 1);
          u16 num = 1 + rand_below(afl, ARITH_MAX);

          *(u16 *)(out_buf + pos) =
              SWAP16(SWAP16(*(u16 *)(out_buf + pos)) + num);

          break;
        }

        case 32 ... 33: {
          /* Randomly subtract from dword, little endian. */

          if (temp_len < 4) { break; }

          u32 pos = rand_below(afl, temp_len - 3);
          *(u32 *)(out_buf + pos) -= 1 + rand_below(afl, ARITH_MAX);

          break;
        }

        case 34 ... 35: {
          /* Randomly subtract from dword, big endian. */

          if (temp_len < 4) { break; }

          u32 pos = rand_below(afl, temp_len - 3);
          u32 num = 1 + rand_below(afl, ARITH_MAX);

          *(u32 *)(out_buf + pos) =
              SWAP32(SWAP32(*(u32 *)(out_buf + pos)) - num);

          break;
        }

        case 36 ... 37: {
          /* Randomly add to dword, little endian. */

          if (temp_len < 4) { break; }

          u32 pos = rand_below(afl, temp_len - 3);

          *(u32 *)(out_buf + pos) += 1 + rand_below(afl, ARITH_MAX);

          break;
        }

        case 38 ... 39: {
          /* Randomly add to dword, big endian. */

          if (temp_len < 4) { break; }

          u32 pos = rand_below(afl, temp_len - 3);
          u32 num = 1 + rand_below(afl, ARITH_MAX);

          *(u32 *)(out_buf + pos) =
              SWAP32(SWAP32(*(u32 *)(out_buf + pos)) + num);

          break;
        }

        case 40 ... 43: {
          /* Just set a random byte to a random value. Because,
             why not. We use XOR with 1-255 to eliminate the
             possibility of a no-op. */

          out_buf[rand_below(afl, temp_len)] ^= 1 + rand_below(afl, 255);
          break;
        }

        case 44 ... 46: {
          if (temp_len + HAVOC_ARGV_BLK_XL < ARGV_MAX_SIZE) {
            /* Clone bytes. */

            u32 clone_len = choose_block_len_small(afl, temp_len);
            u32 clone_from = rand_below(afl, temp_len - clone_len + 1);
            u32 clone_to = rand_below(afl, temp_len);

            u8 *new_buf =
                afl_realloc(AFL_BUF_PARAM(out_scratch), temp_len + clone_len);
            if (unlikely(!new_buf)) { PFATAL("alloc"); }

            /* Head */

            memcpy(new_buf, out_buf, clone_to);

            /* Inserted part */

            memcpy(new_buf + clone_to, out_buf + clone_from, clone_len);

            /* Tail */
            memcpy(new_buf + clone_to + clone_len, out_buf + clone_to,
                   temp_len - clone_to);

            out_buf = new_buf;
            afl_swap_bufs(AFL_BUF_PARAM(out), AFL_BUF_PARAM(out_scratch));
            temp_len += clone_len;
          }

          break;
        }

        case 47: {
          if (temp_len + HAVOC_ARGV_BLK_XL < ARGV_MAX_SIZE) {
            /* Insert a block of constant bytes (25%). */

            u32 clone_len = choose_block_len_small(afl, HAVOC_ARGV_BLK_XL);
            u32 clone_to = rand_below(afl, temp_len);

            u8 *new_buf =
                afl_realloc(AFL_BUF_PARAM(out_scratch), temp_len + clone_len);
            if (unlikely(!new_buf)) { PFATAL("alloc"); }

            /* Head */

            memcpy(new_buf, out_buf, clone_to);

            /* Inserted part */

            memset(new_buf + clone_to,
                   rand_below(afl, 2) ? rand_below(afl, 256)
                                      : out_buf[rand_below(afl, temp_len)],
                   clone_len);

            /* Tail */
            memcpy(new_buf + clone_to + clone_len, out_buf + clone_to,
                   temp_len - clone_to);

            out_buf = new_buf;
            afl_swap_bufs(AFL_BUF_PARAM(out), AFL_BUF_PARAM(out_scratch));
            temp_len += clone_len;
          }

          break;
        }

        case 48 ... 50: {
          /* Overwrite bytes with a randomly selected chunk bytes. */

          if (temp_len < 2) { break; }

          u32 copy_len = choose_block_len_small(afl, temp_len - 1);
          u32 copy_from = rand_below(afl, temp_len - copy_len + 1);
          u32 copy_to = rand_below(afl, temp_len - copy_len + 1);

          if (likely(copy_from != copy_to)) {
            memmove(out_buf + copy_to, out_buf + copy_from, copy_len);
          }

          break;
        }

        case 51: {
          /* Overwrite bytes with fixed bytes. */

          if (temp_len < 2) { break; }

          u32 copy_len = choose_block_len_small(afl, temp_len - 1);
          u32 copy_to = rand_below(afl, temp_len - copy_len + 1);

          memset(out_buf + copy_to,
                 rand_below(afl, 2) ? rand_below(afl, 256)
                                    : out_buf[rand_below(afl, temp_len)],
                 copy_len);

          break;
        }

        case 52: {
          /* Increase byte by 1. */
          out_buf[rand_below(afl, temp_len)]++;
          break;
        }

        case 53: {
          /* Decrease byte by 1. */
          out_buf[rand_below(afl, temp_len)]--;
          break;
        }

        case 54: {
          /* Flip byte. */

          out_buf[rand_below(afl, temp_len)] ^= 0xff;
          break;
        }

        case 55 ... 56: {
          if (temp_len < 4) { break; }

          /* Switch bytes. */

          u32 to_end, switch_to, switch_len, switch_from;
          switch_from = rand_below(afl, temp_len);
          do {
            switch_to = rand_below(afl, temp_len);

          } while (switch_from == switch_to);

          if (switch_from < switch_to) {
            switch_len = switch_to - switch_from;
            to_end = temp_len - switch_to;

          } else {
            switch_len = switch_from - switch_to;
            to_end = temp_len - switch_from;
          }

          switch_len = choose_block_len_small(afl, MIN(switch_len, to_end));

          u8 *new_buf = afl_realloc(AFL_BUF_PARAM(out_scratch), switch_len);
          if (unlikely(!new_buf)) { PFATAL("alloc"); }

          /* Backup */

          memcpy(new_buf, out_buf + switch_from, switch_len);

          /* Switch 1 */

          memcpy(out_buf + switch_from, out_buf + switch_to, switch_len);

          /* Switch 2 */

          memcpy(out_buf + switch_to, new_buf, switch_len);

          break;
        }

        // MAX_HAVOC_ENTRY = 64
        case 57 ... MAX_HAVOC_ENTRY: {
          /* Delete bytes. */

          if (temp_len < 2) { break; }

          /* Don't delete too much. */

          u32 del_len = choose_block_len_small(afl, temp_len - 1);
          u32 del_from = rand_below(afl, temp_len - del_len + 1);

#ifdef INTROSPECTION
          snprintf(afl->m_tmp, sizeof(afl->m_tmp), " DEL-%u-%u", del_from,
                   del_len);
          strcat(afl->mutation, afl->m_tmp);
#endif
          memmove(out_buf + del_from, out_buf + del_from + del_len,
                  temp_len - del_from - del_len);

          temp_len -= del_len;

          break;
        }

        default:

          r -= (MAX_HAVOC_ENTRY + 1);

          if (afl->extras_cnt) {
            if (r < 2) {
              /* Use the dictionary. */

              u32 use_extra = rand_below(afl, afl->extras_cnt);
              u32 extra_len = afl->extras[use_extra].len;

              if (extra_len > temp_len) { break; }

              u32 insert_at = rand_below(afl, temp_len - extra_len + 1);
#ifdef INTROSPECTION
              snprintf(afl->m_tmp, sizeof(afl->m_tmp), " EXTRA_OVERWRITE-%u-%u",
                       insert_at, extra_len);
              strcat(afl->mutation, afl->m_tmp);
#endif
              memcpy(out_buf + insert_at, afl->extras[use_extra].data,
                     extra_len);

              break;

            } else if (r < 4) {
              u32 use_extra = rand_below(afl, afl->extras_cnt);
              u32 extra_len = afl->extras[use_extra].len;
              if (temp_len + extra_len >= ARGV_MAX_SIZE) { break; }

              u8 *ptr = afl->extras[use_extra].data;
              u32 insert_at = rand_below(afl, temp_len + 1);
#ifdef INTROSPECTION
              snprintf(afl->m_tmp, sizeof(afl->m_tmp), " EXTRA_INSERT-%u-%u",
                       insert_at, extra_len);
              strcat(afl->mutation, afl->m_tmp);
#endif

              out_buf = afl_realloc(AFL_BUF_PARAM(out), temp_len + extra_len);
              if (unlikely(!out_buf)) { PFATAL("alloc"); }

              /* Tail */
              memmove(out_buf + insert_at + extra_len, out_buf + insert_at,
                      temp_len - insert_at);

              /* Inserted part */
              memcpy(out_buf + insert_at, ptr, extra_len);
              temp_len += extra_len;

              break;

            } else {
              r -= 4;
            }
          }

          if (afl->a_extras_cnt) {
            u32 r_cmp = 2;

            if (unlikely(afl->cmplog_binary && afl->queue_cur->is_ascii)) {
              r_cmp = MUTATE_ASCII_DICT >> 1;
            }

            if (r < r_cmp) {
              /* Use the dictionary. */

              u32 use_extra = rand_below(afl, afl->a_extras_cnt);
              u32 extra_len = afl->a_extras[use_extra].len;

              if (extra_len > temp_len) { break; }

              u32 insert_at = rand_below(afl, temp_len - extra_len + 1);
#ifdef INTROSPECTION
              snprintf(afl->m_tmp, sizeof(afl->m_tmp),
                       " AUTO_EXTRA_OVERWRITE-%u-%u", insert_at, extra_len);
              strcat(afl->mutation, afl->m_tmp);
#endif
              memcpy(out_buf + insert_at, afl->a_extras[use_extra].data,
                     extra_len);

              break;

            } else if (r < (r_cmp << 1)) {
              u32 use_extra = rand_below(afl, afl->a_extras_cnt);
              u32 extra_len = afl->a_extras[use_extra].len;
              if (temp_len + extra_len >= ARGV_MAX_SIZE) { break; }

              u8 *ptr = afl->a_extras[use_extra].data;
              u32 insert_at = rand_below(afl, temp_len + 1);
#ifdef INTROSPECTION
              snprintf(afl->m_tmp, sizeof(afl->m_tmp),
                       " AUTO_EXTRA_INSERT-%u-%u", insert_at, extra_len);
              strcat(afl->mutation, afl->m_tmp);
#endif

              out_buf = afl_realloc(AFL_BUF_PARAM(out), temp_len + extra_len);
              if (unlikely(!out_buf)) { PFATAL("alloc"); }

              /* Tail */
              memmove(out_buf + insert_at + extra_len, out_buf + insert_at,
                      temp_len - insert_at);

              /* Inserted part */
              memcpy(out_buf + insert_at, ptr, extra_len);
              temp_len += extra_len;

              break;

            } else {
              r -= (r_cmp << 1);
            }
          }

          /* Splicing otherwise if we are still here.
             Overwrite bytes with a randomly selected chunk from another
             testcase or insert that chunk. */

          /* Pick a random queue entry and seek to it. */

          u32 tid;
          do {
            tid = rand_below(afl, afl->queued_items);

          } while (tid == afl->current_entry || afl->queue_buf[tid]->len < 4);

          /* Get the testcase for splicing. */
          struct queue_entry *target = afl->queue_buf[tid];
          u32                 new_len = target->argv_len;
          u8                 *new_buf = target->argv;

          if ((temp_len >= 2 && r % 2) ||
              temp_len + HAVOC_ARGV_BLK_XL >= ARGV_MAX_SIZE) {
            /* overwrite mode */

            u32 copy_from, copy_to, copy_len;

            copy_len = choose_block_len_small(afl, new_len - 1);
            if (copy_len > temp_len) copy_len = temp_len;

            copy_from = rand_below(afl, new_len - copy_len + 1);
            copy_to = rand_below(afl, temp_len - copy_len + 1);

            memmove(out_buf + copy_to, new_buf + copy_from, copy_len);

          } else {
            /* insert mode */

            u32 clone_from, clone_to, clone_len;

            clone_len = choose_block_len_small(afl, new_len);
            clone_from = rand_below(afl, new_len - clone_len + 1);
            clone_to = rand_below(afl, temp_len + 1);

            u8 *temp_buf = afl_realloc(AFL_BUF_PARAM(out_scratch),
                                       temp_len + clone_len + 1);
            if (unlikely(!temp_buf)) { PFATAL("alloc"); }

            /* Head */

            memcpy(temp_buf, out_buf, clone_to);

            /* Inserted part */

            memcpy(temp_buf + clone_to, new_buf + clone_from, clone_len);

            /* Tail */
            memcpy(temp_buf + clone_to + clone_len, out_buf + clone_to,
                   temp_len - clone_to);

            out_buf = temp_buf;
            afl_swap_bufs(AFL_BUF_PARAM(out), AFL_BUF_PARAM(out_scratch));
            temp_len += clone_len;
          }

          break;

          // end of default
      }
    }

    if (unlikely(temp_len < 4)) {
      out_buf = afl_realloc(AFL_BUF_PARAM(out), len);
      if (unlikely(!out_buf)) { PFATAL("alloc"); }
      temp_len = len;
      memcpy(out_buf, in_buf, len);
      continue;
    }

    {
      u8  has_placeholder = false;
      u32 idx1 = 0;
      while (idx1 < temp_len - 3) {
        if (out_buf[idx1] == '@' && out_buf[idx1 + 1] == '@') {
          has_placeholder = true;
          break;
        }
        idx1++;
      }

      if (!has_placeholder && !afl->fsrv.use_stdin) {
        idx1 = rand_below(afl, temp_len - 3);
        out_buf[idx1] = '@';
        out_buf[idx1 + 1] = '@';
      }
    }

    out_buf[temp_len - 2] = 0;
    out_buf[temp_len - 1] = 0;

    if (common_fuzz_stuff(afl, file_buf, file_len, out_buf, temp_len)) {
      goto abandon_entry;
    }

    /* out_buf might have been mangled a bit, so let's restore it to its
       original size and shape. */

    out_buf = afl_realloc(AFL_BUF_PARAM(out), len);
    if (unlikely(!out_buf)) { PFATAL("alloc"); }
    temp_len = len;
    memcpy(out_buf, in_buf, len);

    /* If we're finding new stuff, let's run for a bit longer, limits
       permitting. */

    if (afl->queued_items != havoc_queued) {
      if (perf_score <= afl->havoc_max_mult * 100) {
        afl->stage_max *= 2;
        perf_score *= 2;
      }

      havoc_queued = afl->queued_items;
    }
  }

  new_hit_cnt = afl->queued_items + afl->saved_crashes;
  u64 new_found_cnt = new_hit_cnt - orig_hit_cnt;

  if (!splice_cycle) {
    afl->stage_finds[STAGE_HAVOC_ARGV] += new_found_cnt;
    afl->stage_cycles[STAGE_HAVOC_ARGV] += afl->stage_max;

  } else {
    afl->stage_finds[STAGE_SPLICE_ARGV] += new_found_cnt;
    afl->stage_cycles[STAGE_SPLICE_ARGV] += afl->stage_max;
  }

  u32 argv_id = afl->queue_cur->argv_id;
  u32 file_id = afl->queue_cur->file_id;
  afl->argv_num_finds[argv_id] += new_found_cnt;
  afl->argv_num_mut[argv_id] += afl->stage_max;
  afl->file_num_argv_finds[file_id] += new_found_cnt;
  afl->file_num_argv_mut[file_id] += afl->stage_max;

  /************
   * SPLICING *
   ************/

  /* This is a last-resort strategy triggered by a full round with no findings.
     It takes the current input file, randomly selects another input, and
     splices them together at some offset, then relies on the havoc
     code to mutate that blob. */

retry_splicing:

  if (afl->use_splicing && splice_cycle++ < SPLICE_CYCLES &&
      afl->ready_for_splicing_count > 1 && afl->queue_cur->len >= 4) {
    struct queue_entry *target;
    u32                 tid, split_at;
    u8                 *new_buf;
    s32                 f_diff, l_diff;

    /* First of all, if we've modified in_buf for havoc, let's clean that
       up... */

    if (in_buf != orig_in) {
      in_buf = orig_in;
      len = afl->queue_cur->argv_len;
    }

    /* Pick a random queue entry and seek to it. Don't splice with yourself. */

    do {
      tid = rand_below(afl, afl->queued_items);

    } while (tid == afl->current_entry || afl->queue_buf[tid]->argv_len < 4);

    /* Get the testcase */
    afl->splicing_with = tid;
    target = afl->queue_buf[tid];
    new_buf = target->argv;

    /* Find a suitable splicing location, somewhere between the first and
       the last differing byte. Bail out if the difference is just a single
       byte or so. */

    locate_diffs(in_buf, new_buf, MIN(len, (s64)target->argv_len), &f_diff,
                 &l_diff);

    if (f_diff < 0 || l_diff < 2 || f_diff == l_diff) { goto retry_splicing; }

    /* Split somewhere between the first and last differing byte. */

    split_at = f_diff + rand_below(afl, l_diff - f_diff);

    /* Do the thing. */

    len = target->argv_len;
    afl->in_scratch_buf = afl_realloc(AFL_BUF_PARAM(in_scratch), len);
    memcpy(afl->in_scratch_buf, in_buf, split_at);
    memcpy(afl->in_scratch_buf + split_at, new_buf, len - split_at);
    in_buf = afl->in_scratch_buf;
    afl_swap_bufs(AFL_BUF_PARAM(in), AFL_BUF_PARAM(in_scratch));

    out_buf = afl_realloc(AFL_BUF_PARAM(out), len);
    if (unlikely(!out_buf)) { PFATAL("alloc"); }
    memcpy(out_buf, in_buf, len);

    goto havoc_stage;
  }

  ret_val = 0;

/* we are through with this queue entry - for this iteration */
abandon_entry:

  afl->splicing_with = -1;

  /* Update afl->pending_not_fuzzed count if we made it through the calibration
     cycle and have not seen this entry before. */

  if (!afl->stop_soon && !afl->queue_cur->cal_failed &&
      !afl->queue_cur->was_fuzzed && !afl->queue_cur->disabled) {
    --afl->pending_not_fuzzed;
    afl->queue_cur->was_fuzzed = 1;
    afl->reinit_table = 1;
    if (afl->queue_cur->favored) { --afl->pending_favored; }
  }

  ++afl->queue_cur->fuzz_level_argv;
  orig_in = NULL;
  return ret_val;

#undef FLIP_BIT
}

u8 fuzz_one_comb_argv(afl_state_t *afl) {
  u32  file_len, len;
  u32  i, idx;
  u8  *in_buf, *file_buf, *out_buf = 0;
  u64  havoc_queued = 0, orig_hit_cnt, new_hit_cnt = 0;
  u32  perf_score = 100, orig_perf;
  u8 **orig_argv = 0, **argv_buf = 0;
  u32  orig_argv_len = 0;

  u8 ret_val = 1, doing_det = 0;

  // //selcect tc again
  // {
  //   u32 argv_idx = rand_below(afl, afl->num_argvs);
  //   u32 num_queue = afl->argv_to_queue_cnt[argv_idx];
  //   u32 queue_idx = rand_below(afl, num_queue);
  //   afl->current_entry = afl->argv_to_queue[argv_idx][queue_idx];
  //   afl->queue_cur = afl->queue_buf[afl->current_entry];
  // }

  file_buf = queue_testcase_get(afl, afl->queue_cur);
  file_len = afl->queue_cur->len;
  in_buf = afl->queue_cur->argv;
  len = afl->queue_cur->argv_len;

  afl->subseq_tmouts = 0;

  afl->cur_depth = afl->queue_cur->depth;

  /*********************
   * PERFORMANCE SCORE *
   *********************/

  if (likely(!afl->old_seed_selection))
    orig_perf = perf_score = afl->queue_cur->perf_score;
  else
    afl->queue_cur->perf_score = orig_perf = perf_score =
        calculate_score(afl, afl->queue_cur);

  if (unlikely(perf_score <= 0 && afl->active_items > 1)) {
    goto abandon_entry;
  }

  afl->stage_name = "havoc_argv_comb";
  afl->stage_short = "havoc_argv_comb";
  afl->stage_max = (doing_det ? HAVOC_CYCLES_INIT : HAVOC_CYCLES) * perf_score /
                   afl->havoc_div / 100;

  if (afl->stage_max < HAVOC_MIN) { afl->stage_max = HAVOC_MIN; }

  orig_hit_cnt = afl->queued_items + afl->saved_crashes;

  havoc_queued = afl->queued_items;

  // split argv
  orig_argv = malloc(sizeof(u8 *) * MAX_ARGV_WORDS);

  u8 *cur_ptr = in_buf;
  for (idx = 0; idx < len - 1; idx++) {
    if (in_buf[idx] == 0) {
      orig_argv[orig_argv_len++] = strdup(cur_ptr);
      cur_ptr = in_buf + idx + 1;

      if (unlikely(orig_argv_len >= MAX_ARGV_WORDS)) { goto abandon_entry; }
    }
  }

  argv_buf = malloc(sizeof(u8 *) * MAX_ARGV_WORDS);
  for (idx = 0; idx < orig_argv_len; idx++) {
    argv_buf[idx] = orig_argv[idx];
  }

  u32 pos, keyword_idx;
  u8 *new_word;
  out_buf = malloc(ARGV_MAX_SIZE);
  u32 cur_len = 0, cur_argv_len = orig_argv_len;
  u8  r;

  for (afl->stage_cur = 0; afl->stage_cur < afl->stage_max; ++afl->stage_cur) {
    u32 use_stacking = 1 << (1 + rand_below(afl, afl->havoc_stack_pow2));

    afl->stage_cur_val = use_stacking;

    for (i = 0; i < use_stacking; ++i) {
      switch ((r = rand_below(afl, 3))) {
        case 0:  // word addition
          if (cur_argv_len + 1 >= MAX_ARGV_WORDS) { break; }

          pos = rand_below(afl, cur_argv_len);
          keyword_idx = rand_below(afl, afl->argv_dict_cnt);
          new_word = afl->argv_dict[keyword_idx];

          memmove(argv_buf + pos + 1, argv_buf + pos,
                  (cur_argv_len - pos) * sizeof(u8 *));

          argv_buf[pos] = new_word;
          cur_argv_len++;
          break;
        case 1:  // word replacement

          pos = rand_below(afl, cur_argv_len);
          keyword_idx = rand_below(afl, afl->argv_dict_cnt);
          new_word = afl->argv_dict[keyword_idx];

          argv_buf[pos] = new_word;
          break;
        case 2:  // word deletion

          if (cur_argv_len <= 1) { break; }

          pos = rand_below(afl, cur_argv_len);

          memmove(argv_buf + pos, argv_buf + pos + 1,
                  (cur_argv_len - pos - 1) * sizeof(u8 *));

          cur_argv_len--;
          break;
      }
    }

    cur_len = 0;

    for (idx = 0; idx < cur_argv_len; idx++) {
      u32 word_len = strlen(argv_buf[idx]) + 1;
      if (unlikely(cur_len + word_len + 1 >= ARGV_MAX_SIZE)) { break; }

      memcpy(out_buf + cur_len, argv_buf[idx], word_len);
      cur_len += word_len;
    }

    for (idx = 0; idx < cur_len; idx++) {
      if (out_buf[idx] == ' ') { out_buf[idx] = 0; }
    }

    out_buf[cur_len++] = 0;

    if (unlikely(cur_len < 4)) {
      for (idx = 0; idx < orig_argv_len; idx++) {
        argv_buf[idx] = orig_argv[idx];
      }

      cur_argv_len = orig_argv_len;
      continue;
    }

    {
      u8  has_placeholder = false;
      u32 num_spaces = 0;
      while (idx < cur_len - 2) {
        if (out_buf[idx] == '@' && out_buf[idx + 1] == '@') {
          has_placeholder = true;
          break;
        }
        if (out_buf[idx] == 0) { num_spaces++; }
        idx++;
      }

      if (!has_placeholder && !afl->fsrv.use_stdin) {
        if (unlikely(cur_len + 3 >= ARGV_MAX_SIZE)) {
          for (idx = 0; idx < orig_argv_len; idx++) {
            argv_buf[idx] = orig_argv[idx];
          }

          cur_argv_len = orig_argv_len;
          continue;
        }

        u32 idx1 = rand_below(afl, num_spaces + 2);

        if (idx1 == 0) {
          memmove(out_buf + 3, out_buf, cur_len);
          out_buf[0] = '@';
          out_buf[1] = '@';
          out_buf[2] = 0;
          cur_len += 3;
        } else if (idx1 == num_spaces + 1) {
          out_buf[cur_len - 1] = '@';
          out_buf[cur_len] = '@';
          out_buf[cur_len + 1] = 0;
          out_buf[cur_len + 2] = 0;
          cur_len += 3;
        } else {
          idx = 0;
          u32 cur_space = 0;
          while (idx < cur_len - 2) {
            if (out_buf[idx] == 0) {
              cur_space++;
              if (cur_space == idx1) { break; }
            }
            idx++;
          }
          memmove(out_buf + idx + 3, out_buf + idx, cur_len - idx);
          out_buf[idx] = 0;
          out_buf[idx + 1] = '@';
          out_buf[idx + 2] = '@';
          cur_len += 3;
        }
      }
    }

    if (common_fuzz_stuff(afl, file_buf, file_len, out_buf, cur_len)) {
      goto abandon_entry;
    }

    for (idx = 0; idx < orig_argv_len; idx++) {
      argv_buf[idx] = orig_argv[idx];
    }

    cur_argv_len = orig_argv_len;

    if (afl->queued_items != havoc_queued) {
      if (perf_score <= afl->havoc_max_mult * 100) {
        afl->stage_max *= 2;
        perf_score *= 2;
      }

      havoc_queued = afl->queued_items;
    }
  }

  new_hit_cnt = afl->queued_items + afl->saved_crashes;

  afl->stage_finds[STAGE_ARGV_COMB] += new_hit_cnt - orig_hit_cnt;
  afl->stage_cycles[STAGE_ARGV_COMB] += afl->stage_max;

  u32 argv_id = afl->queue_cur->argv_id;
  afl->argv_num_mut[argv_id] += afl->stage_max;
  afl->argv_num_finds[argv_id] += new_hit_cnt - orig_hit_cnt;

  ret_val = 0;

abandon_entry:

  free(out_buf);
  free(argv_buf);

  afl->splicing_with = -1;

  /* Update afl->pending_not_fuzzed count if we made it through the calibration
     cycle and have not seen this entry before. */

  if (!afl->stop_soon && !afl->queue_cur->cal_failed &&
      !afl->queue_cur->was_fuzzed && !afl->queue_cur->disabled) {
    --afl->pending_not_fuzzed;
    afl->queue_cur->was_fuzzed = 1;
    afl->reinit_table = 1;
    if (afl->queue_cur->favored) { --afl->pending_favored; }
  }

  for (idx = 0; idx < orig_argv_len; idx++) {
    free(orig_argv[idx]);
  }
  free(orig_argv);

  ++afl->queue_cur->fuzz_level_argv;
  return ret_val;
}

static inline u32 choose_block_len_small(afl_state_t *afl, u32 limit) {
  u32 min_value, max_value;
  u32 rlim = MIN(afl->queue_cycle, (u32)3);

  if (unlikely(!afl->run_over10m)) { rlim = 1; }

  switch (rand_below(afl, rlim)) {
    case 0:
      min_value = 1;
      max_value = HAVOC_ARGV_BLK_SMALL;
      break;

    case 1:
      min_value = HAVOC_ARGV_BLK_SMALL;
      max_value = HAVOC_ARGV_BLK_MEDIUM;
      break;

    default:

      if (likely(rand_below(afl, 10))) {
        min_value = HAVOC_ARGV_BLK_MEDIUM;
        max_value = HAVOC_ARGV_BLK_LARGE;

      } else {
        min_value = HAVOC_ARGV_BLK_LARGE;
        max_value = HAVOC_ARGV_BLK_XL;
      }
  }

  if (min_value >= limit) { min_value = 1; }

  return min_value + rand_below(afl, MIN(max_value, limit) - min_value + 1);
}

static float get_jaccard_dist(u32 *func_calls1, u32 func_cnt1, u32 *func_calls2,
                              u32 func_cnt2) {
  u32 idx1, idx2;
  u32 num_common = 0;
  u32 num_union = 0;

  idx1 = 0;
  idx2 = 0;
  while ((idx1 < func_cnt1) && (idx2 < func_cnt2)) {
    if (func_calls1[idx1] == func_calls2[idx2]) {
      idx1++;
      idx2++;
      num_common++;
    } else if (func_calls1[idx1] < func_calls2[idx2]) {
      idx1++;
    } else {
      idx2++;
    }
  }

  num_union = func_cnt1 + func_cnt2 - num_common;

  return 1.0 - ((float)num_common / (float)num_union);
}

static void argv_clustering(afl_state_t *afl, u32 *zero_argvs,
                            u32 num_zero_argvs, u32 **rank_scores,
                            u32 **rank_idxes, u32 *cluster_num_argvs) {
  u32                 idx1, idx2, idx3, argv_idx, queue_idx;
  struct queue_entry *q;

  u32 **func_calls = (u32 **)calloc(num_zero_argvs, sizeof(u32 *));
  u32  *func_call_cnts = (u32 *)calloc(num_zero_argvs, sizeof(u32));
  u8   *func_map = afl->shm.func_map;
  u8   *in_buf = 0;

  for (idx1 = 0; idx1 < num_zero_argvs; idx1++) {
    argv_idx = zero_argvs[idx1];

    memset(func_map, 0, FUNC_MAP_SIZE);

    queue_idx = afl->argv_to_queue[argv_idx][0];
    q = afl->queue_buf[queue_idx];

    in_buf = queue_testcase_get(afl, q);
    write_argv_file(afl, q->argv, q->argv_len);
    (void)write_to_testcase(afl, (void **)&in_buf, q->len, 1);
    (void)fuzz_run_target(afl, &afl->fsrv, afl->fsrv.exec_tmout);

    u32  called_funcs_size = 512;
    u32 *called_funcs = (u32 *)malloc(sizeof(u32) * 512);
    u32  called_funcs_cnt = 0;

    for (idx2 = 0; idx2 < FUNC_MAP_SIZE; idx2++) {
      if (func_map[idx2] == 0) { continue; }

      called_funcs[called_funcs_cnt++] = idx2;

      if (unlikely(called_funcs_cnt == called_funcs_size)) {
        called_funcs_size *= 2;
        called_funcs =
            (u32 *)realloc(called_funcs, sizeof(u32) * called_funcs_size);
      }
    }

    func_calls[idx1] = called_funcs;
    func_call_cnts[idx1] = called_funcs_cnt;

    if (unlikely(afl->stop_soon)) { break; }
  }

  u32 **clusters = (u32 **)malloc(sizeof(u32 *) * NUM_ARGV_CLUSTERS);
  u8   *selected_argvs_bits = (u8 *)calloc(num_zero_argvs, sizeof(u8));

  // 1. pick random centroids
  for (idx1 = 0; idx1 < NUM_ARGV_CLUSTERS; idx1++) {
    u32 rand_argv_idx = rand_below(afl, num_zero_argvs);
    while (selected_argvs_bits[rand_argv_idx]) {
      rand_argv_idx = rand_below(afl, num_zero_argvs);
    }
    selected_argvs_bits[rand_argv_idx] = 1;
    clusters[idx1] = (u32 *)malloc(sizeof(u32) * num_zero_argvs);
    clusters[idx1][0] = rand_argv_idx;
  }

  u8  centroid_changed = 1;
  u32 num_iteration = 0;
  while (centroid_changed && (num_iteration++ < 30) && (afl->stop_soon == 0)) {
    // 2. assign argvs to clusters
    centroid_changed = 0;

    memset(selected_argvs_bits, 0, sizeof(u8) * num_zero_argvs);
    for (idx1 = 0; idx1 < NUM_ARGV_CLUSTERS; idx1++) {
      selected_argvs_bits[clusters[idx1][0]] = 1;
      cluster_num_argvs[idx1] = 1;
    }

    for (idx1 = 0; idx1 < num_zero_argvs; idx1++) {
      if (selected_argvs_bits[idx1]) { continue; }

      float min_dist = 1;
      u32   min_dist_cluster = 0;

      u32 *cur_argv_func_calls = func_calls[idx1];
      u32  cur_argv_func_call_cnt = func_call_cnts[idx1];

      for (idx2 = 0; idx2 < NUM_ARGV_CLUSTERS; idx2++) {
        u32 *centroid_func_calls = func_calls[clusters[idx2][0]];
        u32  centroid_func_call_cnt = func_call_cnts[clusters[idx2][0]];

        float dist =
            get_jaccard_dist(cur_argv_func_calls, cur_argv_func_call_cnt,
                             centroid_func_calls, centroid_func_call_cnt);

        if (dist < min_dist) {
          min_dist = dist;
          min_dist_cluster = idx2;
        }
      }

      clusters[min_dist_cluster][cluster_num_argvs[min_dist_cluster]++] = idx1;
    }

    // 3. recompute centroids
    for (idx1 = 0; idx1 < NUM_ARGV_CLUSTERS; idx1++) {
      u32 *centroid_func_calls = func_calls[clusters[idx1][0]];
      u32  centroid_func_call_cnt = func_call_cnts[clusters[idx1][0]];

      float min_dist_sum = 0;

      for (idx2 = 1; idx2 < cluster_num_argvs[idx1]; idx2++) {
        u32 *cur_argv_func_calls = func_calls[clusters[idx1][idx2]];
        u32  cur_argv_func_call_cnt = func_call_cnts[clusters[idx1][idx2]];

        min_dist_sum +=
            get_jaccard_dist(cur_argv_func_calls, cur_argv_func_call_cnt,
                             centroid_func_calls, centroid_func_call_cnt);
      }

      u32 min_dist_centroid = 0;

      for (idx2 = 1; idx2 < cluster_num_argvs[idx1]; idx2++) {
        u32 *cur_argv_func_calls = func_calls[clusters[idx1][idx2]];
        u32  cur_argv_func_call_cnt = func_call_cnts[clusters[idx1][idx2]];

        float cur_dist_sum = 0;

        for (idx3 = 0; idx3 < cluster_num_argvs[idx1]; idx3++) {
          if (idx2 == idx3) { continue; }

          u32 *other_argv_func_calls = func_calls[clusters[idx1][idx3]];
          u32  other_argv_func_call_cnt = func_call_cnts[clusters[idx1][idx3]];

          cur_dist_sum +=
              get_jaccard_dist(cur_argv_func_calls, cur_argv_func_call_cnt,
                               other_argv_func_calls, other_argv_func_call_cnt);
        }

        if (cur_dist_sum < min_dist_sum) {
          min_dist_sum = cur_dist_sum;
          min_dist_centroid = idx2;
        }
      }

      if (min_dist_centroid != 0) {
        centroid_changed = 1;
        clusters[idx1][0] = clusters[idx1][min_dist_centroid];
      }
    }
  }

  for (idx1 = 0; idx1 < NUM_ARGV_CLUSTERS; idx1++) {
    fprintf(afl->shrink_log_f, "shrink cluster %u:", idx1);
    u32 *cluster = clusters[idx1];
    u32  num_argv_in_cluster = cluster_num_argvs[idx1];

    u32 *cur_rank_score = rank_scores[idx1];
    u32 *cur_rank_idxes = rank_idxes[idx1];

    memset(cur_rank_score, 0, sizeof(u32) * num_argv_in_cluster);

    for (idx2 = 0; idx2 < num_argv_in_cluster; idx2++) {
      idx3 = cluster[idx2];
      argv_idx = zero_argvs[idx3];
      fprintf(afl->shrink_log_f, "%u,", argv_idx);

      u32   num_q_in_argv = afl->argv_to_queue_cnt[argv_idx];
      float avg_score = 0;

      for (idx3 = 0; idx3 < num_q_in_argv; idx3++) {
        queue_idx = afl->argv_to_queue[argv_idx][idx3];
        avg_score += calculate_score(afl, afl->queue_buf[queue_idx]);
      }

      avg_score /= (float)num_q_in_argv;

      for (idx3 = 0; idx3 < idx2; idx3++) {
        if (cur_rank_score[idx3] <= avg_score) {
          memmove(&cur_rank_score[idx3 + 1], &cur_rank_score[idx3],
                  sizeof(u32) * (num_argv_in_cluster - idx3 - 1));
          memmove(&cur_rank_idxes[idx3 + 1], &cur_rank_idxes[idx3],
                  sizeof(u32) * (num_argv_in_cluster - idx3 - 1));
          cur_rank_score[idx3] = avg_score;
          cur_rank_idxes[idx3] = argv_idx;
          break;
        }
      }

      if (idx3 == idx2) {
        cur_rank_score[idx2] = avg_score;
        cur_rank_idxes[idx2] = argv_idx;
      }
    }

    fprintf(afl->shrink_log_f, "\n");
  }

  for (idx1 = 0; idx1 < num_zero_argvs; idx1++) {
    free(func_calls[idx1]);
  }
  free(func_calls);
  free(func_call_cnts);

  for (idx1 = 0; idx1 < NUM_ARGV_CLUSTERS; idx1++) {
    free(clusters[idx1]);
  }

  free(selected_argvs_bits);
}

static void file_clustering(afl_state_t *afl, u32 *zero_files,
                            u32 num_zero_files, u32 **rank_scores,
                            u32 **rank_idxes, u32 *cluster_num_files) {
  u32                 idx1, idx2, idx3, file_idx, queue_idx, active_idx;
  struct queue_entry *q;

  u32 **func_calls = (u32 **)calloc(num_zero_files, sizeof(u32 *));
  u32  *func_call_cnts = (u32 *)calloc(num_zero_files, sizeof(u32));
  u8   *func_map = afl->shm.func_map;
  u8   *in_buf;

  for (idx1 = 0; idx1 < num_zero_files; idx1++) {
    file_idx = zero_files[idx1];

    memset(func_map, 0, FUNC_MAP_SIZE);

    queue_idx = afl->file_to_queue[file_idx][0];
    q = afl->queue_buf[queue_idx];

    in_buf = queue_testcase_get(afl, q);
    write_argv_file(afl, q->argv, q->argv_len);
    (void)write_to_testcase(afl, (void **)&in_buf, q->len, 1);
    (void)fuzz_run_target(afl, &afl->fsrv, afl->fsrv.exec_tmout);

    u32  called_funcs_size = 512;
    u32 *called_funcs = (u32 *)malloc(sizeof(u32) * 512);
    u32  called_funcs_cnt = 0;

    for (idx2 = 0; idx2 < FUNC_MAP_SIZE; idx2++) {
      if (func_map[idx2] == 0) { continue; }

      called_funcs[called_funcs_cnt++] = idx2;

      if (unlikely(called_funcs_cnt == called_funcs_size)) {
        called_funcs_size *= 2;
        called_funcs =
            (u32 *)realloc(called_funcs, sizeof(u32) * called_funcs_size);
      }
    }

    func_calls[idx1] = called_funcs;
    func_call_cnts[idx1] = called_funcs_cnt;

    if (unlikely(afl->stop_soon)) { break; }
  }

  u32 **clusters = (u32 **)malloc(sizeof(u32 *) * NUM_FILE_CLUSTERS);
  u8   *selected_file_bits = (u8 *)calloc(num_zero_files, sizeof(u8));

  // 1. pick random centroids
  for (idx1 = 0; idx1 < NUM_FILE_CLUSTERS; idx1++) {
    u32 rand_file_idx = rand_below(afl, num_zero_files);
    while (selected_file_bits[rand_file_idx]) {
      rand_file_idx = rand_below(afl, num_zero_files);
    }
    selected_file_bits[rand_file_idx] = 1;
    clusters[idx1] = (u32 *)malloc(sizeof(u32) * num_zero_files);
    clusters[idx1][0] = rand_file_idx;
  }

  u8  centroid_changed = 1;
  u32 num_iteration = 0;
  while (centroid_changed && (num_iteration++ < 30) && (afl->stop_soon == 0)) {
    // 2. assign files to clusters
    centroid_changed = 0;

    memset(selected_file_bits, 0, sizeof(u8) * num_zero_files);
    for (idx1 = 0; idx1 < NUM_FILE_CLUSTERS; idx1++) {
      selected_file_bits[clusters[idx1][0]] = 1;
      cluster_num_files[idx1] = 1;
    }

    for (idx1 = 0; idx1 < num_zero_files; idx1++) {
      if (selected_file_bits[idx1]) { continue; }

      float min_dist = 1;
      u32   min_dist_cluster = 0;

      u32 *cur_file_func_calls = func_calls[idx1];
      u32  cur_file_func_call_cnt = func_call_cnts[idx1];

      for (idx2 = 0; idx2 < NUM_FILE_CLUSTERS; idx2++) {
        u32 *centroid_func_calls = func_calls[clusters[idx2][0]];
        u32  centroid_func_call_cnt = func_call_cnts[clusters[idx2][0]];

        float dist =
            get_jaccard_dist(cur_file_func_calls, cur_file_func_call_cnt,
                             centroid_func_calls, centroid_func_call_cnt);

        if (dist < min_dist) {
          min_dist = dist;
          min_dist_cluster = idx2;
        }
      }

      clusters[min_dist_cluster][cluster_num_files[min_dist_cluster]++] = idx1;
    }

    // 3. recompute centroids
    for (idx1 = 0; idx1 < NUM_FILE_CLUSTERS; idx1++) {
      u32 *centroid_func_calls = func_calls[clusters[idx1][0]];
      u32  centroid_func_call_cnt = func_call_cnts[clusters[idx1][0]];

      float min_dist_sum = 0;

      for (idx2 = 1; idx2 < cluster_num_files[idx1]; idx2++) {
        u32 *cur_file_func_calls = func_calls[clusters[idx1][idx2]];
        u32  cur_file_func_call_cnt = func_call_cnts[clusters[idx1][idx2]];

        min_dist_sum +=
            get_jaccard_dist(cur_file_func_calls, cur_file_func_call_cnt,
                             centroid_func_calls, centroid_func_call_cnt);
      }

      u32 min_dist_centroid = 0;

      for (idx2 = 1; idx2 < cluster_num_files[idx1]; idx2++) {
        u32 *cur_file_func_calls = func_calls[clusters[idx1][idx2]];
        u32  cur_file_func_call_cnt = func_call_cnts[clusters[idx1][idx2]];

        float cur_dist_sum = 0;

        for (idx3 = 0; idx3 < cluster_num_files[idx1]; idx3++) {
          if (idx2 == idx3) { continue; }

          u32 *other_file_func_calls = func_calls[clusters[idx1][idx3]];
          u32  other_file_func_call_cnt = func_call_cnts[clusters[idx1][idx3]];

          cur_dist_sum +=
              get_jaccard_dist(cur_file_func_calls, cur_file_func_call_cnt,
                               other_file_func_calls, other_file_func_call_cnt);
        }

        if (cur_dist_sum < min_dist_sum) {
          min_dist_sum = cur_dist_sum;
          min_dist_centroid = idx2;
        }
      }

      if (min_dist_centroid != 0) {
        centroid_changed = 1;
        clusters[idx1][0] = clusters[idx1][min_dist_centroid];
      }

      if (unlikely(afl->stop_soon)) { break; }
    }
  }

  for (idx1 = 0; idx1 < NUM_FILE_CLUSTERS; idx1++) {
    fprintf(afl->shrink_log_f, "shrink file cluster %u:", idx1);
    u32 *cluster = clusters[idx1];
    u32  num_file_in_cluster = cluster_num_files[idx1];

    u32 *cur_rank_vals = rank_scores[idx1];
    u32 *cur_rank_idxes = rank_idxes[idx1];

    memset(cur_rank_vals, 0, sizeof(u32) * num_file_in_cluster);

    for (idx2 = 0; idx2 < num_file_in_cluster; idx2++) {
      active_idx = cluster[idx2];
      file_idx = zero_files[active_idx];
      fprintf(afl->shrink_log_f, "%u,", file_idx);

      float avg_score = 0;
      u32   num_q_in_file = afl->file_to_queue_cnt[file_idx];

      for (idx3 = 0; idx3 < num_q_in_file; idx3++) {
        queue_idx = afl->file_to_queue[file_idx][idx3];
        avg_score += calculate_score(afl, afl->queue_buf[queue_idx]);
      }

      avg_score /= (float)num_q_in_file;

      for (idx3 = 0; idx3 < idx2; idx3++) {
        if (cur_rank_vals[idx3] <= avg_score) {
          memmove(&cur_rank_vals[idx3 + 1], &cur_rank_vals[idx3],
                  sizeof(float) * (num_file_in_cluster - idx3 - 1));
          memmove(&cur_rank_idxes[idx3 + 1], &cur_rank_idxes[idx3],
                  sizeof(u32) * (num_file_in_cluster - idx3 - 1));
          cur_rank_vals[idx3] = avg_score;
          cur_rank_idxes[idx3] = file_idx;
          break;
        }
      }

      if (idx3 == idx2) {
        cur_rank_vals[idx2] = avg_score;
        cur_rank_idxes[idx2] = file_idx;
      }
    }

    fprintf(afl->shrink_log_f, "\n");
  }

  for (idx1 = 0; idx1 < num_zero_files; idx1++) {
    free(func_calls[idx1]);
  }
  free(func_calls);
  free(func_call_cnts);

  free(selected_file_bits);

  for (idx1 = 0; idx1 < NUM_FILE_CLUSTERS; idx1++) {
    free(clusters[idx1]);
  }
  free(clusters);

  return;
}

void shrink_corpus(afl_state_t *afl) {
  // shrink
  u32                 idx1, idx2, queue_idx;
  struct queue_entry *q;

  u32  num_queue;
  u32 *active_zero_argvs = malloc(sizeof(u32) * afl->num_argvs);
  u32  num_active_zero_argvs = 0;

  u32 *good_argvs = malloc(sizeof(u32) * afl->num_argvs);
  u32  num_good_argvs = 0;
  u32  num_active_tcs = 0;

  u32 *active_zero_files = malloc(sizeof(u32) * afl->num_unique_files);
  u32  num_active_zero_files = 0;

  u32 *good_files = malloc(sizeof(u32) * afl->num_unique_files);
  u32  num_good_files = 0;

  u32 num_active = 0;
  u32 num_active_files = 0;

  for (idx1 = 0; idx1 < afl->num_argvs; idx1++) {
    num_queue = afl->argv_to_queue_cnt[idx1];

    num_active = 0;
    for (queue_idx = 0; queue_idx < num_queue; queue_idx++) {
      q = afl->queue_buf[afl->argv_to_queue[idx1][queue_idx]];
      num_active += !q->disabled;
    }

    num_active_tcs += num_active;

    if ((num_queue == 1) && (num_active == 1)) {
      active_zero_argvs[num_active_zero_argvs++] = idx1;
    } else if (num_active > 1) {
      good_argvs[num_good_argvs++] = idx1;
    }
  }

  for (idx1 = 0; idx1 < afl->num_unique_files; idx1++) {
    num_queue = afl->file_to_queue_cnt[idx1];

    num_active = 0;
    for (queue_idx = 0; queue_idx < num_queue; queue_idx++) {
      q = afl->queue_buf[afl->file_to_queue[idx1][queue_idx]];
      num_active += !q->disabled;
    }

    if (num_active) { num_active_files++; }

    if ((num_queue == 1) && (num_active == 1)) {
      active_zero_files[num_active_zero_files++] = idx1;
    } else if (num_active > 1) {
      good_files[num_good_files++] = idx1;
    }
  }

  fprintf(afl->shrink_log_f, "# of file mutated last period: %u, ",
          afl->num_selected_file_for_mut);

  u32 num_min_selected_tcs = afl->num_selected_file_for_mut;

  afl->num_selected_file_for_mut = 0;

  fprintf(afl->shrink_log_f, "# of tcs : %u, # of active tcs: %u\n",
          afl->queued_items, num_active_tcs);
  fprintf(afl->shrink_log_f, "# of argvs : %u, # Active Argvs : %u\n",
          afl->num_argvs, num_active_zero_argvs + num_good_argvs);
  fprintf(afl->shrink_log_f, "# of unique files : %u, # active files: %u\n",
          afl->num_unique_files, num_active_files);

  if ((num_active_tcs < num_min_selected_tcs) ||
      (num_active_zero_argvs < NUM_ARGV_CLUSTERS) ||
      (num_active_zero_files < NUM_FILE_CLUSTERS)) {
    free(active_zero_argvs);
    free(good_argvs);
    free(active_zero_files);
    free(good_files);

    fprintf(afl->shrink_log_f,
            "Not enough tcs/argvs/files to do clustering, skip\n");
    write_shrink_log_after(afl);
    return;
  }

  u64 time_begin = get_cur_time();

  u32 **argv_rank_scores = (u32 **)malloc(sizeof(u32 *) * NUM_ARGV_CLUSTERS);
  u32 **argv_rank_idxes = (u32 **)malloc(sizeof(u32 *) * NUM_ARGV_CLUSTERS);
  u32  *cluster_num_argvs = (u32 *)calloc(NUM_ARGV_CLUSTERS, sizeof(u32));

  for (idx1 = 0; idx1 < NUM_ARGV_CLUSTERS; idx1++) {
    argv_rank_scores[idx1] = (u32 *)malloc(sizeof(u32) * num_active_zero_argvs);
    argv_rank_idxes[idx1] = (u32 *)malloc(sizeof(u32) * num_active_zero_argvs);
  }

  argv_clustering(afl, active_zero_argvs, num_active_zero_argvs,
                  argv_rank_scores, argv_rank_idxes, cluster_num_argvs);

  u32 **file_rank_scores = (u32 **)malloc(sizeof(u32 *) * NUM_FILE_CLUSTERS);
  u32 **file_rank_idxes = (u32 **)malloc(sizeof(u32 *) * NUM_FILE_CLUSTERS);
  u32  *cluster_num_files = (u32 *)calloc(NUM_FILE_CLUSTERS, sizeof(u32));

  for (idx1 = 0; idx1 < NUM_FILE_CLUSTERS; idx1++) {
    file_rank_scores[idx1] = (u32 *)malloc(sizeof(u32) * num_active_zero_files);
    file_rank_idxes[idx1] = (u32 *)malloc(sizeof(u32) * num_active_zero_files);
  }

  file_clustering(afl, active_zero_files, num_active_zero_files,
                  file_rank_scores, file_rank_idxes, cluster_num_files);

  u8 *selected_argvs_bits = (u8 *)calloc(afl->num_argvs, sizeof(u8));
  u8 *selected_files_bits = (u8 *)calloc(afl->num_unique_files, sizeof(u8));

  for (idx1 = 0; idx1 < num_good_argvs; idx1++) {
    selected_argvs_bits[good_argvs[idx1]] = 1;
  }

  for (idx1 = 0; idx1 < NUM_ARGV_CLUSTERS; idx1++) {
    for (idx2 = 0; idx2 < NUM_SEL_IN_ARGV_CLUSTER; idx2++) {
      if (idx2 >= cluster_num_argvs[idx1]) { break; }

      selected_argvs_bits[argv_rank_idxes[idx1][idx2]] = 1;
    }
  }

  for (idx1 = 0; idx1 < num_good_files; idx1++) {
    selected_files_bits[good_files[idx1]] = 1;
  }

  for (idx1 = 0; idx1 < NUM_FILE_CLUSTERS; idx1++) {
    for (idx2 = 0; idx2 < NUM_SEL_IN_FILE_CLUSTER; idx2++) {
      if (idx2 >= cluster_num_files[idx1]) { break; }

      selected_files_bits[file_rank_idxes[idx1][idx2]] = 1;
    }
  }

  u32 *selected_queue_idxes = (u32 *)malloc(sizeof(u32) * num_active_tcs);
  u8  *selected_queue_bits = (u8 *)calloc(afl->queued_items, sizeof(u8));
  u32  num_selected_queue = 0;

  for (idx1 = 0; idx1 < afl->queued_items; idx1++) {
    q = afl->queue_buf[idx1];

    if (q->disabled) { continue; }

    if (!selected_argvs_bits[q->argv_id]) { continue; }
    if (!selected_files_bits[q->file_id]) { continue; }

    selected_queue_idxes[num_selected_queue++] = idx1;
    selected_queue_bits[idx1] = 1;
  }

  if (num_selected_queue > 0) {
    for (idx1 = 0; idx1 < afl->queued_items; idx1++) {
      q = afl->queue_buf[idx1];

      if (q->disabled) { continue; }

      if (selected_queue_bits[idx1]) { continue; }

      q->disabled = 1;
      q->weight = 0.0;
      q->perf_score = 0.0;
      q->favored = 0;

      q->tc_ref = 0;
      ck_free(q->trace_mini);
      q->trace_mini = NULL;
    }

    for (idx1 = 0; idx1 < afl->fsrv.map_size; idx1++) {
      if (!afl->top_rated[idx1]) { continue; }

      q = afl->top_rated[idx1];

      if (q->disabled) { afl->top_rated[idx1] = 0; }
    }
  }

  for (idx1 = 0; idx1 < NUM_ARGV_CLUSTERS; idx1++) {
    free(argv_rank_scores[idx1]);
    free(argv_rank_idxes[idx1]);
  }

  free(argv_rank_scores);
  free(argv_rank_idxes);
  free(cluster_num_argvs);

  for (idx1 = 0; idx1 < NUM_FILE_CLUSTERS; idx1++) {
    free(file_rank_scores[idx1]);
    free(file_rank_idxes[idx1]);
  }

  free(file_rank_scores);
  free(file_rank_idxes);
  free(cluster_num_files);

  free(selected_argvs_bits);
  free(selected_files_bits);

  free(selected_queue_idxes);
  free(selected_queue_bits);

  free(active_zero_argvs);
  free(good_argvs);

  free(active_zero_files);
  free(good_files);

  u64 time_passed = get_cur_time() - time_begin;
  fprintf(afl->shrink_log_f, "SHRINK took %llums\n", time_passed);

  write_shrink_log_after(afl);
  afl->score_changed = 1;
}

static void write_shrink_log_after(afl_state_t *afl) {
  u32                 idx1, num_queue, num_active, queue_idx;
  struct queue_entry *q;
  u32                 num_active_total = 0;
  u32                 num_active_argvs = 0;

  for (idx1 = 0; idx1 < afl->num_argvs; idx1++) {
    num_queue = afl->argv_to_queue_cnt[idx1];
    num_active = 0;
    for (queue_idx = 0; queue_idx < num_queue; queue_idx++) {
      q = afl->queue_buf[afl->argv_to_queue[idx1][queue_idx]];
      num_active += !q->disabled;
    }
    num_active_argvs += !!num_active;
    num_active_total += num_active;
    fprintf(afl->shrink_log_f, "SHRINK res3: Argv #%u : %u/%u active\n", idx1,
            num_active, num_queue);
  }

  for (idx1 = 0; idx1 < afl->num_unique_files; idx1++) {
    num_queue = afl->file_to_queue_cnt[idx1];
    num_active = 0;
    for (queue_idx = 0; queue_idx < num_queue; queue_idx++) {
      q = afl->queue_buf[afl->file_to_queue[idx1][queue_idx]];
      num_active += !q->disabled;
    }
    fprintf(afl->shrink_log_f, "SHRINK res4: File #%u : %u/%u active\n", idx1,
            num_active, num_queue);
  }

  fprintf(afl->shrink_log_f, "SHIRNK sum : %u/%u active, # active argv : %u\n",
          num_active_total, afl->queued_items, num_active_argvs);
  fprintf(afl->shrink_log_f, "finish2\n");
  fflush(afl->shrink_log_f);
}
