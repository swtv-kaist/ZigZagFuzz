#include <float.h>
#include <limits.h>
#include <string.h>

#include "afl-fuzz.h"
#include "cmplog.h"

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
  u32 file_id = afl->num_unique_files++;
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

  return file_id;
}
