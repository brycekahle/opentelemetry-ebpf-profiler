// this file contains the code for collecting profiles on Go OOMs

#include "bpfdefs.h"
#include "extmaps.h"
#include "kernel.h"
#include "tracemgmt.h"
#include "types.h"

#define E2BIG       7
#define SIGKILL     9
#define MAX_BUCKETS 30000

struct _trace_event_raw_mark_victim {
  u64 unused;
  int pid;
};

struct loop_ctx {
  u64 gobp;
  bool complete;
};

BPF_RODATA_VAR(u16, origin_id_oom, 0)

struct mbuckets_data_t {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __type(key, int);
  __type(value, struct GoBucket);
  __uint(max_entries, MAX_BUCKETS);
  __uint(map_flags, BPF_F_MMAPABLE);
} mbuckets_data SEC(".maps");

struct profile_task_t {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, u32);
  __type(value, u64);
  __uint(max_entries, 4096);
} profile_task SEC(".maps");

SEC("tp_btf/mark_victim")
int mark_victim_handler(u64 *ctx)
{
  u64 task = ctx[0];
  u32 pid  = 0;
  if (!task_tgid_offset) {
    DEBUG_PRINT("invalid tgid offset");
    return 0;
  }
  if (bpf_probe_read_kernel(&pid, sizeof(pid), (void *)(task + task_tgid_offset))) {
    DEBUG_PRINT("unable to read task tgid");
    return 0;
  }

  GoRuntimeOffsets *go_offsets = bpf_map_lookup_elem(&go_procs, &pid);
  if (!go_offsets || !go_offsets->mbuckets_addr) {
    DEBUG_PRINT("victim is not a Go process, or runtime.mbuckets was not located. pid=%u", pid);
    return 0;
  }
  DEBUG_PRINT("marking victim pid=%u mbuckets=%lx", pid, go_offsets->mbuckets_addr);
  if (bpf_map_update_elem(&profile_task, &pid, &go_offsets->mbuckets_addr, BPF_ANY)) {
    DEBUG_PRINT("error updating profile_task");
    return 0;
  }
  return 0;
}

static long read_mbucket(u64 index, void *raw_ctx)
{
  struct loop_ctx *ctx = (struct loop_ctx *)raw_ctx;
  GoBucket *mbp        = bpf_map_lookup_elem(&mbuckets_data, &index);
  if (!mbp) {
    return 1;
  }

  u64 gobp = ctx->gobp;
  long err = 0;
  if ((err = bpf_probe_read_user(&mbp->header, sizeof(GoBucketHeader), (void *)gobp))) {
    DEBUG_PRINT("failed to read bucket header at %lx err: %ld\n", gobp, err);
    return 1;
  }
  ctx->gobp = mbp->header.allnext;

  u64 stack_size = mbp->header.nstk * sizeof(u64);
  if (stack_size > (MAX_GO_OOM_STACK_DEPTH * sizeof(u64))) {
    DEBUG_PRINT(
      "skipping bucket %lu: nstk=%lu > MAX=%d\n ", index, mbp->header.nstk, MAX_GO_OOM_STACK_DEPTH);
    return 0;
  }
  if ((err = bpf_probe_read_user(
         &mbp->stk, (u32)stack_size, (void *)(gobp + sizeof(GoBucketHeader))))) {
    DEBUG_PRINT(
      "failed to read bucket stack at %lx err: %ld\n", gobp + sizeof(GoBucketHeader), err);
    return 1;
  }
  if ((err = bpf_probe_read_user(
         &mbp->mem, sizeof(GoMemRecord), (void *)(gobp + sizeof(GoBucketHeader) + stack_size)))) {
    DEBUG_PRINT(
      "failed to read bucket memRecord at %lx err: %ld\n",
      gobp + sizeof(GoBucketHeader) + stack_size,
      err);
    return 1;
  }

  if (!ctx->gobp) {
    ctx->complete = true;
    return 1;
  }

  return 0;
}

SEC("tp_btf/signal_deliver")
int signal_deliver_handler(u64 *ctx)
{
  u32 pid          = 0;
  u32 tid          = 0;
  u64 group_leader = 0;
  if (!get_pid_tgid_leader(&pid, &tid, &group_leader)) {
    DEBUG_PRINT("error getting pid/tgid/leader");
    return 0;
  }

  int sig = (int)ctx[0];
  if (sig != SIGKILL) {
    return 0;
  }
  DEBUG_PRINT("SIGKILL pid=%u", pid);

  u64 *mbuckets_addr_ptr = bpf_map_lookup_elem(&profile_task, &pid);
  if (!mbuckets_addr_ptr) {
    DEBUG_PRINT("no mbuckets pointer pid=%u", pid);
    return 0;
  }
  u64 mbuckets_addr = *mbuckets_addr_ptr;
  if (!mbuckets_addr) {
    DEBUG_PRINT("invalid mbuckets pointer pid=%u", pid);
    return 0;
  }
  DEBUG_PRINT("OOM killing pid=%u", pid);
  if (bpf_map_delete_elem(&profile_task, &pid)) {
    DEBUG_PRINT("error deleting profile_task pid=%u", pid);
    return 0;
  }

  u64 gobp = 0;
  long err = 0;
  if ((err = bpf_probe_read_user(&gobp, sizeof(void *), (void *)mbuckets_addr))) {
    DEBUG_PRINT("error read mbuckets pointer pid=%u err=%ld", pid, err);
    return 0;
  }
  if (!gobp) {
    DEBUG_PRINT("zero gobucket pointer pid=%u", pid);
    return 0;
  }
  DEBUG_PRINT("starting mbuckets data collection");

  PerCPURecord *record = prepare_trace(origin_id_oom, pid, tid, group_leader, bpf_ktime_get_ns());
  if (!record) {
    DEBUG_PRINT("error preparing trace pid=%u", pid);
    return 0;
  }

  struct loop_ctx lctx = {.gobp = gobp, .complete = false};
  long buckets_read    = bpf_loop(MAX_BUCKETS, read_mbucket, &lctx, 0);
  if (buckets_read == -E2BIG) {
    buckets_read = MAX_BUCKETS;
  }
  if (buckets_read <= 0 || !lctx.complete) {
    return 0;
  }
  DEBUG_PRINT("read %ld buckets", buckets_read);

  Trace *trace = &record->trace;
  u64 *values  = push_context_values(trace, 1);
  if (!values) {
    DEBUG_PRINT("error pushing context values pid=%u", pid);
    return 0;
  }
  values[0] = (u64)buckets_read;
  send_trace(ctx, trace);
  return 0;
}
