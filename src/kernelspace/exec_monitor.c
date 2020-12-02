/*
 * Copyright 2020 Google LLC
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
*/

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "process_info.hpp"

#define min(a, b) ((a) < (b) ? (a) : (b))

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24);
} ringbuf SEC(".maps");

long ringbuffer_flags = 0;

SEC("lsm/bprm_committed_creds")
void BPF_PROG(exec_audit, struct linux_binprm *bprm)
{
	int err;
	long pid_tgid;
	struct exec_monitor_entry *process, *args;
	struct task_struct *current_task;
	const char msg[] = "bpf_probe_read returned %d for size %d (%p)\n";

	// Reserve space on the ringbuffer for the sample
	process = bpf_ringbuf_reserve(&ringbuf, sizeof(*process), ringbuffer_flags);
	if (!process)
		return;

	process->type = PROCESS_INFO;

	// Get information about the current process
	pid_tgid = bpf_get_current_pid_tgid();
	process->header.pid = pid_tgid;
	process->header.tgid = pid_tgid >> 32;

	// Get the parent pid
	current_task = (struct task_struct *)bpf_get_current_task();
	process->header.ppid = BPF_CORE_READ(current_task, real_parent, pid);

	// Get the executable name
	bpf_get_current_comm(&process->header.name, sizeof(process->header.name));

	bpf_ringbuf_submit(process, ringbuffer_flags);

	unsigned int alloc_size = sizeof(process->args_chunk) + 100;
	args = bpf_ringbuf_reserve(&ringbuf, alloc_size, ringbuffer_flags);
	if (!args) {
		const char mosg[] = "alloc of %d bytes failed";
		bpf_trace_printk(mosg, sizeof(mosg), alloc_size);
		return;
	}

	const char misg[] = "alloc of %d bytes succed";
	bpf_trace_printk(misg, sizeof(misg), alloc_size);

	args->type = ARGS;

	unsigned int args_size = bprm->vma->vm_end - bprm->vma->vm_start;
	unsigned int read_size = min(args_size, 16ull);
	err = bpf_probe_read_user(&args->args_chunk.args, read_size, (void *)bprm->p);
	if (err) {
		const char mosg[] = "read of %d bytes failed: %d";
		bpf_trace_printk(mosg, sizeof(mosg), read_size, err);
		bpf_ringbuf_discard(args, ringbuffer_flags);
		return;
	}

	args->args_chunk.size = read_size;
	bpf_ringbuf_submit(args, ringbuffer_flags);
}

char _license[] SEC("license") = "GPL";

