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
#include <bpf/libbpf.h>
#include <unistd.h>
#include <bpf/bpf.h>
#include <iostream>
#include "exec_monitor.skel.h"
#include "process_info.hpp"
#include "exec_monitor.hpp"

static void hexdump(const char *buf, int size)
{
	int row_length = 16;;

	for (int i = 0; i <= (size / row_length); i++) {
		for (int j = 0; j < row_length; j++) {
			int offset = i * row_length + j;
			if (offset >= size)
				printf("   ");
			else
				printf("%02x ", buf[offset]);
		}
		printf("| ");
		for (int j = 0; j < row_length; j++) {
			int offset = i * row_length + j;
			if (offset >= size)
				printf("   ");
			else
				printf("%c ", buf[offset]);
		}
		printf("\n");
	}
}

static int process_sample(void *ctx, void *data, size_t len)
{
	struct process_info *s = NULL;

	struct exec_monitor_entry *e = (exec_monitor_entry*)data;
	switch (e->type) {
	case PROCESS_INFO:
		if (len < sizeof(*e)) {
			printf("Invalid len %d", len);
			return -1;
		}

		s = &e->header;
		printf("%d\t%d\t%d\t%s\n", s->ppid, s->pid, s->tgid, s->name);
		fflush(stdout);
		return 0;
	case ARGS:
		if (len < sizeof(e->args_chunk) + e->args_chunk.size) {
			printf("Invalid len %d", len);
			return -1;
		}
		hexdump(e->args_chunk.args, e->args_chunk.size);
		return 0;
	default:
		printf("Bad type %d\n", e->type);
		return 0;
	}
}

ExecMonitor::ExecMonitor(Config config)
{
	n_proc = config.n_proc;
	ppid_list = config.ppid_list;
	name_list = config.name_list;
}

int ExecMonitor::run()
{
	struct exec_monitor *skel = exec_monitor__open_and_load();
	struct ring_buffer *ringbuffer;
	int ringbuffer_fd;

	if (!skel) {
		std::cerr << "[EXEC_MONITOR]: Error loading the eBPF program.\n";
		goto out;
	}

	if (exec_monitor__attach(skel) != 0) {
		std::cerr << "[EXEC_MONITOR]: Error attaching the eBPF program.\n";
		goto out;
	}

	ringbuffer_fd = bpf_map__fd(skel->maps.ringbuf);
	if (ringbuffer_fd < 0) {
		std::cerr << "[EXEC_MONITOR]: Error accessing the ringbuffer file descriptor.\n";
		goto out;
	}

	ringbuffer = ring_buffer__new(ringbuffer_fd, process_sample, NULL, NULL);
	if (!ringbuffer) {
		std::cerr << "[EXEC_MONITOR]: Error allocating the ringbufffer.\n";
		goto out;
	}

	printf("PPID\tPID\tTGID\tPCOM\n");
	while (1) {
		// poll for new data with a timeout of -1 ms, waiting indefinitely
		int x = ring_buffer__poll(ringbuffer, -1);
	}

	exec_monitor__destroy(skel);
	return 0;

out:
	exec_monitor__destroy(skel);
	return -1;

}

int ExecMonitor::export_data() { return 0;} // TODO
