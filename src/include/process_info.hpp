#ifndef PROCESS_INFO_HPP
#define PROCESS_INFO_HPP

#include <linux/limits.h>

struct process_info {
	int ppid;
	int pid;
	int tgid;
	char name[PATH_MAX];
};

enum exec_monitor_entry_type {
	PROCESS_INFO,
	ARGS,
};

struct exec_monitor_entry {
	enum exec_monitor_entry_type type;
	union {
		struct process_info header;
		struct {
			int size;
			char args[0];
		} args_chunk;
	};
};

#endif
