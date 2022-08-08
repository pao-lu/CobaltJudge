#ifndef _WORKER_THREAD_INCLUDED
#define _WORKER_THREAD_INCLUDED

#include <stdint.h>

int clone_namespace_process(uint32_t id, struct ns_proc_info *desc);
int free_namespace_process(struct ns_proc_info *info);
int send_job(struct ns_proc_info *info, const struct job_desc *desc);

#endif
