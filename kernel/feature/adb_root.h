#ifndef __KSU_H_ADB_ROOT
#define __KSU_H_ADB_ROOT
#include <asm/ptrace.h>

struct user_arg_ptr;
long ksu_adb_root_handle_execve_manual(const char *filename, void ***envp_p);

long ksu_adb_root_handle_execve(struct pt_regs *regs);
long ksu_adb_root_handle_execveat(struct pt_regs *regs);

#ifdef CONFIG_KSU_FEATURE_ADBROOT
void ksu_adb_root_init(void);
void ksu_adb_root_exit(void);
#else
void ksu_adb_root_init(void) { } // no-op
void ksu_adb_root_exit(void) { } // no-op
#endif

#endif
