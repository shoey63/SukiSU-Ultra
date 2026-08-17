#include "linux/file.h"
#include "linux/fcntl.h"
#include "linux/namei.h"
#include <linux/compiler_types.h>
#include <linux/preempt.h>
#include <linux/printk.h>
#include <linux/mm.h>
#include <linux/pgtable.h>
#include <linux/uaccess.h>
#include <asm/current.h>
#include <linux/cred.h>
#include <linux/fs.h>
#include <linux/types.h>
#include <linux/version.h>
#include <linux/sched/task_stack.h>
#include <linux/ptrace.h>

#include "arch.h"
#include "policy/allowlist.h"
#include "policy/feature.h"
#include "klog.h"
#include "runtime/ksud.h"
#include "feature/sucompat.h"
#include "policy/app_profile.h"
#include "hook/syscall_hook.h"
#include "sulog/event.h"
#include "ksu.h"
#include "util.h"
#define SU_PATH "/system/bin/su"
#define SH_PATH "/system/bin/sh"

#include "../hook/syscall_event_bridge.h"

bool ksu_su_compat_enabled __read_mostly = true;
static const char su_path[] = SU_PATH;
static const char sh_path[] = SH_PATH;
static const char ksud_path[] = KSUD_PATH;

static int su_compat_feature_get(u64 *value)
{
    *value = ksu_su_compat_enabled ? 1 : 0;
    return 0;
}

static int su_compat_feature_set(u64 value)
{
    bool enable = value != 0;
    ksu_su_compat_enabled = enable;
    pr_info("su_compat: set to %d\n", enable);
    return 0;
}

static const struct ksu_feature_handler su_compat_handler = {
    .feature_id = KSU_FEATURE_SU_COMPAT,
    .name = "su_compat",
    .get_handler = su_compat_feature_get,
    .set_handler = su_compat_feature_set,
};

static void __user *userspace_stack_buffer(const void *d, size_t len)
{
    // To avoid having to mmap a page in userspace, just write below the stack
    // pointer.
    char __user *p = (void __user *)current_user_stack_pointer() - len;

    return copy_to_user(p, d, len) ? NULL : p;
}

static char __user *sh_user_path(void)
{
    return userspace_stack_buffer(sh_path, sizeof(sh_path));
}

static char __user *ksud_user_path(void)
{
    return userspace_stack_buffer(ksud_path, sizeof(ksud_path));
}

static char __user *empty_user_path(void)
{
    return userspace_stack_buffer("", 1);
}

static bool is_ksud_exists(void)
{
    struct path path;
    if (kern_path(KSUD_PATH, 0, &path) == 0) {
        path_put(&path);
        return true;
    }
    return false;
}

#ifdef CONFIG_KSU_SUSFS
extern const char __user *get_user_arg_ptr(struct user_arg_ptr argv, int nr);
/*
 * return 0 -> No further checks should be required afterwards
 * return non-zero -> Further checks should be continued afterwards
 */
int ksu_handle_execveat_init(struct filename *filename, struct user_arg_ptr *argv_user, struct user_arg_ptr *envp_user) {
    int ret = 0;

    if (current->pid == 1)
        return -EINVAL;

    if (!is_init(get_current_cred()))
        return -EINVAL;

    if (unlikely(!strcmp(filename->name, KSUD_PATH))) {
        const char __user *argv_user_ptr = get_user_arg_ptr(*argv_user, 0);
        struct ksu_sulog_pending_event *pending_sucompat = NULL;

        pr_info("hook_manager: escape to root for init executing ksud: %d\n", current->pid);
        pending_sucompat = ksu_sulog_capture_sucompat(filename->name, argv_user, GFP_KERNEL);
        escape_to_root_for_init();
        if (ret) {
            pr_err("escape_to_root_for_init() failed: %d\n", ret);
            return ret;
        }
        if (!argv_user_ptr || IS_ERR(argv_user_ptr)) {
            pr_err("!argv_user_ptr || IS_ERR(argv_user_ptr)\n");
            return 0;
        }
        ksu_sulog_emit_pending(pending_sucompat, ret, GFP_KERNEL);
        return 0;
    }

    if (likely(!strstr(filename->name, "/app_process") && !strstr(filename->name, "/adbd"))) {
        pr_info("susfs: mark no sucompat checks for pid: '%d', exec: '%s'\n", current->pid, filename->name);
        susfs_set_current_proc_umounted();
        return 0;
    }

#ifdef CONFIG_KSU_FEATURE_ADBROOT
#ifdef CONFIG_COMPAT
    if (unlikely(envp_user->is_compat))
        ret = ksu_adb_root_handle_execve_manual(filename->name, (void ***)&envp_user->ptr.compat);
    else
        ret = ksu_adb_root_handle_execve_manual(filename->name, (void ***)&envp_user->ptr.native);
#else
        ret = ksu_adb_root_handle_execve_manual(filename->name, (void ***)&envp_user->ptr.native);
#endif
#endif

    if (ret)
        pr_err("adb root failed: %d\n", ret);

    return ret;
}

// Renamed internally to _vfs so it doesn't conflict with the new upstream tracepoint hook signatures below
int ksu_handle_execveat_sucompat_vfs(int *fd, struct filename **filename_ptr,
                 void *argv_user, void *envp_user,
                 int *__never_use_flags)
{
    struct filename *filename;
    struct ksu_sulog_pending_event *pending_sucompat = NULL;
    int ret;

    if (unlikely(!filename_ptr))
        return 0;

    filename = *filename_ptr;
    if (IS_ERR(filename))
        return 0;

    if (!ksu_handle_execveat_init(filename, (struct user_arg_ptr*)argv_user, (struct user_arg_ptr*)envp_user))
        return 0;

    if (!(__ksu_is_allow_uid_for_current(current_uid().val)))
        return 0;

    if (likely(memcmp(filename->name, su_path, sizeof(su_path))))
        return 0;

    if (current_chrooted())
    {
        pr_err("ksu_handle_execveat_sucompat: su found but NOT allowed! Because current process is running in chrooted environment\n");
        return 0;
    }

    pr_info("ksu_handle_execveat_sucompat: su found\n");

    memcpy((void *)filename->name, ksud_path, sizeof(ksud_path));

    pending_sucompat = ksu_sulog_capture_sucompat(filename->name, (struct user_arg_ptr*)argv_user, GFP_KERNEL);

    ret = escape_with_root_profile();
    if (ret)
        pr_err("escape_with_root_profile() failed: %d\n", ret);

    const char __user *argv_user_ptr = get_user_arg_ptr(*((struct user_arg_ptr*)argv_user), 0);
    if (!argv_user_ptr || IS_ERR(argv_user_ptr)) {
        pr_err("!argv_user_ptr || IS_ERR(argv_user_ptr)\n");
        return 0;
    }

    ksu_sulog_emit_pending(pending_sucompat, ret, GFP_KERNEL);
    return 0;
}

long ksu_handle_newfstatat(int orig_nr, struct pt_regs *regs)
{
    const char __user **filename_user, *orig_filename;
    long ret;
    const struct cred *old_cred;

    if (!ksu_is_allow_uid_for_current(current_uid().val)) {
        goto do_orig_stat;
    }

    filename_user = (const char __user **)&PT_REGS_PARM2(regs);

    char path[sizeof(su_path) + 1];
    memset(path, 0, sizeof(path));
    strncpy_from_user_nofault(path, *filename_user, sizeof(path));

    if (unlikely(!memcmp(path, su_path, sizeof(su_path)))) {
        old_cred = override_creds(ksu_cred);
        if (is_ksud_exists()) {
            pr_info("newfstatat su->ksud!\n");
            orig_filename = *filename_user;
            *filename_user = ksud_user_path();
            ret = 0;
            revert_creds(old_cred);
            *filename_user = orig_filename;
            return ret;
        } else {
            revert_creds(old_cred);
        }
    }

do_orig_stat:
    return 0;
}

#ifdef KSU_COMPAT_USE_STATIC_KEY
extern struct static_key_true is_first_zygote;
#endif

int ksu_handle_execveat(int *fd, struct filename **filename_ptr, void *argv,
            void *envp, int *flags)
{
#ifdef KSU_COMPAT_USE_STATIC_KEY
    if (static_branch_unlikely(&is_first_zygote))
#else
    if (unlikely(first_zygote))
#endif
        (void)ksu_handle_execveat_ksud(fd, filename_ptr, argv, envp, flags);

    return ksu_handle_execveat_sucompat_vfs(fd, filename_ptr, argv, envp, flags);
}

int ksu_handle_faccessat(int *dfd, const char __user **filename_user, int *mode,
             int *__unused_flags)
{
    char path[sizeof(su_path) + 1] = {0};

    strncpy_from_user(path, *filename_user, sizeof(path));

    if (unlikely(!memcmp(path, su_path, sizeof(su_path)))) {
        if (current_chrooted())
        {
            pr_err("ksu_handle_faccessat: su found but NOT allowed! Because current process is running in chrooted environment\n");
            return 0;
        }
        pr_info("ksu_handle_faccessat: su->sh!\n");
        *filename_user = sh_user_path();
    }

    return 0;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
int ksu_handle_stat(int *dfd, struct filename **filename, int *flags) {
    if (unlikely(IS_ERR(*filename) || (*filename)->name == NULL))
        return 0;

    if (likely(memcmp((*filename)->name, su_path, sizeof(su_path))))
        return 0;

    if (current_chrooted())
    {
        pr_err("ksu_handle_stat: su found but NOT allowed! Because current process is running in chrooted environment\n");
        return 0;
    }
    pr_info("ksu_handle_stat: su->sh!\n");
    memcpy((void *)((*filename)->name), sh_path, sizeof(sh_path));
    return 0;
}
#else
int ksu_handle_stat(int *dfd, const char __user **filename_user, int *flags)
{
    if (unlikely(!filename_user))
        return 0;

    char path[sizeof(su_path) + 1] = {0};

    strncpy_from_user(path, *filename_user, sizeof(path));

    if (unlikely(!memcmp(path, su_path, sizeof(su_path)))) {
        if (current_chrooted())
        {
            pr_err("ksu_handle_stat: su found but NOT allowed! Because current process is running in chrooted environment\n");
            return 0;
        }
        pr_info("ksu_handle_stat: su->sh!\n");
        *filename_user = sh_user_path();
    }

    return 0;
}
#endif // #if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
#endif // CONFIG_KSU_SUSFS

// --- NEW UPSTREAM SYSCALL-BASED HOOKS ---

static long ksu_handle_execve_sucompat_common(const char __user **filename_user,
                                              const char __user *const __user *argv_user, unsigned long envp,
                                              bool execveat, int orig_nr, struct pt_regs *regs)
{
    struct ksu_sulog_pending_event *pending_sucompat = NULL;
    int tmp_fd, ret;
    struct file *ksud_file;
    const struct cred *old_cred;
    unsigned long orig_regs[5];

    if (execveat && ((int)PT_REGS_PARM1(regs) != AT_FDCWD || (int)PT_REGS_PARM5(regs) != 0))
        goto do_orig_execve;

    if (unlikely(!filename_user))
        goto do_orig_execve;

    char path[sizeof(su_path) + 1];
    memset(path, 0, sizeof(path));
    strncpy_from_user_nofault(path, *filename_user, sizeof(path));

    if (!ksu_is_allow_uid_for_current(current_uid().val)) {
        goto do_orig_execve;
    }

    if (unlikely(!memcmp(path, su_path, sizeof(su_path)))) {
#ifdef CONFIG_KSU_SUSFS
        if (current_chrooted()) {
            pr_err("ksu_handle_execve_sucompat_common: su found but NOT allowed! chrooted environment\n");
            goto do_orig_execve;
        }
#endif
        pr_info("sucompat su->ksud!\n");

        tmp_fd = get_unused_fd_flags(O_CLOEXEC);
        if (tmp_fd < 0) {
            pr_err("alloc tmp fd err: %d\n", tmp_fd);
            goto do_orig_execve;
        }

        old_cred = override_creds(ksu_cred);
        ksud_file = filp_open(KSUD_PATH, O_PATH, 0);
        revert_creds(old_cred);
        if (IS_ERR(ksud_file)) {
            pr_err("open ksud err: %ld\n", PTR_ERR(ksud_file));
            put_unused_fd(tmp_fd);
            goto do_orig_execve;
        }

        fd_install(tmp_fd, ksud_file);

#ifdef CONFIG_KSU_SUSFS
        struct user_arg_ptr argv_ptr = { .ptr.native = (void __user *)argv_user };
        pending_sucompat = ksu_sulog_capture_sucompat(*filename_user, &argv_ptr, GFP_KERNEL);
#else
        pending_sucompat = ksu_sulog_capture_sucompat(*filename_user, (void*)argv_user, GFP_KERNEL);
#endif

        orig_regs[0] = regs->__PT_PARM1_REG;
        orig_regs[1] = regs->__PT_PARM2_REG;
        orig_regs[2] = regs->__PT_PARM3_REG;
        orig_regs[3] = regs->__PT_SYSCALL_PARM4_REG;
        orig_regs[4] = regs->__PT_PARM5_REG;
        regs->__PT_PARM5_REG = AT_EMPTY_PATH;
        regs->__PT_SYSCALL_PARM4_REG = envp;
        regs->__PT_PARM3_REG = (unsigned long)argv_user;
        regs->__PT_PARM2_REG = (unsigned long)empty_user_path();
        regs->__PT_PARM1_REG = tmp_fd;

        ret = escape_with_root_profile();
        if (ret)
            pr_err("escape_with_root_profile() failed: %d\n", ret);

        ksu_sulog_emit_pending(pending_sucompat, ret, GFP_KERNEL);
        return 0;
    }

do_orig_execve:
    return 0;
}

long ksu_handle_execve_sucompat(const char __user **filename_user, int orig_nr, struct pt_regs *regs)
{
    return ksu_handle_execve_sucompat_common(filename_user, (const char __user *const __user *)PT_REGS_PARM2(regs),
                                             PT_REGS_PARM3(regs), false, orig_nr, regs);
}

long ksu_handle_execveat_sucompat(const char __user **filename_user, int orig_nr, struct pt_regs *regs)
{
    return ksu_handle_execve_sucompat_common(filename_user, (const char __user *const __user *)PT_REGS_PARM3(regs),
                                             PT_REGS_SYSCALL_PARM4(regs), true, orig_nr, regs);
}

// sucompat: permitted process can execute 'su' to gain root access.
void __init ksu_sucompat_init(void)
{
    if (ksu_register_feature_handler(&su_compat_handler)) {
        pr_err("Failed to register su_compat feature handler\n");
    }
}

void __exit ksu_sucompat_exit(void)
{
    ksu_unregister_feature_handler(KSU_FEATURE_SU_COMPAT);
}
