// SPDX-License-Identifier: GPL-2.0
/*
 * susfs_priority_filter.c - CMD_SUSFS_SET_PRIORITY_UID_FILTER (0x60030), new in susfs4ksu
 * v2.4.0.
 *
 * Upstream hides a set of app uids from the priority syscalls: a caller with uid >= 10000
 * (i.e. an app) that asks getpriority/setpriority for PRIO_USER, or ioprio_get/ioprio_set for
 * IOPRIO_WHO_USER, gets -ESRCH for any uid on the list, exactly as if no process of that user
 * existed.  The list arrives as package names and is resolved through the shared app-uid
 * bitmap (sus_app_uid.c), so renames count as new apps and reinstalls are picked up by the
 * refresh trigger.
 *
 * Upstream patches the kernel's sys.c and block/ioprio.c around the "who" loop; an LKM cannot
 * add code inside those functions, so the four entries are wrapped in sys_call_table instead
 * (the same mechanism susfs_kstat.c uses for the stat family).  The whole filter is one
 * early-return before the original entry: no argument inspection past `which`/`who`, and no
 * post-processing, because -ESRCH is the complete answer.
 *
 * Limitation, and it is the only one: the wrappers sit in the NATIVE table only.  arm64's
 * AArch32 syscall numbers for these four live in compat_sys_call_table and their wrappers have
 * a different signature; a 32-bit app therefore reaches the filter's blind side.  Android 12+
 * is 64-bit-only for apps, so this is the same coverage the module already gives the
 * 32-bit-facing control nodes.
 *
 * The filter being empty (no bitmap) is the fast path: one pointer load in the wrapper, then
 * the original entry - the hooks stay installed whether or not a list was ever set, because
 * the supercall can arm the filter at any time.
 */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/slab.h>
#include <linux/errno.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/resource.h>     /* PRIO_USER */
#include <linux/ioprio.h>       /* IOPRIO_WHO_USER */
#include <linux/sched.h>
#include <linux/cred.h>
#include <asm/syscall.h>
#include <asm/unistd.h>

#include "susfs_abi.h"
#include "susfs_log.h"
#include "susfs.h"
#include "susfs_fp_hook.h"
#include "sus_app_uid.h"

static susfs_syscall_fn_t prio_orig_getpriority;
static susfs_syscall_fn_t prio_orig_setpriority;
static susfs_syscall_fn_t prio_orig_ioprio_get;
static susfs_syscall_fn_t prio_orig_ioprio_set;

/* The filter applies to app callers only, like upstream's `cred->uid.val >= 10000`: a root
 * shell asking about the same uid is answered normally, which is what lets an operator check
 * that the uid exists. */
static inline bool prio_filter_applies(unsigned int which, unsigned long who, int user_which)
{
    if (which != (unsigned int)user_which)
        return false;
    if (current_uid().val < SUS_APP_UID_MIN)
        return false;
    return sus_app_uid_filter_hides(&sus_priority_uid_filter, (uid_t)who);
}

static __nocfi long prio_wrap_getpriority(const struct pt_regs *regs)
{
    susfs_syscall_fn_t orig = READ_ONCE(prio_orig_getpriority);
    unsigned long a[6];

    if (!orig)
        return -ENOSYS;
    if (sus_app_uid_filter_active(&sus_priority_uid_filter)) {
        syscall_get_arguments(current, (struct pt_regs *)regs, a);
        if (prio_filter_applies((unsigned int)a[0], a[1], PRIO_USER))
            return -ESRCH;
    }
    return orig(regs);
}

static __nocfi long prio_wrap_setpriority(const struct pt_regs *regs)
{
    susfs_syscall_fn_t orig = READ_ONCE(prio_orig_setpriority);
    unsigned long a[6];

    if (!orig)
        return -ENOSYS;
    if (sus_app_uid_filter_active(&sus_priority_uid_filter)) {
        syscall_get_arguments(current, (struct pt_regs *)regs, a);
        if (prio_filter_applies((unsigned int)a[0], a[1], PRIO_USER))
            return -ESRCH;
    }
    return orig(regs);
}

static __nocfi long prio_wrap_ioprio_get(const struct pt_regs *regs)
{
    susfs_syscall_fn_t orig = READ_ONCE(prio_orig_ioprio_get);
    unsigned long a[6];

    if (!orig)
        return -ENOSYS;
    if (sus_app_uid_filter_active(&sus_priority_uid_filter)) {
        syscall_get_arguments(current, (struct pt_regs *)regs, a);
        if (prio_filter_applies((unsigned int)a[0], a[1], IOPRIO_WHO_USER))
            return -ESRCH;
    }
    return orig(regs);
}

static __nocfi long prio_wrap_ioprio_set(const struct pt_regs *regs)
{
    susfs_syscall_fn_t orig = READ_ONCE(prio_orig_ioprio_set);
    unsigned long a[6];

    if (!orig)
        return -ENOSYS;
    if (sus_app_uid_filter_active(&sus_priority_uid_filter)) {
        syscall_get_arguments(current, (struct pt_regs *)regs, a);
        if (prio_filter_applies((unsigned int)a[0], a[1], IOPRIO_WHO_USER))
            return -ESRCH;
    }
    return orig(regs);
}

static struct susfs_fp_hook prio_hooks[] = {
    { .nr = __NR_getpriority, .nr_compat = 0, .name = "priority/getpriority",
      .sym = "__arm64_sys_getpriority",
      .wrapper = prio_wrap_getpriority, .orig_slot = &prio_orig_getpriority },
    { .nr = __NR_setpriority, .nr_compat = 0, .name = "priority/setpriority",
      .sym = "__arm64_sys_setpriority",
      .wrapper = prio_wrap_setpriority, .orig_slot = &prio_orig_setpriority },
    { .nr = __NR_ioprio_get, .nr_compat = 0, .name = "priority/ioprio_get",
      .sym = "__arm64_sys_ioprio_get",
      .wrapper = prio_wrap_ioprio_get, .orig_slot = &prio_orig_ioprio_get },
    { .nr = __NR_ioprio_set, .nr_compat = 0, .name = "priority/ioprio_set",
      .sym = "__arm64_sys_ioprio_set",
      .wrapper = prio_wrap_ioprio_set, .orig_slot = &prio_orig_ioprio_set },
};

/* Every one of the four has to be in the table: a partial set would answer -ESRCH on
 * getpriority but still let ioprio_get confirm the uid exists, which is the leak this feature
 * exists to close.  Refusing to arm the whole feature is the honest outcome; the supercall
 * then answers ERR_CMD_NOT_SUPPORTED like any other layer that did not come up. */
int susfs_priority_filter_init(void)
{
    int i, rc, armed = 0;

    sus_app_uid_filter_init(&sus_priority_uid_filter, "priority");

    for (i = 0; i < (int)ARRAY_SIZE(prio_hooks); i++) {
        struct susfs_fp_hook *h = &prio_hooks[i];

        rc = susfs_fp_install(h);
        if (rc) {
            pr_warn("priority uid filter: %s not installed (%d)\n", h->name, rc);
            break;
        }
        armed++;
    }

    if (armed != (int)ARRAY_SIZE(prio_hooks)) {
        int n;

        for (n = 0; n < (int)ARRAY_SIZE(prio_hooks); n++) {
            if (prio_hooks[n].installed)
                susfs_fp_remove(&prio_hooks[n]);
        }
        if (armed)
            susfs_fp_drain();
        sus_app_uid_filter_exit(&sus_priority_uid_filter);
        pr_warn("priority uid filter: %d/%u syscall entries armable - the feature stays off\n",
                armed, (unsigned int)ARRAY_SIZE(prio_hooks));
        return -ENOENT;
    }

    SUSFS_LOGI("priority uid filter: getpriority/setpriority and ioprio_get/ioprio_set wrapped\n");
    return 0;
}

void susfs_priority_filter_exit(void)
{
    int i;

    for (i = 0; i < (int)ARRAY_SIZE(prio_hooks); i++) {
        if (prio_hooks[i].installed)
            susfs_fp_remove(&prio_hooks[i]);
    }
    susfs_fp_drain();
    sus_app_uid_filter_exit(&sus_priority_uid_filter);
}

/* CMD_SUSFS_SET_PRIORITY_UID_FILTER (0x60030).  Struct layout: 65535 bytes of names then
 * `int err`, so 65540 total, allocated with kvmalloc for the same order-4 reason as sus_path's
 * uid filter supercall. */
void susfs_priority_filter_supercall(void __user **arg)
{
    struct st_susfs_priority_uid_filter *info;
    int err = -ENOMEM;

    info = kvmalloc(sizeof(*info), GFP_KERNEL | __GFP_ZERO);
    if (info) {
        if (copy_from_user(info, (void __user *)*arg, sizeof(*info))) {
            err = -EFAULT;
        } else if (!memchr(info->app_strings, '\0', sizeof(info->app_strings))) {
            err = -EINVAL;
        } else {
            err = sus_app_uid_filter_set(&sus_priority_uid_filter, info->app_strings);
        }
    }
    if (copy_to_user(&((struct st_susfs_priority_uid_filter __user *)*arg)->err,
                     &err, sizeof(err)))
        pr_warn("priority uid filter supercall copy_to_user failed\n");
    kvfree(info);
}
