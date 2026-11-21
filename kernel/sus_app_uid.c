// SPDX-License-Identifier: GPL-2.0
/*
 * sus_app_uid.c - app package name -> uid bitmap, shared by sus_path's uid whitelist and the
 * getpriority/setpriority uid blacklist (both added upstream in susfs4ksu v2.4.0).
 *
 * Upstream resolves every package name from /data/system/packages.list while the caller's
 * SELinux domain is temporarily switched to KernelSU's, because the su domain may read the
 * file and the default domain may not.  An LKM cannot commit credentials into the calling
 * task safely from a kprobe, so this port borrows KernelSU's own ksu_cred through
 * override_creds(): KernelSU reads packages.list in exactly that context itself
 * (kernel/manager/throne_tracker.c: override_creds(ksu_cred)), and it works whatever the su
 * domain is called in this fork.  ksu_cred is a data symbol, resolved once by name and then
 * read with copy_from_kernel_nofault(); when it cannot be found the caller's own credentials
 * are used instead (the supercall caller is root in the su domain).
 *
 * Why refresh at all: an app's uid changes on reinstall, so a bitmap resolved once goes stale.
 * Upstream re-resolves from KernelSU's package observer; here a kprobe on KernelSU's
 * track_throne() kicks a delayable work.  A kprobe keeps a reference on the module that owns
 * the probed symbol, so while the probe is registered the kernelsu module cannot be unloaded;
 * app_uid_auto_refresh=0 avoids that pin (and gives up the automatic refresh - an explicit
 * /proc `refresh` still works).
 */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/cred.h>
#include <linux/err.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/jiffies.h>
#include <linux/bitmap.h>
#include <linux/rculist.h>
#include <linux/kprobes.h>

#include "susfs_abi.h"
#include "susfs_log.h"
#include "symbol_resolver.h"
#include <linux/proc_fs.h>
#include <linux/seq_file.h>

#include "susfs.h"
#include "ksu_allow_gate.h"
#include "sus_app_uid.h"

#define SUS_APP_PACKAGES_LIST "/data/system/packages.list"
#define SUS_APP_PACKAGES_MAX  (4 * 1024 * 1024)
/* One refresh per filter at most this often: track_throne() runs after every package event, and
 * each refresh reads and parses a file of a few hundred KB. */
#define SUS_APP_REFRESH_MIN_MS 5000

/* The filters a refresh trigger may kick.  Writers add/remove under @registry_lock with the RCU
 * variants; the kprobe walks the list under rcu_read_lock(). */
static LIST_HEAD(sus_app_uid_filters);
static DEFINE_MUTEX(sus_app_uid_registry_lock);

/* ---- credentials ---- */

/* Returns a reference the caller must put_cred(), or NULL when KernelSU's data symbol cannot be
 * resolved/read.  A data symbol is a POINTER VARIABLE: the address kallsyms gives us holds the
 * pointer, not the struct, and a stale/unset value must be rejected before get_cred() touches it
 * (get_cred() writes the refcount word). */
static const struct cred *sus_app_uid_ksu_cred(void)
{
    unsigned long addr;
    struct cred *cred = NULL;

    addr = find_kernel_symbol_exact("ksu_cred");
    if (!addr)
        return NULL;
    if (copy_from_kernel_nofault(&cred, (void *)addr, sizeof(cred)))
        return NULL;
    if (!cred || IS_ERR(cred) || (unsigned long)cred < 0x1000UL)
        return NULL;
    return get_cred(cred);
}

/* Same shape as sus_path.c's pending-cred borrow: get_cred() keeps the cred alive for the read,
 * override_creds() is undone by revert_creds(), and the reference we took is put here. */
static const struct cred *sus_app_uid_cred_begin(const struct cred **borrowed)
{
    const struct cred *cred;

    *borrowed = NULL;
    cred = sus_app_uid_ksu_cred();
    if (!cred)
        return NULL;
    *borrowed = cred;
    return override_creds(cred);
}

static void sus_app_uid_cred_end(const struct cred *saved, const struct cred *borrowed)
{
    if (saved)
        revert_creds(saved);
    if (borrowed)
        put_cred(borrowed);
}

/* ---- /data/system/packages.list ---- */

/* Reads the whole file into a kvmalloc'ed, NUL-terminated buffer.  Returns the size on success
 * and a negative errno on failure; *out is only set on success. */
static ssize_t sus_app_uid_read_packages(char **out)
{
    struct file *fp;
    const struct cred *borrowed;
    const struct cred *saved;
    char *buf;
    loff_t pos = 0;
    size_t size;
    ssize_t n;

    *out = NULL;
    saved = sus_app_uid_cred_begin(&borrowed);

    fp = filp_open(SUS_APP_PACKAGES_LIST, O_RDONLY | O_NOATIME, 0);
    if (IS_ERR(fp))
        fp = filp_open(SUS_APP_PACKAGES_LIST, O_RDONLY, 0);
    if (IS_ERR(fp)) {
        n = PTR_ERR(fp);
        goto out_end;
    }

    size = i_size_read(file_inode(fp));
    if (!size || size > SUS_APP_PACKAGES_MAX) {
        filp_close(fp, NULL);
        n = size ? -EFBIG : -EIO;
        goto out_end;
    }

    buf = kvmalloc(size + 1, GFP_KERNEL);
    if (!buf) {
        filp_close(fp, NULL);
        n = -ENOMEM;
        goto out_end;
    }
    buf[size] = '\0';

    n = kernel_read(fp, buf, size, &pos);
    filp_close(fp, NULL);
    if (n != (ssize_t)size) {
        kvfree(buf);
        n = -EIO;
        goto out_end;
    }

    *out = buf;
    n = (ssize_t)size;

out_end:
    sus_app_uid_cred_end(saved, borrowed);
    return n;
}

/* packages.list, one package per line: "<package> <uid> <gid> ...".  Compares the package name
 * byte for byte (no NUL-termination assumption: the buffer is a whole file) and reads the
 * decimal uid that follows.  Returns 0 when found, -ENOENT otherwise. */
static int sus_app_uid_lookup(const char *list, size_t list_len,
                              const char *name, size_t name_len, uid_t *uid)
{
    size_t pos = 0;

    while (pos < list_len) {
        size_t line_end = pos;
        size_t q, pkg_start, pkg_len;
        unsigned long val = 0;
        bool digit = false;

        while (line_end < list_len && list[line_end] != '\n')
            line_end++;

        q = pos;
        while (q < line_end && (list[q] == ' ' || list[q] == '\t'))
            q++;
        pkg_start = q;
        while (q < line_end && list[q] != ' ' && list[q] != '\t' && list[q] != '\r')
            q++;
        pkg_len = q - pkg_start;

        if (pkg_len == name_len && !memcmp(list + pkg_start, name, name_len)) {
            while (q < line_end && (list[q] == ' ' || list[q] == '\t'))
                q++;
            while (q < line_end && list[q] >= '0' && list[q] <= '9') {
                digit = true;
                if (val <= 1000000UL)
                    val = val * 10UL + (unsigned long)(list[q] - '0');
                q++;
            }
            if (!digit)
                return -EINVAL;
            *uid = (uid_t)(val % 100000UL);
            return 0;
        }

        pos = line_end + 1;
    }

    return -ENOENT;
}

/* Resolves every name in @apps into @bm.  Invalid names fail the whole call (upstream's
 * -EINVAL); names that are not in packages.list are skipped and only counted (upstream calls
 * that skip_failed, so a just-uninstalled package does not make set_sus_path_uid_filter fail).
 * A missing/unreadable packages.list also leaves the bitmap empty instead of failing: the names
 * are stored anyway and the refresh worker fills it in once /data is readable. */
static int sus_app_uid_parse_names(const char *label, const char *apps,
                                   struct sus_app_uid_bitmap *bm)
{
    char *list = NULL;
    ssize_t list_len;
    size_t total = 0, resolved = 0;
    const char *p = apps;

    while (*p) {
        const char *comma = strchr(p, ',');
        size_t len = comma ? (size_t)(comma - p) : strlen(p);

        while (len && (*p == ' ' || *p == '\t')) {
            p++;
            len--;
        }
        while (len && (p[len - 1] == ' ' || p[len - 1] == '\t'))
            len--;

        if (len) {
            total++;
            if (!sus_app_uid_name_valid(p, len)) {
                pr_warn("susfs_guard_lkm: %s uid filter: invalid app name '%.*s'\n",
                        label, (int)len, p);
                kvfree(list);
                return -EINVAL;
            }

            if (!list) {
                list_len = sus_app_uid_read_packages(&list);
                if (list_len < 0) {
                    pr_warn("susfs_guard_lkm: %s uid filter: cannot read %s (%zd) - the names are stored and resolved on refresh\n",
                            label, SUS_APP_PACKAGES_LIST, list_len);
                    return 0;
                }
            }

            {
                uid_t uid = 0;

                if (!sus_app_uid_lookup(list, (size_t)list_len, p, len, &uid)) {
                    if (sus_app_uid_in_range(uid)) {
                        set_bit(sus_app_uid_index(uid), bm->bits);
                        resolved++;
                        SUSFS_LOGI("%s uid filter: app '%.*s' -> uid %u\n",
                                label, (int)len, p, uid);
                    }
                }
            }
        }

        if (!comma)
            break;
        p = comma + 1;
    }

    kvfree(list);
    if (total && !resolved)
        pr_warn("susfs_guard_lkm: %s uid filter: none of the %zu name(s) resolved to an app uid in %s\n",
                label, total, SUS_APP_PACKAGES_LIST);
    return 0;
}

/* ---- bitmap lifecycle ---- */

static void sus_app_uid_publish(struct sus_app_uid_filter *f,
                                struct sus_app_uid_bitmap *bm, char *strings)
{
    struct sus_app_uid_bitmap *old;

    mutex_lock(&f->lock);
    old = rcu_dereference_protected(f->bitmap, lockdep_is_held(&f->lock));
    rcu_assign_pointer(f->bitmap, bm);
    if (strings) {
        kvfree(f->app_strings);
        f->app_strings = strings;
        f->has_strings = true;
    }
    mutex_unlock(&f->lock);

    if (old)
        kfree_rcu(old, rcu);
}

int sus_app_uid_filter_set(struct sus_app_uid_filter *f, const char *apps)
{
    struct sus_app_uid_bitmap *bm;
    char *strings;
    size_t len;

    if (!f || !apps || !apps[0])
        return -EINVAL;
    len = strlen(apps);
    if (len >= SUSFS_APP_STR_BUF_SIZE)
        return -EINVAL;

    strings = kvzalloc(len + 1, GFP_KERNEL);
    if (!strings)
        return -ENOMEM;
    memcpy(strings, apps, len + 1);

    bm = kzalloc(sizeof(*bm), GFP_KERNEL);
    if (!bm) {
        kvfree(strings);
        return -ENOMEM;
    }

    if (sus_app_uid_parse_names(f->label, strings, bm)) {
        kvfree(strings);
        kfree(bm);
        return -EINVAL;
    }

    sus_app_uid_publish(f, bm, strings);
    return 0;
}

void sus_app_uid_filter_clear(struct sus_app_uid_filter *f)
{
    if (!f)
        return;
    mutex_lock(&f->lock);
    kvfree(f->app_strings);
    f->app_strings = NULL;
    f->has_strings = false;
    mutex_unlock(&f->lock);
    sus_app_uid_publish(f, NULL, NULL);
}

/* ---- readers ---- */

bool sus_app_uid_filter_active(const struct sus_app_uid_filter *f)
{
    return f && rcu_access_pointer(f->bitmap) != NULL;
}

int sus_app_uid_filter_uid_count(const struct sus_app_uid_filter *f)
{
    struct sus_app_uid_bitmap *bm;
    int n = 0;

    if (!f)
        return 0;
    rcu_read_lock();
    bm = rcu_dereference(f->bitmap);
    if (bm)
        n = bitmap_weight(bm->bits, SUS_APP_UID_NUM);
    rcu_read_unlock();
    return n == 0 ? 0 : n;
}

bool sus_app_uid_filter_allows(const struct sus_app_uid_filter *f, uid_t uid)
{
    struct sus_app_uid_bitmap *bm;
    uint32_t app_id = (uint32_t)(uid % 100000UL);
    bool allowed = false;

    if (sus_app_uid_visible_by_default(app_id))
        return true;
    if (!sus_app_uid_in_range(app_id) || !f)
        return false;

    rcu_read_lock();
    bm = rcu_dereference(f->bitmap);
    if (bm && test_bit(sus_app_uid_index(app_id), bm->bits))
        allowed = true;
    rcu_read_unlock();
    return allowed;
}

bool sus_app_uid_filter_hides(const struct sus_app_uid_filter *f, uid_t uid)
{
    struct sus_app_uid_bitmap *bm;
    uint32_t app_id = (uint32_t)(uid % 100000UL);
    bool hidden = false;

    if (!sus_app_uid_in_range(app_id) || !f)
        return false;

    rcu_read_lock();
    bm = rcu_dereference(f->bitmap);
    if (bm && test_bit(sus_app_uid_index(app_id), bm->bits))
        hidden = true;
    rcu_read_unlock();
    return hidden;
}

/* ---- refresh ---- */

static int sus_app_uid_refresh(struct sus_app_uid_filter *f)
{
    struct sus_app_uid_bitmap *bm;
    char *strings;

    mutex_lock(&f->lock);
    if (!f->has_strings || !f->app_strings) {
        mutex_unlock(&f->lock);
        return 0;
    }
    strings = kstrdup(f->app_strings, GFP_KERNEL);
    mutex_unlock(&f->lock);
    if (!strings)
        return -ENOMEM;

    bm = kzalloc(sizeof(*bm), GFP_KERNEL);
    if (!bm) {
        kfree(strings);
        return -ENOMEM;
    }

    if (sus_app_uid_parse_names(f->label, strings, bm)) {
        kfree(strings);
        kfree(bm);
        return -EINVAL;
    }
    kfree(strings);

    sus_app_uid_publish(f, bm, NULL);
    SUSFS_LOGI("%s uid filter: re-resolved the stored app names (%d uid(s))\n",
            f->label, sus_app_uid_filter_uid_count(f));
    return 0;
}

int sus_app_uid_filter_refresh_now(struct sus_app_uid_filter *f)
{
    return f ? sus_app_uid_refresh(f) : -EINVAL;
}

static void sus_app_uid_refresh_work(struct work_struct *work)
{
    struct sus_app_uid_filter *f =
        container_of(to_delayed_work(work), struct sus_app_uid_filter, refresh_work);

    if (atomic_cmpxchg(&f->refreshing, 0, 1))
        return;   /* one refresh at a time is enough */
    sus_app_uid_refresh(f);
    atomic_set(&f->refreshing, 0);
}

void sus_app_uid_filter_kick(struct sus_app_uid_filter *f)
{
    unsigned long now = jiffies;

    if (!f || !READ_ONCE(f->has_strings))
        return;
    if (READ_ONCE(f->next_refresh) && time_before(now, READ_ONCE(f->next_refresh)))
        return;
    WRITE_ONCE(f->next_refresh, now + msecs_to_jiffies(SUS_APP_REFRESH_MIN_MS));
    queue_delayed_work(system_wq, &f->refresh_work, 0);
}

/* ---- refresh trigger: KernelSU's package observer ---- */

static bool sus_app_uid_auto_refresh = true;
module_param_named(app_uid_auto_refresh, sus_app_uid_auto_refresh, bool, 0644);
MODULE_PARM_DESC(app_uid_auto_refresh,
    "re-resolve the uid filters when KernelSU sees a package change (kprobe on track_throne; pins the kernelsu module while loaded)");

static int sus_app_refresh_pre(struct kprobe *kp, struct pt_regs *regs)
{
    struct sus_app_uid_filter *f;

    rcu_read_lock();
    list_for_each_entry_rcu(f, &sus_app_uid_filters, node)
        sus_app_uid_filter_kick(f);
    rcu_read_unlock();
    return 0;
}

static struct kprobe sus_app_refresh_kp = {
    .symbol_name = "track_throne",
    .pre_handler = sus_app_refresh_pre,
};

static bool sus_app_refresh_probe_armed;

static int sus_app_refresh_probe_arm(void)
{
    int rc;

    if (sus_app_refresh_probe_armed)
        return 0;
    if (!sus_app_uid_auto_refresh) {
        SUSFS_LOGI("app uid filter: auto refresh disabled (app_uid_auto_refresh=0)\n");
        return 0;
    }

    rc = register_kprobe(&sus_app_refresh_kp);
    if (rc) {
        /* Not fatal: the uids resolved at set time stay correct until the next set or an
         * explicit /proc refresh. */
        pr_warn("susfs_guard_lkm: app uid filter: track_throne probe not registered (%d) - filters will not self-refresh\n", rc);
        return rc;
    }
    sus_app_refresh_probe_armed = true;
    SUSFS_LOGI("app uid filter: refresh trigger armed on KernelSU's track_throne()\n");
    return 0;
}

static void sus_app_refresh_probe_disarm(void)
{
    if (!sus_app_refresh_probe_armed)
        return;
    unregister_kprobe(&sus_app_refresh_kp);
    sus_app_refresh_probe_armed = false;
}

/* ---- init/exit ---- */

void sus_app_uid_filter_init(struct sus_app_uid_filter *f, const char *label)
{
    f->label = label;
    f->bitmap = NULL;
    f->app_strings = NULL;
    f->has_strings = false;
    f->next_refresh = 0;
    f->registered = false;
    mutex_init(&f->lock);
    INIT_DELAYED_WORK(&f->refresh_work, sus_app_uid_refresh_work);
    INIT_LIST_HEAD(&f->node);
    atomic_set(&f->refreshing, 0);

    mutex_lock(&sus_app_uid_registry_lock);
    if (list_empty(&sus_app_uid_filters))
        sus_app_refresh_probe_arm();
    list_add_tail_rcu(&f->node, &sus_app_uid_filters);
    mutex_unlock(&sus_app_uid_registry_lock);
    f->registered = true;
}

void sus_app_uid_filter_exit(struct sus_app_uid_filter *f)
{
    struct sus_app_uid_bitmap *bm;

    /* Idempotent, and required: susfs_layers_down() runs the exit of every layer it ATTEMPTED,
     * including one whose init failed (fail_layer=...).  A filter that was never initialised has
     * an uninitialised delayed_work, which cancel_delayed_work_sync() must not see. */
    if (!f || !f->registered)
        return;

    cancel_delayed_work_sync(&f->refresh_work);

    mutex_lock(&sus_app_uid_registry_lock);
    list_del_rcu(&f->node);
    if (list_empty(&sus_app_uid_filters))
        sus_app_refresh_probe_disarm();
    mutex_unlock(&sus_app_uid_registry_lock);
    f->registered = false;
    synchronize_rcu();   /* the kprobe may still be walking the list */

    mutex_lock(&f->lock);
    bm = rcu_dereference_protected(f->bitmap, lockdep_is_held(&f->lock));
    rcu_assign_pointer(f->bitmap, NULL);
    kvfree(f->app_strings);
    f->app_strings = NULL;
    f->has_strings = false;
    mutex_unlock(&f->lock);

    if (bm) {
        synchronize_rcu();   /* the LSM hooks / syscall wrappers may still hold a pointer */
        kfree(bm);
    }
}

/* ---- /proc status line ---- */

int sus_app_uid_filter_status(const struct sus_app_uid_filter *f, char *buf, size_t size)
{
    int n;

    if (!f)
        return scnprintf(buf, size, "active=0");
    n = scnprintf(buf, size, "active=%d uids=%d apps=",
                  sus_app_uid_filter_active(f) ? 1 : 0,
                  sus_app_uid_filter_uid_count(f));
    if (n < (int)size && f->has_strings && f->app_strings) {
        size_t len = strnlen(f->app_strings, 160);

        n += scnprintf(buf + n, size - n, "%.*s%s", (int)len, f->app_strings,
                       len < strlen(f->app_strings) ? "..." : "");
    }
    return n;
}


/* ---- /proc/susfs_app_uid ---- */

struct sus_app_uid_filter sus_path_uid_filter;
struct sus_app_uid_filter sus_priority_uid_filter;

static struct proc_dir_entry *sus_app_uid_node;

static void sus_app_uid_status_lines(struct seq_file *m)
{
    char line[512];

    if (sus_path_uid_filter.registered) {
        sus_app_uid_filter_status(&sus_path_uid_filter, line, sizeof(line));
        seq_printf(m, "sus_path: %s\n", line);
    } else {
        seq_printf(m, "sus_path: unavailable (layer did not load)\n");
    }
    if (sus_priority_uid_filter.registered) {
        sus_app_uid_filter_status(&sus_priority_uid_filter, line, sizeof(line));
        seq_printf(m, "priority: %s\n", line);
    } else {
        seq_printf(m, "priority: unavailable (layer did not load)\n");
    }
}

static int sus_app_uid_proc_show(struct seq_file *m, void *v)
{
    sus_app_uid_status_lines(m);
    return 0;
}

static int sus_app_uid_proc_open(struct inode *inode, struct file *file)
{
    if (!susfs_control_visible())
        return -ENOENT;
    return single_open(file, sus_app_uid_proc_show, NULL);
}

static struct sus_app_uid_filter *sus_app_uid_target(const char *name)
{
    if (!strcmp(name, "sus_path"))
        return sus_path_uid_filter.registered ? &sus_path_uid_filter : NULL;
    if (!strcmp(name, "priority"))
        return sus_priority_uid_filter.registered ? &sus_priority_uid_filter : NULL;
    return NULL;
}

/* Grammar:
 *     sus_path <pkg,pkg,...>      priority <pkg,pkg,...>
 *     clear [sus_path|priority]   refresh [sus_path|priority]
 * A bare `clear` applies to both filters that are up. */
static int sus_app_uid_command(char *cmd)
{
    char *arg, *name;
    int rc = 0;

    arg = cmd;
    while (*arg == ' ' || *arg == '\t')
        arg++;

    if (!strncmp(arg, "sus_path", 8) && (arg[8] == ' ' || arg[8] == '\t')) {
        arg += 8;
        while (*arg == ' ' || *arg == '\t')
            arg++;
        if (!*arg)
            return -EINVAL;
        return sus_app_uid_filter_set(&sus_path_uid_filter, arg);
    }
    if (!strncmp(arg, "priority", 8) && (arg[8] == ' ' || arg[8] == '\t')) {
        arg += 8;
        while (*arg == ' ' || *arg == '\t')
            arg++;
        if (!*arg)
            return -EINVAL;
        return sus_app_uid_filter_set(&sus_priority_uid_filter, arg);
    }

    name = NULL;
    if (!strcmp(arg, "clear") || !strcmp(arg, "refresh")) {
        bool clear = (arg[0] == 'c');

        if (sus_path_uid_filter.registered) {
            if (clear)
                sus_app_uid_filter_clear(&sus_path_uid_filter);
            else
                rc = sus_app_uid_filter_refresh_now(&sus_path_uid_filter);
        }
        if (sus_priority_uid_filter.registered) {
            if (clear)
                sus_app_uid_filter_clear(&sus_priority_uid_filter);
            else
                rc = sus_app_uid_filter_refresh_now(&sus_priority_uid_filter);
        }
        return rc;
    }

    if (!strncmp(arg, "clear ", 6))
        name = arg + 6;
    else if (!strncmp(arg, "refresh ", 8))
        name = arg + 8;
    if (!name)
        return -EINVAL;
    while (*name == ' ' || *name == '\t')
        name++;
    if (!*name)
        return -EINVAL;

    if (arg[0] == 'c') {
        struct sus_app_uid_filter *f = sus_app_uid_target(name);

        if (!f)
            return -ENODEV;
        sus_app_uid_filter_clear(f);
        return 0;
    }
    {
        struct sus_app_uid_filter *f = sus_app_uid_target(name);

        if (!f)
            return -ENODEV;
        return sus_app_uid_filter_refresh_now(f);
    }
}

static ssize_t sus_app_uid_proc_write(struct file *file, const char __user *ubuf,
                                      size_t len, loff_t *off)
{
    char *cmd;
    int rc;

    if (!susfs_control_visible())
        return -ENOENT;
    if (!len)
        return 0;
    /* One command byte for the selector plus the ABI's app-string buffer. */
    if (len > SUSFS_APP_STR_BUF_SIZE + 16)
        return -E2BIG;

    cmd = kvzalloc(len + 1, GFP_KERNEL);
    if (!cmd)
        return -ENOMEM;
    if (copy_from_user(cmd, ubuf, len)) {
        kvfree(cmd);
        return -EFAULT;
    }
    for (rc = (int)len - 1; rc >= 0 &&
         (cmd[rc] == '\n' || cmd[rc] == '\r' || cmd[rc] == ' ' || cmd[rc] == '\t'); rc--)
        cmd[rc] = '\0';

    rc = sus_app_uid_command(cmd);
    kvfree(cmd);
    return rc ? rc : (ssize_t)len;
}

static const struct proc_ops sus_app_uid_proc_ops = {
    .proc_open = sus_app_uid_proc_open,
    .proc_read = seq_read,
    .proc_write = sus_app_uid_proc_write,
    .proc_lseek = seq_lseek,
    .proc_release = single_release,
};

void sus_app_uid_proc_init(void)
{
    if (!susfs_control_node_allowed())
        return;
    sus_app_uid_node = proc_create(SUSFS_APP_UID_NODE, 0777, NULL, &sus_app_uid_proc_ops);
    if (!sus_app_uid_node)
        pr_warn("susfs_guard_lkm: cannot create %s\n", SUSFS_APP_UID_NODE);
}

void sus_app_uid_proc_exit(void)
{
    if (sus_app_uid_node) {
        proc_remove(sus_app_uid_node);
        sus_app_uid_node = NULL;
    }
}
