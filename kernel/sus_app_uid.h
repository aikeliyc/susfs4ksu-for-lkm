/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * sus_app_uid.h - the app-uid bitmap filters introduced by susfs4ksu v2.4.0.
 *
 * Upstream stores a list of app PACKAGE NAMES, resolves their uids from
 * /data/system/packages.list and maps those uids into a 10000-bit bitmap
 * (10000..19999).  The names are kept so the uids can be resolved again after
 * an app is reinstalled (its uid changes); upstream refreshes them from
 * KernelSU's package observer, this LKM kicks a workqueue from a kprobe on
 * KernelSU's track_throne().
 *
 * Two consumers share the machinery:
 *   sus_path          CMD_SUSFS_SET_SUS_PATH_UID_FILTER  (0x55554) - WHITELIST:
 *                     a listed uid still sees the registered sus paths, every other app uid
 *                     keeps them hidden.
 *   priority          CMD_SUSFS_SET_PRIORITY_UID_FILTER  (0x60030) - BLACKLIST:
 *                     a listed uid is invisible to getpriority/setpriority and
 *                     ioprio_get/ioprio_set from every caller with uid >= 10000.
 *
 * The bitmap is published with RCU: the sus_path LSM hooks and the four
 * priority syscall wrappers are hot paths and must never take a mutex.  The
 * name list and the bitmap are replaced as a pair, so a reader either sees the
 * old pair or the new one.  All writers (the supercall, the /proc commands and
 * the refresh worker) run in process context and serialise on @lock.
 */
#ifndef __SUS_APP_UID_H
#define __SUS_APP_UID_H

#include <linux/types.h>
#include <linux/bitmap.h>
#include <linux/cred.h>
#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/rcupdate.h>
#include <linux/workqueue.h>

#include "sus_app_uid_view.h"

#define SUS_APP_UID_BITMAP_LEN BITS_TO_LONGS(SUS_APP_UID_NUM)

struct sus_app_uid_bitmap {
    struct rcu_head rcu;
    unsigned long bits[SUS_APP_UID_BITMAP_LEN];
};

struct sus_app_uid_filter {
    const char *label;                      /* "sus_path" / "priority", for logs */
    struct sus_app_uid_bitmap __rcu *bitmap; /* NULL = no filter armed */
    char *app_strings;                      /* the names, as the caller sent them */
    bool has_strings;
    struct mutex lock;                      /* writers + the name list */
    struct delayed_work refresh_work;
    struct list_head node;                  /* registry the track_throne probe walks */
    bool registered;
    unsigned long next_refresh;             /* rate limit for the kprobe kick */
    atomic_t refreshing;                    /* one refresh at a time */
};

/* The two consumers' state.  They are defined in sus_app_uid.c so the /proc node and the
 * refresh trigger can name them without either feature file owning the other's state.  A
 * feature whose layer did not come up leaves .registered false. */
extern struct sus_app_uid_filter sus_path_uid_filter;
extern struct sus_app_uid_filter sus_priority_uid_filter;

#define SUSFS_APP_UID_NODE "/proc/susfs_app_uid"

/* Static initialisation only: registers the filter with the refresh trigger and INITs the
 * work; no memory is allocated and it cannot fail. */
void sus_app_uid_filter_init(struct sus_app_uid_filter *f, const char *label);
/* Cancels the refresh work, unregisters and frees what set() published.  Process context. */
void sus_app_uid_filter_exit(struct sus_app_uid_filter *f);

/* Replaces the whole filter with @apps (a comma-separated package-name list).  Resolves the
 * names NOW, stores the names for later refreshes and publishes the bitmap.  Package names that
 * cannot be found in /data/system/packages.list are skipped (upstream does the same, so a
 * just-uninstalled app does not make the command fail) and counted in the log; an invalid name
 * makes the whole call fail with -EINVAL, like upstream.  Process context. */
int sus_app_uid_filter_set(struct sus_app_uid_filter *f, const char *apps);

/* Drops the filter (no bitmap, no names): both consumers go back to their unfiltered behaviour. */
void sus_app_uid_filter_clear(struct sus_app_uid_filter *f);

/* Lockless hot-path queries.  @uid is the raw current uid; the % PER_USER_RANGE is done here. */
bool sus_app_uid_filter_active(const struct sus_app_uid_filter *f);
/* sus_path: true = this uid is listed and therefore keeps seeing the rules. */
bool sus_app_uid_filter_allows(const struct sus_app_uid_filter *f, uid_t uid);
/* priority: true = this uid is listed and therefore hidden from the priority syscalls. */
bool sus_app_uid_filter_hides(const struct sus_app_uid_filter *f, uid_t uid);

/* Resolve the stored names again, synchronously (the /proc `refresh` command).  Returns 0 or
 * a negative errno; with no names stored it is a no-op success. */
int sus_app_uid_filter_refresh_now(struct sus_app_uid_filter *f);

/* Schedule the same work on system_wq.  Safe from atomic context (the kprobe). */
void sus_app_uid_filter_kick(struct sus_app_uid_filter *f);

/* One line for /proc: "active=1 apps=24 chars uids=3 sample=com.a,com.b". */
int sus_app_uid_filter_status(const struct sus_app_uid_filter *f, char *buf, size_t size);

/* Number of uids currently in the bitmap (0 when no filter). */
int sus_app_uid_filter_uid_count(const struct sus_app_uid_filter *f);

/* /proc/susfs_app_uid: one node for both filters (`sus_path <apps>`, `priority <apps>`,
 * `clear [sus_path|priority]`, `refresh [sus_path|priority]`).  Created after every layer has
 * initialised and removed before the layers go down; a no-op when expose_proc=0 or sus_path's
 * LSM layer is not there. */
void sus_app_uid_proc_init(void);
void sus_app_uid_proc_exit(void);

/* The refresh trigger (a kprobe on KernelSU's track_throne(), armed by the first filter init and
 * disarmed by the last filter exit) is internal to sus_app_uid.c; see its file header for the
 * app_uid_auto_refresh=0 escape hatch. */

#endif /* __SUS_APP_UID_H */
