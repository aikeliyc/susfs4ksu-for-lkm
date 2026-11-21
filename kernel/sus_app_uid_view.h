/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * sus_app_uid_view.h - value-only rules for the app-uid filters.
 *
 * The two filters upstream v2.4.0 added (sus_path's uid whitelist and the
 * getpriority/setpriority uid blacklist) share one shape: a list of app package
 * names is resolved to uids in 10000..19999 and stored as a bitmap.  What
 * decides membership is pure arithmetic and byte classification, so it lives
 * here without a kernel dependency and is checked by
 * tools/sus_app_uid_view_test.c on the host; the RCU bitmap and the
 * /data/system/packages.list reader stay in sus_app_uid.c.
 */

#ifndef __SUS_APP_UID_VIEW_H
#define __SUS_APP_UID_VIEW_H

#ifdef __KERNEL__
#include <linux/types.h>
#else
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#endif

/* Android's per-user app id range (PER_USER_RANGE is 100000, app ids start at 10000).  Same
 * numbers as upstream susfs_def.h SUSFS_UID_FILTER_MIN_UID/MAX_UID. */
#define SUS_APP_UID_MIN 10000u
#define SUS_APP_UID_MAX 19999u
#define SUS_APP_UID_NUM (SUS_APP_UID_MAX - SUS_APP_UID_MIN + 1u)

/* Upstream rejects package names longer than 255 bytes. */
#define SUS_APP_NAME_MAX 255u

/* A package name is stored in packages.list and compared byte for byte.  Upstream's validator
 * (susfs_is_valid_app_name): 1..255 bytes of [A-Za-z0-9._], and neither "." nor ".." so a
 * crafted name cannot be read as a relative path by anything downstream. */
static inline bool sus_app_uid_name_valid(const char *name, size_t len)
{
    size_t i;

    if (!name || len == 0 || len > SUS_APP_NAME_MAX)
        return false;
    if (len == 1 && name[0] == '.')
        return false;
    if (len == 2 && name[0] == '.' && name[1] == '.')
        return false;
    for (i = 0; i < len; i++) {
        char c = name[i];

        if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
            (c >= '0' && c <= '9') || c == '.' || c == '_')
            continue;
        return false;
    }
    return true;
}

/* Only the primary user's app id range is filterable, which is what both upstream filters do
 * with `uid % 100000`. */
static inline bool sus_app_uid_in_range(uint32_t uid)
{
    return uid >= SUS_APP_UID_MIN && uid <= SUS_APP_UID_MAX;
}

static inline uint32_t sus_app_uid_index(uint32_t uid)
{
    return uid - SUS_APP_UID_MIN;
}

/* Upstream's susfs_is_uid_allowed_for_sus_path(): 90000..99999 (system-ish ids) always keep
 * seeing the paths, ids outside 10000..19999 are not app processes at all and answer "not
 * allowed" - the caller decides what that means.  The bitmap can only add to the 10000..19999
 * range. */
static inline bool sus_app_uid_visible_by_default(uint32_t app_id)
{
    return app_id >= 90000u;
}

#endif /* __SUS_APP_UID_VIEW_H */
