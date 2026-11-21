/* SPDX-License-Identifier: GPL-2.0-only */
/* Host contract test for sus_app_uid_view.h (the pure half of the v2.4.0 app-uid filters). */
#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "sus_app_uid_view.h"

static bool name_ok(const char *s)
{
	return sus_app_uid_name_valid(s, strlen(s));
}

int main(void)
{
	char long_name[SUS_APP_NAME_MAX + 2];

	/* Package names that packages.list really carries. */
	assert(name_ok("com.android.chrome"));
	assert(name_ok("com.example_1.app-2") == false);	/* '-' is not in the allowed set */
	assert(name_ok("a"));
	assert(name_ok("A0._z"));
	assert(name_ok("com.android.chrome2"));

	/* Upstream's validator is [A-Za-z0-9._] and neither "." nor "..". */
	assert(name_ok("") == false);
	assert(name_ok(".") == false);
	assert(name_ok("..") == false);
	assert(name_ok("com/example") == false);
	assert(name_ok("com example") == false);
	assert(name_ok("com\\example") == false);
	assert(name_ok("com-example") == false);
	assert(name_ok("com:example") == false);
	assert(name_ok("\x01") == false);
	assert(name_ok("com.example\n") == false);		/* a newline would split the list command */

	memset(long_name, 'a', sizeof(long_name));
	long_name[sizeof(long_name) - 1] = '\0';
	assert(sus_app_uid_name_valid(long_name, SUS_APP_NAME_MAX) == true);
	assert(sus_app_uid_name_valid(long_name, SUS_APP_NAME_MAX + 1) == false);
	assert(sus_app_uid_name_valid(NULL, 1) == false);

	/* The filter range is the primary user's app ids. */
	assert(sus_app_uid_in_range(10000) == true);
	assert(sus_app_uid_in_range(19999) == true);
	assert(sus_app_uid_in_range(9999) == false);
	assert(sus_app_uid_in_range(20000) == false);
	assert(sus_app_uid_in_range(0) == false);

	assert(sus_app_uid_index(10000) == 0);
	assert(sus_app_uid_index(19999) == SUS_APP_UID_NUM - 1);

	/* susfs_is_uid_allowed_for_sus_path(): 90000..99999 always see the paths; no other
	 * outside-range id does. */
	assert(sus_app_uid_visible_by_default(90000) == true);
	assert(sus_app_uid_visible_by_default(99999) == true);
	assert(sus_app_uid_visible_by_default(89999) == false);
	assert(sus_app_uid_visible_by_default(10000) == false);
	assert(sus_app_uid_visible_by_default(0) == false);

	puts("sus_app_uid_view: ok");
	return 0;
}
