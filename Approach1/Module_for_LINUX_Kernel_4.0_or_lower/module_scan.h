// SPDX-License-Identifier: GPL
#ifndef MODULE_SCAN_H
#define MODULE_SCAN_H

#include <linux/module.h>
#include <linux/init.h>
#include <linux/kprobes.h>
#include <linux/workqueue.h>
#include <linux/slab.h>
#include <linux/kallsyms.h>
#include <linux/errno.h>
#include <linux/ratelimit.h>
#include <linux/version.h>
#include <linux/uaccess.h>
#include <linux/bug.h>
#include <linux/rcupdate.h>
#include <linux/sched.h>

/* Module parameters */
extern unsigned int syscall_count;
extern unsigned int interval_ms;

/* Table watch structure */
#define MAX_TABLES 2
#define SYMNAME_LEN KSYM_SYMBOL_LEN

struct tbl_watch {
	const char   *name;
	unsigned long addr;
	unsigned long *tbl;
	unsigned long *baseline;
	bool          active;
};

#endif // MODULE_SCAN_H

