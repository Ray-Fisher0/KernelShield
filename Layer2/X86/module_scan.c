// SPDX-License-Identifier: GPL
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/kallsyms.h>
#include <linux/workqueue.h>
#include <linux/slab.h>
#include <linux/delay.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Security Research");
MODULE_DESCRIPTION("Simple sys_call_table snapshot detector");

#define SCAN_INTERVAL 30000   // 30 seconds

typedef unsigned long (*kln_t)(const char *name);

static unsigned long **sys_call_table;
static unsigned long *baseline;
static unsigned int syscall_count = 512;  // adjust if needed

static struct delayed_work scan_work;

/* Resolve kallsyms_lookup_name */
static unsigned long resolve_kallsyms_lookup_name(void)
{
    struct kprobe kp = { .symbol_name = "kallsyms_lookup_name" };
    unsigned long addr = 0;

    if (register_kprobe(&kp) == 0) {
        addr = (unsigned long)kp.addr;
        unregister_kprobe(&kp);
    }

    return addr;
}

/* Scan and compare */
static void scan_syscall_table(struct work_struct *work)
{
    unsigned int i;

    for (i = 0; i < syscall_count; i++) {
        unsigned long current = sys_call_table[i];

        if (current != baseline[i]) {
            pr_warn("[ROOTKIT DETECTOR] sys_call_table modified at index %u\n", i);
            pr_warn("    Old: %px\n", (void *)baseline[i]);
            pr_warn("    New: %px\n", (void *)current);

            baseline[i] = current;  // update snapshot to avoid spam
        }
    }

    schedule_delayed_work(&scan_work, msecs_to_jiffies(SCAN_INTERVAL));
}

/* Module init */
static int __init detector_init(void)
{
    kln_t kln;
    unsigned long addr;

    addr = resolve_kallsyms_lookup_name();
    if (!addr) {
        pr_err("Failed to resolve kallsyms_lookup_name\n");
        return -ENOENT;
    }

    kln = (kln_t)addr;

    sys_call_table = (unsigned long **)kln("sys_call_table");
    if (!sys_call_table) {
        pr_err("Could not locate sys_call_table\n");
        return -ENOENT;
    }

    baseline = kcalloc(syscall_count, sizeof(unsigned long), GFP_KERNEL);
    if (!baseline)
        return -ENOMEM;

    memcpy(baseline, sys_call_table,
           syscall_count * sizeof(unsigned long));

    INIT_DELAYED_WORK(&scan_work, scan_syscall_table);
    schedule_delayed_work(&scan_work, msecs_to_jiffies(SCAN_INTERVAL));

    pr_info("Rootkit detector started (scanning every 30s)\n");
    return 0;
}

/* Module exit */
static void __exit detector_exit(void)
{
    cancel_delayed_work_sync(&scan_work);

    if (baseline)
        kfree(baseline);

    pr_info("Rootkit detector stopped\n");
}

module_init(detector_init);
module_exit(detector_exit);