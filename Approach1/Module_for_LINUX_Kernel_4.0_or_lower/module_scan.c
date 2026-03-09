// SPDX-License-Identifier: GPL
#include <module_scan.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Rootkit Detector Group");
MODULE_DESCRIPTION("Simple watcher for sys_call_table modifications");

/*
 * ===== Module parameters =====
 *
 * syscall_count: number of entries to monitor in each table.
 *   - On many x86_64 kernels, 512–600 is typical, but this varies.
 *   - If you know your kernel's NR_syscalls, set it here.
 *
 * interval_ms: periodic check interval.
 */
static unsigned int syscall_count = 512;
module_param(syscall_count, uint, 0444);
MODULE_PARM_DESC(syscall_count, "Number of syscalls to monitor (default 512)");

static unsigned int interval_ms = 1000;
module_param(interval_ms, uint, 0644);
MODULE_PARM_DESC(interval_ms, "Scan interval in milliseconds (default 1000)");


// Utilities to resolve kallsyms_lookup_name() even when symbol is not exported
typedef unsigned long (*kln_t)(const char *name);

static unsigned long resolve_kallsyms_lookup_name(void)
{
    struct kprobe kp = { .symbol_name = "kallsyms_lookup_name" };
    unsigned long addr = 0;
    int ret = register_kprobe(&kp);
    if (ret == 0) {
        addr = (unsigned long)kp.addr;
        unregister_kprobe(&kp);
    }
    return addr;
}

// sprint_symbol helper wrapper (prints "name+0xoff/0xlen")
static void addr_to_symbol(unsigned long addr, char *buf, size_t buflen)
{
    if (!buf || buflen == 0) return;
    buf[0] = '\0';
#if defined(CONFIG_KALLSYMS)
    sprint_symbol(buf, addr);
#else
    scnprintf(buf, buflen, "0x%lx", addr);
#endif
}

/* ===== Table watch state ===== */

static struct tbl_watch tw[MAX_TABLES] = {
    {.name = "sys_call_table"},
    {.name = "ia32_sys_call_table"}, /* present on x86_64 for compat; harmless if absent */
};

static struct delayed_work scan_work;
static kln_t kln = NULL;

/* ===== Scanning logic ===== */
static void scan_once(struct tbl_watch *w)
{
    unsigned int i;
    unsigned long cur, old;
    char sym_old[SYMNAME_LEN], sym_new[SYMNAME_LEN];

    if (!w->active || !w->tbl || !w->baseline)
        return;

    for (i = 0; i < syscall_count; i++) {
        cur = READ_ONCE(w->tbl[i]);
        old = w->baseline[i];
        if (cur != old) {
            addr_to_symbol(old, sym_old, sizeof(sym_old));
            addr_to_symbol(cur, sym_new, sizeof(sym_new));
            pr_warn_ratelimited("[syscalltbl-watch] %-18s idx=%u changed: %s -> %s\n",
                                w->name, i, sym_old, sym_new);
            /* Update baseline so we don't spam */
            w->baseline[i] = cur;
        }
    }
}

static void scan_workfn(struct work_struct *ws)
{
    int t;
    for (t = 0; t < MAX_TABLES; t++)
        scan_once(&tw[t]);

    if (interval_ms == 0)
        return;
    schedule_delayed_work(&scan_work, msecs_to_jiffies(interval_ms));
}

/* ===== Setup and teardown ===== */
static int setup_table(struct tbl_watch *w)
{
    unsigned long addr;

    if (!kln)
        return -ENOSYS;

    addr = kln(w->name);
    if (!addr) {
        pr_info("[syscalltbl-watch] %s not found; skipping.\n", w->name);
        return -ENOENT;
    }

    w->addr = addr;
    w->tbl  = (unsigned long *)addr;

    w->baseline = kmalloc_array(syscall_count, sizeof(unsigned long), GFP_KERNEL);
    if (!w->baseline)
        return -ENOMEM;

    /* Snapshot baseline */
    memcpy(w->baseline, w->tbl, syscall_count * sizeof(unsigned long));

    w->active = true;

    pr_info("[syscalltbl-watch] monitoring %-18s at 0x%lx (%u entries)\n",
            w->name, w->addr, syscall_count);
    return 0;
}

static void teardown_table(struct tbl_watch *w)
{
    if (w->baseline) {
        kfree(w->baseline);
        w->baseline = NULL;
    }
    w->tbl = NULL;
    w->addr = 0;
    w->active = false;
}

static int __init syscalltbl_watch_init(void)
{
    int t, ok = 0;
    unsigned long kln_addr;

    if (syscall_count == 0) {
        pr_err("[syscalltbl-watch] syscall_count=0 is invalid\n");
        return -EINVAL;
    }

    kln_addr = resolve_kallsyms_lookup_name();
    if (!kln_addr) {
        pr_err("[syscalltbl-watch] cannot resolve kallsyms_lookup_name; need CONFIG_KPROBES & kallsyms\n");
        return -ENOENT;
    }
    kln = (kln_t)kln_addr;

    for (t = 0; t < MAX_TABLES; t++) {
        if (setup_table(&tw[t]) == 0)
            ok++;
    }

    if (!ok) {
        pr_err("[syscalltbl-watch] no syscall tables found; nothing to do.\n");
        return -ENOENT;
    }

    INIT_DELAYED_WORK(&scan_work, scan_workfn);
    schedule_delayed_work(&scan_work, msecs_to_jiffies(interval_ms));

    pr_info("[syscalltbl-watch] initialized (interval_ms=%u, syscall_count=%u)\n",
            interval_ms, syscall_count);
    return 0;
}

static void __exit syscalltbl_watch_exit(void)
{
    int t;
    cancel_delayed_work_sync(&scan_work);
    for (t = 0; t < MAX_TABLES; t++)
        teardown_table(&tw[t]);
    pr_info("[syscalltbl-watch] unloaded.\n");
}

module_init(syscalltbl_watch_init);
module_exit(syscalltbl_watch_exit);