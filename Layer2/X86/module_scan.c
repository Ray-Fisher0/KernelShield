// SPDX-License-Identifier: GPL
#include "module_scan.h"

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
unsigned int syscall_count = 512;
module_param(syscall_count, uint, 0444);
MODULE_PARM_DESC(syscall_count, "Number of syscalls to monitor (default 512)");

unsigned int interval_ms = 1000;
module_param(interval_ms, uint, 0644);
MODULE_PARM_DESC(interval_ms, "Scan interval in milliseconds (default 1000)");

/* ===== Utilities to resolve kallsyms_lookup_name() even when symbol is not exported ===== */
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

/* sprint_symbol helper wrapper (prints "name+0xoff/0xlen") */
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

/* ===== Minimal edit indicator for /proc =====
 * Tracks whether the primary sys_call_table (tw[0]) has diverged from baseline.
 * We record the first observer's task name and pid at detection time.
 */
static atomic_t sys_call_table_edited = ATOMIC_INIT(0);
static pid_t first_observer_pid;
static char first_observer_comm[TASK_COMM_LEN];

static void record_first_observer_if_needed(void)
{
    if (!atomic_read(&sys_call_table_edited)) {
        /* Best-effort: record current context when edit is first observed.
         * NOTE: This is usually the kworker running the scan, not the culprit.
         */
        get_task_comm(first_observer_comm, current);
        first_observer_pid = task_pid_nr(current);
        atomic_set(&sys_call_table_edited, 1);
    }
}

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

            /* If this is the primary sys_call_table, mark edited once */
            if (w == &tw[0]) {
                record_first_observer_if_needed();
            }

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

/* ===== /proc: /proc/syscalltbl_status ===== */

static struct proc_dir_entry *proc_entry;

static int proc_show(struct seq_file *m, void *v)
{
    if (atomic_read(&sys_call_table_edited)) {
        seq_puts(m, "edited: yes\n");
        seq_printf(m, "first_observed_by: pid=%d comm=%s\n",
                   first_observer_pid, first_observer_comm);
    } else {
        seq_puts(m, "edited: no\n");
    }
    return 0;
}

static int proc_open(struct inode *inode, struct file *file)
{
    return single_open(file, proc_show, NULL);
}

static ssize_t proc_write(struct file *file, const char __user *ubuf,
                          size_t len, loff_t *ppos)
{
    char buf[32];
    size_t n = min_t(size_t, len, sizeof(buf) - 1);

    if (copy_from_user(buf, ubuf, n))
        return -EFAULT;
    buf[n] = '\0';

    /* Strip trailing newline */
    while (n > 0 && (buf[n - 1] == '\n' || buf[n - 1] == '\r')) {
        buf[--n] = '\0';
    }

    if (!strcmp(buf, "clear")) {
        atomic_set(&sys_call_table_edited, 0);
        first_observer_pid = 0;
        memset(first_observer_comm, 0, sizeof(first_observer_comm));
        pr_info("[syscalltbl-watch] /proc: cleared edited flag\n");
    } else {
        pr_info("[syscalltbl-watch] /proc: unknown command '%s' (supported: 'clear')\n", buf);
        return -EINVAL;
    }

    *ppos += len;
    return len;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,6,0)
static const struct proc_ops syscalltbl_proc_ops = {
    .proc_open    = proc_open,
    .proc_read    = seq_read,
    .proc_lseek   = seq_lseek,
    .proc_release = single_release,
    .proc_write   = proc_write,
};
#else
static const struct file_operations syscalltbl_proc_ops = {
    .owner   = THIS_MODULE,
    .open    = proc_open,
    .read    = seq_read,
    .llseek  = seq_lseek,
    .release = single_release,
    .write   = proc_write,
};
#endif

/* ===== Module init/exit ===== */

static int __init syscalltbl_watch_init(void)
{
    int t, ok = 0;
    unsigned long kln_addr;

    if (syscall_count == 0) {
        pr_err("[syscalltbl-watch] syscall_count=0 is invalid\n");
        return -EINVAL;
    }

    /* Reset indicator on load */
    atomic_set(&sys_call_table_edited, 0);
    first_observer_pid = 0;
    memset(first_observer_comm, 0, sizeof(first_observer_comm));

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

    proc_entry = proc_create("syscalltbl_status", 0664, NULL, &syscalltbl_proc_ops);
    if (!proc_entry) {
        pr_err("[syscalltbl-watch] failed to create /proc/syscalltbl_status\n");
        cancel_delayed_work_sync(&scan_work);
        for (t = 0; t < MAX_TABLES; t++)
            teardown_table(&tw[t]);
        return -ENOMEM;
    }

    pr_info("[syscalltbl-watch] initialized (interval_ms=%u, syscall_count=%u); /proc/syscalltbl_status ready\n",
            interval_ms, syscall_count);
    return 0;
}

static void __exit syscalltbl_watch_exit(void)
{
    int t;
    if (proc_entry) {
        remove_proc_entry("syscalltbl_status", NULL);
        proc_entry = NULL;
    }
    cancel_delayed_work_sync(&scan_work);
    for (t = 0; t < MAX_TABLES; t++)
        teardown_table(&tw[t]);
    pr_info("[syscalltbl-watch] unloaded.\n");
}

module_init(syscalltbl_watch_init);
module_exit(syscalltbl_watch_exit);