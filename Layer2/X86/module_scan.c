// SPDX-License-Identifier: GPL
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
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/delay.h>
#include <linux/string.h>
#include <linux/jiffies.h>
#include <linux/sched/task.h>
#include <linux/mm.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Rootkit Detector Group");
MODULE_DESCRIPTION("Simple watcher for sys_call_table modifications");

#define MAX_TABLES 2
#define SYMNAME_LEN KSYM_SYMBOL_LEN

struct tbl_watch {
	const char   *name;
	unsigned long addr;
	unsigned long *tbl;
	unsigned long *baseline;
	bool          active;
};

unsigned int syscall_count = 512;
module_param(syscall_count, uint, 0444);
MODULE_PARM_DESC(syscall_count, "Number of syscalls to monitor");

unsigned int interval_ms = 1000;
module_param(interval_ms, uint, 0644);
MODULE_PARM_DESC(interval_ms, "Scan interval in milliseconds");

typedef unsigned long (*kln_t)(const char *name);

static struct tbl_watch tw[MAX_TABLES] = {
    {.name = "sys_call_table"},
    {.name = "ia32_sys_call_table"},
};

static struct delayed_work scan_work;
static kln_t kln = NULL;

static atomic_t sys_call_table_edited = ATOMIC_INIT(0);
static pid_t first_observer_pid;
static char first_observer_comm[TASK_COMM_LEN];

static struct proc_dir_entry *proc_entry;

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

static void addr_to_symbol(unsigned long addr, char *buf, size_t buflen)
{
    if (!buf || buflen == 0)
        return;

#if defined(CONFIG_KALLSYMS)
    sprint_symbol(buf, addr);
#else
    scnprintf(buf, buflen, "0x%lx", addr);
#endif
}

static void record_first_observer_if_needed(void)
{
    if (!atomic_read(&sys_call_table_edited)) {
        get_task_comm(first_observer_comm, current);
        first_observer_pid = task_pid_nr(current);
        atomic_set(&sys_call_table_edited, 1);
    }
}

static void scan_once(struct tbl_watch *w)
{
    unsigned int i;
    unsigned long cur, old;
    char sym_old[SYMNAME_LEN], sym_new[SYMNAME_LEN];

    if (!w->active || !w->tbl || !w->baseline)
        return;

    rcu_read_lock();

    for (i = 0; i < syscall_count; i++) {

        cur = READ_ONCE(w->tbl[i]);
        old = w->baseline[i];

        if (cur != old) {

            addr_to_symbol(old, sym_old, sizeof(sym_old));
            addr_to_symbol(cur, sym_new, sizeof(sym_new));

            pr_warn_ratelimited(
                "[syscalltbl-watch] %-18s idx=%u changed: %s -> %s\n",
                w->name, i, sym_old, sym_new);

            if (w == &tw[0])
                record_first_observer_if_needed();

            w->baseline[i] = cur;
        }

        /* Detect syscall handlers outside kernel text */
        if (!core_kernel_text(cur)) {
            pr_warn_ratelimited(
                "[syscalltbl-watch] suspicious pointer in %s[%u]: %px\n",
                w->name, i, (void *)cur);
        }
    }

    rcu_read_unlock();
}

static void scan_workfn(struct work_struct *ws)
{
    int t;

    for (t = 0; t < MAX_TABLES; t++)
        scan_once(&tw[t]);

    if (interval_ms)
        schedule_delayed_work(&scan_work, msecs_to_jiffies(interval_ms));
}

static int setup_table(struct tbl_watch *w)
{
    unsigned long addr;

    if (!kln)
        return -ENOSYS;

    addr = kln(w->name);

    if (!addr) {
        pr_info("[syscalltbl-watch] %s not found\n", w->name);
        return -ENOENT;
    }

    w->addr = addr;
    w->tbl  = (unsigned long *)addr;

    w->baseline = kcalloc(syscall_count, sizeof(unsigned long), GFP_KERNEL);
    if (!w->baseline)
        return -ENOMEM;

    memcpy(w->baseline, w->tbl, syscall_count * sizeof(unsigned long));

    w->active = true;

    pr_info("[syscalltbl-watch] monitoring %s at %lx\n",
            w->name, w->addr);

    return 0;
}

static void teardown_table(struct tbl_watch *w)
{
    if (w->baseline)
        kfree(w->baseline);

    w->baseline = NULL;
    w->tbl = NULL;
    w->addr = 0;
    w->active = false;
}

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

    if (!strcmp(buf, "clear")) {
        atomic_set(&sys_call_table_edited, 0);
        first_observer_pid = 0;
        memset(first_observer_comm, 0, sizeof(first_observer_comm));

        pr_info("[syscalltbl-watch] cleared edited flag\n");
    } else {
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

static int __init syscalltbl_watch_init(void)
{
    int t, ok = 0;
    unsigned long kln_addr;

    atomic_set(&sys_call_table_edited, 0);

    kln_addr = resolve_kallsyms_lookup_name();
    if (!kln_addr)
        return -ENOENT;

    kln = (kln_t)kln_addr;

    for (t = 0; t < MAX_TABLES; t++)
        if (setup_table(&tw[t]) == 0)
            ok++;

    if (!ok)
        return -ENOENT;

    INIT_DELAYED_WORK(&scan_work, scan_workfn);
    schedule_delayed_work(&scan_work, msecs_to_jiffies(interval_ms));

    proc_entry = proc_create("syscalltbl_status", 0664, NULL,
                             &syscalltbl_proc_ops);

    if (!proc_entry) {
        cancel_delayed_work_sync(&scan_work);

        for (t = 0; t < MAX_TABLES; t++)
            teardown_table(&tw[t]);

        return -ENOMEM;
    }

    pr_info("[syscalltbl-watch] initialized\n");
    return 0;
}

static void __exit syscalltbl_watch_exit(void)
{
    int t;

    if (proc_entry)
        remove_proc_entry("syscalltbl_status", NULL);

    cancel_delayed_work_sync(&scan_work);

    for (t = 0; t < MAX_TABLES; t++)
        teardown_table(&tw[t]);

    pr_info("[syscalltbl-watch] unloaded\n");
}

module_init(syscalltbl_watch_init);
module_exit(syscalltbl_watch_exit);