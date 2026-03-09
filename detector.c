// detector.c — Rootkit Detection LKM
// Tested on Linux 6.1.0-43-arm64 Debian 12

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/kprobes.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/timer.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/mm.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Horrisberger, Edelson, Fisher");
MODULE_DESCRIPTION("Rootkit Detection via syscall table monitoring");

#define PROC_FILENAME   "rootkit_alerts"
#define SYSCALL_COUNT   256
#define CHECK_INTERVAL  (5 * HZ)

/* ── Alert ring buffer ─────────────────────────────────────── */
#define ALERT_BUF_SIZE  4096
static char alert_buf[ALERT_BUF_SIZE];
static int  alert_len = 0;
static DEFINE_SPINLOCK(alert_lock);

static void add_alert(const char *msg)
{
    unsigned long flags;
    spin_lock_irqsave(&alert_lock, flags);
    alert_len += snprintf(alert_buf + alert_len,
                          ALERT_BUF_SIZE - alert_len,
                          "[ALERT] %s\n", msg);
    spin_unlock_irqrestore(&alert_lock, flags);
    pr_warn("rootkit-detector: %s\n", msg);
}

/* ── proc interface ────────────────────────────────────────── */
static int proc_show(struct seq_file *m, void *v)
{
    unsigned long flags;
    spin_lock_irqsave(&alert_lock, flags);
    seq_printf(m, "%s", alert_len ? alert_buf : "No alerts.\n");
    spin_unlock_irqrestore(&alert_lock, flags);
    return 0;
}

static int proc_open(struct inode *inode, struct file *file)
{
    return single_open(file, proc_show, NULL);
}

static const struct proc_ops proc_fops = {
    .proc_open    = proc_open,
    .proc_read    = seq_read,
    .proc_lseek   = seq_lseek,
    .proc_release = single_release,
};

/* ── Detection 1: kprobe on kallsyms_lookup_name ───────────── */
static struct kprobe kp_lookup = {
    .symbol_name = "kallsyms_lookup_name",
};

static int handler_pre(struct kprobe *p, struct pt_regs *regs)
{
    char name[64] = {0};
    const char *name_ptr = (const char *)regs->regs[0];

    if (name_ptr) {
        strncpy(name, name_ptr, sizeof(name) - 1);
        name[sizeof(name) - 1] = '\0';
    }

    if (strstr(name, "sys_call_table"))
        add_alert("kallsyms_lookup_name('sys_call_table') called - possible rootkit probing!");

    return 0;
}

/* ── Detection 2 & 3: syscall table integrity + text check ─── */
static unsigned long *sys_call_table_ptr = NULL;
static unsigned long  baseline[SYSCALL_COUNT];
static struct timer_list check_timer;

static struct kprobe kp_sct = {
    .symbol_name = "sys_call_table",
};

static unsigned long get_syscall_table_addr(void)
{
    unsigned long addr = 0;
    if (register_kprobe(&kp_sct) == 0) {
        addr = (unsigned long)kp_sct.addr;
        unregister_kprobe(&kp_sct);
    }
    return addr;
}

static bool addr_in_kernel_text(unsigned long addr)
{
    if (addr < PAGE_OFFSET)
        return false;
    if (!virt_addr_valid(addr))
        return false;
    return true;
}

static void do_integrity_check(struct timer_list *t)
{
    int i;
    char msg[128];

    if (!sys_call_table_ptr)
        goto reschedule;

    for (i = 0; i < SYSCALL_COUNT; i++) {
        unsigned long cur = sys_call_table_ptr[i];

        /* Detection 2: compare to baseline */
        if (cur != baseline[i]) {
            snprintf(msg, sizeof(msg),
                     "syscall table[%d] modified! was %pK now %pK",
                     i, (void *)baseline[i], (void *)cur);
            add_alert(msg);
            baseline[i] = cur;
        }

        /* Detection 3: address outside kernel space */
        if (cur && !addr_in_kernel_text(cur)) {
            snprintf(msg, sizeof(msg),
                     "syscall table[%d] points outside kernel space: %pK",
                     i, (void *)cur);
            add_alert(msg);
        }
    }

reschedule:
    mod_timer(&check_timer, jiffies + CHECK_INTERVAL);
}

/* ── Module init / exit ────────────────────────────────────── */
static int __init detector_init(void)
{
    int ret;
    unsigned long sct_addr;

    pr_info("rootkit-detector: loading\n");

    /* proc entry */
    if (!proc_create(PROC_FILENAME, 0444, NULL, &proc_fops)) {
        pr_err("rootkit-detector: failed to create /proc/%s\n", PROC_FILENAME);
        return -ENOMEM;
    }

    /* Detection 1: kprobe on kallsyms_lookup_name */
    kp_lookup.pre_handler = handler_pre;
    ret = register_kprobe(&kp_lookup);
    if (ret < 0) {
        pr_warn("rootkit-detector: kprobe registration failed (%d)\n", ret);
    } else {
        pr_info("rootkit-detector: kprobe on kallsyms_lookup_name registered\n");
    }

    /* Detections 2 & 3: get table, save baseline */
    sct_addr = get_syscall_table_addr();
    if (sct_addr) {
        sys_call_table_ptr = (unsigned long *)sct_addr;
        memcpy(baseline, sys_call_table_ptr,
               sizeof(unsigned long) * SYSCALL_COUNT);
        pr_info("rootkit-detector: syscall table baseline saved @ %pK\n",
                sys_call_table_ptr);
    } else {
        pr_warn("rootkit-detector: could not locate sys_call_table\n");
    }

    /* periodic timer */
    timer_setup(&check_timer, do_integrity_check, 0);
    mod_timer(&check_timer, jiffies + CHECK_INTERVAL);

    pr_info("rootkit-detector: loaded successfully\n");
    return 0;
}

static void __exit detector_exit(void)
{
    del_timer_sync(&check_timer);
    if (kp_lookup.addr)
        unregister_kprobe(&kp_lookup);
    remove_proc_entry(PROC_FILENAME, NULL);
    pr_info("rootkit-detector: unloaded\n");
}

module_init(detector_init);
module_exit(detector_exit);