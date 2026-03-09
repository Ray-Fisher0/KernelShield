#include <module.h>

// SPDX-License-Identifier: GPL-2.0
MODULE_DESCRIPTION("Kprobe-based watcher for kallsyms_lookup_name('sys_call_table')");
MODULE_AUTHOR("Rootkit Detector Group");
MODULE_LICENSE("GPL");

// Global variables for kretprobe and alert message
static char alert_msg[ALERT_MSG_LEN];
static struct proc_dir_entry *alert_proc_entry;

// Helpers to safely copy a C-string from a kernel pointer
static int safe_copy_kstr(char *dst, const void *src, size_t dst_len)
{
    // dst must be a kernel buffer, src is a user/kernel pointer we want to read safely
    int ret;
    if (!dst || !src || dst_len == 0)
        return -EINVAL;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,8,0)
    ret = copy_from_kernel_nofault(dst, src, dst_len - 1);
    if (ret)
        return ret;
    dst[dst_len - 1] = '\0';
#else
    ret = probe_kernel_read(dst, src, dst_len - 1);
    if (ret)
        return ret;
    dst[dst_len - 1] = '\0';
#endif
    // Ensure it’s NUL-terminated if source exceeded buffer
    dst[dst_len - 1] = '\0';
    return 0;
}

// /proc read handler to show the last alert message
static ssize_t alert_proc_read(struct file *file, char __user *buf, size_t count, loff_t *ppos)
{
    int len;
    if (*ppos > 0)
        return 0;
    len = strnlen(alert_msg, ALERT_MSG_LEN);
    if (copy_to_user(buf, alert_msg, len))
        return -EFAULT;
    *ppos = len;
    return len;
}

static const struct proc_ops alert_proc_fops = {
    .proc_read = alert_proc_read,
};

// Support for multiple architectures to get instruction pointer and first argument
static inline unsigned long get_ip_from_regs(struct pt_regs *regs)
{
#if defined(CONFIG_X86_64) || defined(CONFIG_X86)
    return regs->ip;
#elif defined(CONFIG_ARM64)
    return regs->pc;
#else
    return 0;
#endif
}

static inline const char *get_arg0_strptr(struct pt_regs *regs)
{
#if defined(CONFIG_X86_64)
    return (const char *)regs->di;
#elif defined(CONFIG_X86)
    return (const char *)regs->ax; /* rarely used; x86 32-bit calling conv differs */
#elif defined(CONFIG_ARM64)
    return (const char *)regs->regs[0];
#else
#warning "Unsupported architecture: arg0 accessor not implemented."
    return NULL;
#endif
}

// kretprobe handlers for kallsyms_lookup_name
static char target_func[] = "kallsyms_lookup_name";

static int entry_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct lookup_event *ev;
    const char *arg_name = get_arg0_strptr(regs);

    ev = (struct lookup_event *)ri->data;
    memset(ev, 0, sizeof(*ev));

    if (arg_name) {
        if (safe_copy_kstr(ev->name, arg_name, sizeof(ev->name)) == 0) {
            ev->matched = true; // Always mark as matched to log all calls
        }
    }

    ev->caller_ip = get_ip_from_regs(regs);
    ev->pid = current->pid;
    get_task_comm(ev->comm, current);
    return 0;
}

static int ret_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct lookup_event *ev = (struct lookup_event *)ri->data;

    if (ev->matched) {
        unsigned long ret = (unsigned long)regs_return_value(regs);
        snprintf(alert_msg, ALERT_MSG_LEN,
                 "ALERT: pid=%d comm=%s requested=\"%s\" ip=0x%lx addr=0x%lx\n",
                 ev->pid, ev->comm, ev->name, ev->caller_ip, ret);
        pr_warn("[kprobe-kallsyms] %s", alert_msg);
    }
    return 0;
}

static struct kretprobe krp = {
    .kp.symbol_name = target_func,
    .handler = ret_handler,
    .entry_handler = entry_handler,
    .data_size = sizeof(struct lookup_event),
    .maxactive = 64, /* adjust for expected concurrency */
};

// Linux module initialization and exit
static int __init kprobe_syscalltbl_init(void)
{
    int ret;

    ret = register_kretprobe(&krp);
    if (ret < 0) {
        pr_err("register_kretprobe failed, returned %d\n", ret);
        return ret;
    }
    pr_info("kretprobe registered for %s (maxactive=%d)\n", target_func, krp.maxactive);
    alert_proc_entry = proc_create(ALERT_PROC_NAME, 0444, NULL, &alert_proc_fops);
    if (!alert_proc_entry) {
        pr_err("Failed to create /proc/%s\n", ALERT_PROC_NAME);
    }
    alert_msg[0] = '\0';
    return 0;
}

static void __exit kprobe_syscalltbl_exit(void)
{
    unregister_kretprobe(&krp);
    if (alert_proc_entry)
        proc_remove(alert_proc_entry);
    pr_info("kretprobe unregistered: %d instances missed\n", krp.nmissed);
}

module_init(kprobe_syscalltbl_init);
module_exit(kprobe_syscalltbl_exit);