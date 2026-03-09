#ifndef MODULE_H
#define MODULE_H

#include <linux/proc_fs.h>
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/uaccess.h>
#include <linux/sched.h>
#include <linux/version.h>

// Suport for multiple architectures
#define MAX_SYM_NAME   64
#define WATCH1         "sys_call_table"
#define WATCH2         "ia32_sys_call_table"

#define ALERT_PROC_NAME "kallsyms_alert"
#define ALERT_MSG_LEN 256

struct lookup_event {
    char name[MAX_SYM_NAME];
    bool matched;
    unsigned long caller_ip;
    pid_t pid;
    char comm[TASK_COMM_LEN];
};

int safe_copy_kstr(char *dst, const void *src, size_t dst_len);
ssize_t alert_proc_read(struct file *file, char __user *buf, size_t count, loff_t *ppos);

unsigned long get_ip_from_regs(struct pt_regs *regs);
const char *get_arg0_strptr(struct pt_regs *regs);

extern char alert_msg[ALERT_MSG_LEN];
extern struct proc_dir_entry *alert_proc_entry;

#endif
