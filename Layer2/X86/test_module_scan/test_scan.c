// SPDX-License-Identifier: GPL
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kallsyms.h>
#include <linux/kprobes.h>
#include <linux/syscalls.h>
#include <linux/uaccess.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Test");
MODULE_DESCRIPTION("Test module to modify sys_call_table");

typedef unsigned long (*kln_t)(const char *name);

static unsigned long **sys_call_table;
static asmlinkage long (*original_getpid)(void);

/* Resolve kallsyms_lookup_name using kprobe */
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

/* Fake syscall */
asmlinkage long hooked_getpid(void)
{
    pr_info("[hook_test] getpid intercepted\n");
    return original_getpid();
}

/* Disable write protection */
static void disable_wp(void)
{
    write_cr0(read_cr0() & (~0x10000));
}

/* Enable write protection */
static void enable_wp(void)
{
    write_cr0(read_cr0() | 0x10000);
}

static int __init hook_test_init(void)
{
    kln_t kln;
    unsigned long addr;

    addr = resolve_kallsyms_lookup_name();
    if (!addr) {
        pr_err("[hook_test] kallsyms_lookup_name not found\n");
        return -ENOENT;
    }

    kln = (kln_t)addr;

    sys_call_table = (unsigned long **)kln("sys_call_table");
    if (!sys_call_table) {
        pr_err("[hook_test] sys_call_table not found\n");
        return -ENOENT;
    }

    original_getpid = (void *)sys_call_table[__NR_getpid];

    disable_wp();
    sys_call_table[__NR_getpid] = (unsigned long *)hooked_getpid;
    enable_wp();

    pr_info("[hook_test] sys_getpid hooked\n");

    return 0;
}

static void __exit hook_test_exit(void)
{
    if (!sys_call_table)
        return;

    disable_wp();
    sys_call_table[__NR_getpid] = (unsigned long *)original_getpid;
    enable_wp();

    pr_info("[hook_test] sys_getpid restored\n");
}

module_init(hook_test_init);
module_exit(hook_test_exit);