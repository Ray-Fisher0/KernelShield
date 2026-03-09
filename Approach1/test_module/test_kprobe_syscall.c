// SPDX-License-Identifier: GPL
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/errno.h>
#include <linux/init.h>

MODULE_DESCRIPTION("Test module: invoke kallsyms_lookup_name(\"sys_call_table\")");
MODULE_AUTHOR("Your Name");
MODULE_LICENSE("GPL");

typedef unsigned long (*kln_t)(const char *name);

static unsigned long kln_addr;

static int __init test_kln_init(void)
{
    int ret;
    struct kprobe kp = {
        .symbol_name = "kallsyms_lookup_name",
    };

    pr_info("[test-kln] loading; resolving address of kallsyms_lookup_name...\n");

    /* 1) Resolve the address via a temporary kprobe (works even if unexported) */
    ret = register_kprobe(&kp);
    if (ret) {
        pr_err("[test-kln] register_kprobe failed: %d\n", ret);
        return ret;
    }
    kln_addr = (unsigned long)kp.addr;
    unregister_kprobe(&kp);

    if (!kln_addr) {
        pr_err("[test-kln] could not resolve kallsyms_lookup_name address\n");
        return -ENOENT;
    }

    pr_info("[test-kln] kallsyms_lookup_name at 0x%lx\n", kln_addr);

    /* 2) Call it via function pointer */
    {
        kln_t kln = (kln_t)kln_addr;
        unsigned long sys_call_tbl = kln("sys_call_table");
        unsigned long ia32_tbl     = kln("ia32_sys_call_table");

        pr_info("[test-kln] kallsyms_lookup_name(\"sys_call_table\") => 0x%lx\n", sys_call_tbl);
        pr_info("[test-kln] kallsyms_lookup_name(\"ia32_sys_call_table\") => 0x%lx\n", ia32_tbl);
        if (!sys_call_tbl && !ia32_tbl) {
            pr_warn("[test-kln] neither sys_call_table nor ia32_sys_call_table found; "
                    "this can be normal on some kernels.\n");
        }
    }

    pr_info("[test-kln] init complete.\n");
    return 0;
}

static void __exit test_kln_exit(void)
{
    pr_info("[test-kln] unloaded.\n");
}

module_init(test_kln_init);
module_exit(test_kln_exit);
``