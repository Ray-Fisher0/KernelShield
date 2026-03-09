// Test file for rkdetector.c kernel module
#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>
#include <linux/fs.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Rootkit Detector Tester");
MODULE_DESCRIPTION("Test module for rkdetector.c");

#define PROC_PATH "/proc/rootkit_scan"
#define TEST_BUF_SIZE 256

static void test_proc_read(void) {
    struct file *f;
    char buf[TEST_BUF_SIZE];
    mm_segment_t old_fs;
    
    printk(KERN_INFO "[rkdetector_test] Testing /proc read...\n");
    f = filp_open(PROC_PATH, O_RDONLY, 0);
    if (IS_ERR(f)) {
        printk(KERN_ERR "[rkdetector_test] Failed to open proc file\n");
        return;
    }
    old_fs = get_fs();
    set_fs(KERNEL_DS);
    if (vfs_read(f, (void __user *)buf, TEST_BUF_SIZE - 1, &f->f_pos) > 0) {
        printk(KERN_INFO "[rkdetector_test] /proc read successful\n");
    } else {
        printk(KERN_ERR "[rkdetector_test] /proc read failed\n");
    }
    set_fs(old_fs);
    filp_close(f, NULL);
}

static void test_proc_write(void) {
    struct file *f;
    char buf[] = "scan";
    mm_segment_t old_fs;
    
    printk(KERN_INFO "[rkdetector_test] Testing /proc write (manual scan)...\n");
    f = filp_open(PROC_PATH, O_WRONLY, 0);
    if (IS_ERR(f)) {
        printk(KERN_ERR "[rkdetector_test] Failed to open proc file for write\n");
        return;
    }
    old_fs = get_fs();
    set_fs(KERNEL_DS);
    if (vfs_write(f, (void __user *)buf, sizeof(buf) - 1, &f->f_pos) > 0) {
        printk(KERN_INFO "[rkdetector_test] /proc write successful, manual scan triggered\n");
    } else {
        printk(KERN_ERR "[rkdetector_test] /proc write failed\n");
    }
    set_fs(old_fs);
    filp_close(f, NULL);
}

static int __init rkdetector_test_init(void)
{
    printk(KERN_INFO "[rkdetector_test] Test module loaded.\n");
    test_proc_read();
    msleep(100);
    test_proc_write();
    msleep(100);
    test_proc_read();
    printk(KERN_INFO "[rkdetector_test] All tests completed.\n");
    return 0;
}

static void __exit rkdetector_test_exit(void)
{
    printk(KERN_INFO "[rkdetector_test] Test module unloaded.\n");
}

module_init(rkdetector_test_init);
module_exit(rkdetector_test_exit);
