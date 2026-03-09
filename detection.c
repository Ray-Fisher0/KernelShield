#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/uaccess.h>
#include <linux/kprobes.h>
#include <linux/version.h>

//module metadata
MODULE_AUTHOR("Ben");
MODULE_DESCRIPTION("Kprobe detection on symbol lookup for sys_call_table");
MODULE_LICENSE("GPL");

//create a local kprobe struct
static struct kprobe kp;

//return the symbol name from rdi register
static unsigned long get_first_argument(struct pt_regs* regs)
{
	return regs->di;
}

//pre symbol look up hander
static int pre_handler(struct kprobe* kp, struct pt_regs* regs)
{
	unsigned long argument_address;
	char* symbol_name;
	char buf[KSYM_NAME_LEN];

	argument_address = get_first_argument(regs);

	//copy agrument string from kernel memory
	if (copy_from_kernel_nofault(buf, (void *)argument_address, KSYM_NAME_LEN - 1))
	{
		printk(KERN_DEBUG "kprobe: failed to read symbol name from kernel");
		return 0;
	}

	buf[KSYM_NAME_LEN - 1] = '\0';
	symbol_name = buf;

	//alert if the the used symbol is sys_call_table
	if (strcmp(symbol_name, "sys_call_table") == 0)
	{
		printk("==========================================\n");
		printk("ALERT: SYS_CALL_TABLE lookup detected!\n");
		printk("==========================================\n");

	}

	return 0;
}

//custom init and exit functions
static int __init detection_init(void)
{

	int probe_up;

	//set up kprobe structer
	kp.symbol_name = "kallsyms_lookup_name";
	kp.pre_handler = pre_handler;

	//could add a post handler and fault handler
	//for more forensic details
	
	probe_up = register_kprobe(&kp);

	//check probe registraightion
	if (probe_up < 0)
	{
		printk(KERN_ERR "Detection init: failed to register probe: code %d\n", probe_up);
		return probe_up;
	}	
	printk(KERN_INFO "Detection module loaded");
	printk(KERN_INFO "Probe planeted at: %pS\n", kp.addr);

	return 0;
}

static void __exit detection_exit(void)
{
	unregister_kprobe(&kp);
	printk(KERN_INFO "Detection module exited");
}

module_init(detection_init);
module_exit(detection_exit);
