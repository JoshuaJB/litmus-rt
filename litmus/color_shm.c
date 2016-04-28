#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/fs.h>
#include <linux/miscdevice.h>
#include <linux/spinlock.h>
#include <linux/module.h>
#include <linux/highmem.h>
#include <linux/slab.h>
#include <linux/mutex.h>
#include <asm/uaccess.h>

#include <litmus/litmus.h>

#define DEV_NAME	"litmus/color_shm"

/* Major number assigned to our device. 
 * Refer Documentation/devices.txt */
#define SHM_MAJOR			240
#define MAX_COLORED_PAGE	256
#define NUM_BANKS			8
#define NUM_COLORS			16

static struct mutex dev_lock;
static int bypass_cache;

struct color_ioctl_cmd {
	unsigned int color;
	unsigned int bank;
};

struct color_ioctl_offset {
	unsigned long offset;
	int lock;
};

#define SET_COLOR_SHM_CMD		_IOW(SHM_MAJOR, 0x1, struct color_ioctl_cmd)
#define SET_COLOR_SHM_OFFSET	_IOW(SHM_MAJOR, 0x2, struct color_ioctl_offset)

struct color_ioctl_cmd color_param;
struct color_ioctl_offset color_offset;

static int mmap_common_checks(struct vm_area_struct *vma)
{
	/* you can only map the "first" page */
	if (vma->vm_pgoff != 0)
		return -EINVAL;

	return 0;
}

static void mmap_common_vma_flags(struct vm_area_struct *vma)
{
	/* This mapping should not be kept across forks,
	 * cannot be expanded, and is not a "normal" page. */
	//vma->vm_flags |= VM_DONTCOPY | VM_DONTEXPAND | VM_IO | VM_SHARED | VM_MAYSHARE;
	vma->vm_flags |= VM_SHARED | VM_MAYSHARE | VM_LOCKED;

	/* We don't want the first write access to trigger a "minor" page fault
	 * to mark the page as dirty.  This is transient, private memory, we
	 * don't care if it was touched or not. __S011 means RW access, but not
	 * execute, and avoids copy-on-write behavior.
	 * See protection_map in mmap.c.  */
	vma->vm_page_prot = PAGE_SHARED;
}

#define vma_nr_pages(vma) \
	({unsigned long v = ((vma->vm_end - vma->vm_start) >> PAGE_SHIFT); v;})

extern struct page* get_colored_page(unsigned long color);

static int do_map_colored_page(struct vm_area_struct *vma,
		const unsigned long addr,
		const unsigned long color_no)
{
	int err = 0;
	unsigned long offset = 2048;
	
	struct page *page = get_colored_page(color_no);

	if (!page) {
		printk(KERN_INFO "Could not get page with color %lu.\n",
				color_no);
		err = -ENOMEM;
		goto out;
	}

	printk(KERN_INFO "vma: %p  addr: 0x%lx  color_no: %lu\n",
			vma, addr, color_no);
	
	printk(KERN_INFO "vm_start: %lu vm_end: %lu\n",
			vma->vm_start, vma->vm_end);

	printk(KERN_INFO "inserting page (pa: 0x%lx) at vaddr: 0x%lx  "
			"flags: 0x%lx  prot: 0x%lx\n",
			page_to_phys(page), addr,
			vma->vm_flags, pgprot_val(vma->vm_page_prot));

	
	err = vm_insert_page(vma, addr, page);
	if (err) {
		printk(KERN_INFO "vm_insert_page() failed (%d)\n", err);
		err = -EINVAL;
		goto out;
	}
out:
	return err;
}
	
static int do_map_colored_pages(struct vm_area_struct *vma)
{
	const unsigned long nr_pages = vma_nr_pages(vma);
	unsigned long nr_mapped;
	int i, start_bank = -1, start_color = -1;
	int cur_bank = -1, cur_color = -1, err = 0;
	int colors[16] = {0}, banks[8] = {0};

	if (bypass_cache == 1)
		vma->vm_page_prot = pgprot_noncached(vma->vm_page_prot);
	
	for (i = 0; i < NUM_BANKS; i++) {
		if (((color_param.bank >> i)&0x1) == 1)
			banks[i] = 1;
	}
	
	for (i = 0; i < NUM_COLORS; i++) {
		if (((color_param.color >> i)&0x1) == 1)
			colors[i] = 1;
	}
	
	for (i = 0; i < NUM_BANKS; i++) {
		if (banks[i] == 1) {
			start_bank = i;
			break;
		}
	}
	for (i = 0; i < NUM_COLORS; i++) {
		if (colors[i] == 1) {
			start_color = i;
			break;
		}
	}	
		
	cur_bank = start_bank;
	cur_color = start_color;
	
	for (i = 0; i < NUM_BANKS; i++) {
		printk(KERN_INFO "BANK[%d] = %d\n", i, banks[i]);
	}
	printk(KERN_INFO "cur_bank = %d\n", cur_bank);
	for (i = 0; i < NUM_COLORS; i++) {
		printk(KERN_INFO "COLOR[%d] = %d\n", i, colors[i]);
	}
	printk(KERN_INFO "cur_color = %d\n", cur_color);
	
	
	TRACE_CUR("allocating %lu pages (flags:%lx prot:%lx)\n",
			nr_pages, vma->vm_flags, pgprot_val(vma->vm_page_prot));
	
	for (nr_mapped = 0; nr_mapped < nr_pages; nr_mapped++) {
		const unsigned long addr = vma->vm_start + (nr_mapped << PAGE_SHIFT);
		const unsigned long color_no = cur_bank*NUM_COLORS + cur_color;
		
		err = do_map_colored_page(vma, addr, color_no);
		printk(KERN_INFO "mapped bank[%d], color[%d], color_no = %lu at 0x%lx\n", 
			cur_bank, cur_color, color_no, addr);
		if (err) {
			TRACE_CUR("Could not map colored page set.\n");
			err = -EINVAL;
			goto out;
		}
		do {
			cur_color++;
		} while(colors[cur_color] == 0);
		
		if (cur_color >= NUM_COLORS) {
			do {
				cur_bank++;
			} while(banks[cur_bank] == 0);
			cur_color = start_color;
		}
		
		if (cur_bank >= NUM_BANKS) {
			cur_bank = start_bank;
		}			
	}
	TRACE_CUR("Successfully mapped %lu pages.\n", nr_mapped);
 out:
	return err;
}

static int map_colored_pages(struct vm_area_struct *vma)
{
	int err = 0;

	printk(KERN_INFO "User requests %lu pages.\n", vma_nr_pages(vma));
	if (MAX_COLORED_PAGE < vma_nr_pages(vma)) {
		TRACE_CUR("Max page request %lu but want %lu.\n",
				MAX_COLORED_PAGE, vma_nr_pages(vma));
		err = -EINVAL;
		goto out;
	}
	err = do_map_colored_pages(vma);
out:
	return err;
}

static void litmus_color_shm_vm_close(struct vm_area_struct *vma)
{

	TRACE_CUR("flags=0x%lx prot=0x%lx\n",
			vma->vm_flags, pgprot_val(vma->vm_page_prot));

	TRACE_CUR("%p:%p vma:%p vma->vm_private_data:%p closed.\n",
			(void*) vma->vm_start, (void*) vma->vm_end, vma,
			vma->vm_private_data);

}

static int litmus_color_shm_vm_fault(struct vm_area_struct *vma,
		struct vm_fault *vmf)
{
	/* This function should never be called, since
	 * all pages should have been mapped by mmap()
	 * already. */
	TRACE_CUR("flags=0x%lx (off:%ld)\n", vma->vm_flags, vmf->pgoff);
	printk(KERN_INFO "flags=0x%lx (off:%ld)\n", vma->vm_flags, vmf->pgoff);

	printk(KERN_INFO "Page fault in color ctrl page! prot=0x%lx\n", pgprot_val(vma->vm_page_prot));

	return VM_FAULT_SIGBUS;
}

static struct vm_operations_struct litmus_color_shm_vm_ops = {
	.close	= litmus_color_shm_vm_close,
	.fault	= litmus_color_shm_vm_fault,
};

static int litmus_color_shm_mmap(struct file *filp, struct vm_area_struct *vma)
{
	int err = 0;

	printk(KERN_INFO "mmap called\n");
	
	if (color_param.color == 0x00000000 || color_param.bank == 0x00000000) {
		printk(KERN_INFO "color_info not set.\n");
		return -EINVAL;
	}
	if (color_offset.offset == 0xffffffff || color_offset.lock == -1) {
		printk(KERN_INFO "color_offset not set.\n");
		return -EINVAL;
	}
	
	err = mmap_common_checks(vma);
	if (err) {
		TRACE_CUR("failed mmap common checks\n");
		goto out;
	}

	vma->vm_ops = &litmus_color_shm_vm_ops;
	mmap_common_vma_flags(vma);

	err = map_colored_pages(vma);

	TRACE_CUR("flags=0x%lx prot=0x%lx\n", vma->vm_flags,
			pgprot_val(vma->vm_page_prot));
out:
	color_param.color == 0x00000000;
	color_param.bank == 0x00000000;
	color_offset.offset == 0xffffffff;
	color_offset.lock == -1;
	
	return err;

}

static long litmus_color_shm_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	long err = -ENOIOCTLCMD;
	struct color_ioctl_cmd color_info;
	struct color_ioctl_offset color_off;
				
	printk(KERN_INFO "color_shm ioctl\n");
	
	if (_IOC_TYPE(cmd) != SHM_MAJOR)
		return -ENOTTY;
	
	
	switch (cmd) {
		case SET_COLOR_SHM_CMD:
			
			err = copy_from_user(&color_info, (void*)arg, sizeof(struct color_ioctl_cmd));
	
			color_param.color = color_info.color;
			color_param.bank = color_info.bank;
			printk(KERN_INFO "COLOR = %x\n", color_param.color);
			printk(KERN_INFO "BANK  = %x\n", color_param.bank);
			err = 0;
			break;
		case SET_COLOR_SHM_OFFSET:
			err = copy_from_user(&color_off, (void*)arg, sizeof(struct color_ioctl_offset));
	
			color_offset.offset = color_off.offset;
			color_offset.lock = color_off.lock;
			printk(KERN_INFO "OFFSET = %x\n", color_offset.offset);
			printk(KERN_INFO "LOCK   = %d\n", color_offset.lock);
			err = 0;
			break;
			
		default:
			printk(KERN_INFO "Invalid IOCTL CMD\n");
			err = -EINVAL;
	}

	return err;
}

static struct file_operations litmus_color_shm_fops = {
	.owner	= THIS_MODULE,
	.mmap	= litmus_color_shm_mmap,
	.unlocked_ioctl	= litmus_color_shm_ioctl,
};

static struct miscdevice litmus_color_shm_dev = {
	.name	= DEV_NAME,
	.minor	= MISC_DYNAMIC_MINOR,
	.fops	= &litmus_color_shm_fops,
};

struct mutex bypass_mutex;

int bypass_proc_handler(struct ctl_table *table, int write,
		void __user *buffer, size_t *lenp, loff_t *ppos)
{
	int ret, mode;

	mutex_lock(&bypass_mutex);
	ret = proc_dointvec(table, write, buffer, lenp, ppos);
	printk(KERN_INFO "shm_bypass = %d\n", bypass_cache);
	mutex_unlock(&bypass_mutex);
	
	return ret;
}

static int zero = 0;
static int one = 1;

static struct ctl_table cache_table[] =
{
	{
		.procname	= "shm_bypass",
		.mode		= 0666,
		.proc_handler	= bypass_proc_handler,
		.data		= &bypass_cache,
		.maxlen		= sizeof(bypass_cache),
		.extra1		= &zero,
		.extra2		= &one,
	},	
	{ }
};

static struct ctl_table litmus_dir_table[] = {
	{
		.procname	= "litmus",
 		.mode		= 0555,
		.child		= cache_table,
	},
	{ }
};

static struct ctl_table_header *litmus_sysctls;

static int __init init_color_shm_devices(void)
{
	int err;

	printk(KERN_INFO "Registering LITMUS^RT color_shm devices.\n");
	litmus_sysctls = register_sysctl_table(litmus_dir_table);
	if (!litmus_sysctls) {
		printk(KERN_WARNING "Could not register LITMUS^RT color_shm sysctl.\n");
		err = -EFAULT;
	}
	
	mutex_init(&dev_lock);
	mutex_init(&bypass_mutex);
	color_param.color = 0x00000000;
	color_param.bank = 0x00000000;
	color_offset.offset = 0xffffffff;
	color_offset.lock = -1;
	bypass_cache = 0;
	err = misc_register(&litmus_color_shm_dev);
	
	return err;
}

static void __exit exit_color_shm_devices(void)
{
	misc_deregister(&litmus_color_shm_dev);
	printk(KERN_INFO "Unregistering %s device.\n", DEV_NAME);
}

module_init(init_color_shm_devices);
module_exit(exit_color_shm_devices);