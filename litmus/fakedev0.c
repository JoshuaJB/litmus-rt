#include <linux/sched.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/fs.h>
#include <linux/errno.h>
#include <linux/highmem.h>
#include <asm/page.h>
#include <linux/miscdevice.h>
#include <linux/module.h>

#include <litmus/litmus.h>

/* device for allocating pages not cached by the CPU */

#define FAKEDEV0_NAME        "litmus/fakedev0"

#define NUM_BANKS	8
#define BANK_MASK	0x38000000
#define BANK_SHIFT  27

#define NUM_COLORS	16
#define CACHE_MASK  0x0000f000
#define CACHE_SHIFT 12

/* Decoding page color, 0~15 */
static inline unsigned int page_color(struct page *page)
{
	return ((page_to_phys(page)& CACHE_MASK) >> CACHE_SHIFT);
}

/* Decoding page bank number, 0~7 */
static inline unsigned int page_bank(struct page *page)
{
	return ((page_to_phys(page)& BANK_MASK) >> BANK_SHIFT);
}

void litmus_fakedev0_vm_open(struct vm_area_struct *vma)
{
}

void litmus_fakedev0_vm_close(struct vm_area_struct *vma)
{
}

int litmus_fakedev0_vm_fault(struct vm_area_struct* vma,
							struct vm_fault* vmf)
{
	/* modeled after SG DMA video4linux, but without DMA. */
	/* (see drivers/media/video/videobuf-dma-sg.c) */
	struct page *page;

	page = alloc_page(GFP_USER|GFP_COLOR|GFP_CPU1);
	if (!page)
		return VM_FAULT_OOM;

	clear_user_highpage(page, (unsigned long)vmf->virtual_address);
	vmf->page = page;

	return 0;
}

static struct vm_operations_struct litmus_fakedev0_vm_ops = {
	.open = litmus_fakedev0_vm_open,
	.close = litmus_fakedev0_vm_close,
	.fault = litmus_fakedev0_vm_fault,
};

static int litmus_fakedev0_mmap(struct file* filp, struct vm_area_struct* vma)
{
	/* first make sure mapper knows what he's doing */

	/* you can only map the "first" page */
	if (vma->vm_pgoff != 0)
		return -EINVAL;

	/* you can't share it with anyone */
	if (vma->vm_flags & (VM_MAYSHARE | VM_SHARED))
		return -EINVAL;

	/* cannot be expanded, and is not a "normal" page. */
	vma->vm_flags |= (VM_DONTEXPAND|VM_DONOTMOVE);

	/* noncached pages are not explicitly locked in memory (for now). */
	//vma->vm_page_prot = pgprot_noncached(vma->vm_page_prot);

	vma->vm_ops = &litmus_fakedev0_vm_ops;

	return 0;
}

static struct file_operations litmus_fakedev0_fops = {
	.owner = THIS_MODULE,
	.mmap  = litmus_fakedev0_mmap,
};

static struct miscdevice litmus_fakedev0_dev = {
	.name  = FAKEDEV0_NAME,
	.minor = MISC_DYNAMIC_MINOR,
	.fops  = &litmus_fakedev0_fops,
	/* pages are not locked, so there is no reason why
	   anyone cannot allocate an fakedev0 pages */
	.mode  = (S_IRUGO | S_IWUGO),
};

static int __init init_litmus_fakedev0_dev(void)
{
	int err;

	printk("Initializing LITMUS^RT fakedev0 device.\n");
	err = misc_register(&litmus_fakedev0_dev);
	if (err)
		printk("Could not allocate %s device (%d).\n", FAKEDEV0_NAME, err);
	return err;
}

static void __exit exit_litmus_fakedev0_dev(void)
{
	misc_deregister(&litmus_fakedev0_dev);
}

module_init(init_litmus_fakedev0_dev);
module_exit(exit_litmus_fakedev0_dev);

