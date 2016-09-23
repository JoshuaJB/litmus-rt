/*
 *	linux/mm/replication.c
 *  pagecache replication
 */
#include <linux/init.h>
#include <linux/mm.h>
#include <linux/mmzone.h>
#include <linux/swap.h>
#include <linux/fs.h>
#include <linux/pagemap.h>
#include <linux/page-flags.h>
#include <linux/pagevec.h>
#include <linux/gfp.h>
#include <linux/slab.h>
#include <linux/radix-tree.h>
#include <linux/spinlock.h>

#include <litmus/litmus.h>

#include "internal.h"

#define MAX_NUMCPUS			4

static struct kmem_cache *pcache_desc_cachep;

void __init replication_init(void)
{
	pcache_desc_cachep = kmem_cache_create("pcache_desc",
			sizeof(struct pcache_desc), 0, SLAB_PANIC, NULL);
	printk(KERN_INFO "Page replication initialized.\n");
}

static struct pcache_desc *alloc_pcache_desc(void)
{
	struct pcache_desc *ret;

	/* NOIO because find_get_page_readonly may be called in the IO path */
	ret = kmem_cache_alloc(pcache_desc_cachep, GFP_ATOMIC);
	if (ret) {
		memset(ret, 0, sizeof(struct pcache_desc));
		/* XXX: should use non-atomic preloads */
		INIT_RADIX_TREE(&ret->page_tree, GFP_ATOMIC);		
	}
	return ret;
}

static void free_pcache_desc(struct pcache_desc *pcd)
{
	kmem_cache_free(pcache_desc_cachep, pcd);
}

/*
 * Free the struct pcache_desc, and all slaves. The pagecache refcount is
 * retained for the master (because presumably we're collapsing the replication.
 *
 * Returns 1 if any of the slaves had a non-zero mapcount (in which case, we'll
 * have to unmap them), otherwise returns 0.
 */
static int release_pcache_desc(struct pcache_desc *pcd)
{
	int ret = 0;
	int i;

	page_cache_get(pcd->master);
	for_each_cpu(i, &pcd->cpus_present) {
		struct page *page;

		page = radix_tree_delete(&pcd->page_tree, i);
		BUG_ON(!page);
		if (page != pcd->master) {
			BUG_ON(PageDirty(page));
			BUG_ON(!PageUptodate(page));
			dec_zone_page_state(page, NR_REPL_PAGES);
			page->mapping = NULL;
			if (page_mapped(page))
				ret = 1; /* tell caller to unmap the ptes */
		}
		page_cache_release(page);
	}

	free_pcache_desc(pcd);

	return ret;
}

#define PCACHE_DESC_BIT	4 /* 1 is used internally by the radix-tree */

static inline int __is_pcache_desc(void *ptr)
{
	if ((unsigned long)ptr & PCACHE_DESC_BIT)
		return 1;
	return 0;
}

int is_pcache_desc(void *ptr)
{
	return __is_pcache_desc(ptr);
}

struct pcache_desc *ptr_to_pcache_desc(void *ptr)
{
	BUG_ON(!__is_pcache_desc(ptr));
	return (struct pcache_desc *)((unsigned long)ptr & ~PCACHE_DESC_BIT);
}

void *pcache_desc_to_ptr(struct pcache_desc *pcd)
{
	BUG_ON(__is_pcache_desc(pcd));
	return (void *)((unsigned long)pcd | PCACHE_DESC_BIT);
}

/*
 * Must be called with the page locked and tree_lock held to give a non-racy
 * answer.
 */
static int should_replicate_pcache(struct page *page, struct address_space *mapping,
									unsigned long offset)
{
	umode_t mode;

	if (unlikely(PageSwapCache(page)))
		return 0;
printk(KERN_INFO "[Pg %ld] _count = %d, _mapcount = %d\n", page_to_pfn(page), page_count(page), page_mapcount(page));
	if (page_count(page) != 2 + page_mapcount(page))
		return 0;
	smp_rmb();
	if (!PageUptodate(page) || PageDirty(page) || PageWriteback(page))
		return 0;

	if (!PagePrivate(page))
		return 1;

	mode = mapping->host->i_mode;
	if (S_ISREG(mode) || S_ISBLK(mode))
		return 1;

	return 0;
}

/*
 * Try to convert pagecache coordinate (mapping, offset) (with page residing)
 * into a replicated pagecache.
 *
 * Returns 1 if we leave with a successfully converted pagecache. Otherwise 0.
 * (note, that return value is racy, so it is a hint only)
 */
static int try_to_replicate_pcache(struct page *page, struct address_space *mapping,
									unsigned long offset)
{
	int cpu;
	void **pslot;
	struct pcache_desc *pcd;
	int ret = 0;
	
	//lock_page(page);
	if (!trylock_page(page)) {
printk(KERN_INFO "TRYLOCK_PAGE failed\n");
		return ret;
	}
	
	if (unlikely(!page->mapping))
		goto out;

	pcd = alloc_pcache_desc();
	if (!pcd)
		goto out;

	if (!tsk_rt(current)) {
		BUG();
		goto out;
	}
	
	cpu = tsk_rt(current)->task_params.cpu;
	
	pcd->master = page;
	//cpumask_set_cpu(cpu, &pcd->cpus_present);
	//if (radix_tree_insert(&pcd->page_tree, cpu, page))
	//	goto out_pcd;

	spin_lock_irq(&mapping->tree_lock);

	/* The non-racy check */
	if (unlikely(!should_replicate_pcache(page, mapping, offset)))
		goto out_lock;

	pslot = radix_tree_lookup_slot(&mapping->page_tree, offset);

	/* Already been replicated? Return yes! */
	if (unlikely(is_pcache_desc(radix_tree_deref_slot(pslot)))) {
		free_pcache_desc(pcd);
		ret = 1;
		goto out_lock;
	}
	/*
	 * The page is being held in pagecache and kept unreplicated because
	 * it is locked. The following bugchecks.
	 */
	BUG_ON(!pslot);
	BUG_ON(page != radix_tree_deref_slot(pslot));
	BUG_ON(is_pcache_desc(radix_tree_deref_slot(pslot)));
	
	radix_tree_replace_slot(pslot, pcache_desc_to_ptr(pcd));
	radix_tree_tag_set(&mapping->page_tree, offset, PAGECACHE_TAG_REPLICATED);
	ret = 1;

out_lock:
	spin_unlock_irq(&mapping->tree_lock);
out_pcd:
	if (ret == 0)
		free_pcache_desc(pcd);
out:
	unlock_page(page);
	return ret;
}

/*
 * Called with tree_lock held for write, and (mapping, offset) guaranteed to be
 * replicated. Drops tree_lock.
 */
static void __unreplicate_pcache(struct address_space *mapping, 
							unsigned long offset)
{
	void **pslot;
	struct pcache_desc *pcd;
	struct page *page;

	pslot = radix_tree_lookup_slot(&mapping->page_tree, offset);
	
	/* Gone? Success */
	if (unlikely(!pslot)) {
		spin_unlock_irq(&mapping->tree_lock);
		return;
	}
	
	/* Already been un-replicated? Success */
	if (unlikely(!is_pcache_desc(radix_tree_deref_slot(pslot)))) {
		spin_unlock_irq(&mapping->tree_lock);
		return;
	}
	
	pcd = ptr_to_pcache_desc(radix_tree_deref_slot(pslot));

	page = pcd->master;
	BUG_ON(PageDirty(page));
	BUG_ON(!PageUptodate(page));
	
	radix_tree_replace_slot(pslot, page);
	radix_tree_tag_clear(&mapping->page_tree, offset, PAGECACHE_TAG_REPLICATED);
	
	spin_unlock_irq(&mapping->tree_lock);

	/*
	 * XXX: this actually changes all the find_get_pages APIs, so
	 * we might want to just coax unmap_mapping_range into not
	 * sleeping instead.
	 */
	//might_sleep();

	if (release_pcache_desc(pcd)) {
		/* release_pcache_desc saw some mapped slaves */
		unmap_mapping_range(mapping, (loff_t)offset<<PAGE_CACHE_SHIFT,
					PAGE_CACHE_SIZE, 0);
	}
}

/*
 * Collapse pagecache coordinate (mapping, offset) into a non-replicated
 * state. Must not fail.
 */
void unreplicate_pcache(struct address_space *mapping, unsigned long offset)
{
	spin_lock_irq(&mapping->tree_lock);
	__unreplicate_pcache(mapping, offset);
}

/*
 * Insert a newly replicated page into (mapping, offset) at node nid.
 * Called without tree_lock. May not be successful.
 *
 * Returns 1 on success, otherwise 0.
 */
static int insert_replicated_page(struct page *page, struct address_space *mapping,
									unsigned long offset, int cpu)
{
	void **pslot;
	struct pcache_desc *pcd;

	BUG_ON(!PageUptodate(page));

	spin_lock_irq(&mapping->tree_lock);
	pslot = radix_tree_lookup_slot(&mapping->page_tree, offset);

	/* Truncated? */
	if (unlikely(!pslot))
		goto failed;

	/* Not replicated? */
	if (unlikely(!is_pcache_desc(radix_tree_deref_slot(pslot))))
		goto failed;

	pcd = ptr_to_pcache_desc(radix_tree_deref_slot(pslot));

	if (unlikely(cpumask_test_cpu(cpu, &pcd->cpus_present)))
		goto failed;

	if (radix_tree_insert(&pcd->page_tree, cpu, page))
		goto failed;
	
	page_cache_get(page);
	cpumask_set_cpu(cpu, &pcd->cpus_present);
	__inc_zone_page_state(page, NR_REPL_PAGES);
	spin_unlock_irq(&mapping->tree_lock);
	
	page->mapping = mapping;
	page->index = offset;
	
	lru_cache_add(page);

	return 1;

failed:
	spin_unlock_irq(&mapping->tree_lock);
	return 0;
}

/*
 * Removes a replicated (not master) page. Called with tree_lock held for write
 */
static void __remove_replicated_page(struct pcache_desc *pcd, struct page *page,
			struct address_space *mapping, unsigned long offset)
{
	//int nid = page_to_nid(page);
	int cpu;
	BUG_ON(page == pcd->master);
	//BUG_ON(!node_isset(nid, pcd->nodes_present));
	//BUG_ON(radix_tree_delete(&pcd->page_tree, cpu) != page);
	//node_clear(nid, pcd->nodes_present);
	//for_each_node_mask(nid, pcd->nodes_present) {
	for_each_cpu(cpu, &pcd->cpus_present) {
		if (radix_tree_lookup(&pcd->page_tree, cpu) != page)
			continue;
		BUG_ON(radix_tree_delete(&pcd->page_tree, cpu) != page);
		//node_clear(nid, pcd->nodes_present);
		cpumask_clear_cpu(cpu, &pcd->cpus_present);
		page->mapping = NULL;
		__dec_zone_page_state(page, NR_REPL_PAGES);
		return;
	}
	BUG();
}

/*
 * Reclaim a replicated page. Called with tree_lock held for write and the
 * page locked.
 * Drops tree_lock and returns 1 and the caller should retry. Otherwise
 * retains the tree_lock and returns 0 if successful.
 */
int reclaim_replicated_page(struct address_space *mapping, struct page *page)
{
	struct pcache_desc *pcd;

	pcd = radix_tree_lookup(&mapping->page_tree, page->index);
	if (page == pcd->master) {
		__unreplicate_pcache(mapping, page->index);
		return 1;
	} else {
		__remove_replicated_page(pcd, page, mapping, page->index);
		return 0;
	}
}

/*
 * Try to create a replica of page at the given nid.
 * Called without any locks held. page has its refcount elevated.
 * Returns the newly replicated page with an elevated refcount on
 * success, or NULL on failure.
 */
static struct page *try_to_create_replica(struct address_space *mapping,
			unsigned long offset, struct page *page, int nid)
{
	struct page *repl_page;

//	repl_page = alloc_pages_node(nid, mapping_gfp_mask(mapping) |
//					  __GFP_THISNODE | __GFP_NORETRY, 0);
	repl_page = alloc_pages(GFP_ATOMIC,0); //page_cache_alloc(mapping);
	if (!repl_page)
		return page; /* failed alloc, just return the master */

	copy_highpage(repl_page, page);
	flush_dcache_page(repl_page);
	page->mapping = mapping;
	page->index = offset;
	SetPageUptodate(repl_page); /* XXX: can use nonatomic */

	page_cache_release(page);
	insert_replicated_page(repl_page, mapping, offset, nid);

printk(KERN_INFO "[Pg %ld] P%d copied to %ld\n", page_to_pfn(page), nid, page_to_pfn(repl_page));
	return repl_page;
}

/*
 * find_get_page - find and get a page reference
 * @mapping: the address_space to search
 * @offset: the page index
 *
 * Is there a pagecache struct page at the given (mapping, offset) tuple?
 * If yes, increment its refcount and return it; if no, return NULL.
 */
struct page *find_get_page_readonly(struct address_space *mapping,
						unsigned long offset)
{
	int cpu;
	struct page *page;
	page = NULL;
	
	rcu_read_lock();
retry:
	if (!tsk_rt(current))
		goto unlock;
	
	cpu = tsk_rt(current)->task_params.cpu;
	page = radix_tree_lookup(&mapping->page_tree, offset);
	if (!page)
		goto unlock;

	if (is_pcache_desc(page)) {
		struct pcache_desc *pcd;
		pcd = ptr_to_pcache_desc(page);
		if (!cpumask_test_cpu(cpu, &pcd->cpus_present)) {
			page = pcd->master;
			page_cache_get(page);
			
			page = try_to_create_replica(mapping, offset, page, cpu);
printk(KERN_INFO "[Pg %ld] P%d SECOND TRY: page replicated\n", page_to_pfn(page), cpu);					
		} else {
			page = radix_tree_lookup(&pcd->page_tree, cpu);
			page_cache_get(page);
printk(KERN_INFO "[Pg %ld] P%d replicated page found\n", page_to_pfn(page), cpu);					
		}
		BUG_ON(!page);
		goto out;
	} else if (page) {
		page_cache_get(page);

		if (should_replicate_pcache(page, mapping, offset)) {
			if (try_to_replicate_pcache(page, mapping, offset)) {
				page_cache_release(page);
printk(KERN_INFO "[Pg %ld] P%d FIRST TRY: replace page with pcd\n", page_to_pfn(page), cpu);
				goto retry;
			}
			goto out;
		}
	}
unlock:
	rcu_read_unlock();
out:
	return page;
}
/*
struct page *find_get_page_readonly(struct address_space *mapping,
						unsigned long offset)
{
	int cpu;
	struct page *page;
	page = NULL;
retry:
	spin_lock_irq(&mapping->tree_lock);

	if (!tsk_rt(current))
		goto out;
	
	cpu = tsk_rt(current)->task_params.cpu;
	page = radix_tree_lookup(&mapping->page_tree, offset);
	if (!page)
		goto out;

	if (is_pcache_desc(page)) {
		struct pcache_desc *pcd;
		pcd = ptr_to_pcache_desc(page);
		if (!cpumask_test_cpu(cpu, &pcd->cpus_present)) {
			page = pcd->master;
			page_cache_get(page);
			spin_unlock_irq(&mapping->tree_lock);
			
			page = try_to_create_replica(mapping, offset, page, cpu);
printk(KERN_INFO "[Pg %ld] P%d SECOND TRY: page replicated\n", page_to_pfn(page), cpu);					
		} else {
			page = radix_tree_lookup(&pcd->page_tree, cpu);
			page_cache_get(page);
			spin_unlock_irq(&mapping->tree_lock);
printk(KERN_INFO "[Pg %ld] P%d replicated page found\n", page_to_pfn(page), cpu);					
		}
		BUG_ON(!page);
		return page;
	} else if (page) {
		page_cache_get(page);

		if (should_replicate_pcache(page, mapping, offset)) {
			spin_unlock_irq(&mapping->tree_lock);
			if (try_to_replicate_pcache(page, mapping, offset)) {
				page_cache_release(page);
printk(KERN_INFO "[Pg %ld] P%d FIRST TRY: replace page with pcd\n", page_to_pfn(page), cpu);
				goto retry;
			}
			return page;
		}
	}
out:
	spin_unlock_irq(&mapping->tree_lock);
	return page;
}
*/
/*
 * Takes a page at the given mapping, and returns an unreplicated
 * page with elevated refcount.
 *
 * Called with rcu_read_lock held for read
 */
struct page *get_unreplicated_page(struct address_space *mapping,
				unsigned long offset, struct page *page)
{
	if (page) {
		if (is_pcache_desc(page)) {
			struct pcache_desc *pcd;

			pcd = ptr_to_pcache_desc(page);
			page = pcd->master;
			page_cache_get(page);
			
			//spin_unlock_irq(&mapping->tree_lock);
			unreplicate_pcache(mapping, page->index);

			return page;
		}

		page_cache_get(page);
	}
	//spin_unlock_irq(&mapping->tree_lock);
	return page;
}

/*
 * Collapse a possible page replication. The page is held unreplicated by
 * the elevated refcount on the passed-in page.
 */
struct page *get_unreplicated_page_fault(struct page *page)
{
	struct address_space *mapping;
	struct page *master;
	pgoff_t offset;

	/* could be broken vs truncate? but at least truncate will remove pte */
	offset = page->index;
	mapping = page->mapping;
	if (!mapping)
		return page;

	/*
	 * Take the page lock in order to ensure that we're synchronised
	 * against another task doing clear_page_dirty_for_io()
	 */
	master = find_lock_entry(mapping, offset);
	if (master) {
		/*
		 * Dirty the page to prevent the replication from being
		 * set up again.
		 */
		set_page_dirty(master);
		unlock_page(master);
		//page_cache_release(page);
	}

	return master;
}
