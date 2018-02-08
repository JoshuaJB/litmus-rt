#ifndef LITMUS_CACHE_PROC_H
#define LITMUS_CACHE_PROC_H

#ifdef __KERNEL__

void litmus_setup_lockdown(void __iomem*, u32);
void enter_irq_mode(void);
void exit_irq_mode(void);
void flush_cache(int all);
void lock_cache(int cpu, u32 val);
void cache_lockdown(u32 lock_val, int cpu);

extern struct page *new_alloc_page_color(unsigned long color);

u32 color_read_in_mem_lock(u32 lock_val, u32 unlock_val, void *start, void *end);
u32 color_read_in_mem(u32 lock_val, u32 unlock_val, void *start, void *end);

#endif

#endif

