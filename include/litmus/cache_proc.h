#ifndef LITMUS_CACHE_PROC_H
#define LITMUS_CACHE_PROC_H

#ifdef __KERNEL__

void litmus_setup_lockdown(void __iomem*, u32);
void enter_irq_mode(void);
void exit_irq_mode(void);
void flush_cache(int all);
void lock_cache(int cpu, u32 val);

extern struct page *new_alloc_page_color(unsigned long color);

#endif

#endif

