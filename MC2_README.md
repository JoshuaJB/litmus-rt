# Readme for MC^2 (Mixed Criticality on MultiCore)

Writing TODO:
1. Be consistent in our usage of buddy allocator/freelist/freelist set
2. Be consistent in our usage of memory controller/physical memory node

## Page Coloring

### Background on the Linux's virtual memory
The nesting of memory areas in linux is node, zone, freelist. Typically for
each NUMA node (range of contiguous memory typically associated with a distinct
memory controller) there are several 'zones' which split up the node's physical
address space into areas for normal page allocations and DMA page allocations.
Each zone manages its own buddy allocator with its own set of freelists.

### Overview
Traditional page/cache coloring patches proposed to the Linux kernel have
implemented coloring inside of each zone in one of two ways:
1. On allocation, scan the freelists until a page satisfiying the coloring
   requirements is found and return it (legacy MC^2 approach).
2. Create several sets of freelists per zone, one for each color (2017 proposed
   cache coloring patch by Lukasz Daniluk).

There are some significant downsides:
1. The legacy MC^2 approach has worst-case complexity O(size of memory) as all
   of each freelist may need to be scanned before finding a match.
2. Both approaches cannot be directly controlled from user space
3. Both approaches add significant complexity to the buddy allocator, and in
   the case of the legacy MC^2 approach, are known to add a significant number
   of bugs.

To enable low worst-case complexity and user-space configurability, our
approach eschews modifying the buddy allocator and instead adds uses a clever
combination of the NUMA emulation subsystem with a small coloring filter in the
page free logic.

Linux has the capability to emulate a NUMA system with multiple memory nodes by
contiguously subdividing the physical memory on one or more physical memory
nodes. The emulated NUMA system behaves exactly as a real NUMA system from
user-space (with the exception that inter-node transfer times are zero). This
similarity also extends into kernel space. Each emulated node receives its own
set of zones and freelists. Configuring the NUMA emulation system to emulate
one node for each color in the system provides the ideal, portable
configuration interface, with one enormous issue; there is no way to specify
which pages go into each virtual NUMA node.

To address this issue, it's important to first understand how Linux initializes
memory allocation. Initially, the kernel only has access to static memory that
was compiled in, but it quickly initializes a basic `memblock` allocator which
it uses during the early boot process. Eventually the kernel has determined
enough about your system to have created nodes and zones, so then it can setup
and populate a buddy allocator for each memory zone. Curiously, the buddy
allocator is not populated in bulk. There is no function called something like
`init_allocator_with_memrange(start, end)`. Instead, the kernel progressively
frees every unused page in physical memory to the buddy allocator.

This chokepoint provides a perfect spot to reroute free requests for each page
to the emulated NUMA memory node that matches its color. This one simple change
implements page coloring in both a resilient and efficient manner!

### Quick Setup (Only tested on Ubuntu 20.04 Server)
To install:
1. Run `sudo ./SETUP_MC2.sh` to setup the environment
2. Run `make bzImage modules -j32` to build everything
3. Run `sudo make INSTALL_MOD_STRIP=1 modules_install install` to install everything

To boot with grub-reboot rather than via the interactive menu:
1. Change `GRUB_DEFAULT` to equal `saved` in `/etc/default/grub`
2. Run `sudo update-grub` to apply the changes
3. Run `sudo grub-reboot "Advanced options for Ubuntu>Ubuntu, with Linux 5.4.0-rc7-mc2-v2+"`
   to set the default kernel that it will use at next boot.
4. Save all your work and run `sudo reboot`

### Setup
1. Verify that the constants used in `__filter_color_and_free_one_page()` in
`page_alloc.c` match your platform.
2. Enable `CONFIG_NUMA_EMU` and add `numa=fake=2U` to your kernel's cmdline, where
`2` is the number of colors in your system. (Also add `irqaffinity=0` if you'd
like to use core 0 as the interrupt master.)
3. Boot linux and enjoy colored pages!

For the test systems used at UNC, several drivers dislike the lack of
contiguous memory blocks larger than 32KiB, so several settings need to be
changed:
1. Enable CMDLINE_BOOL "Built-in kernel command line" and set it to
   `nvme.io_queue_depth=512`. The default NVMe submission queue size is 64KiB,
   which cannot be allocated if 32KiB is the largest allocatible order.

Note: When porting this patch to a new platform and the maximum non-colored
allocation is too small to fit in one color, consider switching kmalloc to
kvmalloc. Be careful though, since kvmalloc allocates virtually (not
physically!) contiguous memory, it is not suitable for DMA.

Note 2: There should be no issues at all if you can color at a level which
premits for contiguous blocks of 128KiB. This is the largest contiguous
allocation supported by kmalloc.

### Usage
See documentation for fake NUMA and cpusets, our only difference is that the
fake NUMA memory nodes correspond to set of all pages of one color.

Specifically, use `numactl -m <color>` before your task to specify which memory
color its pages should be allocated in.

### Removal
1. Run `sudo rm /boot/*-mc2-v2+` and `sudo update-grub` to uninstall the kernel
2. Run `sudo rm -rf /usr/lib/modules/*-mc2-v2+` to uninstall the modules
