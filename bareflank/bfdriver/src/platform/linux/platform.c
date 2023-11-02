/*
 * Copyright (C) 2019 Assured Information Security, Inc.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <bfarch.h>
#include <bfdebug.h>
#include <bfplatform.h>

#include <common.h>

#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/module.h>
#include <linux/vmalloc.h>
#include <linux/version.h>
#include <linux/cpumask.h>
#include <linux/sched.h>
#include <linux/kallsyms.h>
#include <linux/version.h>
#include <linux/kernel.h>

#if defined(BF_AARCH64)
#   include <asm/io.h>
#endif

typedef long (*set_affinity_fn)(pid_t, const struct cpumask *);
set_affinity_fn set_cpu_affinity = nullptr;

typedef void* (*__vmalloc_node_range_fn)(unsigned long size, unsigned long align,
                        unsigned long start, unsigned long end, gfp_t gfp_mask,
                        pgprot_t prot, unsigned long vm_flags, int node,
                        const void *caller);
__vmalloc_node_range_fn __vmalloc_node_range_ptr = nullptr;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 7, 0)

#include <asm/io.h>
#include <linux/kprobes.h>

#define KPROBE_KALLSYMS_LOOKUP 1
typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
kallsyms_lookup_name_t kallsyms_lookup_name_func;
#define kallsyms_lookup_name kallsyms_lookup_name_func

static struct kprobe kp = {
    .symbol_name = "kallsyms_lookup_name"
};
#endif

int64_t
platform_init(void)
{

#if KPROBE_KALLSYMS_LOOKUP
    register_kprobe(&kp);
    kallsyms_lookup_name = (kallsyms_lookup_name_t)kp.addr;
    unregister_kprobe(&kp);

    if (!unlikely(kallsyms_lookup_name)) {
        BFALERT("Could not retrieve kallsyms_lookup_name address\n");
        return -1;
    }

    printk(KERN_INFO "cwmyung:bfdriver -- %s found kallsyms_lookup_name\n", __func__);
#endif

    set_cpu_affinity = (set_affinity_fn)kallsyms_lookup_name("sched_setaffinity");
    if (set_cpu_affinity == nullptr) {
        BFALERT("Failed to locate sched_setaffinity\n");
        return -1;
    }

    return BF_SUCCESS;
}

void *
platform_alloc_rw(uint64_t len)
{
    void *addr = nullptr;

    if (len == 0) {
        BFALERT("platform_alloc_rw: invalid length\n");
        return addr;
    }

    addr = vmalloc(len);

    if (addr == nullptr) {
        BFALERT("platform_alloc_rw: failed to vmalloc rw mem: %lld\n", len);
    }

    return addr;
}

void*
vmalloc_nx_disable(uint64_t size)
{
    __vmalloc_node_range_ptr = (__vmalloc_node_range_fn)
                        kallsyms_lookup_name("__vmalloc_node_range");

    if (__vmalloc_node_range_ptr == nullptr) {
        printk(KERN_INFO "cwmyung: (ERROR) couldn't find __vmalloc_node_range\n");
        return NULL;
    }

    return __vmalloc_node_range_ptr(size, 1, VMALLOC_START, VMALLOC_END,
                                GFP_KERNEL, PAGE_KERNEL_EXEC,
                                0, NUMA_NO_NODE,
                                __builtin_return_address(0));
}

void *
platform_alloc_rwe(uint64_t len)
{
    void *addr = nullptr;

    if (len == 0) {
        BFALERT("platform_alloc_rwe: invalid length\n");
        return addr;
    }

    addr = vmalloc_nx_disable(len);
    printk(KERN_INFO "cwmyung: bfdriver -- Allocating %lld bytes for executable pages\n", len);

    if (addr == nullptr) {
        BFALERT("platform_alloc_rwe: failed to vmalloc rwe mem: %lld\n", len);
    }

    return addr;
}

void
platform_free_rw(void *addr, uint64_t len)
{
    bfignored(len);

    if (addr == nullptr) {
        BFALERT("platform_free_rw: invalid address %p\n", addr);
        return;
    }

    vfree(addr);
}

void
platform_free_rwe(void *addr, uint64_t len)
{
    bfignored(len);

    if (addr == nullptr) {
        BFALERT("platform_free_rwe: invalid address %p\n", addr);
        return;
    }

    vfree(addr);
}

void *
platform_virt_to_phys(void *virt)
{
    if (is_vmalloc_addr(virt)) {
        return (void *)page_to_phys(vmalloc_to_page(virt));
    }
    else {
        return (void *)virt_to_phys(virt);
    }
}

void *
platform_memset(void *ptr, char value, uint64_t num)
{
    if (!ptr) {
        return nullptr;
    }

    return memset(ptr, value, num);
}

int64_t
platform_memcpy(
    void *dst, uint64_t dst_size, const void *src, uint64_t src_size, uint64_t num)
{
    if (dst == 0 || src == 0) {
        BFALERT("platform_memcpy: invalid dst or src\n");
        return FAILURE;
    }

    if (num > dst_size || num > src_size) {
        BFALERT("platform_memcpy: num out of range\n");
        return FAILURE;
    }

    memcpy(dst, src, num);
    return SUCCESS;
}

int64_t
platform_num_cpus(void)
{
    int64_t num_cpus = num_online_cpus();

    if (num_cpus < 0) {
        return 0;
    }

    return num_cpus;
}

int64_t
platform_call_vmm_on_core(
    uint64_t cpuid, uint64_t request, uintptr_t arg1, uintptr_t arg2)
{
    int64_t ret = 0;

    if (set_cpu_affinity(current->pid, cpumask_of(cpuid)) != 0) {
        return BF_ERROR_UNKNOWN;
    }

    if (request == BF_REQUEST_VMM_FINI) {
        load_direct_gdt(raw_smp_processor_id());
    }

    ret = common_call_vmm(cpuid, request, arg1, arg2);

    if (request == BF_REQUEST_VMM_FINI) {
        load_fixmap_gdt(raw_smp_processor_id());
    }

    return ret;
}

void *
platform_get_rsdp(void)
{ return 0; }
