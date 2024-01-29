/*
 * BPF program to monitor CPU affinity tuning
 * 2023 Filippo Storniolo
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */

#include <linux/bpf.h>
#include <linux/version.h>
#include <linux/types.h>

#include <asm/ptrace.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include <stdint.h>
#include <sys/types.h>

#include <unistd.h>

#include <string.h>

#define _(P) ({typeof(P) val = 0; bpf_probe_read(&val, sizeof(val), &P); val;})

#define MAX_ENTRIES 4096 * 4096 * 8
#define UNMARKING_MIGRATION_OPERATION	0
#define MARKING_MIGRATION_OPERATION		1
#define MIGRATION_TYPE 					4

int unreserved = 0;

typedef __u64 phys_addr_t;


// Using BPF_MAP_TYPE_ARRAY map type all array elements pre-allocated
// and zero initialized at init time

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
} selected_pid_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, MAX_ENTRIES);
} bpf_ringbuffer SEC(".maps");

struct bpf_iter_buddyallocator {
	/* opaque iterator state; having __u64 here allows to preserve correct
	 * alignment requirements in vmlinux.h, generated from BTF
	 */
	__u64 __opaque[17];
} __attribute__((aligned(8)));

struct return_elem_iter {
	phys_addr_t physical_address;
	__u64 order;
};

typedef struct {
	uint64_t phys_addr;
	uint64_t order;
	uint64_t operation;
} migration_metadata_t;

typedef struct {
	uint64_t type;
	uint64_t size;
	migration_metadata_t migration_metadata;
} container_t;

typedef struct {
	uint64_t type;
	uint64_t size;
	uint64_t tot_entries;
} final_stats_t;

extern int bpf_iter_buddyallocator_new(struct bpf_iter_buddyallocator* it, __s64 order) __weak __ksym;
extern struct return_elem_iter* bpf_iter_buddyallocator_next(struct bpf_iter_buddyallocator* it) __weak __ksym;
extern void bpf_iter_buddyallocator_destroy(struct bpf_iter_buddyallocator* it) __weak __ksym;

int send_to_ringbuff(struct return_elem_iter *ret, uint64_t migration_operation){

	container_t *container_obj;
	container_obj = bpf_ringbuf_reserve(&bpf_ringbuffer,sizeof(container_t),0);
	if(!container_obj){
		unreserved++;
		return -1;
	}
	container_obj->type = MIGRATION_TYPE;
	container_obj->size = sizeof(migration_metadata_t);

	container_obj->migration_metadata.phys_addr = ret->physical_address;
	container_obj->migration_metadata.order = ret->order;
	container_obj->migration_metadata.operation = migration_operation;


	bpf_ringbuf_submit(container_obj,0);

	return 0;
}

int send_to_ringbuff_size(uint64_t counter, uint64_t migration_operation)
{
	final_stats_t *final_stats_obj;
	final_stats_obj = bpf_ringbuf_reserve(&bpf_ringbuffer,sizeof(final_stats_t),0);

	if(!final_stats_obj){
		unreserved++;
		return -1;
	}
	final_stats_obj->type = MIGRATION_TYPE;
	final_stats_obj->size = sizeof(uint64_t);

	final_stats_obj->tot_entries = counter;

	bpf_ringbuf_submit(final_stats_obj,0);

	bpf_printk("eBPF program: writing counter in ring buffer: %lu \n", counter);

	return 0;
}

SEC("kretprobe/__task_pid_nr_ns:")
int bpf_prog1(struct pt_regs *ctx)
{
	int c_pid;
	int *expected_pid_ptr;
	int key = 0;

	uint64_t count = 0;
	__u64 start, stop;
	__u64 values[11];

	struct bpf_iter_buddyallocator it;
	struct return_elem_iter *ret;

	c_pid = (int)PT_REGS_RC(ctx);

	expected_pid_ptr = bpf_map_lookup_elem(&selected_pid_map, &key);

	memset(&values[0], 0, 11 * sizeof(__u64));

	if (expected_pid_ptr == NULL || *expected_pid_ptr != c_pid)
		return 0;

	bpf_printk("kretprobe __task_pid_nr_ns: pid %d \n", c_pid);

	start = bpf_ktime_get_ns();
	bpf_iter_buddyallocator_new(&it, 8);

	uint64_t total_ram = 0;

	while ((ret = bpf_iter_buddyallocator_next(&it))) {
		total_ram += 4 << ret->order;
		if (ret->order <= 10)
			values[ret->order]++;
		// bpf_printk("kretprobe __task_pid_nr_ns: order is %llu \n", ret->order);
		count++;
		send_to_ringbuff(ret, UNMARKING_MIGRATION_OPERATION);
	}

	// bpf_printk("free pages = %lu, unreserved = %d \n", count, unreserved);
	send_to_ringbuff_size(count, UNMARKING_MIGRATION_OPERATION);

	bpf_iter_buddyallocator_destroy(&it);
	stop = bpf_ktime_get_ns();

	bpf_printk("count: %llu\n", count);

	bpf_printk("total ram: %llu\n", total_ram);
	bpf_printk("time spent: %llu\n", stop-start);

	for (int i = 0; i < 11; i++)
		bpf_printk("order %d %llu\n", i, values[i]);

	return 0;
}

char _license[] SEC("license") = "GPL";
__u32 _version SEC("version") = LINUX_VERSION_CODE;		//Useful because kprobe is NOT a stable ABI. (wrong version fails to be loaded)
