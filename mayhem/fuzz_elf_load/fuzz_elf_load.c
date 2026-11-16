/*
 * Fuzzes the remoteproc firmware loader: the input is an ELF image handed to remoteproc_load(),
 * which parses the headers, copies the PT_LOAD segments into two target memory windows and
 * validates/installs the .resource_table section.
 */
#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include <openamp/remoteproc.h>
#include <openamp/remoteproc_loader.h>

#include "../common.h"

#define MEM0_PA   0x00000000UL
#define MEM1_PA   0x3ED00000UL
#define MEM_SIZE  0x8000
#define MAX_IMAGE 0x10000

static uint8_t mem0[MEM_SIZE] __attribute__((aligned(4096)));
static uint8_t mem1[MEM_SIZE] __attribute__((aligned(4096)));

struct image {
	const uint8_t *data;
	size_t size;
};

static int store_open(void *store, const char *path, const void **img_data)
{
	struct image *img = store;

	(void)path;
	*img_data = img->data;
	return (int)img->size;
}

static void store_close(void *store)
{
	(void)store;
}

static int store_load(void *store, size_t offset, size_t size, const void **data,
		      metal_phys_addr_t pa, struct metal_io_region *io, char is_blocking)
{
	struct image *img = store;
	size_t n;

	(void)is_blocking;
	if (offset > img->size)
		return -1;
	n = img->size - offset;
	if (n < size)
		return -1; /* cannot supply the requested range */
	n = size;
	if (pa == RPROC_LOAD_ANYADDR) {
		*data = img->data + offset;
		return (int)n;
	}
	if (!io)
		return -1;
	if (metal_io_block_write(io, metal_io_phys_to_offset(io, pa), img->data + offset, n) < 0)
		return -1;
	*data = img->data + offset;
	return (int)n;
}

static const struct image_store_ops store_ops = {
	.open = store_open,
	.close = store_close,
	.load = store_load,
	.features = SUPPORT_SEEK,
};

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	struct remoteproc rp;
	struct mem_win win0, win1;
	struct image img = { data, size };

	if (size < 52 || size > MAX_IMAGE)
		return -1;

	memset(mem0, 0, sizeof(mem0));
	memset(mem1, 0, sizeof(mem1));

	if (!remoteproc_init(&rp, &stub_ops, NULL))
		return 0;
	mem_win_add(&rp, &win0, "mem0", mem0, MEM_SIZE, MEM0_PA);
	mem_win_add(&rp, &win1, "mem1", mem1, MEM_SIZE, MEM1_PA);
	if (remoteproc_config(&rp, NULL) == 0)
		(void)remoteproc_load(&rp, "fw.elf", &img, &store_ops, NULL);
	remoteproc_remove(&rp);
	return 0;
}
