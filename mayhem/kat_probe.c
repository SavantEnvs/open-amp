/*
 * Known-answer probe for the open-amp library, built with the project's normal flags (no
 * sanitizers). It drives the ELF loader, the resource table parser and an rpmsg-over-virtio
 * driver-role loopback with fixed inputs and prints one `KAT ...` line per result, which
 * mayhem/test.sh compares against the expected values.
 */
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <openamp/elf_loader.h>
#include <openamp/remoteproc.h>
#include <openamp/remoteproc_loader.h>
#include <openamp/remoteproc_virtio.h>
#include <openamp/rpmsg.h>
#include <openamp/rpmsg_virtio.h>
#include <openamp/virtio.h>
#include <openamp/virtqueue.h>

#include "common.h"

#define SHM_PA     0x10000000UL
#define SHM_SIZE   0x10000
#define MEM_SIZE   0x8000
#define NUM_DESCS  16
#define ALIGN      4096
#define VRING0_OFF 0x1000
#define VRING1_OFF 0x3000
#define BUF_OFF    0x5000

static uint8_t shm[SHM_SIZE] __attribute__((aligned(4096)));
static uint8_t mem0[MEM_SIZE] __attribute__((aligned(4096)));

struct image {
	const uint8_t *data;
	size_t size;
};

static int store_open(void *store, const char *path, const void **img)
{
	struct image *i = store;

	(void)path;
	*img = i->data;
	return (int)i->size;
}

static void store_close(void *store)
{
	(void)store;
}

static int store_load(void *store, size_t off, size_t size, const void **data,
		      metal_phys_addr_t pa, struct metal_io_region *io, char blocking)
{
	struct image *i = store;
	size_t n;

	(void)blocking;
	if (off > i->size)
		return -1;
	n = i->size - off;
	if (n > size)
		n = size;
	if (pa != RPROC_LOAD_ANYADDR) {
		if (!io || metal_io_block_write(io, metal_io_phys_to_offset(io, pa), i->data + off, n) < 0)
			return -1;
	}
	*data = i->data + off;
	return (int)n;
}

static const struct image_store_ops store_ops = {
	.open = store_open, .close = store_close, .load = store_load, .features = SUPPORT_SEEK,
};

static void put16(uint8_t *p, uint16_t v) { memcpy(p, &v, 2); }
static void put32(uint8_t *p, uint32_t v) { memcpy(p, &v, 4); }
static void put64(uint8_t *p, uint64_t v) { memcpy(p, &v, 8); }

/* ELF64 little endian: one PT_LOAD of 16 bytes at da 0x1000, entry 0x1004, no sections. */
static size_t build_elf(uint8_t *img, int magic_ok)
{
	memset(img, 0, 256);
	memcpy(img, magic_ok ? "\x7f" "ELF" : "\x7f" "ELX", 4);
	img[4] = 2; /* ELFCLASS64 */
	img[5] = 1; /* little endian */
	img[6] = 1; /* version */
	put16(img + 16, 2);	  /* ET_EXEC */
	put16(img + 18, 183);	  /* EM_AARCH64 */
	put32(img + 20, 1);	  /* e_version */
	put64(img + 24, 0x1004);  /* e_entry */
	put64(img + 32, 64);	  /* e_phoff */
	put64(img + 40, 0);	  /* e_shoff */
	put16(img + 52, 64);	  /* e_ehsize */
	put16(img + 54, 56);	  /* e_phentsize */
	put16(img + 56, 1);	  /* e_phnum */
	put16(img + 58, 64);	  /* e_shentsize */
	put32(img + 64, 1);	  /* p_type = PT_LOAD */
	put32(img + 68, 5);	  /* p_flags */
	put64(img + 72, 128);	  /* p_offset */
	put64(img + 80, 0x1000);  /* p_vaddr */
	put64(img + 88, 0x1000);  /* p_paddr */
	put64(img + 96, 16);	  /* p_filesz */
	put64(img + 104, 32);	  /* p_memsz */
	put64(img + 112, 4);	  /* p_align */
	memcpy(img + 128, "OPENAMP-KAT-0123", 16);
	return 144;
}

static void kat_elf(void)
{
	uint8_t elf[256];
	struct remoteproc rp;
	struct mem_win w;
	struct image img = { elf, 0 };
	char seg[17] = { 0 };
	int ret;

	memset(mem0, 0xAA, sizeof(mem0));
	img.size = build_elf(elf, 1);
	remoteproc_init(&rp, &stub_ops, NULL);
	mem_win_add(&rp, &w, "mem0", mem0, MEM_SIZE, 0);
	remoteproc_config(&rp, NULL);
	ret = remoteproc_load(&rp, "fw", &img, &store_ops, NULL);
	memcpy(seg, mem0 + 0x1000, 16);
	printf("KAT elf_load ret=%d entry=0x%lx seg=%s pad=%02x%02x\n", ret,
	       (unsigned long)rp.bootaddr, seg, mem0[0x1010], mem0[0x101f]);

	memset(mem0, 0xAA, sizeof(mem0));
	img.size = build_elf(elf, 0);
	remoteproc_init(&rp, &stub_ops, NULL);
	mem_win_add(&rp, &w, "mem0", mem0, MEM_SIZE, 0);
	remoteproc_config(&rp, NULL);
	ret = remoteproc_load(&rp, "fw", &img, &store_ops, NULL);
	printf("KAT elf_badmagic ret=%d untouched=%02x\n", ret, mem0[0x1000]);
}

static void build_rsc(uint8_t ver)
{
	struct resource_table *t = (struct resource_table *)shm;
	struct fw_rsc_vdev *v;
	unsigned int i;

	memset(shm, 0, sizeof(shm));
	t->ver = ver;
	t->num = 1;
	t->offset[0] = sizeof(*t) + 4;
	v = (struct fw_rsc_vdev *)(shm + t->offset[0]);
	v->type = RSC_VDEV;
	v->id = VIRTIO_ID_RPMSG;
	v->notifyid = 7;
	v->dfeatures = 1;
	v->num_of_vrings = 2;
	for (i = 0; i < 2; i++) {
		v->vring[i].da = SHM_PA + (i ? VRING1_OFF : VRING0_OFF);
		v->vring[i].align = ALIGN;
		v->vring[i].num = NUM_DESCS;
		v->vring[i].notifyid = 10 + i;
	}
}

static void kat_rsc(void)
{
	struct remoteproc rp;
	struct mem_win w;
	struct virtio_device *vdev;
	int ret;

	build_rsc(2);
	remoteproc_init(&rp, &stub_ops, NULL);
	mem_win_add(&rp, &w, "shm", shm, SHM_SIZE, SHM_PA);
	ret = remoteproc_set_rsc_table(&rp, (struct resource_table *)shm, 256);
	printf("KAT rsc_badver ret=%d\n", ret);

	build_rsc(1);
	remoteproc_init(&rp, &stub_ops, NULL);
	mem_win_add(&rp, &w, "shm", shm, SHM_SIZE, SHM_PA);
	ret = remoteproc_set_rsc_table(&rp, (struct resource_table *)shm, 256);
	vdev = remoteproc_create_virtio(&rp, 0, VIRTIO_DEV_DRIVER, NULL);
	if (vdev)
		printf("KAT rsc_table ret=%d vdev_id=%u notifyid=%u vrings=%u ring1_notifyid=%u\n",
		       ret, (unsigned)vdev->id.device, (unsigned)vdev->notifyid,
		       (unsigned)vdev->vrings_num, (unsigned)vdev->vrings_info[1].notifyid);
	else
		printf("KAT rsc_table ret=%d vdev=none\n", ret);
}

static struct rpmsg_virtio_device rvdev;
static struct rpmsg_virtio_shm_pool pool;
static struct rpmsg_endpoint ept;
static char got[32];
static uint32_t got_src;
static size_t got_len;

static int ept_cb(struct rpmsg_endpoint *e, void *data, size_t len, uint32_t src, void *priv)
{
	(void)e;
	(void)priv;
	got_len = len;
	got_src = src;
	memcpy(got, data, len < sizeof(got) - 1 ? len : sizeof(got) - 1);
	return RPMSG_SUCCESS;
}

static void kat_rpmsg(void)
{
	struct remoteproc rp;
	struct mem_win w;
	struct virtio_device *vdev;
	uint8_t *avail, *used, *desc;
	uint16_t avail_idx, id, used_idx = 1;
	uint64_t addr;
	uint32_t hdr[3], dlen;
	uint16_t hlen;
	struct { uint32_t id, len; } ue = { 0, 20 };
	uint8_t msg[24];
	char payload[5] = { 0 };
	int ret, tx, rx, sent;
	size_t avail_end = NUM_DESCS * 16 + 4 + 2 * NUM_DESCS + 2;

	build_rsc(1);
	remoteproc_init(&rp, &stub_ops, NULL);
	mem_win_add(&rp, &w, "shm", shm, SHM_SIZE, SHM_PA);
	remoteproc_set_rsc_table(&rp, (struct resource_table *)shm, 256);
	vdev = remoteproc_create_virtio(&rp, 0, VIRTIO_DEV_DRIVER, NULL);
	rpmsg_virtio_init_shm_pool(&pool, shm + BUF_OFF, SHM_SIZE - BUF_OFF);
	ret = rpmsg_init_vdev(&rvdev, vdev, NULL, &w.io, &pool);
	rpmsg_create_ept(&ept, &rvdev.rdev, "", 0x400, 0x500, ept_cb, NULL);
	tx = rpmsg_get_tx_buffer_size(&ept);
	rx = rpmsg_get_rx_buffer_size(&ept);
	printf("KAT rpmsg_init ret=%d tx_size=%d rx_size=%d\n", ret, tx, rx);

	sent = rpmsg_trysend(&ept, "ping", 4);
	desc = shm + VRING1_OFF;
	avail = desc + NUM_DESCS * 16;
	memcpy(&avail_idx, avail + 2, 2);
	memcpy(&id, avail + 4, 2);
	memcpy(&addr, desc + id * 16, 8);
	memcpy(&dlen, desc + id * 16 + 8, 4);
	memcpy(hdr, shm + (addr - SHM_PA), 12);
	memcpy(&hlen, shm + (addr - SHM_PA) + 12, 2);
	memcpy(payload, shm + (addr - SHM_PA) + 16, 4);
	printf("KAT rpmsg_send ret=%d avail_idx=%u desc_len=%u src=0x%x dst=0x%x len=%u payload=%s\n",
	       sent, avail_idx, dlen, hdr[0], hdr[1], hlen, payload);

	/* peer answers on the rx ring: header + "pong" into the first posted rx buffer */
	desc = shm + VRING0_OFF;
	memcpy(&addr, desc, 8);
	memset(msg, 0, sizeof(msg));
	put32(msg, 0x500);
	put32(msg + 4, 0x400);
	put16(msg + 12, 4);
	memcpy(msg + 16, "pong", 4);
	memcpy(shm + (addr - SHM_PA), msg, 20);
	used = desc + ((avail_end + ALIGN - 1) & ~(size_t)(ALIGN - 1));
	memcpy(used + 4, &ue, sizeof(ue));
	memcpy(used + 2, &used_idx, 2);
	rproc_virtio_notified(vdev, RSC_NOTIFY_ID_ANY);
	printf("KAT rpmsg_recv src=0x%x len=%zu data=%s\n", got_src, got_len, got);

	rpmsg_deinit_vdev(&rvdev);
	remoteproc_remove_virtio(&rp, vdev);
}

int main(void)
{
	kat_elf();
	kat_rsc();
	kat_rpmsg();
	puts("KAT done");
	return 0;
}
