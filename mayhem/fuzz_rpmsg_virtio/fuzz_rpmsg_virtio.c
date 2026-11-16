/*
 * Fuzzes the RPMsg-over-virtio receive path with a hostile peer. A virtio rpmsg device is built on
 * a static shared-memory window through the remoteproc API, then the input is turned into peer
 * writes to that window: descriptors / avail-ring entries (device role) or used-ring entries and
 * message buffers (driver role). rpmsg_virtio_rx_callback, the name-service callback, the endpoint
 * callbacks and the tx path run over whatever the peer put there.
 *
 * Input: byte 0 bit 0 selects the role (0 = driver/host, 1 = device/remote), then up to 16 records:
 *   u8 flags, u16 plen, plen payload bytes (max 512)
 *   flags bit 0: raw ring entry follows the flags (16-byte descriptor / 8-byte used element)
 *   flags bits 1-2: buffer length reported for the message (512, plen, 16, 0xffffffff)
 */
#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include <openamp/remoteproc.h>
#include <openamp/remoteproc_virtio.h>
#include <openamp/rpmsg.h>
#include <openamp/rpmsg_virtio.h>
#include <openamp/virtio.h>
#include <openamp/virtqueue.h>

#include "../common.h"

#define SHM_PA     0x10000000UL
#define SHM_SIZE   0x10000
#define NUM_DESCS  16
#define VRING_ALIGN 4096
#define VRING0_OFF 0x1000
#define VRING1_OFF 0x3000
#define BUF_OFF    0x5000
#define BUF_SZ     512
#define MAX_MSGS   16
#define NUM_EPTS   4
#define LOCAL_ADDR 0x400
#define PEER_ADDR  0x500

struct vdesc {
	uint64_t addr;
	uint32_t len;
	uint16_t flags;
	uint16_t next;
} __attribute__((packed));

struct vused_elem {
	uint32_t id;
	uint32_t len;
} __attribute__((packed));

static uint8_t shm[SHM_SIZE] __attribute__((aligned(4096)));

static struct rpmsg_endpoint epts[NUM_EPTS];
static unsigned int epts_used;
static struct rpmsg_virtio_device rvdev;
static struct rpmsg_virtio_shm_pool pool;

static uint8_t *vring_desc(unsigned int off) { return shm + off; }
static uint8_t *vring_avail(unsigned int off) { return shm + off + NUM_DESCS * sizeof(struct vdesc); }
static uint8_t *vring_used(unsigned int off)
{
	size_t avail_end = NUM_DESCS * sizeof(struct vdesc) + 4 + 2 * NUM_DESCS + 2;

	return shm + off + ((avail_end + VRING_ALIGN - 1) & ~(size_t)(VRING_ALIGN - 1));
}

static int ept_cb(struct rpmsg_endpoint *ept, void *data, size_t len, uint32_t src, void *priv)
{
	uint8_t op = len ? ((uint8_t *)data)[0] : 0;
	uint32_t sz = 0;
	void *tx;

	(void)priv;
	switch (op & 7) {
	case 1:
		(void)rpmsg_trysend(ept, data, (int)len);
		break;
	case 2:
		rpmsg_hold_rx_buffer(ept, data);
		rpmsg_release_rx_buffer(ept, data);
		break;
	case 3:
		tx = rpmsg_get_tx_payload_buffer(ept, &sz, 0);
		if (tx) {
			if (len > sz)
				len = sz;
			memcpy(tx, data, len);
			(void)rpmsg_send_nocopy(ept, tx, (int)len);
		}
		break;
	case 4:
		(void)rpmsg_trysendto(ept, data, (int)len, src);
		break;
	case 5:
		tx = rpmsg_get_tx_payload_buffer(ept, &sz, 0);
		if (tx)
			(void)rpmsg_release_tx_buffer(ept, tx);
		break;
	default:
		break;
	}
	return RPMSG_SUCCESS;
}

static void ns_bind(struct rpmsg_device *rdev, const char *name, uint32_t dest)
{
	(void)name;
	if (epts_used >= NUM_EPTS)
		return;
	if (rpmsg_create_ept(&epts[epts_used], rdev, "", RPMSG_ADDR_ANY, dest, ept_cb, NULL) == 0)
		epts_used++;
}

static void build_rsc_table(uint8_t status)
{
	struct resource_table *tbl = (struct resource_table *)shm;
	struct fw_rsc_vdev *v;
	unsigned int i;

	tbl->ver = 1;
	tbl->num = 1;
	tbl->offset[0] = sizeof(*tbl) + sizeof(uint32_t);
	v = (struct fw_rsc_vdev *)(shm + tbl->offset[0]);
	v->type = RSC_VDEV;
	v->id = VIRTIO_ID_RPMSG;
	v->notifyid = 0;
	v->dfeatures = 1; /* VIRTIO_RPMSG_F_NS */
	v->gfeatures = 1;
	v->config_len = 0;
	v->status = status;
	v->num_of_vrings = 2;
	for (i = 0; i < 2; i++) {
		v->vring[i].da = SHM_PA + (i ? VRING1_OFF : VRING0_OFF);
		v->vring[i].align = VRING_ALIGN;
		v->vring[i].num = NUM_DESCS;
		v->vring[i].notifyid = i + 1;
	}
}

static void set_desc(unsigned int ring_off, unsigned int i, uint64_t addr, uint32_t len, uint16_t flags)
{
	struct vdesc d = { addr, len, flags, 0 };

	memcpy(vring_desc(ring_off) + i * sizeof(d), &d, sizeof(d));
}

static void set_avail(unsigned int ring_off, unsigned int slot, uint16_t id, uint16_t idx)
{
	uint8_t *a = vring_avail(ring_off);

	memcpy(a + 4 + slot * 2, &id, 2);
	memcpy(a + 2, &idx, 2);
}

static uint32_t pick_len(uint8_t flags, uint16_t plen)
{
	switch ((flags >> 1) & 3) {
	case 0:
		return BUF_SZ;
	case 1:
		return plen;
	case 2:
		return 16;
	default:
		return 0xffffffffu;
	}
}

static void peer_device_role(struct rd *r)
{
	unsigned int i, n = 0;

	/* tx ring (peer-owned avail ring of empty buffers the device may send into) */
	for (i = 0; i < 4; i++) {
		set_desc(VRING0_OFF, i, SHM_PA + BUF_OFF + (MAX_MSGS + i) * BUF_SZ, BUF_SZ, 2);
		set_avail(VRING0_OFF, i, (uint16_t)i, (uint16_t)(i + 1));
	}

	while (r->n >= 3 && n < MAX_MSGS) {
		uint8_t flags = rd_u8(r);
		uint16_t plen = rd_u16(r);
		uint8_t *buf = shm + BUF_OFF + n * BUF_SZ;
		struct vdesc d = { 0 };

		if (plen > BUF_SZ)
			plen = BUF_SZ;
		plen = (uint16_t)rd_bytes(r, buf, plen);
		if (flags & 1) {
			/* raw peer descriptor, address and length as given: rpmsg_virtio_get_rx_buffer
			   rejects ones outside the shared-buffer window without touching them */
			rd_bytes(r, &d, sizeof(d));
		} else {
			d.addr = SHM_PA + BUF_OFF + n * BUF_SZ;
			d.len = pick_len(flags, plen);
			d.flags = 0;
			d.next = 0;
		}
		memcpy(vring_desc(VRING1_OFF) + n * sizeof(d), &d, sizeof(d));
		set_avail(VRING1_OFF, n, (uint16_t)n, (uint16_t)(n + 1));
		n++;
	}
}

static void peer_driver_role(struct rd *r)
{
	unsigned int n = 0;
	uint8_t *used = vring_used(VRING0_OFF);
	uint16_t used_idx;

	while (r->n >= 3 && n < MAX_MSGS) {
		uint8_t flags = rd_u8(r);
		uint16_t plen = rd_u16(r);
		struct vdesc d;
		struct vused_elem e = { 0 };
		uint8_t tmp[BUF_SZ];

		if (plen > BUF_SZ)
			plen = BUF_SZ;
		plen = (uint16_t)rd_bytes(r, tmp, plen);
		if (flags & 1) {
			rd_bytes(r, &e, sizeof(e));
		} else {
			e.id = n;
			e.len = pick_len(flags, plen);
		}
		/* the message lands in the rx buffer the driver posted for descriptor n */
		memcpy(&d, vring_desc(VRING0_OFF) + (n % NUM_DESCS) * sizeof(d), sizeof(d));
		if (d.addr >= SHM_PA + BUF_OFF && d.addr - SHM_PA + plen <= SHM_SIZE)
			memcpy(shm + (d.addr - SHM_PA), tmp, plen);
		memcpy(used + 4 + n * sizeof(e), &e, sizeof(e));
		n++;
	}
	used_idx = (uint16_t)n;
	memcpy(used + 2, &used_idx, 2);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	struct remoteproc rp;
	struct mem_win win;
	struct virtio_device *vdev;
	/* rpmsg_create_ept requires the caller to set release_cb (rpmsg.h); zero the whole endpoint */
	struct rpmsg_endpoint ep = { 0 };
	struct rd r = { data, size };
	unsigned int role;
	uint8_t payload[8] = "fuzzing";
	uint32_t sz;
	void *tx;

	if (size < 4)
		return -1;
	role = (rd_u8(&r) & 1) ? VIRTIO_DEV_DEVICE : VIRTIO_DEV_DRIVER;

	memset(shm, 0, sizeof(shm));
	memset(epts, 0, sizeof(epts));
	memset(&rvdev, 0, sizeof(rvdev));
	epts_used = 0;
	build_rsc_table(role == VIRTIO_DEV_DEVICE ? VIRTIO_CONFIG_STATUS_DRIVER_OK : 0);

	if (!remoteproc_init(&rp, &stub_ops, NULL))
		return 0;
	mem_win_add(&rp, &win, "shm", shm, SHM_SIZE, SHM_PA);
	if (remoteproc_set_rsc_table(&rp, (struct resource_table *)shm, 256) != 0)
		goto out;
	vdev = remoteproc_create_virtio(&rp, 0, role, NULL);
	if (!vdev)
		goto out;
	rpmsg_virtio_init_shm_pool(&pool, shm + BUF_OFF, SHM_SIZE - BUF_OFF);
	if (rpmsg_init_vdev(&rvdev, vdev, ns_bind, &win.io, &pool) != 0) {
		remoteproc_remove_virtio(&rp, vdev);
		goto out;
	}

	if (rpmsg_create_ept(&ep, &rvdev.rdev, "", LOCAL_ADDR, PEER_ADDR, ept_cb, NULL) != 0) {
		rpmsg_deinit_vdev(&rvdev);
		remoteproc_remove_virtio(&rp, vdev);
		goto out;
	}

	if (role == VIRTIO_DEV_DEVICE)
		peer_device_role(&r);
	else
		peer_driver_role(&r);

	rproc_virtio_notified(vdev, RSC_NOTIFY_ID_ANY);

	(void)rpmsg_trysend(&ep, payload, sizeof(payload));
	tx = rpmsg_get_tx_payload_buffer(&ep, &sz, 0);
	if (tx)
		(void)rpmsg_release_tx_buffer(&ep, tx);
	(void)rpmsg_get_tx_buffer_size(&ep);
	(void)rpmsg_get_rx_buffer_size(&ep);

	rpmsg_deinit_vdev(&rvdev);
	remoteproc_remove_virtio(&rp, vdev);
out:
	remoteproc_remove(&rp);
	return 0;
}
