/*
 * Fuzzes the remoteproc resource-table parser and the virtio devices created from it.
 * The input is the resource table image: remoteproc_set_rsc_table() validates it, then every
 * vdev entry is instantiated (remoteproc_create_virtio) and its virtqueues are created.
 */
#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include <openamp/remoteproc.h>
#include <openamp/remoteproc_virtio.h>
#include <openamp/virtio.h>
#include <openamp/virtqueue.h>

#include "../common.h"

#define SHM_PA   0x10000000UL
#define SHM_SIZE 0x10000
#define DDR_PA   0x0UL
#define DDR_SIZE 0x4000
#define TBL_PA   0x100000000UL
#define MAX_TABLE 0x1000
#define MAX_VRINGS 256

static uint8_t shm[SHM_SIZE] __attribute__((aligned(4096)));
static uint8_t ddr[DDR_SIZE] __attribute__((aligned(4096)));
/* the table gets its own window above 4 GiB: vring addresses are 32-bit, so a vring cannot be
   placed over (and overwrite) the table that describes it */
static uint8_t tbl[MAX_TABLE] __attribute__((aligned(4096)));

static void vq_cb(struct virtqueue *vq)
{
	(void)vq;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	struct remoteproc rp;
	struct mem_win shm_win, ddr_win, tbl_win;
	struct virtio_device *vdevs[4] = { 0 };
	bool vqs_ok[4] = { 0 };
	const char *names[MAX_VRINGS];
	vq_callback cbs[MAX_VRINGS];
	unsigned int i, j;

	if (size < sizeof(struct resource_table) || size > MAX_TABLE)
		return -1;

	memset(shm, 0, sizeof(shm));
	memset(ddr, 0, sizeof(ddr));
	memset(tbl, 0, sizeof(tbl));
	memcpy(tbl, data, size);
	for (i = 0; i < MAX_VRINGS; i++) {
		names[i] = "vq";
		cbs[i] = vq_cb;
	}

	if (!remoteproc_init(&rp, &stub_ops, NULL))
		return 0;
	mem_win_add(&rp, &shm_win, "shm", shm, SHM_SIZE, SHM_PA);
	mem_win_add(&rp, &ddr_win, "ddr", ddr, DDR_SIZE, DDR_PA);
	mem_win_add(&rp, &tbl_win, "tbl", tbl, MAX_TABLE, TBL_PA);

	if (remoteproc_set_rsc_table(&rp, (struct resource_table *)tbl, size) == 0) {
		for (i = 0; i < 4; i++) {
			vdevs[i] = remoteproc_create_virtio(&rp, (int)i, VIRTIO_DEV_DRIVER, NULL);
			if (!vdevs[i])
				continue;
			for (j = 0; j < i; j++) {
				if (vdevs[j] == vdevs[i])
					break;
			}
			if (j < i) { /* same notifyid: remoteproc returns the existing vdev */
				vdevs[i] = NULL;
				continue;
			}
			j = vdevs[i]->vrings_num;
			if (j > MAX_VRINGS)
				j = MAX_VRINGS;
			vqs_ok[i] = virtio_create_virtqueues(vdevs[i], 0, j, names, cbs, NULL) == 0;
			if (!vqs_ok[i]) {
				/* a failed create leaves freed queues in vrings_info: drop the vdev */
				remoteproc_remove_virtio(&rp, vdevs[i]);
				vdevs[i] = NULL;
				continue;
			}
			rproc_virtio_notified(vdevs[i], RSC_NOTIFY_ID_ANY);
		}
		remoteproc_get_notification(&rp, 0);
		for (i = 0; i < 4; i++) {
			if (!vdevs[i])
				continue;
			if (vqs_ok[i])
				virtio_delete_virtqueues(vdevs[i]);
			remoteproc_remove_virtio(&rp, vdevs[i]);
		}
	}
	remoteproc_remove(&rp);
	return 0;
}
