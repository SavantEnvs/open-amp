/* Shared helpers for the fuzz harnesses and the KAT probe in mayhem/. */
#ifndef MAYHEM_COMMON_H
#define MAYHEM_COMMON_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <metal/io.h>
#include <openamp/remoteproc.h>

struct rd {
	const uint8_t *p;
	size_t n;
};

static inline uint8_t rd_u8(struct rd *r)
{
	if (!r->n)
		return 0;
	r->n--;
	return *r->p++;
}

static inline uint16_t rd_u16(struct rd *r)
{
	uint16_t v = rd_u8(r);

	return (uint16_t)(v | ((uint16_t)rd_u8(r) << 8));
}

static inline size_t rd_bytes(struct rd *r, void *dst, size_t max)
{
	size_t k = r->n < max ? r->n : max;

	memcpy(dst, r->p, k);
	r->p += k;
	r->n -= k;
	return k;
}

/* A remoteproc memory window backed by a static buffer. */
struct mem_win {
	struct metal_io_region io;
	metal_phys_addr_t phys;
	struct remoteproc_mem mem;
};

static inline void mem_win_add(struct remoteproc *rp, struct mem_win *w,
			       const char *name, void *buf, size_t size,
			       metal_phys_addr_t pa)
{
	w->phys = pa;
	metal_io_init(&w->io, buf, &w->phys, size, -1U, 0, NULL);
	remoteproc_init_mem(&w->mem, name, pa, pa, size, &w->io);
	remoteproc_add_mem(rp, &w->mem);
}

static inline int stub_notify(struct remoteproc *rp, uint32_t id)
{
	(void)rp;
	(void)id;
	return 0;
}

static inline int stub_handle_rsc(struct remoteproc *rp, void *rsc, size_t len)
{
	(void)rp;
	(void)rsc;
	(void)len;
	return 0;
}

static const struct remoteproc_ops stub_ops = {
	.notify = stub_notify,
	.handle_rsc = stub_handle_rsc,
};

#endif
