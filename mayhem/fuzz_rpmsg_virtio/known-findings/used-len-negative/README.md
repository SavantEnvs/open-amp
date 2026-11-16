# tx path: peer-controlled buffer length used as a signed length

`rpmsg_virtio_send_offchannel_raw()` takes the tx buffer length from `rpmsg_virtio_get_tx_buffer()`,
which reads it from a ring the peer owns: the used-ring `len` in the driver role
(`virtqueue_get_buffer(svq, len, idx)`), the avail descriptor `len` in the device role
(`virtqueue_get_first_avail_buffer(svq, idx, len)`). Neither is checked against the shared-memory
window. It then does

    if (len > (int)buff_len) len = buff_len;

With a length >= 0x80000000 the cast is negative, `len` becomes that negative value, and
`metal_io_block_write(io, off, data, len)` converts it to a huge `size_t` and writes past the
shared-memory window (SEGV on WRITE, `metal_io_block_write` io.c:107).

Reproduce: `/mayhem/fuzz_rpmsg_virtio-standalone crash-input`. The input selects the device role. Its
fourth record is a raw rx descriptor whose address is `0x10001000`, the tx ring's own descriptor table
(inside the window, so `rpmsg_virtio_get_rx_buffer` accepts it). Processing that "message" leaves a
huge length in a tx descriptor, and the harness's `rpmsg_trysend` then overflows.

Fix: bound the tx length by the configured buffer size (`h2r_buf_size`/`r2h_buf_size`) and by
`metal_io_region_size(io) - offset`, as `rpmsg_virtio_get_rx_buffer` already does for rx, and compare
as unsigned.
