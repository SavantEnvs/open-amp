#!/usr/bin/env python3
"""Regenerates the committed seed corpora under mayhem/<target>/testsuite/ (run from the repo root)."""
import os
import struct

HERE = os.path.dirname(os.path.abspath(__file__))
SHM = 0x10000000


def out(target, name, data):
    d = os.path.join(HERE, target, "testsuite")
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, name), "wb") as f:
        f.write(data)


def name32(s):
    return s.encode().ljust(32, b"\0")


def vdev(vid=7, notifyid=0, dfeat=1, gfeat=1, status=0, vrings=((SHM + 0x1000, 4096, 16, 1), (SHM + 0x3000, 4096, 16, 2)), config=b""):
    b = struct.pack("<6I", 3, vid, notifyid, dfeat, gfeat, len(config))
    b += struct.pack("<BBBB", status, len(vrings), 0, 0)
    for da, align, num, nid in vrings:
        b += struct.pack("<5I", da, align, num, nid, 0)
    return b + config


def carveout(da=0x3ED00000, pa=0x3ED00000, ln=0x1000, name="cv"):
    return struct.pack("<6I", 0, da, pa, ln, 0, 0) + name32(name)


def devmem(da=0x3ED00000, pa=0x3ED00000, ln=0x1000, name="dm"):
    return struct.pack("<6I", 1, da, pa, ln, 0, 0) + name32(name)


def trace(da=0x3EE00000, ln=0x1000, name="tr"):
    return struct.pack("<4I", 2, da, ln, 0) + name32(name)


def rsc_table(entries, ver=1):
    hdr = 16 + 4 * len(entries)
    offs, body = [], b""
    for e in entries:
        offs.append(hdr + len(body))
        body += e
    return struct.pack("<II8x", ver, len(entries)) + struct.pack("<%dI" % len(offs), *offs) + body


def elf(rsc, bits=64, load_pa=0x1000):
    shstr = b"\0.resource_table\0.shstrtab\0"
    text = b"\x13\x00\x00\x00" * 16
    ehsz, phsz, shsz = (64, 56, 64) if bits == 64 else (52, 32, 40)
    nph = 2
    off_text = ehsz + phsz * nph
    off_rsc = off_text + len(text)
    off_str = off_rsc + len(rsc)
    off_sh = (off_str + len(shstr) + 7) & ~7
    if bits == 64:
        eh = b"\x7fELF" + bytes([2, 1, 1, 0]) + bytes(8) + struct.pack(
            "<HHIQQQIHHHHHH", 2, 183, 1, load_pa, ehsz, off_sh, 0, ehsz, phsz, nph, shsz, 3, 2)
        ph = struct.pack("<IIQQQQQQ", 1, 5, off_text, load_pa, load_pa, len(text), len(text) + 16, 4)
        ph += struct.pack("<IIQQQQQQ", 1, 6, off_rsc, 0x3ED00000, 0x3ED00000, len(rsc), len(rsc), 4)
        sh = bytes(shsz)
        sh += struct.pack("<IIQQQQIIQQ", 1, 1, 2, 0x3ED00000, off_rsc, len(rsc), 0, 0, 4, 0)
        sh += struct.pack("<IIQQQQIIQQ", 17, 3, 0, 0, off_str, len(shstr), 0, 0, 1, 0)
    else:
        eh = b"\x7fELF" + bytes([1, 1, 1, 0]) + bytes(8) + struct.pack(
            "<HHIIIIIHHHHHH", 2, 40, 1, load_pa, ehsz, off_sh, 0, ehsz, phsz, nph, shsz, 3, 2)
        ph = struct.pack("<IIIIIIII", 1, off_text, load_pa, load_pa, len(text), len(text) + 16, 5, 4)
        ph += struct.pack("<IIIIIIII", 1, off_rsc, 0x3ED00000, 0x3ED00000, len(rsc), len(rsc), 6, 4)
        sh = bytes(shsz)
        sh += struct.pack("<IIIIIIIIII", 1, 1, 2, 0x3ED00000, off_rsc, len(rsc), 0, 0, 4, 0)
        sh += struct.pack("<IIIIIIIIII", 17, 3, 0, 0, off_str, len(shstr), 0, 0, 1, 0)
    img = eh + ph + text + rsc + shstr
    img += bytes(off_sh - len(img))
    return img + sh


def rpmsg_hdr(src, dst, payload, flags=0):
    return struct.pack("<IIIHH", src, dst, 0, len(payload), flags) + payload


def rec(msg, flags=0, raw=b""):
    return struct.pack("<BH", flags, len(msg)) + msg + raw


def main():
    base = [vdev(), carveout(), trace()]
    out("fuzz_rsc_table", "rpmsg_vdev.bin", rsc_table([vdev()]))
    out("fuzz_rsc_table", "full.bin", rsc_table(base))
    out("fuzz_rsc_table", "vdev_config.bin", rsc_table([vdev(vid=1, notifyid=3, config=b"\x01\x02\x03\x04")]))
    out("fuzz_rsc_table", "devmem.bin", rsc_table([devmem(), carveout(), vdev(vid=5, notifyid=9)]))
    out("fuzz_rsc_table", "two_vdevs.bin", rsc_table([vdev(notifyid=1), vdev(vid=7, notifyid=2, vrings=((SHM + 0x5000, 4096, 8, 5),))]))
    out("fuzz_rsc_table", "bad_version.bin", rsc_table([vdev()], ver=2))

    rsc = rsc_table([vdev(), carveout(), trace()])
    out("fuzz_elf_load", "elf64_rsc.elf", elf(rsc, 64))
    out("fuzz_elf_load", "elf32_rsc.elf", elf(rsc, 32))
    out("fuzz_elf_load", "elf64_hi.elf", elf(rsc, 64, 0x3ED00100))
    out("fuzz_elf_load", "elf64_vdev_only.elf", elf(rsc_table([vdev()]), 64))

    ns_create = struct.pack("<32sII", b"rpmsg-client-sample", 0x500, 0)
    ns_destroy = struct.pack("<32sII", b"rpmsg-client-sample", 0x500, 1)
    echo = b"\x01hello"
    sendto = b"\x04abc"
    nocopy = b"\x03xyzzy"
    hold = b"\x02hold"
    rel = b"\x05rel"
    for role, tag in ((0, "driver"), (1, "device")):
        b = bytes([role])
        out("fuzz_rpmsg_virtio", tag + "_echo.bin", b + rec(rpmsg_hdr(0x500, 0x400, echo)))
        out("fuzz_rpmsg_virtio", tag + "_ns_create.bin", b + rec(rpmsg_hdr(0x35, 53, ns_create)) + rec(rpmsg_hdr(0x500, 0x400, echo)))
        out("fuzz_rpmsg_virtio", tag + "_ns_destroy.bin", b + rec(rpmsg_hdr(0x35, 53, ns_create)) + rec(rpmsg_hdr(0x35, 53, ns_destroy)))
        out("fuzz_rpmsg_virtio", tag + "_multi.bin", b + b"".join(
            rec(rpmsg_hdr(0x500, 0x400, p)) for p in (sendto, nocopy, hold, rel, echo)))
        out("fuzz_rpmsg_virtio", tag + "_badlen.bin", b + rec(rpmsg_hdr(0x500, 0x400, echo), flags=0x6)
            + rec(rpmsg_hdr(0x500, 0x400, echo), flags=0x4) + rec(rpmsg_hdr(0x500, 0x400, echo), flags=0x2))
    out("fuzz_rpmsg_virtio", "device_raw_desc.bin", bytes([1]) + rec(
        rpmsg_hdr(0x500, 0x400, echo), flags=1, raw=struct.pack("<QIHH", SHM + 0x5000, 512, 0, 0)))
    out("fuzz_rpmsg_virtio", "driver_raw_used.bin", bytes([0]) + rec(
        rpmsg_hdr(0x500, 0x400, echo), flags=1, raw=struct.pack("<II", 0, 20)))


if __name__ == "__main__":
    main()
