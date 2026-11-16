# ELF loader: attacker-sized allocation for the resource table

libFuzzer reports `out-of-memory (malloc(4294967295))` from `remoteproc_get_rsc_table()`
(remoteproc.c:116, called from `remoteproc_load()` remoteproc.c:563): the `.resource_table` section size
taken from the ELF image is passed to `metal_allocate_memory()` without being checked against the size
of the image.

Reproduce: `/mayhem/fuzz_elf_load -rss_limit_mb=2048 oom-input` (the standalone driver has no rss
limit, so it does not report it).

Fix: reject a resource-table size larger than the image (or a sane maximum) before allocating.
