/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */

/* THIS FILE IS AUTOGENERATED BY BPFTOOL! */
#ifndef __FENTRY_BPF_SKEL_H__
#define __FENTRY_BPF_SKEL_H__

#include <errno.h>
#include <stdlib.h>
#include <bpf/libbpf.h>

#define BPF_SKEL_SUPPORTS_MAP_AUTO_ATTACH 1

struct fentry_bpf {
	struct bpf_object_skeleton *skeleton;
	struct bpf_object *obj;
	struct {
		struct bpf_map *rodata;
	} maps;
	struct {
		struct bpf_program *do_unlinkat;
		struct bpf_program *do_unlinkat_exit;
	} progs;
	struct {
		struct bpf_link *do_unlinkat;
		struct bpf_link *do_unlinkat_exit;
	} links;

#ifdef __cplusplus
	static inline struct fentry_bpf *open(const struct bpf_object_open_opts *opts = nullptr);
	static inline struct fentry_bpf *open_and_load();
	static inline int load(struct fentry_bpf *skel);
	static inline int attach(struct fentry_bpf *skel);
	static inline void detach(struct fentry_bpf *skel);
	static inline void destroy(struct fentry_bpf *skel);
	static inline const void *elf_bytes(size_t *sz);
#endif /* __cplusplus */
};

static void
fentry_bpf__destroy(struct fentry_bpf *obj)
{
	if (!obj)
		return;
	if (obj->skeleton)
		bpf_object__destroy_skeleton(obj->skeleton);
	free(obj);
}

static inline int
fentry_bpf__create_skeleton(struct fentry_bpf *obj);

static inline struct fentry_bpf *
fentry_bpf__open_opts(const struct bpf_object_open_opts *opts)
{
	struct fentry_bpf *obj;
	int err;

	obj = (struct fentry_bpf *)calloc(1, sizeof(*obj));
	if (!obj) {
		errno = ENOMEM;
		return NULL;
	}

	err = fentry_bpf__create_skeleton(obj);
	if (err)
		goto err_out;

	err = bpf_object__open_skeleton(obj->skeleton, opts);
	if (err)
		goto err_out;

	return obj;
err_out:
	fentry_bpf__destroy(obj);
	errno = -err;
	return NULL;
}

static inline struct fentry_bpf *
fentry_bpf__open(void)
{
	return fentry_bpf__open_opts(NULL);
}

static inline int
fentry_bpf__load(struct fentry_bpf *obj)
{
	return bpf_object__load_skeleton(obj->skeleton);
}

static inline struct fentry_bpf *
fentry_bpf__open_and_load(void)
{
	struct fentry_bpf *obj;
	int err;

	obj = fentry_bpf__open();
	if (!obj)
		return NULL;
	err = fentry_bpf__load(obj);
	if (err) {
		fentry_bpf__destroy(obj);
		errno = -err;
		return NULL;
	}
	return obj;
}

static inline int
fentry_bpf__attach(struct fentry_bpf *obj)
{
	return bpf_object__attach_skeleton(obj->skeleton);
}

static inline void
fentry_bpf__detach(struct fentry_bpf *obj)
{
	bpf_object__detach_skeleton(obj->skeleton);
}

static inline const void *fentry_bpf__elf_bytes(size_t *sz);

static inline int
fentry_bpf__create_skeleton(struct fentry_bpf *obj)
{
	struct bpf_object_skeleton *s;
	struct bpf_map_skeleton *map __attribute__((unused));
	int err;

	s = (struct bpf_object_skeleton *)calloc(1, sizeof(*s));
	if (!s)	{
		err = -ENOMEM;
		goto err;
	}

	s->sz = sizeof(*s);
	s->name = "fentry_bpf";
	s->obj = &obj->obj;

	/* maps */
	s->map_cnt = 1;
	s->map_skel_sz = 24;
	s->maps = (struct bpf_map_skeleton *)calloc(s->map_cnt,
			sizeof(*s->maps) > 24 ? sizeof(*s->maps) : 24);
	if (!s->maps) {
		err = -ENOMEM;
		goto err;
	}

	map = (struct bpf_map_skeleton *)((char *)s->maps + 0 * s->map_skel_sz);
	map->name = "fentry_b.rodata";
	map->map = &obj->maps.rodata;

	/* programs */
	s->prog_cnt = 2;
	s->prog_skel_sz = sizeof(*s->progs);
	s->progs = (struct bpf_prog_skeleton *)calloc(s->prog_cnt, s->prog_skel_sz);
	if (!s->progs) {
		err = -ENOMEM;
		goto err;
	}

	s->progs[0].name = "do_unlinkat";
	s->progs[0].prog = &obj->progs.do_unlinkat;
	s->progs[0].link = &obj->links.do_unlinkat;

	s->progs[1].name = "do_unlinkat_exit";
	s->progs[1].prog = &obj->progs.do_unlinkat_exit;
	s->progs[1].link = &obj->links.do_unlinkat_exit;

	s->data = fentry_bpf__elf_bytes(&s->data_sz);

	obj->skeleton = s;
	return 0;
err:
	bpf_object__destroy_skeleton(s);
	return err;
}

static inline const void *fentry_bpf__elf_bytes(size_t *sz)
{
	static const char data[] __attribute__((__aligned__(8))) = "\
\x7f\x45\x4c\x46\x02\x01\x01\0\0\0\0\0\0\0\0\0\x01\0\xf7\0\x01\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\x40\x0a\0\0\0\0\0\0\0\0\0\0\x40\0\0\0\0\0\x40\0\x0f\0\
\x01\0\x79\x16\x08\0\0\0\0\0\x85\0\0\0\x0e\0\0\0\x79\x64\0\0\0\0\0\0\x77\0\0\0\
\x20\0\0\0\x18\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xb7\x02\0\0\x21\0\0\0\xbf\x03\0\
\0\0\0\0\0\x85\0\0\0\x06\0\0\0\xb7\0\0\0\0\0\0\0\x95\0\0\0\0\0\0\0\x79\x16\x10\
\0\0\0\0\0\x79\x17\x08\0\0\0\0\0\x85\0\0\0\x0e\0\0\0\x79\x74\0\0\0\0\0\0\x77\0\
\0\0\x20\0\0\0\x18\x01\0\0\x21\0\0\0\0\0\0\0\0\0\0\0\xb7\x02\0\0\x2b\0\0\0\xbf\
\x03\0\0\0\0\0\0\xbf\x65\0\0\0\0\0\0\x85\0\0\0\x06\0\0\0\xb7\0\0\0\0\0\0\0\x95\
\0\0\0\0\0\0\0\x44\x75\x61\x6c\x20\x42\x53\x44\x2f\x47\x50\x4c\0\x66\x65\x6e\
\x74\x72\x79\x3a\x20\x70\x69\x64\x20\x3d\x20\x25\x64\x2c\x20\x66\x69\x6c\x65\
\x6e\x61\x6d\x65\x20\x3d\x20\x25\x73\x0a\0\x66\x65\x78\x69\x74\x3a\x20\x70\x69\
\x64\x20\x3d\x20\x25\x64\x2c\x20\x66\x69\x6c\x65\x6e\x61\x6d\x65\x20\x3d\x20\
\x25\x73\x2c\x20\x72\x65\x74\x20\x3d\x20\x25\x6c\x64\x0a\0\0\0\0\x9f\xeb\x01\0\
\x18\0\0\0\0\0\0\0\xf4\x01\0\0\xf4\x01\0\0\x8d\x02\0\0\0\0\0\0\0\0\0\x02\x02\0\
\0\0\x01\0\0\0\0\0\0\x01\x08\0\0\0\x40\0\0\0\0\0\0\0\x01\0\0\x0d\x04\0\0\0\x14\
\0\0\0\x01\0\0\0\x18\0\0\0\0\0\0\x01\x04\0\0\0\x20\0\0\x01\x1c\0\0\0\x01\0\0\
\x0c\x03\0\0\0\xdf\0\0\0\x05\0\0\x04\x20\0\0\0\xe8\0\0\0\x07\0\0\0\0\0\0\0\xed\
\0\0\0\x07\0\0\0\x40\0\0\0\xf2\0\0\0\x0a\0\0\0\x80\0\0\0\xf9\0\0\0\x0c\0\0\0\
\xc0\0\0\0\xff\0\0\0\x0d\0\0\0\0\x01\0\0\0\0\0\0\0\0\0\x02\x08\0\0\0\0\0\0\0\0\
\0\0\x0a\x09\0\0\0\x05\x01\0\0\0\0\0\x01\x01\0\0\0\x08\0\0\x01\x0a\x01\0\0\0\0\
\0\x08\x0b\0\0\0\0\0\0\0\x01\0\0\x04\x04\0\0\0\x13\x01\0\0\x04\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\x02\x19\0\0\0\0\0\0\0\0\0\0\x03\0\0\0\0\x08\0\0\0\x0e\0\0\0\0\0\0\
\0\x1b\x01\0\0\0\0\0\x01\x04\0\0\0\x20\0\0\0\0\0\0\0\x01\0\0\x0d\x04\0\0\0\x14\
\0\0\0\x01\0\0\0\x76\x01\0\0\x01\0\0\x0c\x0f\0\0\0\0\0\0\0\0\0\0\x03\0\0\0\0\
\x09\0\0\0\x0e\0\0\0\x0d\0\0\0\x34\x02\0\0\0\0\0\x0e\x11\0\0\0\x01\0\0\0\0\0\0\
\0\0\0\0\x03\0\0\0\0\x08\0\0\0\x0e\0\0\0\x21\0\0\0\x3c\x02\0\0\0\0\0\x0e\x13\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\x03\0\0\0\0\x08\0\0\0\x0e\0\0\0\x2b\0\0\0\x54\x02\0\
\0\0\0\0\x0e\x15\0\0\0\0\0\0\0\x71\x02\0\0\x02\0\0\x0f\0\0\0\0\x14\0\0\0\0\0\0\
\0\x21\0\0\0\x16\0\0\0\x21\0\0\0\x2b\0\0\0\x79\x02\0\0\x01\0\0\x0f\0\0\0\0\x12\
\0\0\0\0\0\0\0\x0d\0\0\0\x81\x02\0\0\0\0\0\x07\0\0\0\0\0\x75\x6e\x73\x69\x67\
\x6e\x65\x64\x20\x6c\x6f\x6e\x67\x20\x6c\x6f\x6e\x67\0\x63\x74\x78\0\x69\x6e\
\x74\0\x64\x6f\x5f\x75\x6e\x6c\x69\x6e\x6b\x61\x74\0\x66\x65\x6e\x74\x72\x79\
\x2f\x64\x6f\x5f\x75\x6e\x6c\x69\x6e\x6b\x61\x74\0\x2f\x72\x6f\x6f\x74\x2f\x68\
\x7a\x68\x64\x61\x74\x61\x2f\x37\x2d\x65\x62\x70\x66\x2d\x6c\x65\x61\x72\x6e\
\x69\x6e\x67\x2f\x37\x2d\x70\x72\x6f\x67\x72\x61\x6d\x2f\x74\x65\x73\x74\x2d\
\x66\x65\x6e\x74\x72\x79\x2f\x66\x65\x6e\x74\x72\x79\x2e\x62\x70\x66\x2e\x63\0\
\x69\x6e\x74\x20\x42\x50\x46\x5f\x50\x52\x4f\x47\x28\x64\x6f\x5f\x75\x6e\x6c\
\x69\x6e\x6b\x61\x74\x2c\x20\x69\x6e\x74\x20\x64\x66\x64\x2c\x20\x73\x74\x72\
\x75\x63\x74\x20\x66\x69\x6c\x65\x6e\x61\x6d\x65\x20\x2a\x6e\x61\x6d\x65\x29\0\
\x09\x70\x69\x64\x20\x3d\x20\x62\x70\x66\x5f\x67\x65\x74\x5f\x63\x75\x72\x72\
\x65\x6e\x74\x5f\x70\x69\x64\x5f\x74\x67\x69\x64\x28\x29\x20\x3e\x3e\x20\x33\
\x32\x3b\0\x66\x69\x6c\x65\x6e\x61\x6d\x65\0\x6e\x61\x6d\x65\0\x75\x70\x74\x72\
\0\x72\x65\x66\x63\x6e\x74\0\x61\x6e\x61\x6d\x65\0\x69\x6e\x61\x6d\x65\0\x63\
\x68\x61\x72\0\x61\x74\x6f\x6d\x69\x63\x5f\x74\0\x63\x6f\x75\x6e\x74\x65\x72\0\
\x5f\x5f\x41\x52\x52\x41\x59\x5f\x53\x49\x5a\x45\x5f\x54\x59\x50\x45\x5f\x5f\0\
\x30\x3a\x30\0\x09\x62\x70\x66\x5f\x70\x72\x69\x6e\x74\x6b\x28\x22\x66\x65\x6e\
\x74\x72\x79\x3a\x20\x70\x69\x64\x20\x3d\x20\x25\x64\x2c\x20\x66\x69\x6c\x65\
\x6e\x61\x6d\x65\x20\x3d\x20\x25\x73\x5c\x6e\x22\x2c\x20\x70\x69\x64\x2c\x20\
\x6e\x61\x6d\x65\x2d\x3e\x6e\x61\x6d\x65\x29\x3b\0\x64\x6f\x5f\x75\x6e\x6c\x69\
\x6e\x6b\x61\x74\x5f\x65\x78\x69\x74\0\x66\x65\x78\x69\x74\x2f\x64\x6f\x5f\x75\
\x6e\x6c\x69\x6e\x6b\x61\x74\0\x69\x6e\x74\x20\x42\x50\x46\x5f\x50\x52\x4f\x47\
\x28\x64\x6f\x5f\x75\x6e\x6c\x69\x6e\x6b\x61\x74\x5f\x65\x78\x69\x74\x2c\x20\
\x69\x6e\x74\x20\x64\x66\x64\x2c\x20\x73\x74\x72\x75\x63\x74\x20\x66\x69\x6c\
\x65\x6e\x61\x6d\x65\x20\x2a\x6e\x61\x6d\x65\x2c\x20\x6c\x6f\x6e\x67\x20\x72\
\x65\x74\x29\0\x09\x62\x70\x66\x5f\x70\x72\x69\x6e\x74\x6b\x28\x22\x66\x65\x78\
\x69\x74\x3a\x20\x70\x69\x64\x20\x3d\x20\x25\x64\x2c\x20\x66\x69\x6c\x65\x6e\
\x61\x6d\x65\x20\x3d\x20\x25\x73\x2c\x20\x72\x65\x74\x20\x3d\x20\x25\x6c\x64\
\x5c\x6e\x22\x2c\x20\x70\x69\x64\x2c\x20\x6e\x61\x6d\x65\x2d\x3e\x6e\x61\x6d\
\x65\x2c\x20\x72\x65\x74\x29\x3b\0\x4c\x49\x43\x45\x4e\x53\x45\0\x5f\x5f\x5f\
\x5f\x64\x6f\x5f\x75\x6e\x6c\x69\x6e\x6b\x61\x74\x2e\x5f\x5f\x5f\x5f\x66\x6d\
\x74\0\x5f\x5f\x5f\x5f\x64\x6f\x5f\x75\x6e\x6c\x69\x6e\x6b\x61\x74\x5f\x65\x78\
\x69\x74\x2e\x5f\x5f\x5f\x5f\x66\x6d\x74\0\x2e\x72\x6f\x64\x61\x74\x61\0\x6c\
\x69\x63\x65\x6e\x73\x65\0\x61\x75\x64\x69\x74\x5f\x6e\x61\x6d\x65\x73\0\0\0\0\
\x9f\xeb\x01\0\x20\0\0\0\0\0\0\0\x24\0\0\0\x24\0\0\0\xd4\0\0\0\xf8\0\0\0\x34\0\
\0\0\x08\0\0\0\x28\0\0\0\x01\0\0\0\0\0\0\0\x05\0\0\0\x87\x01\0\0\x01\0\0\0\0\0\
\0\0\x10\0\0\0\x10\0\0\0\x28\0\0\0\x06\0\0\0\0\0\0\0\x3b\0\0\0\x7c\0\0\0\x05\
\x28\0\0\x08\0\0\0\x3b\0\0\0\xb6\0\0\0\x08\x38\0\0\x10\0\0\0\x3b\0\0\0\x33\x01\
\0\0\x02\x3c\0\0\x18\0\0\0\x3b\0\0\0\xb6\0\0\0\x23\x38\0\0\x20\0\0\0\x3b\0\0\0\
\x33\x01\0\0\x02\x3c\0\0\x48\0\0\0\x3b\0\0\0\x7c\0\0\0\x05\x28\0\0\x87\x01\0\0\
\x06\0\0\0\0\0\0\0\x3b\0\0\0\x99\x01\0\0\x05\x50\0\0\x10\0\0\0\x3b\0\0\0\xb6\0\
\0\0\x08\x60\0\0\x18\0\0\0\x3b\0\0\0\xe2\x01\0\0\x02\x64\0\0\x20\0\0\0\x3b\0\0\
\0\xb6\0\0\0\x23\x60\0\0\x28\0\0\0\x3b\0\0\0\xe2\x01\0\0\x02\x64\0\0\x58\0\0\0\
\x3b\0\0\0\x99\x01\0\0\x05\x50\0\0\x10\0\0\0\x28\0\0\0\x01\0\0\0\x10\0\0\0\x06\
\0\0\0\x2f\x01\0\0\0\0\0\0\x87\x01\0\0\x01\0\0\0\x18\0\0\0\x06\0\0\0\x2f\x01\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x03\
\0\x03\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x31\0\0\0\x01\0\x08\0\0\0\0\0\0\0\0\0\
\x21\0\0\0\0\0\0\0\0\0\0\0\x03\0\x05\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x14\0\0\
\0\x01\0\x08\0\x21\0\0\0\0\0\0\0\x2b\0\0\0\0\0\0\0\0\0\0\0\x03\0\x08\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\x7b\0\0\0\x12\0\x03\0\0\0\0\0\0\0\0\0\x58\0\0\0\0\0\0\
\0\x49\0\0\0\x12\0\x05\0\0\0\0\0\0\0\0\0\x68\0\0\0\0\0\0\0\xbe\0\0\0\x11\0\x07\
\0\0\0\0\0\0\0\0\0\x0d\0\0\0\0\0\0\0\x20\0\0\0\0\0\0\0\x01\0\0\0\x05\0\0\0\x28\
\0\0\0\0\0\0\0\x01\0\0\0\x05\0\0\0\xd4\x01\0\0\0\0\0\0\x03\0\0\0\x05\0\0\0\xe0\
\x01\0\0\0\0\0\0\x03\0\0\0\x05\0\0\0\xf8\x01\0\0\0\0\0\0\x04\0\0\0\x08\0\0\0\
\x2c\0\0\0\0\0\0\0\x04\0\0\0\x01\0\0\0\x3c\0\0\0\0\0\0\0\x04\0\0\0\x03\0\0\0\
\x50\0\0\0\0\0\0\0\x04\0\0\0\x01\0\0\0\x60\0\0\0\0\0\0\0\x04\0\0\0\x01\0\0\0\
\x70\0\0\0\0\0\0\0\x04\0\0\0\x01\0\0\0\x80\0\0\0\0\0\0\0\x04\0\0\0\x01\0\0\0\
\x90\0\0\0\0\0\0\0\x04\0\0\0\x01\0\0\0\xa0\0\0\0\0\0\0\0\x04\0\0\0\x01\0\0\0\
\xb8\0\0\0\0\0\0\0\x04\0\0\0\x03\0\0\0\xc8\0\0\0\0\0\0\0\x04\0\0\0\x03\0\0\0\
\xd8\0\0\0\0\0\0\0\x04\0\0\0\x03\0\0\0\xe8\0\0\0\0\0\0\0\x04\0\0\0\x03\0\0\0\
\xf8\0\0\0\0\0\0\0\x04\0\0\0\x03\0\0\0\x08\x01\0\0\0\0\0\0\x04\0\0\0\x03\0\0\0\
\x24\x01\0\0\0\0\0\0\x04\0\0\0\x01\0\0\0\x3c\x01\0\0\0\0\0\0\x04\0\0\0\x03\0\0\
\0\x10\x11\x12\x03\x05\0\x2e\x74\x65\x78\x74\0\x2e\x72\x65\x6c\x2e\x42\x54\x46\
\x2e\x65\x78\x74\0\x5f\x5f\x5f\x5f\x64\x6f\x5f\x75\x6e\x6c\x69\x6e\x6b\x61\x74\
\x5f\x65\x78\x69\x74\x2e\x5f\x5f\x5f\x5f\x66\x6d\x74\0\x5f\x5f\x5f\x5f\x64\x6f\
\x5f\x75\x6e\x6c\x69\x6e\x6b\x61\x74\x2e\x5f\x5f\x5f\x5f\x66\x6d\x74\0\x64\x6f\
\x5f\x75\x6e\x6c\x69\x6e\x6b\x61\x74\x5f\x65\x78\x69\x74\0\x2e\x72\x65\x6c\x66\
\x65\x6e\x74\x72\x79\x2f\x64\x6f\x5f\x75\x6e\x6c\x69\x6e\x6b\x61\x74\0\x2e\x72\
\x65\x6c\x66\x65\x78\x69\x74\x2f\x64\x6f\x5f\x75\x6e\x6c\x69\x6e\x6b\x61\x74\0\
\x2e\x6c\x6c\x76\x6d\x5f\x61\x64\x64\x72\x73\x69\x67\0\x6c\x69\x63\x65\x6e\x73\
\x65\0\x2e\x73\x74\x72\x74\x61\x62\0\x2e\x73\x79\x6d\x74\x61\x62\0\x2e\x72\x6f\
\x64\x61\x74\x61\0\x2e\x72\x65\x6c\x2e\x42\x54\x46\0\x4c\x49\x43\x45\x4e\x53\
\x45\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x9d\0\0\0\
\x03\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x75\x09\0\0\0\0\0\0\xc6\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\0\0\0\x01\0\0\0\x06\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x40\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\x04\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x5e\0\0\0\x01\0\0\0\x06\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\x40\0\0\0\0\0\0\0\x58\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x08\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\x5a\0\0\0\x09\0\0\0\x40\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x20\
\x08\0\0\0\0\0\0\x10\0\0\0\0\0\0\0\x0e\0\0\0\x03\0\0\0\x08\0\0\0\0\0\0\0\x10\0\
\0\0\0\0\0\0\x75\0\0\0\x01\0\0\0\x06\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x98\0\0\0\0\
\0\0\0\x68\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x08\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x71\
\0\0\0\x09\0\0\0\x40\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x30\x08\0\0\0\0\0\0\x10\0\0\
\0\0\0\0\0\x0e\0\0\0\x05\0\0\0\x08\0\0\0\0\0\0\0\x10\0\0\0\0\0\0\0\x95\0\0\0\
\x01\0\0\0\x03\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\0\0\0\0\0\0\x0d\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xad\0\0\0\x01\0\0\0\x02\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x0d\x01\0\0\0\0\0\0\x4c\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xb9\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\x5c\x01\0\0\0\0\0\0\x99\x04\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x04\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\xb5\0\0\0\x09\0\0\0\x40\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\x40\x08\0\0\0\0\0\0\x30\0\0\0\0\0\0\0\x0e\0\0\0\x09\0\0\0\x08\0\0\0\0\0\0\0\
\x10\0\0\0\0\0\0\0\x0b\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xf8\x05\
\0\0\0\0\0\0\x4c\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x04\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\x07\0\0\0\x09\0\0\0\x40\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x70\x08\0\0\0\0\0\0\
\0\x01\0\0\0\0\0\0\x0e\0\0\0\x0b\0\0\0\x08\0\0\0\0\0\0\0\x10\0\0\0\0\0\0\0\x87\
\0\0\0\x03\x4c\xff\x6f\0\0\0\x80\0\0\0\0\0\0\0\0\0\0\0\0\x70\x09\0\0\0\0\0\0\
\x05\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xa5\0\0\0\
\x02\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x48\x07\0\0\0\0\0\0\xd8\0\0\0\0\0\0\
\0\x01\0\0\0\x06\0\0\0\x08\0\0\0\0\0\0\0\x18\0\0\0\0\0\0\0";

	*sz = sizeof(data) - 1;
	return (const void *)data;
}

#ifdef __cplusplus
struct fentry_bpf *fentry_bpf::open(const struct bpf_object_open_opts *opts) { return fentry_bpf__open_opts(opts); }
struct fentry_bpf *fentry_bpf::open_and_load() { return fentry_bpf__open_and_load(); }
int fentry_bpf::load(struct fentry_bpf *skel) { return fentry_bpf__load(skel); }
int fentry_bpf::attach(struct fentry_bpf *skel) { return fentry_bpf__attach(skel); }
void fentry_bpf::detach(struct fentry_bpf *skel) { fentry_bpf__detach(skel); }
void fentry_bpf::destroy(struct fentry_bpf *skel) { fentry_bpf__destroy(skel); }
const void *fentry_bpf::elf_bytes(size_t *sz) { return fentry_bpf__elf_bytes(sz); }
#endif /* __cplusplus */

__attribute__((unused)) static void
fentry_bpf__assert(struct fentry_bpf *s __attribute__((unused)))
{
#ifdef __cplusplus
#define _Static_assert static_assert
#endif
#ifdef __cplusplus
#undef _Static_assert
#endif
}

#endif /* __FENTRY_BPF_SKEL_H__ */
