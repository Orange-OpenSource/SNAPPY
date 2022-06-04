#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <err.h>
#include <linux/bpf.h>
#include "bpf/libbpf.h"
#include <bpf/bpf.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/sysinfo.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <sys/resource.h>

int main(int argc, char** argv) {
    struct bpf_object *prog_obj;
    struct bpf_prog_load_attr attr;
    int prog_fd, target_fd;
    int ret;
	
	if(argc < 2 || !(argc % 2))
		errx(EXIT_FAILURE,
			"Usage %s <bpf1.ko> <hook1> [<bpf2.ko> <hook2>] [...]", argv[0]);
	
	for(int i=0; i<argc/2; ++i) {

	    memset(&attr, 0, sizeof(struct bpf_prog_load_attr));
    	attr.prog_type = BPF_PROG_TYPE_SNAPPY;
    	attr.expected_attach_type = BPF_SNAPPY;
    	attr.file = argv[2*i + 1];
	
    	/* Attach the BPF program to the given hook */
    	target_fd = open(argv[2*i + 2], O_RDWR);

    	if (target_fd < 0)
        	err(EXIT_FAILURE, "Failed to open target file");

	    if (bpf_prog_load_xattr(&attr, &prog_obj, &prog_fd))
    	    err(EXIT_FAILURE, "Failed to load eBPF program");

	    ret = bpf_prog_attach(prog_fd, target_fd, BPF_SNAPPY, 0);
    	if (ret < 0)
        	err(EXIT_FAILURE, "Failed to attach prog to LSM hook");
	}
	return EXIT_SUCCESS;
}
