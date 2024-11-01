#!/usr/bin/python3

from bcc import BPF

source = r"""
#include <linux/fs.h>
#include <linux/dcache.h>




LSM_PROBE(inode_create, struct inode *dir, struct dentry *dentry,
     umode_t mode)

{
        char x[20];
        char y[20];
        bpf_probe_read_kernel_str(x, 20, dentry->d_name.name);
        //bpf_probe_read_kernel_str(y, 20, (dentry->d_parent)->d_iname);
        bpf_probe_read_kernel_str(y, 20, (((dentry->d_parent)->d_parent)->d_parent)->d_iname);
        bpf_trace_printk("hello %s    %s\n",y, x);





	return 0;
}
"""

b = BPF(text=source)
try:
    b.trace_print()
except KeyboardInterrupt:
    pass
