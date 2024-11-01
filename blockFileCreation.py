#!/usr/bin/python3

from bcc import BPF

source = r"""
#include <linux/fs.h>
#include <linux/dcache.h>
#include <linux/path.h>




LSM_PROBE(inode_create, struct inode *dir, struct dentry *dentry,
     umode_t mode)

{        
        char x[20];

        char y[20];


        unsigned long forbiddenInode=6903720; /// home/sharma/509/hw2/test
        bpf_probe_read_kernel_str(x, 20, dentry->d_name.name);
        bpf_probe_read_kernel_str(y, 20, (dentry->d_parent)->d_iname);
        //bpf_probe_read_kernel_str(y, 20, (((dentry->d_parent)->d_parent)->d_parent)->d_iname);
       // bpf_trace_printk("file: %s\n",x);
       // bpf_trace_printk("dir: %s\n",y);

        if (dir->i_ino==forbiddenInode){
            bpf_trace_printk("file: %s\n",x);
            bpf_trace_printk("dir: %s\n",y);


            return -EPERM;
        }
 



	return 0;
}
"""

b = BPF(text=source)
try:
    b.trace_print()
except KeyboardInterrupt:
    pass
