#!/usr/bin/python3

from bcc import BPF

source = r"""
#include <linux/binfmts.h>

LSM_PROBE(bprm_check_security, struct linux_binprm *bprm)
{

        char x[20];
        bpf_probe_read_kernel_str(x, 20, bprm->filename);
        if(
        x[0]=='/' &&
        x[1]=='b' &&
        x[2]=='i' &&
        x[3]=='n' &&
        x[4]=='/' &&
        x[5]=='l' &&
        x[6]=='s' &&
        x[7]=='\0'
        )
        return -EPERM;
        else
        bpf_trace_printk("hello %s\n",x);




	return 0;
}
"""

b = BPF(text=source)
try:
    b.trace_print()
except KeyboardInterrupt:
    pass
