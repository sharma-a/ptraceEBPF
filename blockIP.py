#!/usr/bin/python3

from bcc import BPF

source = r"""
#include <linux/socket.h>
#include <linux/in.h>

LSM_PROBE(socket_connect, struct socket *sock, struct sockaddr *address,
	 int addrlen)
{
        char x[20];
        uint32_t a=((struct sockaddr_in*) address)->sin_addr.s_addr;

        //bpf_probe_read_kernel_str(x, 20, (struct sockaddr_in)address->sin_addr.s_addr);
        
        unsigned char a1=(a&0xff000000)>>24;
        unsigned char a2=(a&0x00ff0000)>>16;
        unsigned char a3=(a&0x0000ff00)>>8;
        unsigned char a4=(a&0x000000ff);

        bpf_trace_printk("hello %d.%d.%d \n",a1,a2,a3);
        bpf_trace_printk("hello %d",a4);





	return 0;
}
"""

b = BPF(text=source)
try:
    b.trace_print()
except KeyboardInterrupt:
    pass
