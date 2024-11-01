#!/usr/bin/python3

from bcc import BPF
import psutil
from datetime import datetime
import ipaddress

source = r"""
#include <linux/socket.h>
#include <linux/in.h>

BPF_RINGBUF_OUTPUT(output, 1); 

struct data_t{
    unsigned int ip;
    int syscall;
    long time;
    int uid;
    int pid;
    int allowed;
};


LSM_PROBE(socket_connect, struct socket *sock, struct sockaddr *address,
	 int addrlen)
{
        //char x[20];

        uint32_t disallowedIP=3232267645; //corresponding to 192.168.125.125
        uint32_t ip=((struct sockaddr_in*) address)->sin_addr.s_addr;
        struct data_t data={};
        data.syscall=1;// 1 for connect
        data.pid = bpf_get_current_pid_tgid() >> 32;
        data.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
        data.ip=ip;
        data.time=bpf_ktime_get_ns();
        if(ip==disallowedIP){
            data.allowed=0;
            output.ringbuf_output(&data, sizeof(data),0);
            return -EPERM;
        }
        data.allowed=1;
        output.ringbuf_output(&data, sizeof(data),0);
        return 0;

}
"""

bootTime=int(psutil.boot_time())
b = BPF(text=source)
def printEvent(cpu, data, size):
     data=b["output"].event(data)
     ipadd=str(ipaddress.ip_address(int(data.ip)))
     tm=int(data.time/1_000_000_000)
     tmstr=str(datetime.fromtimestamp(bootTime+tm))
     print(f"{ipadd} {tmstr} {data.allowed}")


b["output"].open_ring_buffer(printEvent)
while True:
   b.ring_buffer_poll()


