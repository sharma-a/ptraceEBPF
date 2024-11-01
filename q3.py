#!/usr/bin/python3

from bcc import BPF
import psutil
from datetime import datetime
import ipaddress

source = r"""
#include <linux/socket.h>
#include <linux/in.h>
#include <linux/fs.h>
#include <linux/dcache.h>
#include <linux/path.h>
#include <linux/binfmts.h>

BPF_RINGBUF_OUTPUT(output, 1); 

struct data_t{
    unsigned int ip;
    unsigned int par_inode;
    int syscall;
    long time;
    int uid;
    int pid;
    int allowed;
    char name[20];
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
        data.par_inode=-1;
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



LSM_PROBE(inode_create, struct inode *dir, struct dentry *dentry,
     umode_t mode)

{        
        char x[20];
        unsigned long forbiddenInode=6903720; /// home/sharma/509/hw2/test
        bpf_probe_read_kernel_str(x, 20, dentry->d_name.name);
        struct data_t data={};
        data.syscall=2;// 1 for open
        data.ip=-1
        data.pid = bpf_get_current_pid_tgid() >> 32;
        data.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
        data.par_inode=dir->i_ino;
        data.time=bpf_ktime_get_ns();
        bpf_probe_read_kernel_str(data.name, 20, x);
        data.allowed=1;
 
        if (dir->i_ino==forbiddenInode){
            data.allowed=0;
            output.ringbuf_output(&data, sizeof(data),0);
            return -EPERM;
        }
        output.ringbuf_output(&data, sizeof(data),0);
	return 0;
}


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






bootTime=int(psutil.boot_time())
b = BPF(text=source)
def printEvent(cpu, data, size):
     data=b["output"].event(data)
     if data.syscall==2:
         ipadd=data.name.decode()
     else:
         ipadd=str(ipaddress.ip_address(int(data.ip)))
     tm=int(data.time/1_000_000_000)
     tmstr=str(datetime.fromtimestamp(bootTime+tm))
     #print(f"{data.syscall} {ipadd} {tmstr} {data.allowed}")
     print(f"{ipadd}        {data.allowed}")


b["output"].open_ring_buffer(printEvent)
while True:
   b.ring_buffer_poll()


