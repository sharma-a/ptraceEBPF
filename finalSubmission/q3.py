#!/usr/bin/python3

from bcc import BPF
import ctypes
from datetime import datetime
import ipaddress
import os
import time
import subprocess

def get_file_path_from_inode(inode, search_path='/home/sharma/509'):
    try:
        # Use the 'find' command to locate the file by inode
        result = subprocess.check_output(
            ['find', search_path, '-inum', str(inode), '-print'],
            stderr=subprocess.DEVNULL,
        ).decode('utf-8').strip()
        if result:
            return result
        else:
            return ""
    except subprocess.CalledProcessError as e:
        return ""


source = r"""
#include <linux/socket.h>
#include <linux/in.h>
#include <linux/fs.h>
#include <linux/dcache.h>
#include <linux/path.h>
#include <linux/binfmts.h>

BPF_RINGBUF_OUTPUT(output, 1); 
BPF_HASH(my_map,u32,u64);

struct data_t{
    unsigned int ip;
    unsigned int par_inode; //parent_inode 
    int syscall; //1 
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
        //data.time=bpf_ktime_get_ns();
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
        u32 key=0;
        u64* p=my_map.lookup(&key);
        unsigned long forbiddenInode=6903720; // need to put a valid thing here home/sharma/509/hw2/test
        if(p) forbiddenInode=*p;
        bpf_probe_read_kernel_str(x, 20, dentry->d_name.name);
        struct data_t data={};
        data.syscall=2;// 2 for open
        data.ip=-1;
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
        struct data_t data={};
        data.syscall=3;// 3 for exec
        data.ip=-1;
        data.pid = bpf_get_current_pid_tgid() >> 32;
        data.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
        data.par_inode=-1;
        data.time=bpf_ktime_get_ns();
        bpf_probe_read_kernel_str(data.name, 20, x);
        data.allowed=1;
 
        if(
        x[0]=='/' &&
        x[1]=='b' &&
        x[2]=='i' &&
        x[3]=='n' &&
        x[4]=='/' &&
        x[5]=='n' &&
        x[6]=='c' &&
        x[7]=='\0'
        ){

            data.allowed=0;
            output.ringbuf_output(&data, sizeof(data),0);
            return -EPERM;
        }

        else{
            output.ringbuf_output(&data, sizeof(data),0);
            return 0;
        }

	return 0;
}


"""






startMonotonic=time.monotonic()
startTime=time.time()
tdiffm=startTime-startMonotonic

forbiddenDirectory="/home/sharma/509/hw2/assignment2/forbid"
forbiddenInode=os.stat(forbiddenDirectory).st_ino
b = BPF(text=source)
my_map=b["my_map"]
key=ctypes.c_uint32(0)
print(forbiddenInode)
value=ctypes.c_uint64(forbiddenInode)
my_map[key]=value

def printEvent(cpu, data, size):
     data=b["output"].event(data)
     if data.syscall==2:
         scall="open"
         name=data.name.decode()
         parInode=data.par_inode
         dirname=get_file_path_from_inode(parInode)
         name=dirname+"/"+name
     elif data.syscall==1:
         scall="connect"
         name=str(ipaddress.ip_address(int(data.ip)))
     else:
         scall="exec"
         name=data.name.decode()
 
     tm=int(data.time/1_000_000_000)
     tm=tm+tdiffm
     tt=time.ctime(tm)
     allow="allowed"
     if data.allowed==0:
         allow="denied"
     uid=data.uid
     pid=data.pid

     print(f"{tt}\t{scall}\t{uid}\t{pid}\t{name}\t{allow}")


b["output"].open_ring_buffer(printEvent)

while True:
   b.ring_buffer_poll()


