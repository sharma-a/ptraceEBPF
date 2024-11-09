#include <stdio.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>

pid_t target;
unsigned long key=0x8723ad7bcf982ade; //encryption/decryption is a simple xor of 8 bytes
                                      //with a key. this is the initial key
                                      //this will be modified using the password provided


int hash[1024]={0}; //a 'hashmap' to store which open files are the confidential ones
                    //not really a hashmap 
                    //file descriptors are small numbers 
                    //if the opened file with fd k is confidential then hash[k]=1
                    //else it is zero.
                    //keep track of this during open and close syscalls
struct user_regs_struct regs;
long syscallNo;
int status;

void handleOpen();
void handleClose();
void handleRead();
void handleWrite();
void handleFork();

void xorTarget(long *buf, size_t count){
    for(int i=0;i<count/8;i++){
        unsigned long rd=ptrace(PTRACE_PEEKDATA,target,buf,NULL);
        unsigned long wrt=rd^key;
        ptrace(PTRACE_POKEDATA,target,buf,wrt);
        buf=buf+1;
    }
    int rem=count%8;
    if(rem!=0){
        unsigned long rd=ptrace(PTRACE_PEEKDATA,target,buf,NULL);
        unsigned long wrt=rd^key;
        unsigned long mask=0xffffffffffffffff >> (8*rem);
        unsigned long wrt2=(rd&mask)+((~mask)&wrt);
        ptrace(PTRACE_POKEDATA,target,buf,wrt);
    }
}

int confidential(char* path){
   int len=strlen(path);
   if(strcmp(path+len-13,".confidential")==0) return 1;
   else return 0;
}



void readString(long* addr, char* str){
    //do the shenanigans to read a string
    int i=0;
    int cont=1;
    for(cont=0;cont<100;cont++){
        unsigned long r;
        r=ptrace(PTRACE_PEEKDATA,target,addr,NULL);
        for(int j=0;j<8;j++){
            char cur;
            cur=r&0xff;
            str[i++]=cur;
            if(cur==0) {cont=800; break;}
            r=r>>8;
        }
        addr++;

    }
}

int main(int argc, char *argv[]) {
    char* pass=argv[1];
    char c;
    while(c=*pass++)
        key=c+(key<<6)+(key<<16)-key;
    target = vfork();
    if(target==0){
        execvp(argv[2],&argv[2]);
    }
    else{
        ptrace(PTRACE_ATTACH,target,NULL,NULL);
        waitpid(target,&status,0);
        while(1){
            ptrace(PTRACE_SYSCALL,target,0,0);
            waitpid(target,&status,0);
            if(WIFEXITED(status)) {break;}

            //at the beginning of a syscall here
            ptrace(PTRACE_GETREGS,target,0,&regs);
            syscallNo=regs.orig_rax;
            switch(syscallNo){
                case __NR_open:
                case __NR_openat:
                case __NR_creat:
                    handleOpen();
                    break;
                case __NR_close:
                    handleClose();
                    break;
                case __NR_read:
                    handleRead();
                    break;
                case __NR_write:
                    handleWrite();
                    break;
                case __NR_clone:
                case __NR_fork:
                case __NR_vfork:
                    handleFork();
                    break;
                default:
                    //let the syscall run
                    ptrace(PTRACE_SYSCALL,target,0,0);
                    waitpid(target,&status,0);
            }
        }

    }
    return 0;
}

void handleOpen(){
    char pathname[200];
    long *p;
    if(syscallNo==__NR_openat) p=(long*) regs.rsi;
    else p=(long*) regs.rdi;
    readString(p,pathname);
    //let the syscall run
    ptrace(PTRACE_SYSCALL,target,0,0);
    waitpid(target,&status,0);
    ptrace(PTRACE_GETREGS,target,0,&regs);
    int retFd=(int) (regs.rax);
    if(retFd>=0 && confidential(pathname)){
        hash[retFd]=1;
    }
}

void handleClose(){
    int fd=(int)(regs.rdi);
    ptrace(PTRACE_SYSCALL,target,0,0);
    waitpid(target,&status,0);
    ptrace(PTRACE_GETREGS,target,NULL,&regs);
    if((int)(regs.rax)>=0 && hash[fd]){
        hash[fd]=0;
    }
}

void handleRead(){
    int fd=(int)(regs.rdi);
    long* buf=(long*) (regs.rsi);
    ptrace(PTRACE_SYSCALL,target,0,0);
    waitpid(target,&status,0);
    ptrace(PTRACE_GETREGS,target,NULL,&regs);
    int retVal=(int) (regs.rax);
    if(retVal>0 && hash[fd]){
        xorTarget(buf,retVal);
    }
}



void handleWrite(){
    int fd=(int)(regs.rdi);
    long* buf=(long*) (regs.rsi);
    size_t numWrite=(size_t)(regs.rdx);
    //decode whether to change or not
    int change=hash[fd] && numWrite>0;
    if(change){
        xorTarget(buf,numWrite);
    }
    //run the syscall
    ptrace(PTRACE_SYSCALL,target,0,0);
    waitpid(target,&status,0);
    ptrace(PTRACE_GETREGS,target,NULL,&regs);
    int retVal=(int) (regs.rax);
    //if call succeeded changed thing was written
    //else nothing was written
    //in any case restore the memory if it was changed
    if(change){
        xorTarget(buf,numWrite);
    }
}


void handleFork(){
    //first let the fork run
    ptrace(PTRACE_SYSCALL,target,0,0);
    waitpid(target,&status,0);
    //get the pid of the process created as the return value
    pid_t newPid;
    ptrace(PTRACE_GETREGS,target,NULL,&regs);
    newPid=(pid_t)regs.rax;
    //fork the tracer
    int ret=fork();
    if(ret>0){
        //original tracer
        return;
    }
    else{
        //newtracer
        target=newPid;
        ptrace(PTRACE_ATTACH,newPid,NULL,NULL);
        waitpid(newPid,&status,0);
        return;
    }
}
