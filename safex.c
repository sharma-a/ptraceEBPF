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

FILE* file;
void trace(pid_t);

void copyFile(char *in, char *out)
{
    int ret=fork();
    if(ret==0){
        execl("/bin/cp","/bin/cp",in,out,NULL);
    }
    else{
        //parent: wait
        wait(NULL);
    }

}


int checkPath(char* p){
    //char* forbidden="/home/sharma/509/hw2/ptraceExamples/xyz";
    char* forbidden="xyz";

    if(strcmp(p,forbidden)) return 1;
    else return 0;
}


void readString(pid_t target, long* addr, char* str){
        //do the shenanigans to read a string
        int i=0;
        int cont=1;
        for(cont=0;cont<100;cont++){
            unsigned long r;
            r=ptrace(PTRACE_PEEKDATA,target,addr,NULL);
            for(int j=0;j<8;j++){
                char cur;     
                //cur=r>>56;
                cur=r&0xff;
                str[i++]=cur;
                if(cur==0) {cont=800; break;}
                //r=r<<8;
                r=r>>8;
            }
            addr++;

        }
        //if(i==0 || str[i-1]!=0) printf("%d\n",i); 
}

int main(int argc, char *argv[]) {
    pid_t target = vfork();
    if(target==0){
        execvp(argv[1],&argv[1]);
    }
    else{
        trace(target);
    }
    return 0;
}

void trace(pid_t target){
    int status;
    struct user_regs_struct regs;
    long syscall;
    char filename[20];
    //sprintf(filename,"%d.log",target);
    //file=fopen(filename,"w");

    ptrace(PTRACE_ATTACH,target,NULL,NULL); //initial attach
    waitpid(target,&status,0);


    char tmpFl[20]="/tmp/sfx_XXXXXX";
    int fd=mkstemp(tmpFl);

    while(1){
        //currently tracee is blocked
        ptrace(PTRACE_SYSCALL,target,NULL,NULL);//let the target run till either   
                                                //receives a signal or makes a syscall
                                                //when either of these happen 
                                                //or when taget exits 
                                                //tracer has to catch that
                                                //so wait
        waitpid(target,&status,0);
        if(WIFEXITED(status)) break;    //if target exited, done
                                        //i am assuming it will be a syscall
                                        //should check it is not a syscall
                                        //and continue in that case
                                        //TODO ... find out and do this

        ptrace(PTRACE_GETREGS,target,NULL,&regs); //get the register (now it is a syscall)
        syscall = regs.orig_rax;

        if(     syscall==__NR_clone
                ||syscall==__NR_fork
                ||syscall==__NR_vfork){
            //fprintf(file,"Started a fork.\n");
            //first let the fork run
            ptrace(PTRACE_SYSCALL,target,NULL,NULL); 
            waitpid(target,&status,0);
            //now the forking is done 
            //original tracee is blocked
            //new one is (I think running)
            //get the new pid
            pid_t newPid;
            ptrace(PTRACE_GETREGS,target,NULL,&regs);
            newPid=(pid_t)regs.rax;
            //fork the tracer
            int ret=fork();
            if(ret>0){
                //original tracer
                //fprintf(file,"Ended the fork.\n");
                continue;

            }
            else{
                //newtracer
                //do i need to detach the old one. i think not
                //sprintf(filename,"%d.log",newPid);
                //printf("New %d : %s\n",getpid(),filename);
                //fclose(file);
                //file=fopen(filename,"w");
                target=newPid;
                ptrace(PTRACE_ATTACH,newPid,NULL,NULL);
                waitpid(newPid,&status,0);
                continue;
            }


        }
        if(syscall==__NR_open | syscall==__NR_openat){
            char pathname[800];
            long* p; //address p has filename in target
            unsigned int fl; //address f has flags in target

            p=syscall==__NR_openat?(long*)(regs.rsi):(long*)(regs.rdi);
            fl=(unsigned int)(syscall==__NR_openat?(regs.rdx):(regs.rsi));
            readString(target, p, pathname);

            //disallow attempts to open a forbidden file from reading
            if(((fl&O_ACCMODE)==O_RDONLY || (fl&O_ACCMODE)==O_RDWR)
                && (!checkPath(pathname))
            ){
                regs.orig_rax = -1; // set to invalid syscall
                ptrace(PTRACE_SETREGS, target, 0, &regs);
                ptrace(PTRACE_SYSCALL,target,NULL,NULL);
                waitpid(target,&status,0);
                regs.rax=-EPERM;
                ptrace(PTRACE_SETREGS, target, 0, &regs);
                continue;
            }
            
            //redirect writes
            if((fl&O_ACCMODE)==O_WRONLY 
                    || (fl&O_ACCMODE)==O_RDWR){
                //if the original file doesn't exist proceed as usual
                //else let the new tmp be created
                //fprintf(stderr,"%s:%d\n",pathname,access(pathname,F_OK));
                if(access(pathname,F_OK)==0){
                    //a tmpFile for each write?
                    //1) get a new filename
                    char tmpFl[20]="/tmp/sfx_XXXXXX";
                    int fd=mkstemp(tmpFl);
                    //2) copy the original file to this new filename
                    copyFile(pathname,tmpFl);
                    //3) POKE the newfile name at the appropriate location
                    long *p;
                    p=syscall==__NR_openat?(long*)(regs.rsi):(long*)(regs.rdi);
                    //POKE 16bytes of tmpFL at this location
                    //create the first long tmpFl[7],tmpFl[6]....,tmpFl[0]
                    long w[2]={0,0};
                    for(int i=0;i<8;i++)
                        w[0]+=(((long)tmpFl[i]) << (i*8));
                    ptrace(PTRACE_POKEDATA,target,p,w[0]);
                    //next long
                    for(int i=0;i<8;i++)
                        w[1]+=(((long)tmpFl[i+8]) << (i*8));
                    ptrace(PTRACE_POKEDATA,target,p+1,w[1]);
               }
               ptrace(PTRACE_SYSCALL,target,NULL,NULL);
               waitpid(target,&status,0);
               continue;  
 
           }
       }
        //other syscalls let them continue
        ptrace(PTRACE_SYSCALL,target,NULL,NULL);
        waitpid(target,&status,0);
        if(WIFEXITED(status)) {break;}
    }
    //fclose(file);

}


