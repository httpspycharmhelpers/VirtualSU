#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/xattr.h>
#include <unistd.h>
#include <fcntl.h>
int main(void){
  char b[4096]={0}; size_t n=sizeof(b); long r; errno=0;
  r=syscall(416, 0, b, sizeof(b), 0);
  printf("416(0,buf,size,0): r=%ld n=%zu val=%s errno=%d\n", r, n, r>=0?b:"-", errno);
  memset(b,0,sizeof(b)); n=sizeof(b); errno=0;
  r=syscall(416, 0, b, 0, 0);
  printf("416 size-query: r=%ld\n", r);
  return 0;
}
