#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/prctl.h>

int main(int argc, char *argv[]) {
    // 1. 修改内核中的线程名 comm
    prctl(PR_SET_NAME, "magiskd", 0, 0, 0);

    // 2. 原地覆盖 argv[0]，让 /proc/PID/cmdline 显示为 magiskd
    if (argc > 0) {
        // 把原名字符串直接用 "magiskd" 填充，多余的用空格补齐
        char *new_name = "magiskd";
        int orig_len = strlen(argv[0]);
        int new_len = strlen(new_name);
        int copy_len = orig_len > new_len ? new_len : orig_len;
        
        memcpy(argv[0], new_name, copy_len);
        // 如果有剩余空间，用空格填充（防止出现空字符导致的截断）
        if (orig_len > new_len) {
            memset(argv[0] + new_len, ' ', orig_len - new_len);
        }
    }

    // 3. 孤儿进程守护：脱离终端，防 SIGHUP 杀死
    if (fork() > 0) {
        // 父进程退出，让子进程变为孤儿进程被 init(1) 收养
        printf("[+] 伪装进程已派生，正在挂机...\n");
        exit(0);
    }
    
    // 子进程继续，脱离控制终端
    setsid(); 

    printf("[+] 当前伪装进程名: magiskd\n");
    printf("[*] 真实 PID: %d\n", getpid());

    // 4. 无限挂机
    while (1) {
        sleep(60);
    }

    return 0;
}
