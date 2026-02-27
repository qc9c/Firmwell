#include <stdio.h>
#include <stdlib.h>
#include <sys/mount.h>
#include <unistd.h>

int main(int argc, char *argv[]) {
    // mount sysfs to /fs/sys
    if (mount("sysfs", "/fs/sys", "sysfs", 0, NULL) != 0) {
        perror("mount sysfs failed");
//        exit(EXIT_FAILURE);
    }

    // mount procfs to /fs/proc
    if (mount("proc", "/fs/proc", "proc", 0, NULL) != 0) {
        perror("mount procfs failed");
//        exit(EXIT_FAILURE);
    }

    // 替换当前进程为 /fs/init.sh
    execv("/fs/init.sh", argv);
    perror("execv failed");
    exit(EXIT_FAILURE);
}
