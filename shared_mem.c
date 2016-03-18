#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>  /*****  For waitpid.                   *****/
#include <sys/types.h>
#include <sys/shm.h>

int main() {
    pid_t pid, kidpid;
    uint64_t i;
    int shmid, key, status;
    uint64_t shared_mem_size;
    uint64_t *data;
    char *target_argv[] = {"./a.out", 0};

    int create_file = open("/tmp/shared_mem", O_RDWR|O_CREAT, 777);
    close(create_file);

    shared_mem_size = 1024;
    key = ftok("/tmp/shared_mem", 'R');
    shmid = shmget(key, shared_mem_size, 0644 | IPC_CREAT);
    data = (uint64_t *)shmat(shmid, (void *)0, 0);
    memset(data, '\0', shared_mem_size);

    if ((pid = fork()) < 0)
    {
        perror("Bad fork!");
        exit(1);
    }

    if (0 == pid) {
        // Child
        execv(target_argv[0], target_argv);
        kill(0, SIGKILL);
    }
    else {
        // Parent
        // Wait until child is done
        // Zero out shared memory
        kidpid = waitpid(pid, &status, WUNTRACED);

        for (i = 0; i < 1024 / sizeof(uint64_t); ++i) {
            printf("0x%08lx.", data[i]);
        }
        memset(data, '\0', shared_mem_size);
    }
}

