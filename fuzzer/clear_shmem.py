import sysv_ipc

def ftok(path, i):
    i = ord(i)
    st = os.stat(path)
    return ((i & 0xff) << 24 | (st.st_dev & 0xff) << 16 | (st.st_ino & 0xffff));

shmem_path = "/tmp/shared_mem"
key = ftok(shmem_path, "R")
memory = sysv_ipc.SharedMemory(key)
memory.write("\x00" * 1024)
