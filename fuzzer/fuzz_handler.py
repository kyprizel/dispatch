import sysv_ipc
import os, struct, subprocess, glob, time
from os import path

def ftok(path, i):
    i = ord(i)
    st = os.stat(path)
    return ((i & 0xff) << 24 | (st.st_dev & 0xff) << 16 | (st.st_ino & 0xffff));

def radamsa(base_file, fuzzed_file):
    os.system("cat {0} | radamsa > {1}".format(base_file, fuzzed_file))

def LOG(s):
    print "[Log]", s

shmem_path = "/tmp/shared_mem"
touch = open(shmem_path, "w+").close()
key = ftok(shmem_path, "R")

memory = sysv_ipc.SharedMemory(key)
memory.write("\x00" * 1024)

target_argv = ["./patched_program", None]
argv_replace_idx = 1
fuzz_dir = "fuzz_tests/"
if not os.path.exists(fuzz_dir):
    os.makedirs(directory)

unique_path_dir = "unique_paths/"
if not os.path.exists(unique_path_dir):
    os.makedirs(directory)

queue = "queue/"
if not os.path.exists(queue):
    os.makedirs(directory)

read_from_stdin = False
unique_paths = []
MAX_FUZZ_DEPTH = 5

def run_fuzz_case(fuzz_file, depth):
    global unique_paths, target_argv, argv_replace_idx

    pid = os.fork()
    if pid == 0:
        if read_from_stdin:
            fuzz_case = open(fuzz_file, "r")
            fuzz_data = fuzz_case.read()
            fuzz_case.close()
            proc = subprocess.Popen(
                target_argv, stdout=subprocess.PIPE,
                stdin=subprocess.PIPE)
            proc.stdin.write(fuzz_data)
            proc.stdin.close()
        else:
            target_argv[argv_replace_idx] = fuzz_file
            proc = subprocess.Popen(
                target_argv, stdout=subprocess.PIPE,
                stdin=subprocess.PIPE)
        exit(0)
    else:
        os.waitpid(pid, os.WUNTRACED)

        child_data = memory.read()

        path_data = struct.unpack("<" + "Q" * (1024 / 8), child_data)
        path_data_trimmed = []
        for i in range(3, len(path_data)):
            if path_data[i] == 0:
                break
            path_data_trimmed.append(path_data[i])

        add_case = True
        case_idx = -1
        for n, fuzz_case in enumerate(unique_paths):
            if len(fuzz_case) == len(path_data_trimmed):
                case_idx = n
            if fuzz_case[2] == path_data_trimmed:
                add_case = False

        if add_case == True:
            new_file_path = path.join(unique_path_dir, path.basename(fuzz_file) + str(int(time.time())))
            os.system("cp {0} {1}".format(fuzz_file, new_file_path))
            unique_paths.insert(case_idx, (depth + 1, new_file_path, path_data_trimmed))
            LOG("Added new case: " + new_file_path)

        memory.write("\x00" * 1024)

def gen_fuzz_cases(seed_file):
    for i in range(5):
        output_file = path.join(queue, path.basename(seed_file) + "_being_fuzzed_{0}".format(i))
        radamsa(seed_file, output_file)
        yield output_file

def remove_fuzzed_cases():
    queue_files = glob.glob(queue + "*")
    for f in queue_files:
        os.remove(f)

def fuzz_unique_paths():
    global unique_paths

    fuzz_idx = 0
    while True:
        fuzz_depth, fuzz_file, fuzz_path = unique_paths[fuzz_idx]
        LOG("Fuzzing: " + fuzz_file)
        if fuzz_depth > MAX_FUZZ_DEPTH:
            continue
        for gen_fuzz_file in gen_fuzz_cases(fuzz_file):
            run_fuzz_case(gen_fuzz_file, fuzz_depth)

        fuzz_idx = fuzz_idx + 1 % len(unique_paths)

def start_fuzzing():
    fuzz_files = glob.glob(fuzz_dir + "*")

    for n, f in enumerate(fuzz_files):
        new_name = path.join(queue, "input_case_{0}".format(n))
        os.system("cp {0} {1}".format(f, new_name))
        run_fuzz_case(new_name, 0)

    fuzz_unique_paths()

start_fuzzing()

