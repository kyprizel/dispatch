from formats import *
from webui.app import run
from sys import argv

if __name__ == '__main__':
    exe = read_executable(argv[1])
    run(exe)
