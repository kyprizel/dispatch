from formats import *
import sys
import pygraphviz as pgv
print "beginning analysis..."
# Load in the executable with read_executable (pass filename)
executable = read_executable(sys.argv[1])

# Invoke the analyzer to find functions
executable.analyze()

cfg = executable.analyzer.cfg()

print "Analysis complete!"

print cfg
print executable.functions

G = pgv.AGraph(directed=True)
for func in executable.functions.values():
    print func, '(size:',func.size,')'
    bbs = list(func.iter_bbs())
    for bb in bbs:
        addr = bb.address
        G.add_node(addr)
        n = G.get_node(addr)
        n.attr['label'] = '-- ' + bb.parent.name + '@' + hex(bb.parent.address) + '+' + hex(bb.address - bb.parent.address) + \
                ' (' + str(len(bb.parent.bbs)) + ' bbs) --\\n\\n' + \
                '\\l'.join(hex(x.address)[2:] + ' ' + str(x) for x in bb.instructions) + '\\l'
        n.attr['shape'] = 'box'

for src,dst in cfg:
    s = executable.bb_containing_vaddr(src)
    d = executable.bb_containing_vaddr(dst)
    if s is None or d is None:
        print hex(src),hex(dst)
        print s, d
        continue
    G.add_edge(s.address, d.address)

G.layout('dot')
#print G
G.draw("cfg.png")
#executable.function_named('main').print_disassembly()
