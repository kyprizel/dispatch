from flask import Flask,render_template,request
import json
import subprocess
import pygraphviz as pgv

app = Flask(__name__)
executable = None
cfg = None

@app.route('/')
def index():
    return render_template('index.html', exe=executable)

@app.route('/function_list')
def function_list():
    return json.dumps([f.name for f in executable.functions.values()])

@app.route('/function_info/<function_name>')
def function_info(function_name):
    function = executable.function_named(function_name)
    return json.dumps({'name':function.name,'address':function.address})

@app.route('/dis/<function_name>')
def get_disas(function_name):
    return '\n'.join(str(x.address) + ' ' + str(x) for x in executable.function_named(function_name).instructions)

@app.route('/cfg/<function_name>')
def get_cfg(function_name):
    cfg = executable.analyzer.cfg() 
    is_valid = lambda x: executable.function_containing_vaddr(x).name == function_name
    return json.dumps([[a,b] for a,b in cfg if is_valid(a) and is_valid(b)])

@app.route('/bbs/<function_name>')
def get_bbs(function_name):
    prep_ins = lambda ins: {'address': ins.address, \
                            'mnemonic': ins.mnemonic, \
                            'op_str': ins.op_str}
    prep_bb = lambda bb: {'address': bb.address, \
                          'size': bb.size, \
                          'instructions':map(prep_ins, bb.instructions)}
    prep_func = lambda func: map(prep_bb, func.iter_bbs())
    return json.dumps(prep_func(executable.function_named(function_name)))

@app.route('/graph/<function_name>')
def graph(function_name):
    #cfg = executable.analyzer.cfg()
    global cfg
    
    G = pgv.AGraph(directed=True, splines="ortho", bgcolor='#E0FFFF')
    func = executable.function_named(function_name)
    for bb in func.iter_bbs():
        addr = bb.address
        G.add_node(addr)
        n = G.get_node(addr)
        n.attr['label'] = '-- ' + bb.parent.name + ' @ ' + hex(bb.parent.address) + '+' + hex(bb.address - bb.parent.address) + \
                ' --\\n\\n' + '\\l'.join(hex(x.address)[2:] + ' ' + str(x) for x in bb.instructions) + '\\l'
        n.attr['shape'] = 'box'
    
    for edge in cfg:
        if func.contains_address(edge.src) and func.contains_address(edge.dst):
            s = executable.bb_containing_vaddr(edge.src)
            d = executable.bb_containing_vaddr(edge.dst)
            if s is None or d is None:
                print hex(edge.src),hex(edge.dst)
                print s, d
                continue
            # we have to hardcode the types here because we can't import CFGEdge...
            if edge.type == 0: # CFGEdge.DEFAULT
                color = "black"
            elif edge.type == 1: # CFGEdge.COND_JUMP
                if edge.value:
                    color = "green"
                else:
                    color = "red"
            elif edge.type == 2: # CFGEdge.SWITCH
                color = "magenta"
            G.add_edge(s.address, d.address, color=color)
    
    dot = subprocess.Popen(['dot', '-Tsvg'], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    stdout, stderr = dot.communicate(str(G))
    return stdout

@app.route('/xrefs/<function_name>')
def xrefs(function_name):
    function_named = lambda x: executable.function_containing_vaddr(x).name
    func = executable.function_named(function_name);
    if func is not None and func.address in executable.xrefs:
        xrefs = executable.xrefs[func.address]
        functions_referring = sorted(list(set(map(function_named, xrefs))))
        return json.dumps(functions_referring)
    else:
        return "[]"

@app.route('/rename/<original_name>/<new_name>', methods=['POST'])
def rename(original_name, new_name):
    func = executable.function_named(original_name)
    if func:
        func.name = new_name
        return "success"
    return "failure, no such function"

def setup_exe(exe):
    # this is absolutely disgusting but it works
    global executable
    global cfg
    executable = exe
    print "Beginning analysis..."
    exe.analyze()
    cfg = exe.analyzer.cfg() # cache cfg for speed
    print "Analysis complete!"

def run(exe):
    setup_exe(exe)
    app.run('0.0.0.0', port=3002, debug=True)
