from flask import Flask,render_template,request
import json
import subprocess

app = Flask(__name__)
executable = None

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

@app.route('/graph', methods=['POST'])
def graph():
    req = request.stream.read()
    dot = subprocess.Popen(['dot', '-Tsvg'], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    stdout, stderr = dot.communicate(req)
    return stdout

def run(exe):
    # this is absolutely disgusting but it works
    global executable
    executable = exe
    print "Beginning analysis..."
    executable.analyze()
    print "Analysis complete!"
    app.run('0.0.0.0', port=3002, debug=True)
