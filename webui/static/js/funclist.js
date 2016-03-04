var load_function_list = function () {
    // Get the list of functions
    $.get('/function_list', function(data) {
        var function_list = document.getElementById('functionlist');

        // clear the old list
        while (function_list.children.length > 0) {
            function_list.removeChild(function_list.children[0]);
        }

        var functions = JSON.parse(data);
        for (var i = 0; i < functions.length; i++) {
            var node = document.createElement('span');
            node.innerText = functions[i];
            node.className = 'function';
            functions[i] = node;
        }

        // Sort the list of functions when we load the page

        functions.sort(function(a, b) {return (a.innerText < b.innerText) ? 1 : -1;});
        for (var i = 0; i < functions.length; i++) {
            function_list.appendChild(functions[i]);
        }

        for (var i = 0; i < functions.length; i++) {
            var func = functions[i];
            func.addEventListener('click', function(e) {
                var func_el = e.srcElement;
                $.get('/function_info/'+func_el.innerText, function(data) {
                    var func = JSON.parse(data);
                    var disas = document.getElementById('disas');
                    $.get('/dis/'+func.name, function(data) {
                        disas.innerText = data;
                        $.get('/bbs/'+func.name, function(data) {
                            disp_bbs(func, JSON.parse(data));
                        });
                    });
                });
            });
        }
    });

    // Register toggle event
    document.getElementsByTagName('body')[0].addEventListener('keydown', toggle_disass_style);
}

var disp_bbs = function(func, bbs) {
    var bbs_container = document.getElementById('bbs');
    while (bbs_container.children.length > 0) {
        bbs_container.removeChild(bbs_container.children[0]);
    }

    for (var i = 0; i < bbs.length; i++) {
        var bb = bbs[i];
        var bb_box = document.createElement('div');
        bb_box.className = 'bb';
        bb_box.id = bb.address;
        for (var j = 0; j < bb.instructions.length; j++) {
            var ins = bb.instructions[j];
            var asm_line = document.createElement('div');
            asm_line.innerHTML = ins.address + ' ' + ins.mnemonic + ' ' + ins.op_str;

            bb_box.appendChild(asm_line);
        }

        bbs_container.appendChild(bb_box);
    }

    $.get('/cfg/'+func.name,function(data){
        layout_bbs(func, bbs, JSON.parse(data));
    })
}


var layout_bbs = function(func, bbs, cfg) {
    var addr_to_bb = {};
    for (var i = 0; i < bbs.length; i++) {
        var bb = bbs[i];
        addr_to_bb[bb.address] = bb;
    }

    var bb_containing_addr = function(addr) {
        for (var i = 0; i < bbs.length; i++) {
            var bb = bbs[i];
            if (bb.address <= addr && addr < bb.address + bb.size) {
                return bb;
            }
        }
        console.error("WTF, couldn't find a BB for addr: " + addr);
    }

    // Let's generate the edges via graphvis now
    var gv_data = "strict digraph G {\n";
    gv_data += 'layout=dot;\n';
    gv_data += 'splines=polyline;\n';
    for (var i = 0; i < bbs.length; i++) {
        var bb = bbs[i];
        var bb_el = $("#" + bb.address);
        gv_data += 'N' + bb.address + ' [width=' + bb_el.width() + ', height=' + bb_el.height() + ', shape="box"];\n';
    }

    for (var i = 0; i < cfg.length; i++) {
        var edge = cfg[i];
        gv_data += 'N' + bb_containing_addr(edge[0]).address + ' -> N' + bb_containing_addr(edge[1]).address + ' [headport=n, tailport=s];\n';
    }
    gv_data += '}';
    $.post('/graph', gv_data, function(data) {
        console.log(data);
        var svg = document.createElement('svg');
        svg.innerHTML = data;
        document.body.appendChild(svg);
        /*
        var graphscale = 1;
        data = data.split("\n").join("").split(";");
        var graphdata = data[0]; // metadata about the graph, we don't really care about this currently
        graphdata = graphdata.split('"')[1].split(',');
        var all_node_attr = data[1]; // line setting some global attributes on nodes. We can ignore it.

        for (var i = 2; i < data.length; i++) {
            if (data[i] == '}') break;
            if (data[i].indexOf('->') != -1) { // edge
                var edge = data[i].replace("\\", ""); // sometimes we get a random \ in there... just delete it
            } else { // node
                var node = data[i];
                //console.log(node);
                var coords = node.split('"')[1].split(',');
                //console.log(coords);
                var x = parseFloat(coords[0])/graphscale, y = parseFloat(coords[1])/graphscale;
                //console.log(x + " " + y);

                var node_id = node.trim().split(' ')[0];
                var node_el = $(node_id.replace('N','#'))[0];
                bbwidth = parseFloat(graphdata[2])/2;
                bbheight = parseFloat(graphdata[3])/2;
                var left = bbwidth - x;
                var top = bbheight - y - node_el.offsetHeight;
                console.log('bounding: ' + bbwidth + ' ' + bbheight);
                console.log('node: ' + left + ' ' + top);
                node_el.style.left = left+"px";
                node_el.style.top = top+"px";
            }
        }
        */
    });
}

var display_graph = true;
var toggle_disass_style = function(e) {
    if (e.keyCode == 32) { // space
        bbs = document.getElementById('bbs');
        disas = document.getElementById('disas');
        if (display_graph) {
            bbs.style.display = 'none';
            disas.style.display = 'block';
        } else {
            bbs.style.display = 'block';
            disas.style.display = 'none';
        }
        display_graph = !display_graph;
    }
}

document.addEventListener('DOMContentLoaded', load_function_list);
