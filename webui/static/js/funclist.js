// data about the current view
var current_view = {
    function_name: undefined,
    functions: undefined,
    selected_element: undefined,
    graph_x: undefined,
    graph_y: undefined
}

var setup = function() {
    load_function_list();

    // Register keyboard events
    document.getElementsByTagName('body')[0].addEventListener('keydown', toggle_disass_style);
    document.getElementsByTagName('body')[0].addEventListener('keydown', rename_function);
    document.getElementsByTagName('body')[0].addEventListener('keydown', sync);
    document.getElementsByTagName('body')[0].addEventListener('keydown', xrefs_button_event);

    document.getElementById('bbs').addEventListener('scroll', scroll_handle);

    //setInterval(reload_data, 1000); // collaborative editing, still WIP

}


var load_function_list = function () {
    // Get the list of functions
    $.get('/function_list', function(data) {
        var function_list = document.getElementById('functionlist');

        // clear the old list
        while (function_list.children.length > 0) {
            function_list.removeChild(function_list.children[0]);
        }

        var functions = JSON.parse(data);
        current_view.functions = Array.from(functions);
        for (var i = 0; i < functions.length; i++) {
            var node = document.createElement('span');
            node.innerText = functions[i];
            node.className = 'functionlist-entry';
            functions[i] = node;
        }

        var heading = document.createElement('div');
        heading.className = 'heading';
        heading.innerHTML = '(✿◕‿◕) functions (◕‿◕✿)';
        function_list.appendChild(heading);

        // Sort the list of functions when we load the page

        functions.sort(function(a, b) {return (a.innerText < b.innerText) ? 1 : -1;});
        for (var i = 0; i < functions.length; i++) {
            function_list.appendChild(functions[i]);
        }

        for (var i = 0; i < functions.length; i++) {
            var func = functions[i];
            func.addEventListener('click', function(e) {
                var func_el = e.srcElement;
                load_function(func_el.innerText);
            });
        }
    });
}

var load_function = function(name) {
    $.get('/function_info/'+name, function(data) {
        var func = JSON.parse(data);
        var disas = document.getElementById('disas');
        current_view.function_name = func.name;
        $.get('/dis/'+func.name, function(data) {
            disas.innerText = data;
            layout_bbs(func);
        });
        load_xrefs_menu(name);
    });
}

var layout_bbs = function(func) {
    $.get('/graph/'+func.name, function(data) {
        var svg = document.createElement('div');
        svg.innerHTML = data;
        document.getElementById('bbs').innerHTML = "";
        document.getElementById('bbs').appendChild(svg);
        divide_instructions();
    });
}

var instruction_delimiters = ['[', ']','+','-','*',' ',','];
var parse_instruction = function(insn) {
    var tokens = [];
    var curr_token = "";
    var in_comment = false;
    Array.from(insn).forEach(function(c) {
        if (!in_comment) {
            if (instruction_delimiters.indexOf(c) != -1) {
                tokens.push(curr_token);
                tokens.push(c);
                curr_token = "";
            } else if (c == ';') {
                in_comment = true;
                tokens.push(curr_token);
                curr_token = c;
            } else {
                curr_token += c;
            }
        } else {
            curr_token += c;
        }
    });
    tokens.push(curr_token);
    return tokens;
}

var divide_instructions = function() {
    var bbs = $('.node');
    var register_names = [
        // x86(_64) registers
        'cs','ds','es','fs','gs','ss',                                                                               // segment registers
        'cf pf af zf sf tf if df of iopl nt rf vm ac vif vip id',                                                    // EFLAGS
        'ah','al','bh','bl','ch','cl','dh','dl','r8l','r9l','r10l','r11l','r12l','r13l','r14l','r15l',               // 8-bit registers
        'ax','bx','cx','dx','di','si','bp','sp','ip','r8w','r9w','r10w','r11w','r12w','r13w','r14w','r15w',          // 16-bit registers
        'eax','ebx','ecx','edx','edi','esi','ebp','esp','eip','r8d','r9d','r10d','r11d','r12d','r13d','r14d','r15d', // 32-bit registers
        'rax','rbx','rcx','rdx','rdi','rsi','rbp','rsp','rip','r8','r9','r10','r11','r12','r13','r14','r15',         // 64-bit registers
        'st','st0', 'st1', 'st2', 'st3', 'st4', 'st5', 'st6', 'st7',                                                 // Floating point registers
        // TODO: ARM, MIPS, etc.
        ];
    var instruction_names = [
        // x86 (or some subset... TODO: literally every x86 instruction)
        'aaa','aad','aam','aas','adc','add','and','call','cbw',
        'clc','cld','cli','cmc','cmp','cmpsb','cmpsw','cwd',
        'daa','das','dec','div','esc','hlt','idiv','imul',
        'in','inc','int','into','iret','jle','jl','jge','jg','ja','jb', 'jbe',
        'je','jne','jz','jnz','jcxz','jmp','lahf','lds','lea',
        'les','lock','lodsb','lodsw','loop','mov','movsb','movsw', 'movsx','movzx',
        'mul','neg','nop','not','or','out','pop','popf','push','pushf',
        'rcl','rcr','ret','retn','retf','rol','ror','sahf','sal','sar',
        'sbb','scasb','scasw','shl','shr','stc','std','sti','stosb',
        'stosw','sub','test','wait','xchg','xlat','xor', 'syscall',
        'repne','leave', 'fld', 'fstp', 'fldcw', 'fldz', 'fxch', 'fucompi',
        'fchs', 'fistp', 'fnstcw', 'fild', 'fsubrp', 'fmulp', 
        'jns', 'js',
        // TODO: ARM, MIPS, etc.
        ];
    bbs.each(function(i, bb) {
        var bb_addr = undefined; // address of the basic block's head
        Array.from(bb.children).forEach(function(insn_block) {
            var new_content = "";
            var ss = parse_instruction(insn_block.innerHTML);
            if (insn_block.tagName.toLowerCase() == 'title') {
                bb_addr = insn_block.innerHTML;
            } else {
                for (var i = 0; i < ss.length; i++) {
                    var x = ss[i];
                    var classes = [bb_addr];
                    // find various attributes for syntax highlighting
                    if (register_names.indexOf(x.toLowerCase()) != -1) {
                        classes.push('register');
                    }
                    if (instruction_delimiters.indexOf(x.toLowerCase()) != -1) {
                        classes.push('delimiter');
                    }
                    if (instruction_names.indexOf(x.toLowerCase()) != -1) {
                        classes.push('instruction');
                    }
                    if (x[0] == ';') {
                        classes.push('comment');
                    }
                    new_content += "<tspan class=\""+classes.join(" ")+"\">"+x+"</tspan>";
                }
                insn_block.innerHTML = new_content;
            }
        });
    });
    var tspans = Array.from($('tspan'));
    tspans.forEach(function(tsp) {
        if (current_view.functions.indexOf(tsp.innerHTML) != -1) {
            tsp.addEventListener('click', instruction_clicked);
        }
    });
    
}

var instruction_clicked = function(e) {
    var ins = e.srcElement;
    if (ins == current_view.selected_element) { // double-clicking element
        if (current_view.functions.indexOf(ins.innerHTML) != -1) { // if it's a function, jump to it
            load_function(ins.innerHTML);
        }
    } else {
        if (current_view.selected_element != undefined) {
            current_view.selected_element.style['stroke'] = 'none';
        }
        current_view.selected_element = ins;
        current_view.selected_element.style['stroke'] = 'blue';
    }
}

var rename_function = function(e) {
    if (e.keyCode == 78 && // n
        current_view.selected_element != undefined) {
        var name = current_view.selected_element.innerHTML;
        var new_name = prompt("Rename " + name + ":");
        if (current_view.functions.indexOf(new_name) != -1) {
            alert("Bad! Another function already has that name!");
        } else if (new_name != null) {
            $.post('/rename/'+name+'/'+new_name, function(data) {
                load_function_list(); // reload data
                if (current_view.function_name == name) {
                    load_function(new_name); // load the new function to be the current view if we renamed the function we're in
                } else {
                    load_function(current_view.function_name); // reload the current view if we changed another function
                }
            });
        }
    }
}

var reload_data = function() {
    load_function_list();
    if (current_view.function_name != undefined) {
        load_function(current_view.function_name);
        // Reload to the last position we were in
        document.getElementById('bbs').scrollTop = current_view.graph_y;
        document.getElementById('bbs').scrollLeft = current_view.graph_x;
    }
}

var xrefs_button_event = function(e) {
    if (e.keyCode == 88 && // x
        current_view.selected_element != undefined &&
        current_view.functions.indexOf(current_view.selected_element.innerHTML) != -1) {
            var function_name = current_view.selected_element.innerHTML;
            load_xrefs_menu(function_name);
    }
}

var load_xrefs_menu = function(function_name) {
    $.get('/xrefs/'+function_name , function(xrefs) {
        xrefs = JSON.parse(xrefs);
        var list = document.createElement('div');
        list.id = 'xrefs';
        var heading = document.createElement('div');
        heading.className = 'heading';
        heading.innerHTML = '(✿◕‿◕) x-refs (◕‿◕✿)';
        list.appendChild(heading);

        xrefs.forEach(function(xref) {
            var li = document.createElement('div');
            li.innerHTML = xref;
            li.className = 'xref';
            list.appendChild(li);
            li.addEventListener('click', function(e) {
                var func_el = e.srcElement;
                load_function(func_el.innerText);
            });
        });

        var func_list = document.querySelectorAll('#functionlist')[0];
        var old_xrefs = document.querySelectorAll('#xrefs')[0];
        if (old_xrefs) {
            func_list.removeChild(document.querySelectorAll('#xrefs')[0]);
        }
        func_list.appendChild(list);
    });
}

var sync = function(e) {
    if (e.keyCode == 82) { // r
        reload_data();
    }
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

var scroll_handle = function(e) {
    current_view.graph_y = e.target.scrollTop;
    current_view.graph_x = e.target.scrollLeft;
}

document.addEventListener('DOMContentLoaded', setup);
