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
                load_function(func_el.innerText);
            });
        }
    });

    // Register keyboard events
    document.getElementsByTagName('body')[0].addEventListener('keydown', toggle_disass_style);
    document.getElementsByTagName('body')[0].addEventListener('keydown', rename_function);
}

var load_function = function(name) {
    $.get('/function_info/'+name, function(data) {
        var func = JSON.parse(data);
        var disas = document.getElementById('disas');
        $.get('/dis/'+func.name, function(data) {
            disas.innerText = data;
            layout_bbs(func);
        });
    });
}

var layout_bbs = function(func) {
    $.get('/graph/'+func.name, function(data) {
        console.log(data);
        var svg = document.createElement('div');
        svg.innerHTML = data;
        document.getElementById('bbs').innerHTML = "";
        document.getElementById('bbs').appendChild(svg);
        divide_instructions();
    });
}

var divide_instructions = function() {
    var bbs = $('.node');
    bbs.each(function(i, bb) {
        Array.from(bb.children).forEach(function(child) {
            var new_content = "";
            // TODO: lex instructions more nicely to improve clickyness (and maybe add coloring?)
            var ss = child.innerHTML.split(' ');
            for (var i = 0; i < ss.length; i++) {
                var x = ss[i];
                new_content += "<tspan>"+x+"</tspan> ";
            }
            child.innerHTML = new_content;
        });
    });
    var tspans = Array.from($('tspan'));
    tspans.forEach(function(tsp) {
        tsp.addEventListener('click', instruction_clicked);
    });
    
}

var selected_element = undefined;
var instruction_clicked = function(e) {
    var ins = e.srcElement;
    if (selected_element != undefined) {
        selected_element.style['stroke'] = 'none';
    }
    selected_element = ins;
    selected_element.style['stroke'] = 'blue';
}

var rename_function = function(e) {
    if (selected_element != undefined && e.keyCode == 78) { // n
        var name = selected_element.innerHTML;
        var new_name = prompt("Rename " + name + ":");
        if (new_name != null) {
            $.post('/rename/'+name+'/'+new_name, function(data) {
                load_function_list(); // reload data
                load_function(new_name); // load the new function to be the current view
            });
        }
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

document.addEventListener('DOMContentLoaded', load_function_list);
