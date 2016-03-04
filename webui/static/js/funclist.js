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
                        layout_bbs(func);
                    });
                });
            });
        }
    });

    // Register toggle event
    document.getElementsByTagName('body')[0].addEventListener('keydown', toggle_disass_style);
}

var layout_bbs = function(func, cfg) {
    $.get('/graph/'+func.name, function(data) {
        console.log(data);
        var svg = document.createElement('div');
        svg.innerHTML = data;
        document.getElementById('bbs').appendChild(svg);
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
