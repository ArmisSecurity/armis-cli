ObjC.import('Foundation');

function readFile(p) {
    var s = $.NSString.stringWithContentsOfFileEncodingError($(p), $.NSUTF8StringEncoding, $());
    return s.isNil() ? null : ObjC.unwrap(s);
}

// merge.js FILE TOPKEY [remove]: add (or remove) the armis-appsec server in FILE, keeping other keys.
function run(argv) {
    var t = readFile(argv[0]), o = {};
    if (t !== null && t.trim() !== '') o = JSON.parse(t);
    if (!o[argv[1]]) o[argv[1]] = {};
    if (argv[2] === 'remove') delete o[argv[1]]['armis-appsec'];
    else o[argv[1]]['armis-appsec'] = { command: 'python', args: ['server.py'] };
    $(JSON.stringify(o, null, 2) + '\n').writeToFileAtomicallyEncodingError($(argv[0]), true, $.NSUTF8StringEncoding, $());
    return '';
}
