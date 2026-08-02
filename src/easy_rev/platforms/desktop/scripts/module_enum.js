/**
 * Easy-Rev desktop Frida: process / module / export enumeration.
 * Authorized targets only. Use to map attack surface before SSL/crypto hooks.
 */
'use strict';

function safeEnum(fn, label) {
  try {
    return fn();
  } catch (e) {
    send({ type: 'error', where: label, error: String(e) });
    return null;
  }
}

send({
  type: 'process',
  id: Process.id,
  arch: Process.arch,
  platform: Process.platform,
  pageSize: Process.pageSize,
  pointerSize: Process.pointerSize,
});

const modules = safeEnum(function () {
  return Process.enumerateModules().slice(0, 80).map(function (m) {
    return {
      name: m.name,
      base: m.base ? m.base.toString() : null,
      size: m.size,
      path: m.path,
    };
  });
}, 'enumerateModules');

if (modules) {
  send({ type: 'modules', count: modules.length, modules: modules });
  // Sample exports from main module + any libssl / crypto-ish
  const interesting = modules.filter(function (m) {
    const n = (m.name || '').toLowerCase();
    return (
      n.indexOf('ssl') >= 0 ||
      n.indexOf('crypto') >= 0 ||
      n.indexOf('security') >= 0 ||
      n.indexOf('curl') >= 0 ||
      n === modules[0].name
    );
  }).slice(0, 6);

  interesting.forEach(function (m) {
    try {
      const mod = Process.findModuleByName(m.name);
      if (!mod || !mod.enumerateExports) return;
      const exports = mod.enumerateExports().slice(0, 40).map(function (e) {
        return { name: e.name, type: e.type, address: e.address ? e.address.toString() : null };
      });
      send({ type: 'exports', module: m.name, count: exports.length, exports: exports });
    } catch (e) {
      send({ type: 'exports', module: m.name, error: String(e) });
    }
  });
}

// Ranges (RWX etc.) — packing / shellcode clues
const ranges = safeEnum(function () {
  return Process.enumerateRanges('r-x').slice(0, 30).map(function (r) {
    return {
      base: r.base.toString(),
      size: r.size,
      protection: r.protection,
      file: r.file ? r.file.path : null,
    };
  });
}, 'enumerateRanges');
if (ranges) {
  send({ type: 'ranges_rx', count: ranges.length, ranges: ranges });
}

send({ type: 'script_loaded', name: 'module_enum' });
