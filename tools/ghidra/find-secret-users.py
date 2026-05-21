# Find every function that reads the deobfuscated hardcoded 33-byte secret.
#
# The chain is:
#   obfuscated raw bytes  @ 0x1007B0490 (33 bytes in __TEXT __const)
#   FUN_100182c80(&DAT_100cf8cf0, &DAT_1007b0490)  loads them to __DATA
#   cipher vt[7] (FUN_100180E90) XORs with mask 0x51..0x71, leaves decoded
#       buffer at &DAT_100cf8d11, returns its address
#   <somebody> calls vt[7], reads 33 bytes, uses for cipher state seeding
#
# Anyone calling vt[7] via `(*((cipher)->vptr + 0x38))(cipher)` would not
# show as a direct ref to FUN_100180E90. But anyone READING addresses
# 0x100cf8cf0 / 0x100cf8d11 / 0x1007b0490 directly would.

# @category Stick

import os, re
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

OUT_DIR = os.path.join(os.path.dirname(getSourceFile().getAbsolutePath()), 'out17')
try: os.makedirs(OUT_DIR)
except OSError: pass

prog = currentProgram
fm = prog.getFunctionManager()
af = prog.getAddressFactory()
ref_mgr = prog.getReferenceManager()
monitor = ConsoleTaskMonitor()
decomp = DecompInterface()
decomp.openProgram(prog)


def addr(a): return af.getDefaultAddressSpace().getAddress(a)


def dump(func, out):
    out.write('==== %s @ %s ====\n' % (func.getName(True), func.getEntryPoint()))
    out.write('size: %d body bytes\n' % func.getBody().getNumAddresses())
    callees = sorted(set('%s @ %s' % (f.getName(True), f.getEntryPoint())
                         for f in func.getCalledFunctions(monitor)))
    out.write('\n-- callees (%d) --\n' % len(callees))
    for c in callees: out.write('  ' + c + '\n')
    callers = sorted(set('%s @ %s' % (f.getName(True), f.getEntryPoint())
                         for f in func.getCallingFunctions(monitor)))
    out.write('\n-- callers (%d) --\n' % len(callers))
    for c in callers: out.write('  ' + c + '\n')
    out.write('\n-- decompilation --\n')
    res = decomp.decompileFunction(func, 240, monitor)
    if res.decompileCompleted():
        out.write(res.getDecompiledFunction().getC())
    else:
        out.write('(decompilation failed: %s)\n' % res.getErrorMessage())
    out.write('\n')


# Addresses involved in the hardcoded-secret deobfuscation
TARGETS = {
    'raw_obfuscated':       0x1007B0490,   # 33 bytes XOR-masked
    'staging_buffer':       0x100CF8CF0,   # bytes loaded here, then XOR'd
    'decoded_pointer':      0x100CF8D11,   # vt[7] returns this; decoded bytes start
    'guard_byte':           0x100CF8D38,   # __cxa_guard for one-time init
    'deobfuscator_fn':      0x100180E90,
    'loader_fn':            0x100182C80,
}

seen = set()
summary = open(os.path.join(OUT_DIR, 'SUMMARY.txt'), 'w')

for label, a in TARGETS.items():
    summary.write('\n#### %s @ 0x%x\n' % (label, a))
    code_refs = set()
    refs = list(ref_mgr.getReferencesTo(addr(a)))
    summary.write('   total refs: %d\n' % len(refs))
    for r in refs:
        fa = r.getFromAddress()
        rtype = r.getReferenceType().getName()
        f = fm.getFunctionContaining(fa)
        if f is not None:
            code_refs.add(f.getEntryPoint())
        else:
            summary.write('     %s @ %s  (%s, not in any fn)\n' %
                          (label, fa, rtype))
    summary.write('   code refs from %d fn(s):\n' % len(code_refs))
    for ep in sorted(code_refs):
        f = fm.getFunctionAt(ep)
        summary.write('     %s @ %s (size %d)\n' %
                      (f.getName(True), f.getEntryPoint(),
                       f.getBody().getNumAddresses()))
        if ep in seen: continue
        seen.add(ep)
        safe = re.sub(r'[^A-Za-z0-9._-]', '_', f.getName(True))[:120]
        with open(os.path.join(OUT_DIR, '%s_%s_%s.txt' %
                                (label, f.getEntryPoint(), safe)), 'w') as o:
            dump(f, o)

summary.write('\n=== total dumped: %d ===\n' % len(seen))
summary.close()
print('find-secret-users: %d functions dumped to %s' % (len(seen), OUT_DIR))
