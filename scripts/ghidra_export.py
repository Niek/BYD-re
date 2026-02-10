#
# Run: for i in $(find byd -name '*.so'); do $(dirname $(readlink $(which ghidraRun)))/support/analyzeHeadless /tmp ghidra_tmp_proj -import $i -processor "AARCH64:LE:64:v8A" -scriptPath scripts -postScript ghidra_export.py -deleteProject; done
#
# scripts/ghidra_export.py
import os
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

# 1. Setup
program = currentProgram
decomp = DecompInterface()
decomp.openProgram(program)

# 2. Define output path
# getExecutablePath() returns the full path of the imported binary (e.g. /abs/path/to/byd/libencrypt...)
# We simply append .c to it.
out_path = program.getExecutablePath() + ".c"
print("Decompiling to: " + out_path)

# 3. Decompile and Write
with open(out_path, "w") as f:
    f.write("// Decompiled with Ghidra Headless\n")
    f.write("// Source: {}\n\n".format(program.getName()))
    
    functions = program.getFunctionManager().getFunctions(True)
    for func in functions:
        results = decomp.decompileFunction(func, 0, ConsoleTaskMonitor())
        if results.decompileCompleted():
            c_code = results.getDecompiledFunction().getC()
            f.write(c_code)
            f.write("\n")

print("Done.")