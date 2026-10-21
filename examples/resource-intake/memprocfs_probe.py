"""Read a self-authored raw image through the MemProcFS Python API and print the observations as JSON."""
import json
import sys

import memprocfs

image, dtb, va = sys.argv[1], int(sys.argv[2], 0), int(sys.argv[3], 0)
vmm = memprocfs.Vmm(["-device", image, "-dtb", hex(dtb), "-disable-python", "-disable-symbolserver"])
process = vmm.process_list()[0]
print(json.dumps({
    "physical": vmm.memory.read(0x1000, 16).hex(),
    "processes": [[p.pid, p.name, p.dtb] for p in vmm.process_list()],
    "virtual": process.memory.read(va, 16).hex(),
    "virt2phys": process.memory.virt2phys(va),
    "pmem_file": vmm.vfs.read("/memory.pmem", 16, 0x1000).hex(),
    "root": sorted(vmm.vfs.list("/")),
}))
vmm.close()
