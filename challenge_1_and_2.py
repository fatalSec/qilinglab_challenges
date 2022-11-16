from qiling import Qiling
from qiling.const import QL_VERBOSE, QL_INTERCEPT
from qiling.os.const import POINTER

ql = Qiling([r'qilinglab-aarch64'],r'/home/kali/Documents/qiling_rootfs/arm64_linux', verbose=QL_VERBOSE.OFF)

base_addr = ql.mem.get_lib_base(ql.path)

def challenge1(ql):
    ql.mem.map(0x1000, 0x1000)
    ql.mem.write(0x1337, ql.pack16s(1337))
    print(f"value @0x1337 : {ql.unpack16s(ql.mem.read(0x1337,2))}")

def challenge2_callback(ql, *args):
    params = ql.os.resolve_fcall_params({'buf':POINTER})
    print(f"{params}")
    struct_addr = params['buf']
    sysname = ql.mem.read(struct_addr, 65)
    version = ql.mem.read(struct_addr+65*3, 65)
    print(f"{sysname} : {version}")
    print(f"{ql.mem.read(ql.arch.regs.sp+0xed, 65)}")
    ql.mem.write(struct_addr+65*3, b"ChallengeStart\x00")

def challenge2(ql):
    ql.os.set_syscall('uname', challenge2_callback, QL_INTERCEPT.EXIT)



challenge1(ql)
challenge2(ql)

ql.run()