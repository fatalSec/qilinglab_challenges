from qiling import Qiling
from qiling.const import QL_VERBOSE, QL_INTERCEPT
from qiling.os.const import POINTER, INT

ql = Qiling([r'qilinglab-aarch64'],r'/home/kali/Documents/qiling_rootfs/arm64_linux', verbose=QL_VERBOSE.OFF)

base_addr = ql.mem.get_lib_base(ql.path)

def challenge3_read_callback(ql,*args):
    params = ql.os.resolve_fcall_params({'fd':INT, 'buf':POINTER, 'size': INT})
    if params['size'] == 32:
        bytes_20 = params['buf']
        print(f"Before modifying bytes_20: {ql.mem.read(bytes_20,20)}")
        ql.mem.write(bytes_20, b"\xFF"*32)
        print(f"After modifying bytes_20: {ql.mem.read(bytes_20,20)}")
    if params['size'] == 1:
        bytes_1 = params['buf']
        print(f"Before modifying bytes_1: {ql.mem.read(bytes_1,1)}")
        ql.mem.write(bytes_1, b"\xAA")
        print(f"After modifying bytes_1: {ql.mem.read(bytes_1,1)}")

def challenge3_getrandom_callback(ql,*args):
    params = ql.os.resolve_fcall_params({'buf':POINTER, 'size': INT})
    bytes_20 = params['buf']
    print(f"Before modifying random bytes_20: {ql.mem.read(bytes_20,32)}")
    ql.mem.write(bytes_20, b"\xFF"*32)
    print(f"After modifying random bytes_20: {ql.mem.read(bytes_20,20)}")

def challenge3(ql):
    ql.os.set_syscall('read', challenge3_read_callback, QL_INTERCEPT.EXIT)
    ql.os.set_syscall('getrandom', challenge3_getrandom_callback, QL_INTERCEPT.EXIT)

def challenge4_callback(ql):
    ql.arch.regs.x0 = 1

def challenge4(ql):
    hook_addr = base_addr + 0xfe0
    ql.hook_address(challenge4_callback, hook_addr)

def challenge5_callback(ql):
    print(f"Before modificatoin x0: {ql.arch.regs.x0}")
    ql.arch.regs.x0 = 0
    print(f"After modificatoin x0: {ql.arch.regs.x0}")

def challenge5(ql):
    ql.os.set_api('rand', challenge5_callback, QL_INTERCEPT.CALL)


challenge3(ql)
challenge4(ql)
challenge5(ql)

ql.run()