

from unicorn import *
from unicorn.arm_const import *
from unicorn.x86_const import *
from unicorn.arm64_const import *

import idc
import idaapi
import idautils
import ida_segment
import binascii
TARGET_ARCH = UC_ARCH_ARM
TARGET_MODE = UC_MODE_ARM

# Define the stack size and address
STACK_SIZE = 0x10000 # 64KB stack
STACK_BASE = 0x7FF00000 # Arbitrary high address for stack

image_base_addr = idaapi.get_imagebase()

min_ea = idc.get_inf_attr(idc.INF_MIN_EA)
max_ea = idc.get_inf_attr(idc.INF_MAX_EA)
image_size = max_ea - min_ea

proc_name = idc.get_processor_name()

def unicorn_emulate_init():
    """
    Initializes the Unicorn engine and sets up the environment.
    This function is called before starting the emulation.
    """
    print("[INFO] Initializing Unicorn engine...")
    # Initialize Unicorn Engine
    
    if proc_name == "ARM":
        TARGET_ARCH = UC_ARCH_ARM
        TARGET_MODE = UC_MODE_ARM
    elif proc_name == "ARM64":
        TARGET_ARCH = UC_ARCH_ARM64
        TARGET_MODE = UC_MODE_ARM64
    elif proc_name == "X86":
        TARGET_ARCH = UC_ARCH_X86
        TARGET_MODE = UC_MODE_32
    elif proc_name == "X64":
        TARGET_ARCH = UC_ARCH_X86
        TARGET_MODE = UC_MODE_64
    else:
        print(f"[ERROR] Unsupported architecture: {proc_name}")
        return None
    
    mu = Uc(TARGET_ARCH, TARGET_MODE)
    print("[INFO] Unicorn engine initialized.")

    #mapped_regions = []
    image_end = (image_base_addr + image_size + 0xFFF) & ~0xFFF

    print(f"[INFO] Mapping image from 0x{image_base_addr:X} to 0x{image_end:X}")
    mu.mem_map(image_base_addr, image_end)

    for seg_ea in idautils.Segments():
        seg_start = idc.get_segm_start(seg_ea)
        seg_end = idc.get_segm_end(seg_ea)
        seg_size = seg_end - seg_start

        # Ensure segment size is positive
        if seg_size <= 0:
            print(f"[WARNING] Skipping invalid segment at 0x{seg_start:X} with size {seg_size}")
            continue

        
        # 3. Load Code and Data into Unicorn's memory
        # Read bytes from IDA and write to Unicorn
        try:
            # Read only the actual segment content, not the aligned padded part
            segment_bytes = idaapi.get_bytes(seg_start, seg_size)
            if segment_bytes:
                mu.mem_write(seg_start, segment_bytes)
                print(f"[INFO] Wrote {len(segment_bytes)} bytes from 0x{seg_start:X} to Unicorn memory.")
            else:
                print(f"[WARNING] No bytes read for segment 0x{seg_start:X}. Skipping write.")
        except Exception as e:
            print(f"[ERROR] Failed to write segment 0x{seg_start:X} to Unicorn memory: {e}")
            return None
    # Map the stack

    mu.mem_map(STACK_BASE, STACK_SIZE, UC_PROT_READ | UC_PROT_WRITE)
    print(f"[INFO] Mapped stack at 0x{STACK_BASE:X} with size 0x{STACK_SIZE:X}")
    initial_sp = STACK_BASE + STACK_SIZE - 8 # Leave space for a dummy return address
    mu.reg_write(UC_ARM_REG_SP, initial_sp)


    return mu


def hook_code(uc, address, size, userdata):
    print (">>> Tracing instruction at 0x%x, instruction size = 0x%x" % (address, size))


def unicorn_emu_start(mu, start_addr, end_addr):
    """
    Starts the emulation at the specified address.
    """
    if proc_name == "ARM":
        if idc.get_sreg(start_addr, "T") == 1:
            print(f"[INFO] Starting emulation in THUMB mode at 0x{start_addr:X}...")
            mu.reg_write(UC_ARM_REG_CPSR, mu.reg_read(UC_ARM_REG_CPSR) | UC_MODE_THUMB)
            start_addr =start_addr + 1
        else:
            print(f"[INFO] Starting emulation in ARM mode at 0x{start_addr:X}...")
            mu.reg_write(UC_ARM_REG_CPSR, mu.reg_read(UC_ARM_REG_CPSR) & ~UC_MODE_THUMB)
        
    print(f"[INFO] Starting emulation at 0x{start_addr:X}...")
    try:
        mu.hook_add(UC_HOOK_CODE, hook_code, 0)
        mu.emu_start(start_addr, end_addr)
        print("[INFO] Emulation finished.")

    except UcError as e:
        print(f"[ERROR] Emulation failed: {e}")



# test1
# def unicorn_emu_result(mu):
#     r2 = mu.reg_read(UC_ARM_REG_R2)

#     result = mu.mem_read(r2, 16)
#     print(binascii.b2a_hex(result))

# def main():
#     mu = unicorn_emulate_init()
#     if mu is None:
#         print("[ERROR] Failed to initialize Unicorn engine.")
#         return 
#     #bytes =  idc.get_bytes(idc.get_screen_ea(), 0x1000)
#     start_addr = target_function_address
#     end_addr = idc.get_func_attr(start_addr, FUNCATTR_END)
#     print(f"[INFO] Function start address: 0x{start_addr:X}, end address: 0x{end_addr:X}")
#     unicorn_emu_start(mu, start_addr, end_addr)
#     unicorn_emu_result(mu)
# main()




# test2

# def unicorn_emu_result(mu):
#     r2 = mu.reg_read(UC_ARM_REG_R2)

#     result = mu.mem_read(r2, 16)
#     print(binascii.b2a_hex(result))

# def main():
#     mu = unicorn_emulate_init()
#     if mu is None:
#         print("[ERROR] Failed to initialize Unicorn engine.")
#         return 
#     #bytes =  idc.get_bytes(idc.get_screen_ea(), 0x1000)
#     target_function_address = idc.here()
#     start_addr = target_function_address
#     end_addr = 0x9C2C
#     unicorn_emu_start(mu, start_addr, end_addr)
#     unicorn_emu_result(mu)
# main()



