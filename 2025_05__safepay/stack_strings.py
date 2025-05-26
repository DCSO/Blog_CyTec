from unicorn import *
from unicorn.x86_const import *


def print_instructions(snippets: list):

    for snippet in snippets:
        for instr in snippet:
            print(f"{instr.getAddress()}: {instr}")
        print("---------------------------------")
    print(f"TOTAL SNIPPETS: {len(snippets)}")


def get_snippets(start_bytes: bytes, end_bytes: bytes):

    snippets = []
    current_snippet = []
    collect = False
    listing = currentProgram.getListing()

    for instr in listing.getInstructions(True):
        if collect and bytes(instr.getParsedBytes()).startswith(end_bytes[:1]):
            collect = False
            current_snippet.append(instr)
            snippets.append(current_snippet)
            current_snippet = []

        if collect:
            current_snippet.append(instr)

        if not collect and bytes(instr.getParsedBytes()) == start_bytes:
            collect = True
            current_snippet.append(instr)

    return snippets


def get_string_offset(instructions):

    for instr in instructions:
        instr_bytes = bytes(instr.getParsedBytes())
        if instr_bytes.startswith(b"\xc7\x45"):
            print(f"{instr.getAddress()}: {instr}")
            return int.from_bytes([instr_bytes[2]], byteorder="little", signed=True)

        elif instr_bytes.startswith(b"\xc7\x85"):
            print(f"{instr.getAddress()}: {instr}")
            return int.from_bytes([instr_bytes[2], instr_bytes[3], instr_bytes[4], instr_bytes[5]], byteorder="little", signed=True)

        else:
            continue

    return None


def patch_snippet(instruction_list, to_patch: bytes, patch: bytes):

    code = b""
    for instr in instruction_list:
        instruction_bytes = bytes(instr.getParsedBytes())

        if instruction_bytes == to_patch:
            instruction_bytes = patch

        code += instruction_bytes

    return code


def emulate_code(code: bytes, offset):

    ADDRESS = 0x1000000
    STACK_ADDR = 0x100000
    EDX_ADDR = 0x000000

    try:
        mu = Uc(UC_ARCH_X86, UC_MODE_32)

        # map code
        mu.mem_map(ADDRESS, 2 * 1024 * 1024)
        mu.mem_write(ADDRESS, code)

        # map stack
        mu.mem_map(STACK_ADDR, 2 * 1024 * 1024)
        mu.reg_write(UC_X86_REG_ESP, STACK_ADDR + 2 * 1024 * 1024 - 4)
        mu.reg_write(UC_X86_REG_EBP, STACK_ADDR+ 2 * 1024 * 1024 - 0x100)

        # map registers
        mu.mem_map(EDX_ADDR, 0x1000)
        mu.reg_write(UC_X86_REG_EDX, EDX_ADDR)
        mu.reg_write(UC_X86_REG_EAX, EDX_ADDR+0x500)
        mu.reg_write(UC_X86_REG_ECX, 0)

        mu.emu_start(ADDRESS, ADDRESS + len(code))

        r_ebp = mu.reg_read(UC_X86_REG_EBP)

        mem = mu.mem_read(r_ebp + offset, 0x100)
        output = mem.decode('utf-8').replace("\x00", "")
        print(f"DECODED OUTPUT: {repr(output)}")

    except UcError as e:
        print(f"ERROR: {e}")


if __name__ == "__main__":

    # 3 possible snippet beginnings:
    # [+] MOV EDX, dword ptr [0x10015ff8]
    # [+] MOV EAX, [0x10015ff8]
    # [+] MOV ECX, dword ptr [0x10015ff8]
    # 1 possible snippet ending:
    # [+] JC <VALUE>

    start_bytes_list = [b'\x8b\x15\xf8\x5f\x01\x10',
                        b'\xa1\xf8\x5f\x01\x10',
                        b"\x8b\x0d\xf8\x5f\x01\x10"]
    end_bytes = b'\x72'

    # patch instruction to emulate:
    # [+] new instr: mov BYTE PTR [REGISTER], 0x4d

    patched_instr_list = [b'\xc6\x02\x4d',
                          b'\xc6\x00\x4d',
                          b'\xc6\x01\x4d']


    for start_bytes, patched_instr in zip(start_bytes_list, patched_instr_list):

        snippets = get_snippets(start_bytes, end_bytes)

        for i, snippet in enumerate(snippets):
            offset = get_string_offset(snippet)
            code = patch_snippet(snippet, start_bytes, patched_instr)
            emulate_code(code, offset)
            print("----------")

