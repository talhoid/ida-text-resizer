#!/usr/bin/env python3
import sys
import argparse
import lief
from capstone import *
from capstone.x86 import *


def align_up(v, a):
    return ((v + a - 1)//a)*a


def parse_args():
    p = argparse.ArgumentParser(
        description=(
            "Patch a PE32+ executable by injecting NOP-equivalent bytes into the .text section, "
            "shifting all later sections, adjusting virtual addresses, and rebiasing all recorded "
            "displacements and immediates in the code. Primarily used to make room for injected shellcode."
        )
    )
    p.add_argument(
        "inpe",
        metavar="INPUT_PE",
        help="Path to original PE32+ executable",
    )
    p.add_argument(
        "dumper",
        metavar="TEXT_REFS",
        help="Path to reference file (output of dumper.py) containing instruction metadata",
    )
    p.add_argument(
        "-n", "--pad",
        metavar="COUNT",
        type=int,
        help="Number of padding bytes to append to the end of .text section",
        dest="amount",
        required=True
    )

    p.add_argument(
        "-b", "--byte",
        default="0x90",
        metavar="HEXBYTE",
        help="Byte value to use for padding (default: 0x90 = NOP). Example: 0xCC for INT3"
    )
    p.add_argument(
        "-o", "--out",
        type=str,
        metavar="OUTPUT",
        required=True,
        help="Path to write patched binary"
    )
    return p.parse_args()


def load_refs(path):
    """ea \t size \t rawhex \t old_target \t disasm"""
    """disasm field is for debugging"""
    refs = []
    for L in open(path):
        ea, sz, raw, ot, _ = L.strip().split("\t", 4)
        refs.append({
            "ea": int(ea, 16),
            "size": int(sz),
            "raw": bytes.fromhex(raw),
            "old": int(ot, 16)
        })
    return refs


def main():
    args = parse_args()
    bin = lief.parse(args.inpe)
    opt = bin.optional_header
    pad_byte = int(args.byte, 16) & 0xff
    FA = opt.file_alignment

    # 1) expand .text & shift following sections
    txt = bin.get_section(".text")
    if not txt:
        sys.exit(".text not found")

    raw_shift = align_up(args.amount, FA)
    va_shift = args.amount

    # pad with NOPs
    txt.content = list(txt.content) + [pad_byte] * args.amount
    txt.size = align_up(len(txt.content), FA)
    txt.virtual_size = txt.virtual_size + args.amount
    text_base_va = txt.virtual_address  # ← Save original .text VA before shifting

    # shift later sections
    for s in sorted(bin.sections, key=lambda s: s.virtual_address):
        if s.virtual_address > txt.virtual_address:
            s.pointerto_raw_data += raw_shift
            s.virtual_address += va_shift
    opt.sizeof_image += va_shift

    # 2) prepare Capstone to give us operand offsets
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True

    # 3) patch each recorded reference
    for r in load_refs(args.dumper):
        ea, sz, raw, old = r["ea"], r["size"], r["raw"], r["old"]
        new_target = old + va_shift

        insns = list(md.disasm(raw, ea))
        if not insns or insns[0].size != sz:
            print(f"[!] disasm mismatch at 0x{ea:x}, skipping")
            continue
        insn = insns[0]

        off = sz
        width = 0

        ops = insn.operands

        if insn.id in (X86_INS_CALL, X86_INS_JMP) and ops[0].type == X86_OP_IMM:
            off = insn.imm_offset
            width = insn.imm_size
        else:
            for op in ops:
                if op.type == X86_OP_MEM and op.mem.base == X86_REG_RIP:
                    off = insn.disp_offset
                    width = insn.disp_size
                    break
            else:
                for op in ops:
                    if op.type == X86_OP_IMM:
                        off = insn.imm_offset
                        width = insn.imm_size
                        break

        if width == 0:
            continue

        # extract, decode, and re-encode the operand value
        orig_bytes = raw[off:off+width]
        orig_val = int.from_bytes(orig_bytes, 'little', signed=False)

        if insn.id in (X86_INS_CALL, X86_INS_JMP) and ops[0].type == X86_OP_IMM:
            new_val = new_target - (ea + sz)
        else:
            new_val = orig_val + va_shift

        new_bytes = (new_val & (2 ** (8 * width) - 1)
                     ).to_bytes(width, 'little')
        assert len(new_bytes) == width

        # Convert VA to RVA
        ea_rva = ea - opt.imagebase
        text_rva = txt.virtual_address
        sec_raw = list(txt.content)  # Make it writable
        sec_len = len(sec_raw)

        for i, b in enumerate(new_bytes):
            idx = (ea_rva - text_rva) + off + i
            if idx < 0 or idx >= sec_len:
                sys.exit(
                    f"[!] Patch out of .text bounds at EA=0x{ea:x}, idx={idx}, section size={sec_len}")
            sec_raw[idx] = b

        txt.content = sec_raw  # Re-assign the modified list back to the section

    if r["ea"] < opt.imagebase:
        sys.exit(
            f"[!] EA 0x{r['ea']:x} appears to be an RVA, not a VA. Check your dumper.")

    opt.sizeof_code = txt.size

    # Fix relocation directory RVA if .reloc section got moved
    reloc_sec = bin.get_section(".reloc")
    if reloc_sec:
        bin.relocation_dir.rva = reloc_sec.virtual_address
        bin.relocation_dir.size = reloc_sec.virtual_size
        print(
            f"[+] Updated relocation directory RVA to 0x{reloc_sec.virtual_address:x}")
        print("[*] Adjusting affected relocations (if any):")
        for reloc in bin.relocations:
            for entry in reloc.entries:
                abs_va = reloc.virtual_address + entry.position
                if abs_va >= text_base_va + txt.virtual_size - args.amount:
                    new_pos = entry.position + va_shift
                    print(
                        f"  [!] Reloc at VA 0x{abs_va:x} → 0x{abs_va + va_shift:x} (position {entry.position} → {new_pos})")
                    entry.position = new_pos
    else:
        print("[+] No .reloc section found, skipping fixing relocation table")

    

    # 5) dump file
    bin.write(args.out)
    print(f"[+] Wrote {args.out}")


if __name__ == "__main__":
    main()
