import idaapi
import idautils
import idc
import os
import ida_segment


def get_segment_bounds(name):
    """Get start and end addresses of a named segment"""
    seg = idaapi.get_segm_by_name(name)
    if seg:
        return seg.start_ea, seg.end_ea
    return None, None


def is_text_segment(seg):
    """Check if a segment is the .text segment"""
    print(ida_segment.get_segm_name(seg))
    return seg and ida_segment.get_segm_name(seg) == '.text'


def main():
    # Get .text segment bounds
    text_start, text_end = get_segment_bounds(".text")
    if None in {text_start, text_end}:
        print("[-] .text segment not found")
        return

    output_file = os.path.join(idaapi.get_user_idadir(), "text_data_refs.txt")
    with open(output_file, "w") as f:
        print(
            f"[+] Writing all non-.text references from .text to: {output_file}")

        # Get all segments except .text
        all_segments = [seg for seg in idautils.Segments()
                        if not is_text_segment(idaapi.getseg(seg))]

        for ea in idautils.Heads(text_start, text_end):
            if not idaapi.is_code(idaapi.get_flags(ea)):
                continue

            # Decode instruction
            insn = idaapi.insn_t()
            if idaapi.decode_insn(insn, ea) == 0:
                continue

            size = idaapi.get_item_size(ea)
            raw_bytes = idaapi.get_bytes(ea, size)
            if not raw_bytes:
                continue

            # Get disassembly without address or comments
            disasm = idc.generate_disasm_line(ea, idc.GENDSM_FORCE_CODE)
            disasm = disasm.split(';')[0].strip()  # Remove comments
            disasm = ' '.join(disasm.split()[1:])   # Remove address

            # Find all cross-references from this instruction
            for ref_ea in idautils.DataRefsFrom(ea):
                # Skip references back to .text
                if text_start <= ref_ea < text_end:
                    continue

                # Check if reference goes to any non-.text segment
                for seg_start, seg_end in [(idaapi.getseg(seg).start_ea, idaapi.getseg(seg).end_ea)
                                           for seg in all_segments]:
                    if seg_start <= ref_ea < seg_end:
                        f.write(
                            f"{ea:x}\t{size}\t{raw_bytes.hex()}\t{ref_ea:x}\t{disasm}\n")
                        break

    print("[+] Done. Found all non-.text references from .text section")


if __name__ == "__main__":
    main()
