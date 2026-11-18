#!/usr/bin/env python3
import json
import re
import sys

OPCODES = {
    'lda': {'imm': 0xa9, 'zp': 0xa5, 'zpx': 0xb5, 'abs': 0xad, 'absx': 0xbd, 'absy': 0xb9, 'indy': 0xb1},
    'ldx': {'imm': 0xa2, 'zp': 0xa6}, 'ldy': {'imm': 0xa0, 'zp': 0xa4},
    'sta': {'zp': 0x85, 'zpx': 0x95, 'abs': 0x8d, 'absx': 0x9d, 'absy': 0x99, 'indy': 0x91},
    'adc': {'imm': 0x69, 'zp': 0x65, 'zpx': 0x75, 'absx': 0x7d, 'absy': 0x79},
    'sbc': {'imm': 0xe9, 'zp': 0xe5}, 'cmp': {'imm': 0xc9, 'zp': 0xc5},
    'inc': {'zp': 0xe6}, 'dec': {'zp': 0xc6},
    'jmp': {'abs': 0x4c}, 'jsr': {'abs': 0x20},
    'bne': {'rel': 0xd0}, 'beq': {'rel': 0xf0}, 'bcc': {'rel': 0x90}, 'bcs': {'rel': 0xb0}, 'bpl': {'rel': 0x10}, 'bmi': {'rel': 0x30},
    **{name: {'imp': code} for name, code in {
        'inx': 0xe8, 'iny': 0xc8, 'dex': 0xca, 'dey': 0x88, 'tax': 0xaa, 'tay': 0xa8, 'txa': 0x8a, 'tya': 0x98,
        'txs': 0x9a, 'clc': 0x18, 'sec': 0x38, 'cld': 0xd8, 'rts': 0x60, 'rti': 0x40, 'lsr': 0x4a, 'asl': 0x0a,
        'pha': 0x48, 'pla': 0x68, 'nop': 0xea}.items()},
}
SIZE = {'imp': 1, 'imm': 2, 'zp': 2, 'zpx': 2, 'indy': 2, 'rel': 2, 'abs': 3, 'absx': 3, 'absy': 3}


def assemble(source):
    symbols, image, listing = {}, bytearray(0x10000), []

    def value(text):
        total = 0
        for term in text.split('+'):
            term = term.strip()
            total += int(term[1:], 16) if term.startswith('$') else int(term) if term.isdigit() else symbols[term]
        return total

    def known(text):
        try:
            return value(text)
        except KeyError:
            return None

    def mode(mnemonic, operand):
        modes = OPCODES[mnemonic]
        if not operand:
            return 'imp', None
        if operand.startswith('#'):
            return 'imm', operand[1:]
        if 'rel' in modes:
            return 'rel', operand
        indirect = re.fullmatch(r'\((.+)\)\s*,\s*y', operand)
        if indirect:
            return 'indy', indirect.group(1)
        indexed = re.fullmatch(r'(.+?)\s*,\s*([xy])', operand)
        base, index = (indexed.group(1), indexed.group(2)) if indexed else (operand, '')
        number = known(base)
        short = 'zp' + index
        if number is not None and number < 0x100 and short in modes:
            return short, base
        return 'abs' + index, base

    for final in (False, True):
        at = 0
        for line in source.splitlines():
            code = line.split(';')[0].strip()
            start = at
            constant = re.fullmatch(r'(\w+)\s*=\s*(.+)', code)
            label = re.match(r'(\w+):\s*', code)
            if constant:
                symbols[constant.group(1)] = value(constant.group(2))
                code = ''
            elif label:
                symbols[label.group(1)] = at
                code = code[label.end():]
            if code.startswith('.org'):
                at = start = value(code[4:])
            elif code.startswith(('.byte', '.word')):
                width = 2 if code.startswith('.word') else 1
                for item in code[5:].split(','):
                    number = value(item) if final else 0
                    image[at:at + width] = number.to_bytes(width, 'little')
                    at += width
            elif code:
                mnemonic, _, operand = code.partition(' ')
                kind, argument = mode(mnemonic.lower(), operand.strip())
                if final:
                    number = value(argument) if argument else 0
                    if kind == 'rel':
                        number = (number - (at + 2)) & 0xff
                    image[at] = OPCODES[mnemonic.lower()][kind]
                    image[at + 1:at + SIZE[kind]] = number.to_bytes(SIZE[kind] - 1, 'little')
                at += SIZE[kind]
            if final and line.strip():
                is_code = bool(code) and not code.startswith('.')
                listing.append({'at': start if is_code else None, 'text': line.rstrip()})
    return image, listing


if __name__ == '__main__':
    image, listing = assemble(open(sys.argv[1]).read())
    open(sys.argv[2], 'wb').write(image)
    json.dump(listing, open(sys.argv[3], 'w'))
