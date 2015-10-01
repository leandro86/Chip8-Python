import struct
import sys


class Disassembler:
    MAX_PROGRAM_SIZE_BYTES = 4096
    OPCODE_LENGTH_BYTES = 2

    def __init__(self, program_path):
        self._program_data = [0] * Disassembler.MAX_PROGRAM_SIZE_BYTES
        self._program_size = 0

        # The key of the dict represents the first nibble of the opcode.
        # The value could be either a function or a tuple. Consider these Chip8
        # instructions:
        #
        #     1nnn - JP addr
        #     8xy1 - OR Vx, Vy
        #     8xy2 - AND Vx, Vy
        #     Ex9E - SKP Vx
        #     ExA1 - SKNP Vx
        #
        # For the "JP" I only need to know the first nibble, because there is no
        # other instruction which first nibble is 1.
        # For the "OR" and "AND" instructions I need the first nibble and the last one. That's
        # why the value of the dict could be a tuple: the first item of the tuple represents
        # how many nibbles do I need to read (starting from the least significant) in order to
        # know the correct opcode. The second item of the tuple is, again, a dict: the key is
        # given by all these others nibbles, and the value is a function.
        self._opcodes = {0x00: (3, {0x0E0: self._00E0,
                                    0x0EE: self._00EE}),
                         0x01: self._1NNN,
                         0x02: self._2NNN,
                         0x03: self._3XKK,
                         0x04: self._4XKK,
                         0x05: self._5XY0,
                         0x06: self._6XKK,
                         0x07: self._7XKK,
                         0x08: (1, {0x00: self._8XY0,
                                    0x01: self._8XY1,
                                    0x02: self._8XY2,
                                    0x03: self._8XY3,
                                    0x04: self._8XY4,
                                    0x05: self._8XY5,
                                    0x06: self._8XY6,
                                    0x07: self._8XY7,
                                    0x0E: self._8XYE}),
                         0x09: self._9XY0,
                         0x0A: self._ANNN,
                         0x0B: self._BNNN,
                         0x0C: self._CXKK,
                         0x0D: self._DXYN,
                         0x0E: (2, {0x9E: self._EX9E,
                                    0xA1: self._EXA1}),
                         0x0F: (2, {0x07: self._FX07,
                                    0x0A: self._FX0A,
                                    0x15: self._FX15,
                                    0x18: self._FX18,
                                    0x1E: self._FX1E,
                                    0x29: self._FX29,
                                    0x33: self._FX33,
                                    0x55: self._FX55,
                                    0x65: self._FX65})
                         }

        self._load_program(program_path)

    def disassemble(self):
        pc = 0x200
        lines = []

        for i in range(0, self._program_size, 2):
            opcode = self._get_opcode(i)
            mnemonic = self._lookup_opcode(opcode)
            line = ("0x{0:04X}".format(pc + i), "0x{0:04X}".format(opcode), mnemonic)
            lines.append(line)

        return lines

    def _load_program(self, program_path):
        with open(program_path, mode="rb") as file:
            byte = file.read(1)
            offset = 0

            while byte and offset < Disassembler.MAX_PROGRAM_SIZE_BYTES:
                self._program_data[offset] = struct.unpack("B", byte)[0]
                byte = file.read(1)
                offset += 1

        self._program_size = offset - 1

    def _get_opcode(self, i):
        return (self._program_data[i] << 8) | self._program_data[i + 1]

    def _lookup_opcode(self, opcode):
        # Get the most significant nibble
        msn = (opcode >> 12) & 0x0F

        try:
            instruction = self._opcodes[msn]
        except KeyError as e:
            return

        if isinstance(instruction, tuple):
            nibbles, sub_intructions = instruction

            # Build a mask. It could be, for example:
            #     1 nibble -> 0xF
            #     2 nibbles -> 0xFF
            #     3 nibbles -> 0xFFF
            mask = (16 ** nibbles) - 1
            key = opcode & mask

            try:
                instruction = sub_intructions[key]
            except KeyError:
                return "UNKNOWN"

        return instruction(opcode)

    def _get_address(self, opcode):
        return "{0:04X}".format(opcode & 0xFFF)

    def _get_x(self, opcode):
        return "{0:X}".format((opcode >> 8) & 0xF)

    def _get_y(self, opcode):
        return "{0:X}".format((opcode >> 4) & 0xF)

    def _get_byte(self, opcode):
        return "{0:02X}".format(opcode & 0xFF)

    def _get_last_nibble(self, opcode):
        return "{0:X}".format(opcode & 0xF)

    def _00E0(self, opcode):
        return "CLS"

    def _00EE(self, opcode):
        return "RET"

    def _1NNN(self, opcode):
        return "JUMP"

    def _2NNN(self, opcode):
        address = self._get_address(opcode)
        return "CALL {0}".format(address)

    def _3XKK(self, opcode):
        x = self._get_x(opcode)
        byte = self._get_byte(opcode)
        return "SE V{0}, {1}".format(x, byte)

    def _4XKK(self, opcode):
        x = self._get_x(opcode)
        byte = self._get_byte(opcode)
        return "SNE V{0}, {1}".format(x, byte)

    def _5XY0(self, opcode):
        x = self._get_x(opcode)
        y = self._get_y(opcode)
        return "SE V{0}, V{1}".format(x, y)

    def _6XKK(self, opcode):
        x = self._get_x(opcode)
        byte = self._get_byte(opcode)
        return "LD V{0}, {1}".format(x, byte)

    def _7XKK(self, opcode):
        x = self._get_x(opcode)
        byte = self._get_byte(opcode)
        return "ADD V{0}, {1}".format(x, byte)

    def _8XY0(self, opcode):
        x = self._get_x(opcode)
        y = self._get_y(opcode)
        return "LD V{0}, V{1}".format(x, y)

    def _8XY1(self, opcode):
        x = self._get_x(opcode)
        y = self._get_y(opcode)
        return "OR V{0}, V{1}".format(x, y)

    def _8XY2(self, opcode):
        x = self._get_x(opcode)
        y = self._get_y(opcode)
        return "AND V{0}, V{1}".format(x, y)

    def _8XY3(self, opcode):
        x = self._get_x(opcode)
        y = self._get_y(opcode)
        return "XOR V{0}, V{1}".format(x, y)

    def _8XY4(self, opcode):
        x = self._get_x(opcode)
        y = self._get_y(opcode)
        return "ADD V{0}, V{1}".format(x, y)

    def _8XY5(self, opcode):
        x = self._get_x(opcode)
        y = self._get_y(opcode)
        return "SUB V{0}, V{1}".format(x, y)

    def _8XY6(self, opcode):
        x = self._get_x(opcode)
        y = self._get_y(opcode)
        return "SHR V{0}, V{1}".format(x, y)

    def _8XY7(self, opcode):
        x = self._get_x(opcode)
        y = self._get_y(opcode)
        return "SUBN V{0}, V{1}".format(x, y)

    def _8XYE(self, opcode):
        x = self._get_x(opcode)
        y = self._get_y(opcode)
        return "SHL V{0}, V{1}".format(x, y)

    def _9XY0(self, opcode):
        x = self._get_x(opcode)
        y = self._get_y(opcode)
        return "SNE V{0}, V{1}".format(x, y)

    def _ANNN(self, opcode):
        address = self._get_address(opcode)
        return "LD I, {0}".format(address)

    def _BNNN(self, opcode):
        address = self._get_address(opcode)
        return "JP V0, {0}".format(address)

    def _CXKK(self, opcode):
        x = self._get_x(opcode)
        byte = self._get_byte(opcode)
        return "RND V{0}, {1}".format(x, byte)

    def _DXYN(self, opcode):
        x = self._get_x(opcode)
        y = self._get_y(opcode)
        nibble = self._get_last_nibble(opcode)
        return "DRW V{0}, V{1}, {2}".format(x, y, nibble)

    def _EX9E(self, opcode):
        x = self._get_x(opcode)
        return "SKP V{0}".format(x)

    def _EXA1(self, opcode):
        x = self._get_x(opcode)
        return "SKNP V{0}".format(x)

    def _FX07(self, opcode):
        x = self._get_x(opcode)
        return "LD V{0}, DT".format(x)

    def _FX0A(self, opcode):
        x = self._get_x(opcode)
        return "LD V{0}, K".format(x)

    def _FX15(self, opcode):
        x = self._get_x(opcode)
        return "LD DT, V{0}".format(x)

    def _FX18(self, opcode):
        x = self._get_x(opcode)
        return "LD ST, V{0}".format(x)

    def _FX1E(self, opcode):
        x = self._get_x(opcode)
        return "ADD I, V{0}".format(x)

    def _FX29(self, opcode):
        x = self._get_x(opcode)
        return "LD F, V{0}".format(x)

    def _FX33(self, opcode):
        x = self._get_x(opcode)
        return "LD B, V{0}".format(x)

    def _FX55(self, opcode):
        x = self._get_x(opcode)
        return "LD [I], V{0}".format(x)

    def _FX65(self, opcode):
        x = self._get_x(opcode)
        return "LD V{0}, [I]".format(x)


def main():
    if len(sys.argv) != 2:
        print("python {0} program".format(sys.argv[0]))
        return

    program_path = sys.argv[1]
    dis = Disassembler(program_path)
    lines = dis.disassemble()

    print("Address\tOpcode\tInstruction")

    for line in lines:
        address, opcode, mnemonic = line
        print("{0}\t{1}\t{2}".format(address, opcode, mnemonic))


if __name__ == "__main__":
    main()
