use byte_core::{bus::Bus, cpu};

const PROGRAM: &[u8; 1 << 16] = include_bytes!("../../.build/plasma.bin");

const W: usize = 64;
const H: usize = 64;
const INSTRUCTIONS_PER_FRAME: usize = 6_400_000 / 60;
const VID: u16 = 0xfd;
const RNG: u16 = 0xfe;

const PALETTE: [[u8; 3]; 16] = [
    [0x00, 0x00, 0x00], [0xFF, 0xFF, 0xFF], [0x88, 0x00, 0x00], [0xAA, 0xFF, 0xEE],
    [0xCC, 0x44, 0xCC], [0x00, 0xCC, 0x55], [0x00, 0x00, 0xAA], [0xEE, 0xEE, 0x77],
    [0x66, 0x44, 0x00], [0xFF, 0x77, 0x77], [0x33, 0x33, 0x33], [0x77, 0x77, 0x77],
    [0xAA, 0xFF, 0x66], [0x00, 0x88, 0xFF], [0x00, 0x88, 0xFF], [0xBB, 0xBB, 0xBB],
];

struct ByteBus {
    data: [u8; 0x10000],
}

impl Bus for ByteBus {
    fn read(&self, addr: u16) -> u8 {
        self.data[addr as usize]
    }

    fn write(&mut self, addr: u16, byte: u8) {
        self.data[addr as usize] = byte;
    }
}

struct Machine {
    cpu: cpu::CPU<ByteBus>,
    random: u32,
    frames: u32,
    until_vblank: usize,
    pixels: [u8; W * H * 4],
}

static mut MACHINE: Option<Machine> = None;

#[allow(static_mut_refs)]
fn machine() -> &'static mut Machine {
    unsafe { MACHINE.as_mut().expect("reset() comes first") }
}

#[unsafe(no_mangle)]
pub extern "C" fn reset(seed: u32) {
    let mut cpu = cpu::CPU {
        bus: ByteBus { data: [0; 0x10000] },
        cycle: 0,
        reg: cpu::Registers::default(),
    };
    cpu.load(PROGRAM, 0x0000);
    cpu.interrupt(cpu::Interrupt::RST);

    unsafe {
        MACHINE = Some(Machine { cpu, random: seed | 1, frames: 0, until_vblank: INSTRUCTIONS_PER_FRAME, pixels: [0; W * H * 4] });
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn run(count: u32) {
    let machine = machine();

    for _ in 0..count {
        machine.random ^= machine.random << 13;
        machine.random ^= machine.random >> 17;
        machine.random ^= machine.random << 5;
        machine.cpu.bus.write(RNG, machine.random as u8);
        let _ = machine.cpu.step();

        machine.until_vblank -= 1;
        if machine.until_vblank == 0 {
            machine.until_vblank = INSTRUCTIONS_PER_FRAME;
            machine.cpu.interrupt(cpu::Interrupt::IRQ);
            machine.frames += 1;
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn pixels() -> *const u8 {
    let machine = machine();
    let vram = ((machine.cpu.bus.read(VID) as usize) & 0xf) << 0xc;

    for index in 0..W * H {
        let [r, g, b] = PALETTE[(machine.cpu.bus.data[(vram + index) & 0xffff] & 0xf) as usize];
        machine.pixels[index * 4..index * 4 + 4].copy_from_slice(&[r, g, b, 0xff]);
    }

    machine.pixels.as_ptr()
}

#[unsafe(no_mangle)]
pub extern "C" fn register(which: u32) -> u32 {
    let machine = machine();
    let reg = &machine.cpu.reg;

    match which {
        0 => reg.pc as u32,
        1 => reg.a as u32,
        2 => reg.x as u32,
        3 => reg.y as u32,
        4 => reg.sp as u32,
        5 => reg.p.bits() as u32,
        6 => machine.frames,
        _ => machine.cpu.cycle as u32,
    }
}
