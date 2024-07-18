# Basic GNU Debugger

This project, **Basic GNU Debugger**, was developed as part of the [Advanced Programming in the UNIX Environment](https://timetable.nycu.edu.tw/?r=main/crsoutline&Acy=111&Sem=2&CrsNo=535512&lang=en-us) course. It provides a simplified debugging tool similar to GDB, offering basic functionalities to assist in program debugging.


## Cloning and Compiling the Source Code

### Clone the Repository

To clone the repository, use the following command:

```sh
git clone https://github.com/yojahuang/SDB.git
cd SDB
```

### Compile the Source Code

To compile the source code, run the following command:

```sh
make
```

This will generate the `sdb` executable.

## How to Execute

To use the debugger, simply type the following command in your terminal:

```sh
./sdb <path_to_your_binary_program>
```

## Supported Instructions

The Basic GNU Debugger supports the following instructions:

- `si`: Simple Step (same as the step instruction in GDB)
- `cont`: Continue execution of the program until a breakpoint set by the user is encountered
- `break`: Set a breakpoint at the current address
- `anchor`: Set an anchor point at the current address and snapshot the program's memory space
- `timetravel`: Travel back to the anchor point and recover the memory space as it was at the anchor point

## Usage

1. **Simple Step (`si`)**:
   - Steps through the program one instruction at a time.

2. **Continue (`cont`)**:
   - Continues execution until a breakpoint is encountered.

3. **Set Breakpoint (`break <address>`)**:
   - Sets a breakpoint at the specified instruction address.

4. **Set Anchor Point (`anchor`)**:
   - Sets an anchor point at the current instruction address and takes a snapshot of the program’s memory space.

5. **Time Travel (`timetravel`)**:
   - Returns to the anchor point and restores the program’s memory space to its state at the time the anchor point was set.

## Example

Here is a basic example of how you might use the debugger:

```sh
$ ./sdb ./hello
** program './hello' loaded. entry point 0x401000
      401000: f3 0f 1e fa                   endbr64        
      401004: 55                            push           rbp
      401005: 48 89 e5                      mov            rbp, rsp
      401008: ba 0e 00 00 00                mov            edx, 0xe
      40100d: 48 8d 05 ec 0f 00 00          lea            rax, [rip + 0xfec]
(sdb) break 0x401030
** set a breakpoint at 0x401030.
(sdb) cont
** hit a breakpoint at 0x401030.
      401030: 0f 05                         syscall        
      401032: c3                            ret            
      401033: b8 00 00 00 00                mov            eax, 0
      401038: 0f 05                         syscall        
      40103a: c3                            ret            
(sdb) anchor 
** dropped an anchor
(sdb) si 
hello world!
      401032: c3                            ret            
      401033: b8 00 00 00 00                mov            eax, 0
      401038: 0f 05                         syscall        
      40103a: c3                            ret            
      40103b: b8 3c 00 00 00                mov            eax, 0x3c
(sdb) timetravel
** go back to the anchor point
      401030: 0f 05                         syscall        
      401032: c3                            ret            
      401033: b8 00 00 00 00                mov            eax, 0
      401038: 0f 05                         syscall        
      40103a: c3                            ret            
(sdb) si
hello world!
      401032: c3                            ret            
      401033: b8 00 00 00 00                mov            eax, 0
      401038: 0f 05                         syscall        
      40103a: c3                            ret            
      40103b: b8 3c 00 00 00                mov            eax, 0x3c
(sdb) cont
** the target program terminated.
```

## Acknowledgments

This project was developed as part of the "Advanced Programming in the UNIX Environment" course given by Prof [Chun-Ying Huang](https://www.cs.nycu.edu.tw/members/detail/chuang).
