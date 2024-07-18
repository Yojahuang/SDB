#include <iostream>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <capstone/capstone.h>
#include <elf.h>
#include <vector>
#include <map>
#include <fstream>
#include <sstream>

void errquit(const char *s)
{
    perror(s);
    exit(-1);
}

struct store_instruction
{
    char *mnemonic;
    char *op_str;
    char *instruction_str;
    uint16_t size;
};

struct store_breakpoint
{
    unsigned long content;
    unsigned long address;
};

struct memory_fragment
{
    unsigned long start, end;
    std::vector<unsigned long> content;
};

struct anchor_snapshot
{
    struct user_regs_struct regs;
    std::vector<memory_fragment> fragments;
};

size_t getTextSectionSize(const char *filePath)
{
    FILE *file = fopen(filePath, "rb");
    if (file == NULL)
    {
        perror("Failed to open binary file");
        return 0;
    }

    // Read ELF header
    Elf64_Ehdr elfHeader;
    fread(&elfHeader, sizeof(Elf64_Ehdr), 1, file);

    // Find section header table offset
    fseek(file, elfHeader.e_shoff, SEEK_SET);

    // Read section header entry for the text section
    Elf64_Shdr sectionHeader;
    size_t textSectionSize = 0;
    for (int i = 0; i < elfHeader.e_shnum; i++)
    {
        fread(&sectionHeader, sizeof(Elf64_Shdr), 1, file);
        if (sectionHeader.sh_type == SHT_PROGBITS && (sectionHeader.sh_flags & SHF_EXECINSTR))
        {
            textSectionSize = sectionHeader.sh_size;
            break;
        }
    }

    fclose(file);

    return textSectionSize;
}

void read_proc_maps(pid_t pid, std::vector<memory_fragment> &fragments)
{
    char filename[20];
    snprintf(filename, sizeof(filename), "/proc/%d/maps", pid);

    FILE *file = fopen(filename, "r");
    if (file == NULL)
    {
        perror("Error opening /proc/<pid>/maps");
        return;
    }

    char line[256];
    char range[256];
    char permission[256];
    while (fgets(line, sizeof(line), file))
    {
        // Check if the line contains "w" permission
        sscanf(line, "%s%s", range, permission);
        if (strstr(permission, "w") != NULL)
        {
            unsigned long start, end;
            sscanf(range, "%lx-%lx", &start, &end);
            memory_fragment item;
            item.start = start;
            item.end = end;
            item.content.clear();

            for (unsigned long i = start; i <= end; ++i)
            {
                unsigned long tmp = ptrace(PTRACE_PEEKTEXT, pid, i, 0);
                item.content.push_back(tmp);
            }
            fragments.push_back(item);
        }
    }

    fclose(file);
}

size_t address_is_in_text_section(unsigned long address, std::pair<unsigned long, unsigned long> &text_range)
{
    unsigned long start, end;
    start = text_range.first;
    end = text_range.second;
    return start <= address && address < end;
}

void store_all_instruction(const char *filePath, unsigned long entry_point_addr, pid_t child, std::pair<unsigned long, unsigned long> text_range,
                           std::map<unsigned long, store_instruction> &store_instructions)
{
    csh handle;

    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK)
    {
        printf("Failed to initialize Capstone\n");
        return;
    }

    unsigned long addr = entry_point_addr;

    while (1)
    {
        if (address_is_in_text_section(addr, text_range) == 0 || store_instructions.find(addr) != store_instructions.end())
        {
            break;
        }

        unsigned long instruction_data = ptrace(PTRACE_PEEKTEXT, child, addr, 0);

        cs_insn *insn;
        size_t count = cs_disasm(handle, (uint8_t *)&instruction_data, sizeof(instruction_data), addr, 1, &insn);

        if (count > 0)
        {
            char instruction_str[100];
            memset(instruction_str, 0, sizeof(instruction_str));

            for (size_t j = 0; j < insn[0].size; ++j)
            {
                int offset = 8 * j;
                int str_offset = 3 * j;
                sprintf(instruction_str + str_offset, "%2.2lx ", (instruction_data >> offset) & 0xff);
            }

            for (size_t j = insn[0].size; j < 10; ++j)
            {
                int str_offset = 3 * j;
                sprintf(instruction_str + str_offset, "   ");
            }

            struct store_instruction ins;
            ins.size = insn[0].size;

            ins.instruction_str = (char *)malloc(sizeof(char) * (strlen(instruction_str) + 5));
            memset(ins.instruction_str, 0, sizeof(char) * strlen(instruction_str) + 5);
            strcpy(ins.instruction_str, instruction_str);

            ins.mnemonic = (char *)malloc(sizeof(char) * 20);
            memset(ins.mnemonic, 0, sizeof(char) * 20);
            strcpy(ins.mnemonic, insn[0].mnemonic);
            for (int i = strlen(insn[0].mnemonic); i < 15; ++i)
            {
                ins.mnemonic[i] = ' ';
            }

            ins.op_str = (char *)malloc(sizeof(char) * (strlen(insn[0].op_str) + 5));
            memset(ins.op_str, 0, sizeof(char) * strlen(insn[0].op_str) + 5);
            strcpy(ins.op_str, insn[0].op_str);

            store_instructions[addr] = ins;

            cs_free(insn, count);

            addr += ins.size;
        }
    }

    cs_close(&handle);
}

// show next five instruction start from addr
void show_next_five_instruction(pid_t child, const char *filePath, unsigned long addr, unsigned long entry_point_addr,
                                std::pair<unsigned long, unsigned long> text_range, std::map<unsigned long, store_instruction> &store_instructions)
{
    bool find = false;
    if (store_instructions.find(addr) != store_instructions.end())
        find = true;

    if (!find)
    {
        store_all_instruction(filePath, addr, child, text_range, store_instructions);
    }

    for (int i = 0; i < 5; ++i)
    {
        if (address_is_in_text_section(addr, text_range) == 0)
        {
            printf("** the address is out of the range of the text section.\n");
            break;
        }

        printf("      %lx: ", addr);
        printf("%s", store_instructions[addr].instruction_str);
        printf("%s%s\n", store_instructions[addr].mnemonic, store_instructions[addr].op_str);

        addr += store_instructions[addr].size;
    }
}

unsigned long get_rip(pid_t child)
{
    struct user_regs_struct regs;
    if (ptrace(PTRACE_GETREGS, child, NULL, &regs) == 0)
    {
        return regs.rip;
    }
    return 0;
}

void my_wait(pid_t child, int *wait_status)
{
    if (waitpid(child, wait_status, 0) < 0)
        errquit("waitpid");
}

bool is_breakpoint(pid_t child, unsigned long address)
{
    long data = ptrace(PTRACE_PEEKTEXT, child, address, NULL);
    if ((data & 0xFF) == 0xCC)
    {
        return true;
    }
    return false;
}

void add_breakpoint(pid_t child, unsigned long address, std::vector<store_breakpoint> &breakpoints)
{
    unsigned long code = ptrace(PTRACE_PEEKTEXT, child, address, 0);

    store_breakpoint item;
    item.address = address;
    item.content = code;

    breakpoints.push_back(item);

    code = (code & (0xffffffffffffff00)) | 0xCC;
    ptrace(PTRACE_POKETEXT, child, address, code);
}

void remove_breakpoint(pid_t child, unsigned long address, std::vector<store_breakpoint> &breakpoints)
{
    for (store_breakpoint &breakpoint : breakpoints)
    {
        if (breakpoint.address == address)
        {
            unsigned long content = breakpoint.content & 0xFF;
            unsigned long current_content = ptrace(PTRACE_PEEKTEXT, child, address, 0);
            current_content = (current_content & (~0xFF)) | content;
            ptrace(PTRACE_POKETEXT, child, address, current_content);
        }
    }
}

void drop_anchor(pid_t child, anchor_snapshot &snapshot)
{
    snapshot.fragments.clear();

    struct user_regs_struct regs;
    if (ptrace(PTRACE_GETREGS, child, NULL, &regs) != 0)
        errquit("ptrace(GETREGS)");

    snapshot.regs = regs;

    read_proc_maps(child, snapshot.fragments);
}

void timetravel(pid_t child, anchor_snapshot &snapshot)
{
    if (ptrace(PTRACE_SETREGS, child, 0, &snapshot.regs) != 0)
        errquit("ptrace(GETREGS)");

    for (memory_fragment &fragment : snapshot.fragments)
    {
        for (unsigned long address = fragment.start; address <= fragment.end; address++)
        {
            ptrace(PTRACE_POKETEXT, child, address, fragment.content[address - fragment.start]);
        }
    }
}

std::pair<unsigned long, unsigned long> calculate_text_section_range(const char* filePath) {
    char readelfCmd[256];
    sprintf(readelfCmd, "readelf -S %s", filePath);
    char result[4096] = {0};

    // Execute readelf command and capture the output
    FILE* pipe = popen(readelfCmd, "r");
    if (!pipe) {
        fprintf(stderr, "Error executing readelf command.\n");
        exit(1);
    }

    char buffer[128];
    while (fgets(buffer, sizeof(buffer), pipe) != NULL) {
        strncat(result, buffer, sizeof(result) - strlen(result) - 1);
    }

    pclose(pipe);

    std::stringstream ss(result);
    std::string s;

    unsigned long startAddr = 0, endAddr = 0;

    while (ss >> s) {
        if (s == ".text") {
            std::string type;
            unsigned long address, offset, size;
            ss >> type;
            ss >> std::hex >> address;
            ss >> std::hex >> offset;
            ss >> std::hex >> size;
            startAddr = address;
            endAddr = startAddr + size;
        }
    }

    return std::make_pair(startAddr, endAddr);
}

int main(int argc, char **argv)
{
    std::map<unsigned long, store_instruction> store_instructions;
    std::vector<store_breakpoint> breakpoints;
    anchor_snapshot snapshot;
    pid_t child;

    if ((child = fork()) < 0)
        errquit("fork");
    if (child == 0)
    {
        if (ptrace(PTRACE_TRACEME, 0, 0, 0) < 0)
            errquit("ptrace@child");
        execvp(argv[1], argv + 1);
        errquit("execvp");
    }
    else
    {
        int wait_status = 0;
        int need_entry_point = 1;
        unsigned long entry_point_addr = 0;

        if (waitpid(child, &wait_status, 0) < 0)
            errquit("wait");
        ptrace(PTRACE_SETOPTIONS, child, 0, PTRACE_O_EXITKILL);

        std::pair<unsigned long, unsigned long> text_start_and_end = calculate_text_section_range(argv[1]);

        if (WIFSTOPPED(wait_status))
        {
            unsigned long rip = get_rip(child);

            if (need_entry_point)
            {
                entry_point_addr = rip;
                printf("** program '%s' loaded. entry point 0x%lx\n", argv[1], rip);
                store_all_instruction(argv[1], entry_point_addr, child, text_start_and_end, store_instructions);
                show_next_five_instruction(child, argv[1], rip, entry_point_addr, text_start_and_end, store_instructions);
                need_entry_point = 0;
            }

            while (1)
            {
                char cmd[100];
                memset(cmd, 0, sizeof(cmd));

                printf("(sdb) ");
                scanf("%s", cmd);

                if (strncmp("si", cmd, 2) == 0 && strlen(cmd) == 2)
                {
                    rip = get_rip(child);

                    bool has_breakpoint = is_breakpoint(child, rip);
                    if (has_breakpoint)
                    {
                        remove_breakpoint(child, rip, breakpoints);
                    }

                    if (ptrace(PTRACE_SINGLESTEP, child, 0, 0) != 0)
                        errquit("ptrace(SINGLESTEP)");

                    my_wait(child, &wait_status);

                    if (has_breakpoint)
                    {
                        add_breakpoint(child, rip, breakpoints);
                    }

                    rip = get_rip(child);
                    if (rip == 0)
                        break;
                    if (is_breakpoint(child, rip))
                    {
                        printf("** hit a breakpoint at 0x%lx.\n", rip);
                    }
                    show_next_five_instruction(child, argv[1], rip, entry_point_addr, text_start_and_end, store_instructions);
                }
                else if (strncmp("cont", cmd, 4) == 0 && strlen(cmd) == 4)
                {
                    rip = get_rip(child);
                    bool has_breakpoint = is_breakpoint(child, rip);
                    if (is_breakpoint(child, rip))
                    {
                        remove_breakpoint(child, rip, breakpoints);
                    }

                    if (ptrace(PTRACE_SINGLESTEP, child, 0, 0) != 0)
                        errquit("ptrace(SINGLESTEP)");
                    my_wait(child, &wait_status);

                    if (has_breakpoint)
                    {
                        add_breakpoint(child, rip, breakpoints);
                    }

                    rip = get_rip(child);
                    if (is_breakpoint(child, rip))
                    {
                        printf("** hit a breakpoint at 0x%lx.\n", rip);
                        show_next_five_instruction(child, argv[1], rip, entry_point_addr, text_start_and_end, store_instructions);
                        continue;
                    }

                    if (ptrace(PTRACE_CONT, child, 0, 0) != 0)
                        errquit("ptrace(CONT)");

                    my_wait(child, &wait_status);

                    rip = get_rip(child);
                    if (rip == 0)
                        break;
                    if (is_breakpoint(child, rip - 1))
                    {
                        printf("** hit a breakpoint at 0x%lx.\n", rip - 1);

                        struct user_regs_struct regs;
                        if (ptrace(PTRACE_GETREGS, child, 0, &regs) != 0)
                            errquit("ptrace(GETREGS)");
                        regs.rip--;
                        if (ptrace(PTRACE_SETREGS, child, 0, &regs) != 0)
                            errquit("ptrace(SETREGS)");

                        rip = get_rip(child);
                    }
                    show_next_five_instruction(child, argv[1], rip, entry_point_addr, text_start_and_end, store_instructions);
                }
                else if (strncmp("break", cmd, 5) == 0 && strlen(cmd) == 5)
                {
                    char addr_str[100];
                    unsigned long addr;
                    scanf("%s", addr_str);
                    sscanf(addr_str, "0x%lx", &addr);
                    printf("** set a breakpoint at 0x%lx.\n", addr);

                    if (store_instructions.find(addr) == store_instructions.end())
                    {
                        store_all_instruction(argv[1], addr, child, text_start_and_end, store_instructions);
                    }

                    add_breakpoint(child, addr, breakpoints);
                }
                else if (strncmp("anchor", cmd, 6) == 0 && strlen(cmd) == 6)
                {
                    printf("** dropped an anchor\n");
                    drop_anchor(child, snapshot);
                }
                else if (strncmp("timetravel", cmd, 10) == 0 && strlen(cmd) == 10)
                {
                    printf("** go back to the anchor point\n");
                    timetravel(child, snapshot);
                    rip = get_rip(child);
                    show_next_five_instruction(child, argv[1], rip, entry_point_addr, text_start_and_end, store_instructions);
                }
            }
        }
    }
    printf("** the target program terminated.\n");
    return 0;
}