#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>

#ifdef _WIN32
#include <windows.h>
#include <psapi.h>
#else
#include <sys/mman.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/prctl.h>
#include <fcntl.h>
#endif


void simple_crypt(uint8_t* data, size_t len, uint8_t key) {
    for (size_t i = 0; i < len; i++) {
        data[i] ^= key ^ (uint8_t)(i & 0xFF);
    }
}


int detect_debugger() {
#ifdef _WIN32
    if (IsDebuggerPresent()) return 1;
    
    BOOL remote_debugger = FALSE;
    CheckRemoteDebuggerPresent(GetCurrentProcess(), &remote_debugger);
    if (remote_debugger) return 1;
    
#else
    // Linux: try to attach to ourselves
    if (ptrace(PTRACE_TRACEME, 0, 1, 0) == -1) {
        return 1; // Already being traced
    }
    
    // Check if we can make ourselves non-dumpable (if prctl is available)
#ifdef PR_SET_DUMPABLE
    if (prctl(PR_SET_DUMPABLE, 0) == -1) {
        // This might fail on some systems, so don't treat as debugger detection
        // return 1;
    }
#endif
#endif
    return 0;
}


uint32_t calculate_checksum(void* start, size_t len) {
    uint32_t checksum = 0;
    uint8_t* bytes = (uint8_t*)start;
    
    for (size_t i = 0; i < len; i++) {
        checksum = (checksum << 1) ^ bytes[i];
    }
    return checksum;
}


uint64_t get_hardware_fingerprint() {
    uint64_t fingerprint = 0;
    
#ifdef _WIN32
    
    DWORD serial = 0;
    GetVolumeInformationA("C:\\", NULL, 0, &serial, NULL, NULL, NULL, 0);
    fingerprint ^= serial;
    
    
    SYSTEM_INFO sysinfo;
    GetSystemInfo(&sysinfo);
    fingerprint ^= sysinfo.dwProcessorType;
    
#else
    
    FILE* f = fopen("/etc/machine-id", "r");
    if (f) {
        char machine_id[64];
        if (fgets(machine_id, sizeof(machine_id), f)) {
            for (int i = 0; i < 8 && machine_id[i]; i++) {
                fingerprint = (fingerprint << 8) ^ machine_id[i];
            }
        }
        fclose(f);
    }
#endif
    
    return fingerprint;
}


typedef struct {
    uint8_t* code;
    size_t ip;
    int32_t stack[256];
    int sp;
    size_t code_len;
} SimpleVM;

typedef enum {
    OP_PUSH = 1,
    OP_POP,
    OP_ADD,
    OP_SUB,
    OP_MUL,
    OP_PRINT,
    OP_RET,
    OP_NOP
} VMOpcode;

void vm_push(SimpleVM* vm, int32_t value) {
    if (vm->sp < 255) {
        vm->stack[++vm->sp] = value;
    }
}

int32_t vm_pop(SimpleVM* vm) {
    if (vm->sp >= 0) {
        return vm->stack[vm->sp--];
    }
    return 0;
}

int32_t vm_run(SimpleVM* vm) {
    while (vm->ip < vm->code_len) {
        uint8_t op = vm->code[vm->ip++];
        
        switch (op) {
            case OP_PUSH: {
                int32_t value = *(int32_t*)(vm->code + vm->ip);
                vm->ip += 4;
                vm_push(vm, value);
                break;
            }
            case OP_POP:
                vm_pop(vm);
                break;
            case OP_ADD: {
                int32_t b = vm_pop(vm);
                int32_t a = vm_pop(vm);
                vm_push(vm, a + b);
                break;
            }
            case OP_SUB: {
                int32_t b = vm_pop(vm);
                int32_t a = vm_pop(vm);
                vm_push(vm, a - b);
                break;
            }
            case OP_MUL: {
                int32_t b = vm_pop(vm);
                int32_t a = vm_pop(vm);
                vm_push(vm, a * b);
                break;
            }
            case OP_PRINT: {
                int32_t value = vm_pop(vm);
                printf("VM Output: %d\n", value);
                break;
            }
            case OP_RET:
                return vm_pop(vm);
            case OP_NOP:
                break;
            default:
                printf("Unknown opcode: %d\n", op);
                return -1;
        }
    }
    return 0;
}

// Protected function (will be encrypted and run in VM)
int protected_calculation(int a, int b) {
    // This would normally be compiled to bytecode
    printf("Performing protected calculation: %d + %d = %d\n", a, b, a + b);
    return a + b;
}

// Runtime loader for encrypted sections
void* load_encrypted_section(uint8_t* encrypted_data, size_t size, uint8_t key) {
#ifdef _WIN32
    void* mem = VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
#else
    void* mem = mmap(NULL, size, PROT_READ | PROT_WRITE | PROT_EXEC, 
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
#endif
    
    if (!mem) {
        printf("Failed to allocate executable memory\n");
        return NULL;
    }
    
    // Decrypt data
    memcpy(mem, encrypted_data, size);
    simple_crypt((uint8_t*)mem, size, key);
    
    return mem;
}

// Main protection system
int main() {
    printf("=== Software Protection Demo ===\n");
    
    // 1. Anti-debugging check
    printf("1. Checking for debuggers...\n");
    if (detect_debugger()) {
        printf("Debugger detected! Exiting.\n");
        return 1;
    }
    printf("   No debugger detected.\n");
    
    // 2. Hardware fingerprinting
    printf("2. Generating hardware fingerprint...\n");
    uint64_t fingerprint = get_hardware_fingerprint();
    printf("   Hardware fingerprint: 0x%llx\n", (unsigned long long)fingerprint);
    
    // 3. Integrity check
    printf("3. Performing integrity check...\n");
    uint32_t checksum = calculate_checksum(main, 1024); // Check first 1KB of main function
    printf("   Code checksum: 0x%x\n", checksum);
    
    // 4. VM execution demo
    printf("4. Running protected code in VM...\n");
    
    // Sample bytecode for: push 10, push 20, add, print, ret
    uint8_t vm_code[] = {
        OP_PUSH, 10, 0, 0, 0,    // push 10
        OP_PUSH, 20, 0, 0, 0,    // push 20
        OP_ADD,                   // add
        OP_PRINT,                 // print result
        OP_RET                    // return
    };
    
    SimpleVM vm = {0};
    vm.code = vm_code;
    vm.code_len = sizeof(vm_code);
    vm.sp = -1;
    
    int result = vm_run(&vm);
    printf("   VM execution result: %d\n", result);
    
    // 5. Encrypted section demo
    printf("5. Loading encrypted section...\n");
    
    // Simulate encrypted function
    uint8_t fake_encrypted[] = {0x48, 0x89, 0xe5, 0xc3}; // Simple x64 function stub
    simple_crypt(fake_encrypted, sizeof(fake_encrypted), 0xAB); // Encrypt it
    
    void* loaded_func = load_encrypted_section(fake_encrypted, sizeof(fake_encrypted), 0xAB);
    if (loaded_func) {
        printf("   Encrypted section loaded at: %p\n", loaded_func);
        
        // In a real implementation, you'd call the decrypted function here
        // ((void(*)())loaded_func)();
        
#ifdef _WIN32
        VirtualFree(loaded_func, 0, MEM_RELEASE);
#else
        munmap(loaded_func, sizeof(fake_encrypted));
#endif
    }
    
    // 6. Regular function call (unprotected)
    printf("6. Calling unprotected function...\n");
    int calc_result = protected_calculation(15, 25);
    printf("   Result: %d\n", calc_result);
    
    printf("\n=== Protection Demo Complete ===\n");
    printf("In a real implementation, the protected_calculation function\n");
    printf("would be encrypted and only run through the VM.\n");
    
    return 0;
}