#pragma once
#include <iostream>
#include <Windows.h>
#include <vector>

struct Patch {
    std::vector<uintptr_t> rvas;
    std::vector<uint8_t> patch;
};

// have fun skidding, bytecode and bstaipan

namespace Patches {
    namespace Update {
        inline uintptr_t generalIntegrity = 0x2AD5E9; // main check, runs every ~5 seconds
        inline std::vector<uintptr_t> subIntegrityJNZ = {
            0x1A9712, 0x1DCB8C, 0x1E05C7,
            0x24C7BA, 0x1E7617, 0x2D9659,
            0x370AA3, 0x1BEB1F, 0x1D8897,
            0x1ECDF9, 0x21C0B2, 0x1E9001,
            0x24D0D9, 0x24E423, 0x24D834,
            0x3A4AD4

        };
        inline std::vector<uintptr_t> staticIntegritycj = { // " why not all? " cuz we are patching function callers away which saves us alot
            0x19E54C, 0x19F45E, 0x1A1DD0, 0x1A2B5B,
            0x1A3B15, 0x1A4986, 0x1A5EAC, 0x1A6513,
            0x1A7AB1, 0x1C0552, 0x1DAAB5, 0x2223B6,
            0x1A030A, 0x1A5827, 0x1A6ECC, 0x1BFE77,
            0xE95875, 0xDC084D, 0xDCC9FE, 0xE593DF,
            0x1BCE01, 0x1BDF14, 0x26F29B, 0x1A494D,
            0x2E9A1D, 0x2F4904,
        };


        inline uintptr_t remapCheck = 0xE4719F; // this is necessary so we can even patch.
        inline uintptr_t clientIntegrity = 0x2AE365; // patching secondview
        inline uintptr_t trampolineIntegrity = 0x35B19F; // Hyperion's ntdll hook trampoline
        inline uintptr_t processScan = 0x1DCE02;// Cheatengine, x64 Dbg, Scylla...
        inline uintptr_t yaraCaller = 0x16CBC1; // Ruleset-based detection for Modules
        inline uintptr_t consoleCheck = 0xE03544; // Console Handle check
        inline uintptr_t whitelist = 0x2EA7E6;  // executable to not executable
        inline uintptr_t loadLock = 0xD4D1B4; // Block NtCreateSection for SEC_IMAGE
        inline uintptr_t dllMainInitCallIntercept = 0x8484F0; // Instand detection of loaded module
        inline uintptr_t controlFlowGuard = 0x56DFD0; // Windows ControlFlowGuard. (RAX == ReturnAddr)
        inline uintptr_t certificateCheck = 0x3571BD; // 1 == valid, 201 == WindowsDll
        inline uintptr_t blockPageEncryption = 0xDAD74A;    // for second view hooking
    }

    inline std::vector<Patch> patches = {

        // INTEGRITY CHECKS 
        {{Update::remapCheck}, {0x90, 0xE9}},                                                   // JMP <IMM64>
        {{Update::clientIntegrity}, {0x90, 0x90, 0x90, 0x90, 0x90, 0x90}},                      // NOP x6
        {{Update::trampolineIntegrity}, {0xEB}},                                                // JMP SHORT
        {{Update::processScan}, {0x90, 0x90, 0x90}},                                            // NOP x3
        {{Update::yaraCaller}, {0x90, 0x90}},                                                   // NOP x2
        {{Update::consoleCheck}, {0x38, 0xC0, 0x90, 0x90, 0x90}},                               // CMP AL, AL ; NOP x3
        {{Update::whitelist}, {0x48, 0x31, 0xC9, 0x90, 0x90, 0x90, 0x90 } },                    // XOR RCX, RCX ; NOP x4
        {{Update::loadLock}, {0x90, 0xE9}},                                                     // JMP <IMM64>
        {{Update::dllMainInitCallIntercept}, {0xC3}},                                           // RET
        {{Update::controlFlowGuard}, {0xFF, 0xE0, 0xC3, 0x90, 0x90, 0x90, 0x90, 0x90}},         // JMP RAX
        {{Update::certificateCheck}, {0x41, 0xB1, 0x01}},                                       // MOV R9B, 1
        //{{Update::blockPageEncryption}, {0x90, 0xE9}},                                          // JMP <IMM64>

        //// PATCH INTEGRITY
        {{Update::generalIntegrity}, {0x90, 0x90, 0x90, 0x90, 0x90, 0x90}},                     // NOP x6
        {Update::subIntegrityJNZ, {0x90, 0x90, 0x90, 0x90, 0x90, 0x90}},                        // NOP x6
        {Update::staticIntegritycj, {0xEB}},                                                    // JMP SHORT
    };
}

// m a d e  b y  v o l x <3
