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
        inline uintptr_t generalIntegrity = 0xCF3082; // main check, runs every ~5 seconds
        inline std::vector<uintptr_t> subIntegrityJNZ = {
            0xCDB2EB, 0xCE4F13, 0xE572F1,
            0xD1552D, 0xD5AAEF, 0xDCD7DD,
            0xDAD7F4, 0xDDC388, 0xCE02CA,
            0xE643D5, 0xE65632, 0xE65F4B,
            0xCF6F28, 0xDAC68E,
        };
        inline std::vector<uintptr_t> staticIntegritycj = { // " why not all? " cuz we are patching function callers away which saves us alot
            0x4E76B4, 0x62702F, 0xE64453,
            0xE0FC27, 0xCD0409, 0xCDA6C7,
            0xCDFC65, 0xD0E5BC, 0xCD100A,
            0xCD1DAD, 0xCD2E43, 0xCD3BB7,
            0xCD55E4, 0xCD65B9, 0xCD6571,
            0xCD4E5F, 0xCD9F66, 0xCDACB6,
            0xCD884B, 0xCD9D63, 0xD25234,
            0xDABFA9, 0xDD289E, 0x5F7C8B,
        };


        inline uintptr_t remapCheck = 0x61192E; // this is necessary so we can even patch.
        inline uintptr_t clientIntegrity = 0xDC9DAB; // patching secondview
        inline uintptr_t processScan = 0xCF70D9;// Cheatengine, x64 Dbg, Scylla...
        inline uintptr_t yaraCaller = 0x5DF3BB; // Ruleset-based detection for Modules
        inline uintptr_t loadLock = 0x8608B8; // Block NtCreateSection for SEC_IMAGE
        inline uintptr_t dllMainInitCallIntercept = 0xB31C40; // Instand detection of loaded module
        inline uintptr_t controlFlowGuard = 0x855FA0; // Windows ControlFlowGuard. (RAX == ReturnAddr)
        inline uintptr_t trampolineIntegrity = 0xE10EE7; // Hyperion's ntdll hook trampoline
        inline uintptr_t consoleCheck = 0x681B1C; // Console Handle check
        inline uintptr_t certificateCheck = 0xE2E879; // 1 == valid, 201 == WindowsDll
        inline uintptr_t devious = 0xDCA45D;    // NEW !!!!!

    }

    inline std::vector<Patch> patches = {

        // INTEGRITY CHECKS 
        {{Update::remapCheck}, {0x38, 0xC0, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90}},   // CMP AL, AL; NOP x8
        {{Update::clientIntegrity}, {0x90, 0x90, 0x90, 0x90, 0x90, 0x90}},                      // NOP x6
        {{Update::trampolineIntegrity}, {0xEB}},                                                // JMP SHORT
        {{Update::devious}, {0x90, 0x90}},                                                      // NOP x2
        {{Update::processScan}, {0x90, 0x90}},                                                  // NOP x2
        {{Update::yaraCaller}, {0x90, 0x90}},                                                   // NOP x2
        {{Update::loadLock}, {0x90, 0xE9}},                                                     // JMP <IMM64>
        {{Update::dllMainInitCallIntercept}, {0xC3}},                                           // RET
        {{Update::controlFlowGuard}, {0xFF, 0xE0, 0xC3, 0x90, 0x90, 0x90, 0x90, 0x90}},         // JMP RAX
        {{Update::consoleCheck}, {0x38, 0xC0, 0x90, 0x90, 0x90}},                               // CMP AL, AL ; NOP x3
        {{Update::certificateCheck}, {0x90, 0xB1, 0x01}},                                       // MOV CL, 1
        
        // PATCH INTEGRITY
        {{Update::generalIntegrity}, {0x90, 0x90, 0x90, 0x90, 0x90, 0x90}},                     // NOP x6
        {Update::subIntegrityJNZ, {0x90, 0x90, 0x90, 0x90, 0x90, 0x90}},                        // NOP x6
        {Update::staticIntegritycj, {0xEB}},                                                    // JMP SHORT
    };
}

// m a d e  b y  v o l x <3