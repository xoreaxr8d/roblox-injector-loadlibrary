#pragma once
#include <iostream>
#include <Windows.h>
#include <vector>

struct Patch {
	std::vector<uintptr_t> rvas;
	std::vector<uint8_t> patch;
};

namespace Patches {
    namespace Update {
        inline uintptr_t generalIntegrity = 0x5B98E6; // main check, runs every ~5 seconds
        inline std::vector<uintptr_t> subIntegrityJNZ = {
            0x592CC0, 0x599C84, 0x59E40F,
            0x5BD889, 0x610B25, 0x681392,
            0x7203C9, 0x5BAF40, 0x5AA53B,
            0x64BF11, 0x5B9F3D, 0x5B9FF5,
            0x5903FA, 0x5BA3EB,

            0x728667, 0x729984, // These usually dont run... ( rtlfailfast crash )

            0x5BA615 // Client Integrity (secondview)
        };

        inline std::vector<uintptr_t> staticIntegritycj = {
            0x56DAAE, 0x58C259, 0x591EE9, 0xFAA454,
            0x592036, 0x58866D, 0x58FF85, 0x589E77,
            0x587A4E, 0x58B3AE, 0x5878A0, 0x58608F,
            0xF8EE47, 0xFA421D, 0xFAA454, 0xFE72C0,
            0xF9EC28, 0x58FF3E, 0xFFCFAB, 0xFE871D,
            0x6D7CE4, 0x5A9B9D, 0x6176F5, 0x589D7B,
            0x59275D, 0x594611, 0x60EFF4, 

        };


        inline uintptr_t remapCheck = 0xFEC163; // this is necessary so we can even patch.
        inline uintptr_t processScan = 0x592DE8;// Cheatengine, x64 Dbg, Scylla...
        inline uintptr_t dllMainInitCallIntercept = 0x9D950; // Instand detection of loaded module
        inline uintptr_t loadLock = 0x8AC2DF; // Block NtCreateSection for SEC_IMAGE
        inline uintptr_t consoleCheck = 0x1001894; // Console Handle check
        inline uintptr_t certificateCheck = 0x708331; // 1 == valid, 201 == WindowsDll
        inline uintptr_t yaraCaller = 0x11AFD6; // Ruleset-based detection for Modules
        inline uintptr_t whitelist = 0x6CF2B5; // RWX gets set to RW
        inline uintptr_t controlFlowGuard = 0xADD50; // Windows ControlFlowGuard. (RAX == ReturnAddr)
        inline uintptr_t blockPageEncryption = 0x5BEF4B; // for secondview hooking
        inline uintptr_t trampolineIntegrity = 0x70BFE4; // Hyperion's ntdll hook trampoline

    }

    inline std::vector<Patch> patches = {

        // INTEGRITY CHECKS
        {{Update::remapCheck}, {0x90, 0x90}},    // NOP x2  ( disgusting patch this update but thats not my fault )
        {{Update::processScan}, {0x90, 0x90}},    // NOP x2
        {{Update::dllMainInitCallIntercept}, {0xC3}}, // RET
        {{Update::loadLock}, {0x90, 0xE9}}, // JMP <IMM64>
        {{Update::consoleCheck}, {0x38, 0xC0, 0x90, 0x90, 0x90}}, // CMP AL, AL ; NOP x3
        {{Update::certificateCheck}, { 0x41, 0xB3, 0x01  }}, // MOV R11B, 1
        {{Update::yaraCaller}, {0x90, 0x90}}, // NOP x2
        {{Update::whitelist}, {0x90, 0xE9}}, // JMP <IMM64>
        {{Update::controlFlowGuard}, {0xFF, 0xE0, 0xC3, 0x90, 0x90, 0x90, 0x90, 0x90}}, // JMP RAX
        {{Update::blockPageEncryption}, {0x90, 0xE9}}, // JMP <IMM64>
        {{Update::trampolineIntegrity}, {0xEB}}, // JMP SHORT

        // PATCH INTEGRITY
        {{Update::generalIntegrity}, {0x90, 0x90, 0x90, 0x90, 0x90, 0x90}}, // NOP x6
        {Update::subIntegrityJNZ, {0x90, 0x90, 0x90, 0x90, 0x90, 0x90}}, // NOP x6
        {Update::staticIntegritycj, {0xEB}}, // JMP SHORT
    };
}
	
// m a d e  b y  v o l x <3
