
#include <windows.h>
#include <stdio.h>

// Simulated API hash table (as used in Maldev Module 55)
const unsigned int g_ApiHashes[] = {
    0x382C0F97, // djb2: VirtualAlloc
    0x16B3FE72, // ROR13: CreateProcessA
    0x3FC1BD8D, // CRC32: LoadLibraryA
    0x20125C5F      // FNV-1a: WSAStartup
};

// Simulated suspicious strings
const char* g_C2_URL = "http://malicious-c2.test/gate.php";
const char* g_RegPath = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run";
const char* g_CmdPayload = "powershell.exe -ExecutionPolicy Bypass -Command Write-Host Triage";

__declspec(dllexport) void TriageTestExport(void) {
    printf("[*] AutoSleuth Triage Sample Export Executed.\n");
}

int main() {
    printf("[*] Benign Triage Verification Sample\n");
    printf("[*] Target C2: %s\n", g_C2_URL);
    printf("[*] Target Registry: %s\n", g_RegPath);
    printf("[*] Hash Count: %zu\n", sizeof(g_ApiHashes)/sizeof(g_ApiHashes[0]));
    return 0;
}
