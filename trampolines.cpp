/*
Trampolines.cpp : 
-----------------
- Defines the hook functions. 
- Hook functions process received parameters from the original function calls and print them. 
- Each API function has its own hook function. 
- For example: OpenProcess --> OldProcess (original OpenProcess withoout hook), NewOpenProcess (execution is redirected to this function after hook patch is written to the 
first 6 bytes of original function in memory. NewOpenProcess is called first and then calls OldOpenProcess to resume execution to original function in memory.
*/

#include "stdafx.h"
#include <iostream>
#include <string>
#include <ctype.h>
#include <windows.h>
#include <Shlwapi.h>
#include <stdio.h>
#include <tlhelp32.h>
#include <winnt.h>
#include <psapi.h>
#include <tchar.h>
#include "hooker.h"
#include <intrin.h>
using namespace std;


TdefOldOpenProcess OldOpenProcess;
TdefOldOpenProcessA OldOpenProcessA;
TdefOldOpenProcessW OldOpenProcessW;
TdefOldVirtualProtect OldVirtualProtect;
TdefOldVirtualAlloc OldVirtualAlloc;
TdefOldVirtualAllocEx OldVirtualAllocEx;
TdefOldVirtualAllocExA OldVirtualAllocExA;
TdefOldVirtualAllocExW OldVirtualAllocExW;
TdefOldWriteProcessMemory OldWriteProcessMemory;
TdefOldResumeThread OldResumeThread;
TdefOldNtResumeThread OldNtResumeThread;
TdefOldSetThreadContext OldSetThreadContext;
TdefOldGetThreadContext OldGetThreadContext;
TdefOldCreateRemoteThread OldCreateRemoteThread;
TdefOldLoadLibraryA OldLoadLibraryA;
TdefOldLoadLibraryW OldLoadLibraryW;
TdefOldRtlDecompressBuffer OldRtlDecompressBuffer;
TdefOldCryptEncrypt OldCryptEncrypt;
TdefOldCryptDecrypt OldCryptDecrypt;
TdefOldCryptGenRandom OldCryptGenRandom;
TdefOldCryptCreateHash OldCryptCreateHash;
TdefOldCryptAcquireContext OldCryptAcquireContext;
TdefOldCryptAcquireCertificatePrivateKey OldCryptAcquireCertificatePrivateKey;
TdefOldCreateProcessA OldCreateProcessA;
TdefOldCreateProcessW OldCreateProcessW;
TdefOldCreateProcessInternalW OldCreateProcessInternalW;
//TdefOldNtCreateUserProcess OldNtCreateUserProcess;
TdefOldGetProcAddress OldGetProcAddress;
TdefOldGetModuleHandleA OldGetModuleHandleA;
//TdefOldFindResource OldFindResource;
TdefOldLoadResource OldLoadResource;
TdefOldFindResourceA OldFindResourceA;
TdefOldCreateThread OldCreateThread;
TdefOldExitProcess OldExitProcess;
TdefOldTerminateProcess OldTerminateProcess;
//TdefOldWriteFile OldWriteFile;
//TdefOldWriteFileW OldWriteFileA;
//TdefOldWriteFileW OldWriteFileW;


HANDLE WINAPI NewOpenProcess(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId) {

	std::cout << "Process ID " << dwProcessId << "was opened with disired access: " << dwDesiredAccess << endl;
	return OldOpenProcess((DWORD)dwDesiredAccess, bInheritHandle, dwProcessId);
}

HANDLE WINAPI NewOpenProcessA(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId) {

	std::cout << "Process ID " << dwProcessId << "was opened with disired access: " << dwDesiredAccess << endl;
	return OldOpenProcess((DWORD)dwDesiredAccess, bInheritHandle, dwProcessId);
}

HANDLE WINAPI NewOpenProcessW(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId) {

	std::cout << "Process ID " << dwProcessId << "was opened with disired access: " << dwDesiredAccess << endl;
	return OldOpenProcess((DWORD)dwDesiredAccess, bInheritHandle, dwProcessId);
}

int WINAPI NewVirtualProtect(LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect) {

	if (flNewProtect != PAGE_EXECUTE_READWRITE || flNewProtect != PAGE_EXECUTE || flNewProtect != PAGE_EXECUTE_READ || flNewProtect != PAGE_EXECUTE_WRITECOPY) {

		return OldVirtualProtect((LPVOID)lpAddress, dwSize, flNewProtect, lpflOldProtect);
	}
	else {

		std::cout << "Memory permissions changed to " << flNewProtect << " on address " << lpAddress << ". The size of the region is " << dwSize << ".\n" << endl;
		return OldVirtualProtect((LPVOID)lpAddress, dwSize, flNewProtect, lpflOldProtect);
	}
}

LPVOID WINAPI NewVirtualAlloc(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect) {

	if (flProtect != PAGE_EXECUTE_READWRITE && flProtect != PAGE_EXECUTE && flProtect != PAGE_EXECUTE_READ && flProtect != PAGE_EXECUTE_WRITECOPY) {

		return OldVirtualAlloc(lpAddress, dwSize, flAllocationType, flProtect);
	} 
	else {
		
		std::cout << "Memory region was allocated at " << lpAddress << "with permissions " << flProtect << ". The size of the region is " << dwSize << ".\n" << endl;
		return OldVirtualAlloc(lpAddress, dwSize, flAllocationType, flProtect);
	}
}

LPVOID WINAPI NewVirtualAllocEx(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect) {

	if (flProtect != PAGE_EXECUTE_READWRITE && flProtect != PAGE_EXECUTE && flProtect != PAGE_EXECUTE_READ && flProtect != PAGE_EXECUTE_WRITECOPY) {

		return OldVirtualAllocEx(hProcess, lpAddress, dwSize, flAllocationType, flProtect);
	}
	else
	{

		std::cout << "Process handle " << hProcess << "was used to allocate memory at " << lpAddress << "with permissions " << flProtect << ". The size of the region is " << dwSize << ".\n" << endl;
		return OldVirtualAllocEx(hProcess, lpAddress, dwSize, flAllocationType, flProtect);
	}
}

LPVOID WINAPI NewVirtualAllocExA(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect) {

	if (flProtect != PAGE_EXECUTE_READWRITE || flProtect != PAGE_EXECUTE || flProtect != PAGE_EXECUTE_READ || flProtect != PAGE_EXECUTE_WRITECOPY) {

		return OldVirtualAllocExA(hProcess, lpAddress, dwSize, flAllocationType, flProtect);
	}
	else
	{

		std::cout << "Process handle " << hProcess << "was used to allocate memory at " << lpAddress << "with permissions " << flProtect << ". The size of the region is " << dwSize << ".\n" << endl;
		return OldVirtualAllocExA(hProcess, lpAddress, dwSize, flAllocationType, flProtect);
	}
}

LPVOID WINAPI NewVirtualAllocExW(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect) {

	if (flProtect != PAGE_EXECUTE_READWRITE || flProtect != PAGE_EXECUTE || flProtect != PAGE_EXECUTE_READ || flProtect != PAGE_EXECUTE_WRITECOPY) {

		return OldVirtualAllocExW(hProcess, lpAddress, dwSize, flAllocationType, flProtect);
	}
	else
	{
		std::cout << "Process handle " << hProcess << "was used to allocate memory at " << lpAddress << "with permissions " << flProtect << ". The size of the region is " << dwSize << ".\n" << endl;
		return OldVirtualAllocExW(hProcess, lpAddress, dwSize, flAllocationType, flProtect);
	}
}

int WINAPI NewWriteProcessMemory(HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T *lpNumberOfBytesWritten) {

	std::cout << "Process handle " << hProcess << "was used to write " << lpNumberOfBytesWritten << " bytes in memory at " << lpBaseAddress << "." << endl;
	return OldWriteProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesWritten);
}

int WINAPI NewNtResumeThread(IN HANDLE ThreadHandle, OUT PULONG SuspendCount) {

	std::cout << "[+] NtResumeThread called --> Handle " << ThreadHandle << " was used to resume a thread.\n" << endl;
	return OldNtResumeThread(ThreadHandle, SuspendCount);
}

int WINAPI NewResumeThread(HANDLE hThread) {

	std::cout << "[+] ResumeThread called --> Handle " << hThread << " was used to resume a thread.\n" << endl;
	return OldResumeThread(hThread);
}

int WINAPI NewSetThreadContext(HANDLE hThread, const CONTEXT *lpContext) {

	std::cout << "[+] SetThreadContext called --> Handle " << hThread << " was used to set the thread context.\n" << endl;
	std::cout << "[+] Thread entry point (saved in EAX register): " << lpContext << ".\n" << endl;
	return OldSetThreadContext(hThread, lpContext);
}

int WINAPI NewGetThreadContext(HANDLE hThread, LPCONTEXT lpContext) {

	std::cout << "[+] GetThreadContext called --> Handle " << hThread << " was used to get the thread context.\n" << endl;
	return OldGetThreadContext(hThread, lpContext);
}

HANDLE WINAPI NewCreateRemoteThread(HANDLE hProcess, LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId) {

	std::cout << "[+] CreateRemoteThread called --> Process handle " << hProcess << " was used to create the remote thread context. New Thread entry point: " << lpStartAddress << ".\n" << endl;
	return OldCreateRemoteThread(hProcess, lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags, lpThreadId);
}

HMODULE WINAPI NewLoadLibraryA(LPCSTR lpLibFileName) {

	std::cout << "[+] LoadLibraryA called --> Loaded module: " << lpLibFileName << ".\n" << endl;
	return OldLoadLibraryA(lpLibFileName);
}

HMODULE WINAPI NewLoadLibraryW(LPCWSTR lpLibFileName) {

	std::cout << "[+] LoadLibraryA called --> Loaded module: " << lpLibFileName << ".\n" << endl;
	return OldLoadLibraryW(lpLibFileName);
}

NTSTATUS WINAPI NewRtlDecompressBuffer(USHORT CompressionFormat, PUCHAR UncompressedBuffer, ULONG  UncompressedBufferSize, PUCHAR CompressedBuffer, ULONG  CompressedBufferSize, PULONG FinalUncompressedSize) {

	std::cout << "[+] RtlDecompressBuffer called --> uncompressed buffer: " << UncompressedBuffer << ", buffer size: " << FinalUncompressedSize << "compression format: " << CompressionFormat << ".\n" << endl;
	return OldRtlDecompressBuffer(CompressionFormat, UncompressedBuffer, UncompressedBufferSize, CompressedBuffer, CompressedBufferSize, FinalUncompressedSize);
}

bool WINAPI NewCryptEncrypt(HCRYPTKEY hKey, HCRYPTHASH hHash, BOOL Final, DWORD dwFlags, BYTE *pbData, DWORD *pdwDataLen, DWORD dwBufLen) {

std::cout << "[+] CryptEncrypt called --> encryption buffer: " << pbData << ", buffer length (bytes): " << pdwDataLen << ".\n" << endl;
	return OldCryptEncrypt(hKey, hHash, Final, dwFlags, pbData, pdwDataLen, dwBufLen);
}

bool WINAPI NewCryptDecrypt(HCRYPTKEY hKey, HCRYPTHASH hHash, BOOL Final, DWORD dwFlags, BYTE *pbData, DWORD *pdwDataLen) {

std:: cout << "[+] CryptDecrypt called --> decryption buffer: " << pbData << ", buffer length (bytes): " << pdwDataLen << ".\n" << endl;
	return OldCryptDecrypt(hKey, hHash, Final, dwFlags, pbData, pdwDataLen);
}

bool WINAPI NewCryptGenRandom(HCRYPTPROV hProv, DWORD dwLen, BYTE *pbBuffer) {

std:: cout << "[+] CryptGenRandom called --> data buffer: " << pbBuffer << ", buffer length: " << dwLen << "\n" << endl;
	return OldCryptGenRandom(hProv, dwLen, pbBuffer);
}

bool WINAPI NewCryptCreateHash(HCRYPTPROV hProv, ALG_ID Algid, HCRYPTKEY  hKey, DWORD dwFlags, HCRYPTHASH *phHash) {

	std::cout << "[+] CryptCreateHash called --> Alg ID: " << Algid << ", key (if keyed-hash such as HMAC/MAC/CBC mode algorithm): " << hKey << "\n" << endl;
	return OldCryptCreateHash(hProv, Algid, hKey, dwFlags, phHash);
}

BOOL WINAPI NewCryptAcquireContext(HCRYPTPROV *phProv, LPCSTR szContainer, LPCSTR szProvider, DWORD dwProvType, DWORD dwFlags) {

	std::cout << "[+] CryptAcquireContext called --> key container name: " << szContainer << ",  CSP name: " << szProvider << ", provider Type: " << dwProvType << ", flags: " << dwFlags << "\n" << endl;
	return OldCryptAcquireContext(phProv, szContainer, szProvider, dwProvType, dwFlags);
}

BOOL WINAPI NewCryptAcquireCertificatePrivateKey(PCCERT_CONTEXT pCert, DWORD dwFlags, void *pvParameters, HCRYPTPROV_OR_NCRYPT_KEY_HANDLE *phCryptProvOrNCryptKey, DWORD *pdwKeySpec, BOOL *pfCallerFreeProvOrNCryptKey) {

std:: cout << "[+] CryptAcquireCertificatePrivateKey  called --> CERT_CONTEXT struct address: " << pCert << ", flags: " << dwFlags << "\n << endl";
	return OldCryptAcquireCertificatePrivateKey(pCert, dwFlags, pvParameters, phCryptProvOrNCryptKey, pdwKeySpec, pfCallerFreeProvOrNCryptKey);
}

HANDLE WINAPI NewCreateProcessA(LPCSTR lpApplicationName, LPSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCSTR lpCurrentDirectory, LPSTARTUPINFOA lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation) {

	std::cout << "[+] CreateProcessA called --> process name: " << lpApplicationName << ", commandline: " << lpCommandLine << ", Creation flags: " << dwCreationFlags << "\n" << endl;
	return OldCreateProcessA(lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation);
}

HANDLE WINAPI NewCreateProcessW(LPCWSTR lpApplicationName, LPWSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCWSTR lpCurrentDirectory, LPSTARTUPINFOA lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation) {

	std::cout << "[+] CreateProcessw called --> process name: " << lpApplicationName << ", commandline: " << lpCommandLine << ", Creation flags: " << dwCreationFlags << "\n" << endl;
	return OldCreateProcessW(lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation);
}

DWORD WINAPI NewCreateProcessInternalW(DWORD unknown1, LPCTSTR lpApplicationName, LPTSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCTSTR lpCurrentDirectory, LPSTARTUPINFO lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation, DWORD unknown2) {

	std::cout << "[+] CreateProcessw called --> process name: " << lpApplicationName << ", commandline: " << lpCommandLine << ", Creation flags: " << dwCreationFlags << "\n" << endl;
	return OldCreateProcessInternalW(unknown1, lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation, unknown2);
}

LPVOID WINAPI NewGetProcAddress(HMODULE hModule, LPCSTR  lpProcName) {

	std::cout << "[+] GetProcAddress called --> Module: " << hModule << ", API function: " << lpProcName << "\n" << endl;
	return OldGetProcAddress(hModule, lpProcName);
}

HMODULE WINAPI NewGetModuleHandleA(LPCSTR lpModuleName) {

	std::cout << "[+] GetModuleHandleA called --> Mudole: " << lpModuleName << "\n" << endl;
	return OldGetModuleHandleA(lpModuleName);
}

HRSRC WINAPI NewFindResourceA(HMODULE hModule, LPCSTR lpName, LPCSTR lpType) {

	std::cout << "[+] FindResourceA called-- > Resource name: " << lpName << ", Owning PE file: " << hModule << "\n" << endl;
	return OldFindResourceA(hModule, lpName, lpType);
}

HGLOBAL WINAPI NewLoadResource(HMODULE hModule, HRSRC hResInfo) {

	std::cout << "[+] LoadResourceA called-- > Resource handle and information: " << hResInfo << ", Owning PE file: " << hModule << "\n" << endl;
	return OldLoadResource(hModule, hResInfo);
}

HANDLE WINAPI NewCreateThread(LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE  lpStartAddress, __drv_aliasesMem LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId) {

	std::cout << "[+] CreateThread called --> Thread start address: " << lpStartAddress << ", Creation flags: " << dwCreationFlags << "\n" << endl;
	return OldCreateThread(lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags, lpThreadId);
}

LPVOID WINAPI NewExitProcess(UINT uExitCode) {

	std::cout << "[+] ExitProcess called --> exit code: " << uExitCode << "\n" << endl;
	return OldExitProcess(uExitCode);
}

int WINAPI NewTerminateProcess(HANDLE hProcess, UINT uExitCode) {

	std::cout << "[+] TerminateProcess called --> Process to terminate: " << hProcess << ", exit code: " << uExitCode << "\n" << endl;
	return OldTerminateProcess(hProcess, uExitCode);
}

/*
BOOL WINAPI NewWriteFile(HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite, LPDWORD lpNumberOfBytesWritten, LPOVERLAPPED lpOverlapped) {

	std::cout << "[+] WriteFile called --> file handle: " << hFile << ", buffer: " << lpBuffer << "\n" << endl;
	return OldWriteFile(hFile, lpBuffer, nNumberOfBytesToWrite, lpNumberOfBytesWritten, lpOverlapped);
}

BOOL WINAPI NewWriteFileA(HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite, LPDWORD lpNumberOfBytesWritten, LPOVERLAPPED lpOverlapped) {

	std::cout << "[+] WriteFileA called --> file handle: " << hFile << ", buffer: " << lpBuffer << "\n" << endl;
	return OldWriteFileA(hFile, lpBuffer, nNumberOfBytesToWrite, lpNumberOfBytesWritten, lpOverlapped);
}

BOOL WINAPI NewWriteFileW(HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite, LPDWORD lpNumberOfBytesWritten, LPOVERLAPPED lpOverlapped) {

	std::cout << "[+] WriteFileW called --> file handle: " << hFile << ", buffer: " << lpBuffer << "\n" << endl;
	return OldWriteFileW(hFile, lpBuffer, nNumberOfBytesToWrite, lpNumberOfBytesWritten, lpOverlapped);
}
*/