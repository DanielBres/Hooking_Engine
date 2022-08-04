#pragma once

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
#include <winsock2.h>
#include <wincrypt.h>
#include <wininet.h>

//#include <sys/socket.h>

using namespace std;

//#include <Wdm.h>
//#include <Ntddk.h>
//#include <Ntifs.h>

typedef struct
{
	const char *dll;
	const char *name;
	LPVOID proxy;
	LPVOID original;

} HOOK_ARRAY;


//typedef int (WINAPI *TdefOldMessageBoxA)(HWND hWnd, LPCSTR lpText, LPCTSTR lpCaption, UINT uType);
//typedef int (WINAPI *TdefOldMessageBoxW)(HWND hWnd, LPWSTR lpText, LPCTSTR lpCaption, UINT uType);
typedef BOOL(WINAPI *TdefOldHttpSendRequest)(HINTERNET hRequest, LPCTSTR lpszHeaders, DWORD dwHeadersLength, LPVOID lpOptional, DWORD dwOptionalLength);
typedef BOOL(WINAPI *TdefOldHttpSendRequestA)(HINTERNET hRequest, LPCTSTR lpszHeaders, DWORD dwHeadersLength, LPVOID lpOptional, DWORD dwOptionalLength);
typedef DWORD(WINAPI *TdefOldGetCurrentProcessId)();
typedef void(WINAPI *TdefOldInternetOpenA)(LPCSTR lpszAgent, DWORD dwAccessType, LPCSTR lpszProxy, LPCSTR lpszProxyBypass, DWORD dwFlags);
typedef int(WSAAPI *TdefOldConnect)(SOCKET s, const sockaddr *name, int namelen);
typedef HANDLE(WINAPI *TdefOldOpenProcess)(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId);
typedef HANDLE(WINAPI *TdefOldOpenProcessA)(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId);
typedef HANDLE(WINAPI *TdefOldOpenProcessW)(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId);
typedef int(WINAPI *TdefOldVirtualProtect)(LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect);
typedef LPVOID(WINAPI *TdefOldVirtualAlloc)(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
typedef LPVOID(WINAPI *TdefOldVirtualAllocEx)(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
typedef LPVOID(WINAPI *TdefOldVirtualAllocExA)(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
typedef LPVOID(WINAPI *TdefOldVirtualAllocExW)(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
typedef int(WINAPI *TdefOldWriteProcessMemory)(HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T *lpNumberOfBytesWritten);
//typedef int (WINAPI *TdefOldNtUnMapViewOfSection)(HANDLE SectionHandle, HANDLE ProcessHandle, PVOID *BaseAddress, ULONG_PTR ZeroBits, SIZE_T CommitSize, PLARGE_INTEGER SectionOffset, PSIZE_T ViewSize, SECTION_INHERIT InheritDisposition, ULONG AllocationType, ULONG Win32Protect);
//typedef int (WINAPI *TdefOldZwUnMapViewOfSection)(HANDLE SectionHandle, HANDLE ProcessHandle, PVOID *BaseAddress, ULONG_PTR ZeroBits, SIZE_T CommitSize, PLARGE_INTEGER SectionOffset, PSIZE_T ViewSize, SECTION_INHERIT InheritDisposition, ULONG AllocationType, ULONG Win32Protect);
//typedef int (WINAPI *TdefOldNtMapViewOfSection)(HANDLE SectionHandle, HANDLE ProcessHandle, PVOID *BaseAddress, ULONG_PTR ZeroBits, SIZE_T CommitSize, PLARGE_INTEGER SectionOffset, PSIZE_T ViewSize, SECTION_INHERIT InheritDisposition, ULONG AllocationType, ULONG Win32Protect);
//typedef int (WINAPI *TdefOldZwMapViewOfSection)(HANDLE SectionHandle, HANDLE ProcessHandle, PVOID *BaseAddress, ULONG_PTR ZeroBits, SIZE_T CommitSize, PLARGE_INTEGER SectionOffset, PSIZE_T ViewSize, SECTION_INHERIT InheritDisposition, ULONG AllocationType, ULONG Win32Protect);
typedef int(WINAPI *TdefOldNtResumeThread)(IN HANDLE ThreadHandle, OUT PULONG SuspendCount);
typedef int(WINAPI *TdefOldResumeThread)(HANDLE hThread);
typedef int(WINAPI *TdefOldSetThreadContext)(HANDLE hThread, const CONTEXT *lpContext);
typedef int(WINAPI *TdefOldGetThreadContext)(HANDLE hThread, LPCONTEXT lpContext);
typedef HANDLE(WINAPI *TdefOldCreateRemoteThread)(HANDLE hProcess, LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId);
typedef HMODULE(WINAPI *TdefOldLoadLibraryA)(LPCSTR lpLibFileName);
typedef HMODULE(WINAPI *TdefOldLoadLibraryW)(LPCWSTR lpLibFileName);
typedef NTSTATUS(WINAPI *TdefOldRtlDecompressBuffer)(USHORT CompressionFormat, PUCHAR UncompressedBuffer, ULONG  UncompressedBufferSize, PUCHAR CompressedBuffer, ULONG  CompressedBufferSize, PULONG FinalUncompressedSize);
typedef bool(WINAPI *TdefOldCryptEncrypt)(HCRYPTKEY hKey, HCRYPTHASH hHash, BOOL Final, DWORD dwFlags, BYTE *pbData, DWORD *pdwDataLen, DWORD dwBufLen);
typedef bool(WINAPI *TdefOldCryptDecrypt)(HCRYPTKEY hKey, HCRYPTHASH hHash, BOOL Final, DWORD dwFlags, BYTE *pbData, DWORD *pdwDataLen);
typedef bool(WINAPI *TdefOldCryptGenRandom)(HCRYPTPROV hProv, DWORD dwLen, BYTE *pbBuffer);
typedef bool(WINAPI *TdefOldCryptCreateHash)(HCRYPTPROV hProv, ALG_ID Algid, HCRYPTKEY  hKey, DWORD dwFlags, HCRYPTHASH *phHash);
typedef BOOL(WINAPI *TdefOldCryptAcquireContext)(HCRYPTPROV *phProv, LPCSTR szContainer, LPCSTR szProvider, DWORD dwProvType, DWORD dwFlags); 
typedef BOOL(WINAPI *TdefOldCryptAcquireCertificatePrivateKey)(PCCERT_CONTEXT pCert, DWORD dwFlags, void *pvParameters, HCRYPTPROV_OR_NCRYPT_KEY_HANDLE *phCryptProvOrNCryptKey, DWORD *pdwKeySpec, BOOL *pfCallerFreeProvOrNCryptKey);
typedef HANDLE(WINAPI *TdefOldCreateProcessA)(LPCSTR lpApplicationName, LPSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCSTR lpCurrentDirectory, LPSTARTUPINFOA lpStartupInfo,LPPROCESS_INFORMATION lpProcessInformation);
typedef HANDLE(WINAPI *TdefOldCreateProcessW)(LPCWSTR lpApplicationName, LPWSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCWSTR lpCurrentDirectory, LPSTARTUPINFOA lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation);
typedef DWORD(WINAPI *TdefOldCreateProcessInternalW)(DWORD unknown1, LPCTSTR lpApplicationName, LPTSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCTSTR lpCurrentDirectory, LPSTARTUPINFO lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation, DWORD unknown2);
//typedef int(WINAPI *TdefOldNtCreateUserProcess)(PHANDLE ProcessHandle, PHANDLE ThreadHandle, ACCESS_MASK ProcessDesiredAccess, ACCESS_MASK ThreadDesiredAccess, POBJECT_ATTRIBUTES ProcessObjectAttributes, POBJECT_ATTRIBUTES ThreadObjectAttributes, ULONG ProcessFlags, ULONG ThreadFlags, PRTL_USER_PROCESS_PARAMETERS ProcessParameters, PPROCESS_CREATE_INFO CreateInfo, PPROCESS_ATTRIBUTE_LIST AttributeList);
typedef LPVOID(WINAPI *TdefOldGetProcAddress)(HMODULE hModule, LPCSTR  lpProcName);
typedef HMODULE(WINAPI *TdefOldGetModuleHandleA)(LPCSTR lpModuleName);
//typedef HRSRC(WINAPI *TdefOldFindResource)(HWND hWnd, LPWSTR lpText, LPCTSTR lpCaption, UINT uType);
typedef HGLOBAL(WINAPI *TdefOldLoadResource)(HMODULE hModule, HRSRC hResInfo);
typedef HRSRC(WINAPI *TdefOldFindResourceA)(HMODULE hModule, LPCSTR lpName, LPCSTR lpType);
typedef HGLOBAL(WINAPI *TdefOldLoadResource)(HMODULE hModule, HRSRC hResInfo);
typedef HANDLE(WINAPI *TdefOldCreateThread)(LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE  lpStartAddress, __drv_aliasesMem LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId); 
typedef LPVOID(WINAPI *TdefOldExitProcess)(UINT uExitCode);
typedef int(WINAPI *TdefOldTerminateProcess)(HANDLE hProcess, UINT uExitCode);
//typedef BOOL(WINAPI *TdefOldWriteFile(HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite, LPDWORD lpNumberOfBytesWritten, LPOVERLAPPED lpOverlapped));
//typedef BOOL(WINAPI *TdefOldWriteFileA(HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite, LPDWORD lpNumberOfBytesWritten, LPOVERLAPPED lpOverlapped));
//typedef BOOL(WINAPI *TdefOldWriteFileW(HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite, LPDWORD lpNumberOfBytesWritten, LPOVERLAPPED lpOverlapped));

int HookAll();
int UnHookAll();
//HANDLE GetMainThread();
//void ResumeMainThread(HANDLE hThread);
int PrintModules();
int CreateLogFile();

BOOL WINAPI NewHttpSendRequest(HINTERNET hRequest, LPCTSTR lpszHeaders, DWORD dwHeadersLength, LPVOID lpOptional, DWORD dwOptionalLength);
BOOL WINAPI NewHttpSendRequestA(HINTERNET hRequest, LPCTSTR lpszHeaders, DWORD dwHeadersLength, LPVOID lpOptional, DWORD dwOptionalLength);
DWORD WINAPI NewGetCurrentProcessId();
void WINAPI NewInternetOpenA(LPCSTR lpszAgent, DWORD dwAccessType, LPCSTR lpszProxy, LPCSTR lpszProxyBypass, DWORD dwFlags);
int WSAAPI NewConnect(SOCKET s, const sockaddr *name, int namelen);
HANDLE WINAPI NewOpenProcess(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId);
HANDLE WINAPI NewOpenProcessA(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId);
HANDLE WINAPI NewOpenProcessW(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId);
int WINAPI NewVirtualProtect(LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect);
LPVOID WINAPI NewVirtualAlloc(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
LPVOID WINAPI NewVirtualAllocEx(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
LPVOID WINAPI NewVirtualAllocExA(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
LPVOID WINAPI NewVirtualAllocExW(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
int WINAPI NewWriteProcessMemory(HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T *lpNumberOfBytesWritten);
//NTSTATUS  WINAPI NewNtUnMapViewOfSection(HANDLE SectionHandle, HANDLE ProcessHandle, PVOID *BaseAddress, ULONG_PTR ZeroBits, SIZE_T CommitSize, PLARGE_INTEGER SectionOffset, PSIZE_T ViewSize, SECTION_INHERIT InheritDisposition, ULONG AllocationType, ULONG Win32Protect);
//NTSTATUS  WINAPI NewZwUnMapViewOfSection(HANDLE SectionHandle, HANDLE ProcessHandle, PVOID *BaseAddress, ULONG_PTR ZeroBits, SIZE_T CommitSize, PLARGE_INTEGER SectionOffset, PSIZE_T ViewSize, SECTION_INHERIT InheritDisposition, ULONG AllocationType, ULONG Win32Protect);
//NTSTATUS  WINAPI NewNtMapViewOfSection(HANDLE SectionHandle, HANDLE ProcessHandle, PVOID *BaseAddress, ULONG_PTR ZeroBits, SIZE_T CommitSize, PLARGE_INTEGER SectionOffset, PSIZE_T ViewSize, SECTION_INHERIT InheritDisposition, ULONG AllocationType, ULONG Win32Protect);
//NTSTATUS  WINAPI NewZwMapViewOfSection(HANDLE SectionHandle, HANDLE ProcessHandle, PVOID *BaseAddress, ULONG_PTR ZeroBits, SIZE_T CommitSize, PLARGE_INTEGER SectionOffset, PSIZE_T ViewSize, SECTION_INHERIT InheritDisposition, ULONG AllocationType, ULONG Win32Protect);
int WINAPI NewNtResumeThread(IN HANDLE ThreadHandle, OUT PULONG SuspendCount);
int WINAPI NewResumeThread(HANDLE hThread);
int WINAPI NewSetThreadContext(HANDLE hThread, const CONTEXT *lpContext);
int WINAPI NewGetThreadContext(HANDLE hThread, LPCONTEXT lpContext);
HANDLE WINAPI NewCreateRemoteThread(HANDLE hProcess, LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId);
HMODULE WINAPI NewLoadLibraryA(LPCSTR lpLibFileName);
HMODULE WINAPI NewLoadLibraryW(LPCWSTR lpLibFileName);
NTSTATUS WINAPI NewRtlDecompressBuffer(USHORT CompressionFormat, PUCHAR UncompressedBuffer, ULONG  UncompressedBufferSize, PUCHAR CompressedBuffer, ULONG  CompressedBufferSize, PULONG FinalUncompressedSize);
bool WINAPI NewCryptEncrypt(HCRYPTKEY hKey, HCRYPTHASH hHash, BOOL Final, DWORD dwFlags, BYTE *pbData, DWORD *pdwDataLen, DWORD dwBufLen);
bool WINAPI NewCryptDecrypt(HCRYPTKEY hKey, HCRYPTHASH hHash, BOOL Final, DWORD dwFlags, BYTE *pbData, DWORD *pdwDataLen);
bool WINAPI NewCryptGenRandom(HCRYPTPROV hProv, DWORD dwLen, BYTE *pbBuffer);
bool WINAPI NewCryptCreateHash(HCRYPTPROV hProv, ALG_ID Algid, HCRYPTKEY  hKey, DWORD dwFlags, HCRYPTHASH *phHash);
BOOL WINAPI NewCryptAcquireContext(HCRYPTPROV *phProv, LPCSTR szContainer, LPCSTR szProvider, DWORD dwProvType, DWORD dwFlags);
BOOL WINAPI NewCryptAcquireCertificatePrivateKey(PCCERT_CONTEXT pCert, DWORD dwFlags, void *pvParameters, HCRYPTPROV_OR_NCRYPT_KEY_HANDLE *phCryptProvOrNCryptKey, DWORD *pdwKeySpec, BOOL *pfCallerFreeProvOrNCryptKey);
HANDLE WINAPI NewCreateProcessA(LPCSTR lpApplicationName, LPSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCSTR lpCurrentDirectory, LPSTARTUPINFOA lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation);
HANDLE WINAPI NewCreateProcessW(LPCWSTR lpApplicationName, LPWSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCWSTR lpCurrentDirectory, LPSTARTUPINFOA lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation);
DWORD WINAPI NewCreateProcessInternalW(DWORD unknown1, LPCTSTR lpApplicationName, LPTSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCTSTR lpCurrentDirectory, LPSTARTUPINFO lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation, DWORD unknown2);
//DWORD WINAPI NewNtCreateUserProcess(PHANDLE ProcessHandle, PHANDLE ThreadHandle, ACCESS_MASK ProcessDesiredAccess, ACCESS_MASK ThreadDesiredAccess, POBJECT_ATTRIBUTES ProcessObjectAttributes, POBJECT_ATTRIBUTES ThreadObjectAttributes, ULONG ProcessFlags, ULONG ThreadFlags, PRTL_USER_PROCESS_PARAMETERS ProcessParameters, PPROCESS_CREATE_INFO CreateInfo, PPROCESS_ATTRIBUTE_LIST AttributeList);
LPVOID WINAPI NewGetProcAddress(HMODULE hModule, LPCSTR  lpProcName);
HMODULE WINAPI NewGetModuleHandleA(LPCSTR lpModuleName);
//HRSRC WINAPI NewFindResource(HWND hWnd, LPWSTR lpText, LPCTSTR lpCaption, UINT uType);
HGLOBAL WINAPI NewLoadResource(HMODULE hModule, HRSRC hResInfo);
HRSRC WINAPI NewFindResourceA(HMODULE hModule, LPCSTR lpName, LPCSTR lpType);
HGLOBAL WINAPI NewLoadResourceA(HMODULE hModule, HRSRC hResInfo);
HANDLE WINAPI NewCreateThread(LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE  lpStartAddress, __drv_aliasesMem LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId);
LPVOID WINAPI NewExitProcess(UINT uExitCode);
int WINAPI NewTerminateProcess(HANDLE hProcess, UINT uExitCode);
//BOOL WINAPI NewWriteFile(HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite, LPDWORD lpNumberOfBytesWritten, LPOVERLAPPED lpOverlapped);
//BOOL WINAPI NewWriteFileA(HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite, LPDWORD lpNumberOfBytesWritten, LPOVERLAPPED lpOverlapped);
//BOOL WINAPI NewWriteFileW(HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite, LPDWORD lpNumberOfBytesWritten, LPOVERLAPPED lpOverlapped);


// HookFunction
// UnHookFunction
// Find the suspended thread by state and resume it with ResumeThread.
//



