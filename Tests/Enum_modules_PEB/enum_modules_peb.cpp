#include <windows.h>
#include <stdio.h>
#include <iostream.h>
#include <tlhelp32.h>
#include <winternl.h>
#include <psapi.h>
#include <conio.h>
#pragma comment(lib,"ntdll")
#pragma comment(lib,"psapi")
using namespace std;

#define CONTAINING_RECORD(address, type, field) ((type *)( \
                                                  (PCHAR)(address) - \
                                                  (ULONG_PTR)(&((type *)0)->field)))

struct LoadedModuleData {
	LoadedModuleData *Next;
	LoadedModuleData *Previous;
	LIST_ENTRY InMemoryOrderLinks;
	void ** DllBase;
	DWORD *UnknowAdressInDLL; // may be start address
	DWORD *UnKnown2;
	UNICODE_STRING FullDllPath;
	UNICODE_STRING DllName;
};

DWORD *FindProcessIDs(char * procName, int *count) {
	PROCESSENTRY32 info;
	int e = 1;
	*count = 0;
	DWORD *ret = (DWORD *)malloc(sizeof(DWORD)* e);
	info.dwSize = sizeof(info);
	HANDLE prc = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (!prc) {
		CloseHandle(prc);
		return 0;
	}
	if (Process32First(prc, &info) != FALSE) {
		while (Process32Next(prc, &info) != 0) {
			if (!strcmp(info.szExeFile, procName) != 0) {
				ret = (DWORD *)realloc(ret, sizeof(DWORD)* e);
				ret[e - 1] = info.th32ProcessID;
				*count = e;
				e++;
			}
		}
	}
	CloseHandle(prc);
	return ret;
	//Free(ret);
}

void main() {
	while (true) {
		LDR_DATA_TABLE_ENTRY inMemoryOrderModuleListItem = *(CONTAINING_RECORD(currentitem_InMemoryOrderModuleList, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks));
		if (inMemoryOrderModuleListItem.FullDllName.Buffer == NULL) {
			break;
		}
		std::cout << inMemoryOrderModuleListItem.FullDllName.Buffer << endl;
		std::cout << inMemoryOrderModuleListItem.DllBase << endl;
		PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)inMemoryOrderModuleListItem.DllBase;
		if (!wcscmp(inMemoryOrderModuleListItem.FullDllName.Buffer, L"C:\\WINDOWS\\System32\\KERNEL32.DLL")) {
			PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)(inMemoryOrderModuleListItem.DllBase);
			std::cout << "-------------------------" << endl;
			PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)dosHeader + dosHeader->e_lfanew); // error on this line because trying to access the dosHeader
		}
		currentitem_InMemoryOrderModuleList = currentitem_InMemoryOrderModuleList->Flink;
	}
}
