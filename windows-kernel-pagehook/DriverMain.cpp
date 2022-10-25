#include "DriverMain.h"

SLIST_ENTRY InlineHook::processListHeadNode;
InlineHook pageHook;

void NtOpenProcessEntry(ULONG64 retAddress, PHookRegs pHookRegs)
{
	DbgPrintEx(77, 0, "NtOpenProcess\n");
}

void NtAllocateVirtualMemoryEntry(ULONG64 retAddress, PHookRegs pHookRegs)
{
	DbgPrintEx(77, 0, "NtAllocateVirtualMemory\n");
}

extern "C"
void DriverUnload(PDRIVER_OBJECT pDriver)
{
	pageHook.UninstallInlineHook();
}

extern "C"
NTSTATUS DriverEntry(PDRIVER_OBJECT pDriver, PUNICODE_STRING pRegPath)
{
	NTSTATUS status = STATUS_SUCCESS;

	pageHook.InitInlineHook(L"test.exe");
	UNICODE_STRING funcName = { 0 };
	RtlInitUnicodeString(&funcName, L"NtOpenProcess");
	ULONG64 NtOpenProcessAddress = reinterpret_cast<ULONG64>(MmGetSystemRoutineAddress(&funcName));

	RtlInitUnicodeString(&funcName, L"NtAllocateVirtualMemory");
	ULONG64 NtAllocateVirtualMemoryAddress = reinterpret_cast<ULONG64>(MmGetSystemRoutineAddress(&funcName));

	pageHook.AddInlineHook(NtOpenProcessAddress, reinterpret_cast<ULONG64>(NtOpenProcessEntry));
	pageHook.AddInlineHook(NtAllocateVirtualMemoryAddress, reinterpret_cast<ULONG64>(NtAllocateVirtualMemoryEntry));
	status = pageHook.InstallInlineHook();
	if (!NT_SUCCESS(status))
	{
		pageHook.UninstallInlineHook();
	}

	pDriver->DriverUnload = DriverUnload;
	return status;
}
