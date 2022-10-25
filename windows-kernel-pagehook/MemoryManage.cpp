#include "DriverMain.h"
#define PTE_BASE 0xFFFFF68000000000
#define PTE_SHIFT 39
#define PAGE_MASK 0xFFFF000000000000

ULONG64 MemoryManage::GetPteBase()
{
	static ULONG64 pteBase = 0;
	if (pteBase) return pteBase;

	RTL_OSVERSIONINFOW systemVersion = { 0 };
	RtlGetVersion(&systemVersion);

	if (systemVersion.dwBuildNumber == 7600 || systemVersion.dwBuildNumber == 7601 || systemVersion.dwBuildNumber < 14316) {
		pteBase = PTE_BASE;
	}
	else {
		PHYSICAL_ADDRESS pageDirectoryPA = { 0 };
		pageDirectoryPA.QuadPart = __readcr3() & (~(PAGE_SIZE - 1));

		PHardwarePml4e pageDirectoryVA = reinterpret_cast<PHardwarePml4e>(MmGetVirtualForPhysical(pageDirectoryPA));
		if (pageDirectoryVA == nullptr) {
			return 0;
		}

		for (int index = 0; index < 512; index++) {
			if (pageDirectoryVA[index].PageFrameNumber == (pageDirectoryPA.QuadPart >> PAGE_SHIFT)) {
				pteBase = (static_cast<ULONG64>(index) << PTE_SHIFT) | PAGE_MASK;
				break;
			}
		}
	}

	DbgPrintEx(77, 0, "[+] pte_base:%llx\n", pteBase);

	return pteBase;
}

ULONG64 MemoryManage::GetPte(ULONG64 virtualAddress)
{
	ULONG64 pteBase = GetPteBase();
	return ((virtualAddress >> 9) & 0x7FFFFFFFF8) + pteBase;
}

ULONG64 MemoryManage::GetPde(ULONG64 virtualAddress)
{
	ULONG64 pteBase = GetPteBase();
	ULONG64 pte = GetPte(virtualAddress);
	return ((pte >> 9) & 0x7FFFFFFFF8) + pteBase;
}

ULONG64 MemoryManage::GetPdpte(ULONG64 virtualAddress)
{
	ULONG64 pteBase = GetPteBase();
	ULONG64 pde = GetPde(virtualAddress);
	return ((pde >> 9) & 0x7FFFFFFFF8) + pteBase;
}

ULONG64 MemoryManage::GetPml4e(ULONG64 virtualAddress)
{
	ULONG64 pteBase = GetPteBase();
	ULONG64 pdpte = GetPdpte(virtualAddress);
	return ((pdpte >> 9) & 0x7FFFFFFFF8) + pteBase;
}

MemoryManage& MemoryManage::Instance()
{
	static MemoryManage inst;
	return inst;
}