#include "DriverMain.h"

#define LARGE_PAGE_SIZE 0x200000
#define LARGE_PAGE_SHFIT 21
#define CR3_OFFSET 0x28

VOID InlineHook::ProcessCallBack(_In_ HANDLE ParentId, _In_ HANDLE ProcessId, _In_ BOOLEAN Create)
{
	PEPROCESS targetProcess = NULL;
	NTSTATUS status = PsLookupProcessByProcessId(ProcessId, &targetProcess);

	if (NT_SUCCESS(status) && !Create)
	{
		PSLIST_ENTRY tmpListLinks = processListHeadNode.Next;
		PSLIST_ENTRY preListLinks = &processListHeadNode;
		while (tmpListLinks)
		{
			PProcessListNode pProcessListNode = CONTAINING_RECORD(tmpListLinks, ProcessListNode, ProcessNodeLinks);
			if (pProcessListNode->Process == targetProcess)
			{
				*reinterpret_cast<PULONG64>((reinterpret_cast<ULONG64>(targetProcess) + CR3_OFFSET)) = pProcessListNode->ProcessCr3;
				preListLinks->Next = tmpListLinks->Next;
				tmpListLinks->Next = NULL;
				ExFreePool(pProcessListNode);
				ObDereferenceObject(targetProcess);
				return;
			}
			tmpListLinks = tmpListLinks->Next;
			preListLinks = preListLinks->Next;
		}

		ObDereferenceObject(targetProcess);
	}
}

VOID InlineHook::InitInlineHook(PWCH processName)
{
	hookListHeadNode.Next = NULL;
	memoryListHeadNode.Next = NULL;
	processListHeadNode.Next = NULL;
	currentProcess = NULL;
	hookNums = 0;
	unsigned char tmpCode[] =
	{
		0xF0, 0xFF, 0x05, 0xB9, 0xFF, 0xFF, 0xFF, 0x41, 0x57, 0x41, 0x56, 0x41, 0x55, 0x41, 0x54, 0x41,
		0x53, 0x41, 0x52, 0x41, 0x51, 0x41, 0x50, 0x57, 0x56, 0x55, 0x54, 0x53, 0x52, 0x51, 0x50, 0x48,
		0x83, 0xEC, 0x40, 0x48, 0x8B, 0x8C, 0x24, 0xC0, 0x00, 0x00, 0x00, 0x48, 0x8D, 0x54, 0x24, 0x40,
		0x48, 0xB8, 0xCA, 0xCA, 0xCA, 0xCA, 0xCA, 0xCA, 0xCA, 0xCA, 0xFF, 0xD0, 0x48, 0x83, 0xC4, 0x40,
		0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F, 0x41, 0x58, 0x41, 0x59, 0x41, 0x5A, 0x41, 0x5B,
		0x41, 0x5C, 0x41, 0x5D, 0x41, 0x5E, 0x41, 0x5F, 0xF0, 0xFF, 0x0D, 0x61, 0xFF, 0xFF, 0xFF, 0xE9,
		0x6C, 0xFF, 0xFF, 0xFF
	};
	RtlZeroMemory(stubHookCode, sizeof(stubHookCode));
	memcpy(stubHookCode, tmpCode, sizeof(tmpCode));

	NTSTATUS status=DriverTool::Instance().GetProcessByName(&currentProcess, processName);
	if (!NT_SUCCESS(status))
	{
		DbgPrintEx(77, 0, "get target process failed please init again\n");
		return;
	}

	PProcessListNode pProcessListNode= reinterpret_cast<PProcessListNode>(ExAllocatePool(NonPagedPool, sizeof(ProcessListNode)));
	if (!pProcessListNode)
	{
		DbgPrintEx(77, 0, "allocate processListNode failed please init again\n");
		return;
	}
	pProcessListNode->Process = currentProcess;
	pProcessListNode->ProcessCr3 = *reinterpret_cast<PULONG64>((reinterpret_cast<ULONG64>(currentProcess) + CR3_OFFSET));

	pProcessListNode->ProcessNodeLinks.Next = processListHeadNode.Next;
	processListHeadNode.Next = &pProcessListNode->ProcessNodeLinks;

	PsSetCreateProcessNotifyRoutine(ProcessCallBack, FALSE);
}

PHookListNode InlineHook::GetHookListNode(PULONG64 pHardwarePml4e,PULONG64 pHardwarePdpte,PULONG64 pHardwarePde, PULONG64 pHardwarePte,ULONG64 funcAddress)
{
	PSLIST_ENTRY tmpListLinks = hookListHeadNode.Next;
	PHookListNode pHookListNode = NULL;
	bool flag = false;

	PHookListNode pNewHookListNode = static_cast<PHookListNode>(ExAllocatePool(NonPagedPool, sizeof(HookListNode)));
	if (!pNewHookListNode) return NULL;
	RtlZeroMemory(pNewHookListNode, sizeof(HookListNode));

	while (tmpListLinks)
	{
		pHookListNode=CONTAINING_RECORD(tmpListLinks, HookListNode, HookNodeLinks);
		
		pNewHookListNode->NewCr3 = pHookListNode->NewCr3;
		pNewHookListNode->OldCr3 = pHookListNode->OldCr3;
		
		if (pHookListNode->OriPml4e == *pHardwarePml4e)
		{
			pNewHookListNode->NewPdpttAddress = pHookListNode->NewPdpttAddress;
		}

		if (pHookListNode->OriPdpte == *pHardwarePdpte)
		{
			pNewHookListNode->NewPdtAddress = pHookListNode->NewPdtAddress;
		}

		if (pHookListNode->OriPde == *pHardwarePde)
		{
			pNewHookListNode->NewPttAddress = pHookListNode->NewPttAddress;
		}

		if ((pHookListNode->OriPde & 0x80) == 0x80 && pHookListNode->OriPde == *pHardwarePde)
		{
			ULONG currentPteIndex = (funcAddress & (LARGE_PAGE_SIZE - 1)) / PAGE_SIZE;
			ULONG targetPteIndex = (pHookListNode->HookFuncAddress & (LARGE_PAGE_SIZE - 1)) / PAGE_SIZE;
			if (targetPteIndex == currentPteIndex) pNewHookListNode->NewPteContent = pHookListNode->NewPteContent;
			else
			{
				PCHAR pteContent= reinterpret_cast<PCHAR>(ExAllocatePool(NonPagedPool, PAGE_SIZE));
				while(!pteContent) pteContent = reinterpret_cast<PCHAR>(ExAllocatePool(NonPagedPool, PAGE_SIZE));

				AddPageMemoryNode(pteContent);

				PCHAR pttAddress = reinterpret_cast<PCHAR>(pHookListNode->NewPttAddress);
				ULONG64 oriPte = *reinterpret_cast<PULONG64>(pttAddress + currentPteIndex * 8);
				PCHAR oriPteContent= reinterpret_cast<PCHAR>(DriverTool::Instance().GetVirtualAddressByPhysical(oriPte & (~(PAGE_SIZE-1))));
				memcpy(pteContent, oriPteContent, PAGE_SIZE);

				*reinterpret_cast<PULONG64>(pttAddress + currentPteIndex * 8) = MmGetPhysicalAddress(pteContent).QuadPart | (oriPte & 0xFFF);
				pNewHookListNode->NewPteContent = pteContent;
			}

		}
		else if(pHookListNode->OriPte == *pHardwarePte)
		{
			pNewHookListNode->NewPteContent = pHookListNode->NewPteContent;
		}

		tmpListLinks = tmpListLinks->Next;
	}

	pNewHookListNode->OriPml4e = *pHardwarePml4e;
	pNewHookListNode->OriPdpte = *pHardwarePdpte;
	pNewHookListNode->OriPde = *pHardwarePde;
	pNewHookListNode->OriPte = *pHardwarePte;

	pNewHookListNode->HookNodeLinks.Next = hookListHeadNode.Next;
	hookListHeadNode.Next = &pNewHookListNode->HookNodeLinks;

	return pNewHookListNode;
}

NTSTATUS InlineHook::SpliteLargePage(PHardwareHugePde pHardwareHugePde, PHookListNode pHookListNode,ULONG64 funcAddress)
{
	PHardwarePte pHardwarePte = NULL;
	PUCHAR pteContent = NULL;

	pHardwarePte= reinterpret_cast<PHardwarePte>(ExAllocatePool(NonPagedPool, PAGE_SIZE));
	if (!pHardwarePte) goto free_memory;

	AddPageMemoryNode(pHardwarePte);

	pteContent = reinterpret_cast<PUCHAR>(ExAllocatePool(NonPagedPool, PAGE_SIZE));
	if (!pteContent) goto free_memory;

	AddPageMemoryNode(pteContent);

	ULONG pteIndex= (funcAddress & (LARGE_PAGE_SIZE - 1)) / PAGE_SIZE;

	PCHAR pdeVirtualAddress = reinterpret_cast<PCHAR>(DriverTool::Instance().GetVirtualAddressByPhysical(pHardwareHugePde->PageFrameNumber << LARGE_PAGE_SHFIT));
	if (!MmIsAddressValid(pdeVirtualAddress)) goto free_memory;
	memcpy(pteContent, pdeVirtualAddress + pteIndex * PAGE_SIZE, PAGE_SIZE);

	for (ULONG i = 0; i < 512; i++)
	{
		memcpy(&pHardwarePte[i], pHardwareHugePde, sizeof(HardwarePte));
		pHardwarePte[i].IsPageValid = 0;
		if (pteIndex == i) pHardwarePte[i].PageFrameNumber = MmGetPhysicalAddress(pteContent).QuadPart / PAGE_SIZE;
		else pHardwarePte[i].PageFrameNumber = (pHardwareHugePde->PageFrameNumber << 9) + i; 
	}

	pHookListNode->NewPttAddress = pHardwarePte;
	pHookListNode->NewPteContent = pteContent;

	return STATUS_SUCCESS;

free_memory:
	if (pHardwarePte) ExFreePool(pHardwarePte);
	if (pteContent) ExFreePool(pteContent);

	return STATUS_UNSUCCESSFUL;
}

NTSTATUS InlineHook::ReplacePageItem(PULONG64 pageArray, ULONG64 targetValue,ULONG64 newValue)
{
	ULONG pageItemIndex = -1;
	for (int i = 0; i < 512; i++)
	{
		if (pageArray[i] == targetValue)
		{
			pageItemIndex = i;
			break;
		}
	}

	if (pageItemIndex == -1) return STATUS_UNSUCCESSFUL;
	
	pageArray[pageItemIndex] = newValue;
	return STATUS_SUCCESS;
}

VOID InlineHook::AddPageMemoryNode(PVOID allocateMemory)
{
	PSLIST_ENTRY tmpListLinks = memoryListHeadNode.Next;
	while (tmpListLinks)
	{
		PPageMemoryListNode pMemoryListNode= CONTAINING_RECORD(tmpListLinks, PageMemoryListNode, MemoryNodeLinks);
		if (pMemoryListNode->MemoryAddress == allocateMemory) return;
		tmpListLinks = tmpListLinks->Next;
	}

	PPageMemoryListNode pMemoryListNode = reinterpret_cast<PPageMemoryListNode>(ExAllocatePool(NonPagedPool, sizeof(PageMemoryListNode)));
	while(!pMemoryListNode) pMemoryListNode = reinterpret_cast<PPageMemoryListNode>(ExAllocatePool(NonPagedPool, sizeof(PageMemoryListNode)));

	pMemoryListNode->MemoryAddress = allocateMemory;
	pMemoryListNode->MemoryNodeLinks.Next = memoryListHeadNode.Next;
	memoryListHeadNode.Next = &pMemoryListNode->MemoryNodeLinks;
}


NTSTATUS InlineHook::AddInlineHook(ULONG64 funcAddress,ULONG64 callBack)
{
	if (!currentProcess || !MmIsAddressValid(reinterpret_cast<PVOID>(funcAddress)) || !MmIsAddressValid(reinterpret_cast<PVOID>(callBack)))
	{
		return STATUS_UNSUCCESSFUL;
	}

	KAPC_STATE kApc = { 0 };
	KeStackAttachProcess(currentProcess, &kApc);

	NTSTATUS status = STATUS_UNSUCCESSFUL;
	BOOLEAN isLargePage = false;
	PHardwarePde pHardwarePde = reinterpret_cast<PHardwarePde>(MemoryManage::Instance().GetPde(funcAddress));
	PHardwarePte pHardwarePte = NULL;
	PHardwarePdpte pHardwarePdpte = NULL;
	PHardwarePml4e pHardwarePml4e = NULL;

	if (!MmIsAddressValid(pHardwarePde)) return status;

	if (pHardwarePde->LargePage) isLargePage = true;
	
	pHardwarePml4e = reinterpret_cast<PHardwarePml4e>(MemoryManage::Instance().GetPml4e(funcAddress));
	pHardwarePdpte = reinterpret_cast<PHardwarePdpte>(MemoryManage::Instance().GetPdpte(funcAddress));
	pHardwarePte = reinterpret_cast<PHardwarePte>(MemoryManage::Instance().GetPte(funcAddress));
	
	if (!MmIsAddressValid(pHardwarePml4e) || !MmIsAddressValid(pHardwarePdpte) || !MmIsAddressValid(pHardwarePde) || (!isLargePage && !MmIsAddressValid(pHardwarePte)))
	{
		KeUnstackDetachProcess(&kApc);
		return status;
	}

	PHookListNode pHookListNode=GetHookListNode(reinterpret_cast<PULONG64>(pHardwarePml4e),
		reinterpret_cast<PULONG64>(pHardwarePdpte),
		reinterpret_cast<PULONG64>(pHardwarePde), 
		reinterpret_cast<PULONG64>(pHardwarePte),
		funcAddress);

	if (!pHookListNode) return status;
	if (isLargePage) pHookListNode->OriPte = 0;

	if (!pHookListNode->NewCr3)
	{
		PVOID newCr3 = ExAllocatePool(NonPagedPool, PAGE_SIZE);
		if (!newCr3) goto free_memory;

		AddPageMemoryNode(newCr3);

		ULONG64 targetCr3 = __readcr3();

		PVOID cr3VirtualAddress = DriverTool::Instance().GetVirtualAddressByPhysical(targetCr3&(~(PAGE_SIZE - 1)));
		if (!MmIsAddressValid(cr3VirtualAddress)) return status;
		memcpy(newCr3, cr3VirtualAddress, PAGE_SIZE);

		pHookListNode->NewCr3 = newCr3;
		pHookListNode->OldCr3 = targetCr3;
	}

	if (!pHookListNode->NewPdpttAddress)
	{
		PVOID newPdpttAddress = ExAllocatePool(NonPagedPool, PAGE_SIZE);
		if (!newPdpttAddress) goto free_memory;

		AddPageMemoryNode(newPdpttAddress);

		PVOID pdpttVirtualAddress = DriverTool::Instance().GetVirtualAddressByPhysical(pHardwarePml4e->PageFrameNumber << PAGE_SHIFT);
		
		if (!MmIsAddressValid(pdpttVirtualAddress)) return status;
		memcpy(newPdpttAddress, pdpttVirtualAddress, PAGE_SIZE);

		pHookListNode->NewPdpttAddress = newPdpttAddress;

		status = ReplacePageItem(reinterpret_cast<PULONG64>(pHookListNode->NewCr3), pHookListNode->OriPml4e, MmGetPhysicalAddress(newPdpttAddress).QuadPart | (pHookListNode->OriPml4e & 0xFFF));
		if (!NT_SUCCESS(status)) goto free_memory;
	}

	if (!pHookListNode->NewPdtAddress)
	{
		PVOID newPdtAddress = ExAllocatePool(NonPagedPool, PAGE_SIZE);
		if (!newPdtAddress) goto free_memory;

		AddPageMemoryNode(newPdtAddress);

		PVOID pdtVirtualAddress = DriverTool::Instance().GetVirtualAddressByPhysical(pHardwarePdpte->PageFrameNumber << PAGE_SHIFT);

		if (!MmIsAddressValid(pdtVirtualAddress)) return status;
		memcpy(newPdtAddress, pdtVirtualAddress, PAGE_SIZE);

		pHookListNode->NewPdtAddress = newPdtAddress;

		status = ReplacePageItem(reinterpret_cast<PULONG64>(pHookListNode->NewPdpttAddress), pHookListNode->OriPdpte, MmGetPhysicalAddress(newPdtAddress).QuadPart | (pHookListNode->OriPdpte & 0xFFF));
		if (!NT_SUCCESS(status)) goto free_memory;
	}

	if (!pHookListNode->NewPttAddress)
	{
		if (isLargePage)
		{
			status = SpliteLargePage(reinterpret_cast<PHardwareHugePde>(pHardwarePde), pHookListNode,funcAddress);
			if (!NT_SUCCESS(status)) goto free_memory;
		}
		else
		{
			PVOID newPttAddress = ExAllocatePool(NonPagedPool, PAGE_SIZE);
			if (!newPttAddress) goto free_memory;

			AddPageMemoryNode(newPttAddress);

			PVOID pttVirtualAddress = DriverTool::Instance().GetVirtualAddressByPhysical(pHardwarePde->PageFrameNumber << PAGE_SHIFT);
			if (!MmIsAddressValid(pttVirtualAddress)) return status;

			memcpy(newPttAddress, pttVirtualAddress, PAGE_SIZE);

			pHookListNode->NewPttAddress = newPttAddress;
		}

		if (isLargePage)
		{
			HardwarePde hardwarePde = { 0 };
			memcpy(&hardwarePde, pHardwarePde, sizeof(HardwarePde));
			hardwarePde.LargePage = 0;
			hardwarePde.PageFrameNumber = MmGetPhysicalAddress(pHookListNode->NewPttAddress).QuadPart / PAGE_SIZE;

			status = ReplacePageItem(reinterpret_cast<PULONG64>(pHookListNode->NewPdtAddress), pHookListNode->OriPde, *reinterpret_cast<PULONG64>(&hardwarePde));
			if (!NT_SUCCESS(status)) goto free_memory;
		}
		else
		{
			status = ReplacePageItem(reinterpret_cast<PULONG64>(pHookListNode->NewPdtAddress), pHookListNode->OriPde, MmGetPhysicalAddress(pHookListNode->NewPttAddress).QuadPart | (pHookListNode->OriPde & 0xFFF));
			if (!NT_SUCCESS(status)) goto free_memory;
		}
		
	}

	if (!pHookListNode->NewPteContent)
	{
		PVOID newPteContent = ExAllocatePool(NonPagedPool, PAGE_SIZE);
		if (!newPteContent) goto free_memory;

		AddPageMemoryNode(newPteContent);

		PVOID pteVirtualAddress = DriverTool::Instance().GetVirtualAddressByPhysical(pHardwarePte->PageFrameNumber << PAGE_SHIFT);
		if (!MmIsAddressValid(pteVirtualAddress)) return status;

		memcpy(newPteContent, pteVirtualAddress, PAGE_SIZE);

		pHookListNode->NewPttAddress = newPteContent;

		status = ReplacePageItem(reinterpret_cast<PULONG64>(pHookListNode->NewPttAddress), pHookListNode->OriPte, MmGetPhysicalAddress(newPteContent).QuadPart | (pHookListNode->OriPte & 0xFFF));
		if (!NT_SUCCESS(status)) goto free_memory;
	}

	PHookStub pHookStub = reinterpret_cast<PHookStub>(ExAllocatePool(NonPagedPool, sizeof(HookStub)));
	if (!pHookStub) goto free_memory;
	RtlZeroMemory(pHookStub, sizeof(HookStub));

	memset(pHookStub->OriCode, 0x90, sizeof(pHookStub->OriCode) + sizeof(pHookStub->HookShellCode));
	memcpy(pHookStub->HookShellCode, stubHookCode, sizeof(stubHookCode));
	//repair shellcode
	for (int i = 0; i < sizeof(stubHookCode); i++)
	{
		unsigned char * current = pHookStub->HookShellCode + i;
		if (*reinterpret_cast<int*>(current) == 0xCACACACA)
		{
			*reinterpret_cast<PULONG64>(current) = callBack;
			break;
		}
	}

	pHookListNode->HookCode = pHookStub;
	pHookListNode->HookFuncAddress = funcAddress;
	pHookListNode->CallBack = callBack;
	pHookListNode->LargePage = isLargePage;

	KeUnstackDetachProcess(&kApc);
	return STATUS_SUCCESS;

free_memory:
	KeUnstackDetachProcess(&kApc);
	if (pHookListNode->NewCr3 && MmIsAddressValid(pHookListNode->NewCr3))
	{
		ExFreePool(pHookListNode->NewCr3);
	}

	if (pHookListNode->NewPdpttAddress && MmIsAddressValid(pHookListNode->NewPdpttAddress))
	{
		ExFreePool(pHookListNode->NewPdpttAddress);
	}

	if (pHookListNode->NewPdtAddress && MmIsAddressValid(pHookListNode->NewPdtAddress))
	{
		ExFreePool(pHookListNode->NewPdtAddress);
	}

	if (pHookListNode->NewPttAddress && MmIsAddressValid(pHookListNode->NewPttAddress))
	{
		ExFreePool(pHookListNode->NewPttAddress);
	}

	if (pHookListNode->NewPteContent && MmIsAddressValid(pHookListNode->NewPteContent))
	{
		ExFreePool(pHookListNode->NewPteContent);
	}

	hookListHeadNode.Next = pHookListNode->HookNodeLinks.Next;
	pHookListNode->HookNodeLinks.Next = NULL;
	ExFreePool(pHookListNode);

	return status;
}

NTSTATUS InlineHook::InstallInlineHook()
{
	PSLIST_ENTRY tmpListLinks = hookListHeadNode.Next;
	NTSTATUS status = STATUS_SUCCESS;
	if (!currentProcess) return STATUS_UNSUCCESSFUL;
	if (!tmpListLinks) return status;

	while (tmpListLinks)
	{
		PHookListNode pHookListNode = CONTAINING_RECORD(tmpListLinks, HookListNode, HookNodeLinks);
		if (!pHookListNode->flag)
		{
			UCHAR jmpCode[] = "\xFF\x25\x00\x00\x00\x00\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF";
			UCHAR jmpOriFuncCode[] = "\xFF\x25\x00\x00\x00\x00\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF";

			int offset = 0;
			offset = pHookListNode->HookFuncAddress & (PAGE_SIZE - 1);

			int insnLength = 0;
			while (insnLength < sizeof(jmpCode))
				insnLength += DriverTool::Instance().insn_len_x86_64(reinterpret_cast<PVOID>(pHookListNode->HookFuncAddress + insnLength));

			ULONG64 retAddress = pHookListNode->HookFuncAddress + insnLength;
			memcpy(&jmpOriFuncCode[6], &retAddress, sizeof(ULONG64));

			PHookStub pHookStub = reinterpret_cast<PHookStub>(pHookListNode->HookCode);
			memcpy(pHookStub->OriCode, reinterpret_cast<PVOID>(pHookListNode->HookFuncAddress), insnLength);
			memcpy(pHookStub->OriCode + insnLength, jmpOriFuncCode, sizeof(jmpOriFuncCode));

			retAddress = reinterpret_cast<ULONG64>(pHookStub->HookShellCode);
			memcpy(&jmpCode[6], &retAddress, sizeof(ULONG64));

			ULONG64 targetAddress = reinterpret_cast<ULONG64>(pHookListNode->NewPteContent) + offset;
			memset(reinterpret_cast<PVOID>(targetAddress), 0x90, insnLength);
			memcpy(reinterpret_cast<PVOID>(targetAddress), jmpCode, sizeof(jmpCode));
			
			pHookListNode->flag = true;
			hookNums++;

			DbgPrintEx(77, 0, "page hook success func:%llx stub:%llx\n", pHookListNode->HookFuncAddress, pHookStub);
		}

		tmpListLinks = tmpListLinks->Next;
	}

	PHookListNode pHookListNode = CONTAINING_RECORD(hookListHeadNode.Next, HookListNode, HookNodeLinks);
	*reinterpret_cast<PULONG64>((reinterpret_cast<ULONG64>(currentProcess) + CR3_OFFSET)) = MmGetPhysicalAddress(pHookListNode->NewCr3).QuadPart | (pHookListNode->OldCr3 & (PAGE_SIZE-1));

	return status;
}

NTSTATUS InlineHook::UninstallInlineHook()
{
	NTSTATUS status = STATUS_SUCCESS;
	PSLIST_ENTRY tmpListLinks = NULL;
	ULONG index = 0;
	PULONG64 pHookStubArray = NULL;
	BOOLEAN isExit = false;

	
	if (!currentProcess) return status;
	if (!hookListHeadNode.Next) return status;

	tmpListLinks = processListHeadNode.Next;
	while (tmpListLinks)
	{
		PProcessListNode pProcessListNode = CONTAINING_RECORD(tmpListLinks, ProcessListNode, ProcessNodeLinks);
		if (pProcessListNode->Process == currentProcess)
		{
			isExit = true;
			break;
		}
		tmpListLinks = tmpListLinks->Next;
	}
	
	if (hookNums)
	{
		pHookStubArray = reinterpret_cast<PULONG64>(ExAllocatePool(NonPagedPool, hookNums * sizeof(ULONG64)));
		while (!pHookStubArray) pHookStubArray = reinterpret_cast<PULONG64>(ExAllocatePool(NonPagedPool, hookNums * sizeof(ULONG64)));
	}

	tmpListLinks = hookListHeadNode.Next;
	while (tmpListLinks)
	{
		PHookListNode pHookListNode = CONTAINING_RECORD(tmpListLinks, HookListNode, HookNodeLinks);
		if (pHookListNode->flag) pHookStubArray[index++] = reinterpret_cast<ULONG64>(pHookListNode->HookCode);

		tmpListLinks = tmpListLinks->Next;
	}
	
	if (isExit)
	{
		PHookListNode pHookListNode = CONTAINING_RECORD(hookListHeadNode.Next, HookListNode, HookNodeLinks);
		*reinterpret_cast<PULONG64>((reinterpret_cast<ULONG64>(currentProcess) + CR3_OFFSET)) = pHookListNode->OldCr3;
		for (int i = 0; i < hookNums; i++)
		{
			PHookStub pHookStub = reinterpret_cast<PHookStub>(pHookStubArray[i]);
			while (InterlockedAnd(reinterpret_cast<volatile long *>(pHookStub->UseCount), (~0)))
			{
				DbgPrintEx(77, 0, "waiting for %lx\n", pHookStub->HookShellCode);
				DriverTool::Instance().Sleep(1000);
			}
		}
	}
	
	tmpListLinks = hookListHeadNode.Next;
	while (tmpListLinks)
	{
		PHookListNode pHookListNode = CONTAINING_RECORD(tmpListLinks, HookListNode, HookNodeLinks);
		ExFreePool(pHookListNode->HookCode);
		tmpListLinks = tmpListLinks->Next;
		ExFreePool(pHookListNode);
	}

	tmpListLinks = memoryListHeadNode.Next;
	while (tmpListLinks)
	{
		PPageMemoryListNode pPageMemoryListNode= CONTAINING_RECORD(tmpListLinks, PageMemoryListNode, MemoryNodeLinks);
		ExFreePool(pPageMemoryListNode->MemoryAddress);
		tmpListLinks = tmpListLinks->Next;
		ExFreePool(pPageMemoryListNode);
	}

	hookListHeadNode.Next = NULL;
	memoryListHeadNode.Next = NULL;
	hookNums = 0;
	if (pHookStubArray) ExFreePool(pHookStubArray);
	ObDereferenceObject(currentProcess);
	currentProcess=NULL;

	PsSetCreateProcessNotifyRoutine(ProcessCallBack, TRUE);
	return status;
}











