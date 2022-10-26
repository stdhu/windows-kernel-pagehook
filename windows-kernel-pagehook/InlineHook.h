#pragma once

typedef struct _HookListNode
{
	ULONG64 OldCr3;
	ULONG64 OriPml4e;
	ULONG64 OriPdpte; 
	ULONG64 OriPde; 
	ULONG64 OriPte; 
	PVOID NewCr3;			
	PVOID NewPdpttAddress;
	PVOID NewPdtAddress; 
	PVOID NewPttAddress; 
	PVOID NewPteContent; 
	PVOID HookCode; 
	ULONG64 HookFuncAddress; 
	ULONG64 CallBack;
	SLIST_ENTRY HookNodeLinks;
	BOOLEAN flag;
	BOOLEAN LargePage;
}HookListNode, *PHookListNode;

typedef struct _ProcessListNode
{
	PEPROCESS Process;
	ULONG64 ProcessCr3;
	SLIST_ENTRY ProcessNodeLinks;
}ProcessListNode,*PProcessListNode;

typedef struct _PageMemoryListNode
{
	PVOID MemoryAddress;
	SLIST_ENTRY MemoryNodeLinks;
}PageMemoryListNode,*PPageMemoryListNode;

typedef struct _HookRegs {
	ULONG64 ax;
	ULONG64 cx;
	ULONG64 dx;
	ULONG64 bx;
	ULONG64 sp;
	ULONG64 bp;
	ULONG64 si;
	ULONG64 di;
	ULONG64 r8;
	ULONG64 r9;
	ULONG64 r10;
	ULONG64 r11;
	ULONG64 r12;
	ULONG64 r13;
	ULONG64 r14;
	ULONG64 r15;
}HookRegs,*PHookRegs;

#pragma pack(push,1)
typedef struct _HookStub
{
	volatile unsigned char UseCount[0x10];
	unsigned char OriCode[0x30];
	unsigned char HookShellCode[0x70];

}HookStub,*PHookStub;
#pragma pack(pop)

class InlineHook
{
public:
	VOID InitInlineHook(PWCH processName);
	NTSTATUS AddInlineHook(ULONG64 funcAddress, ULONG64 callBack);
	NTSTATUS InstallInlineHook();
	NTSTATUS UninstallInlineHook();
	
	static SLIST_ENTRY processListHeadNode;

private:
	int hookNums;
	PEPROCESS currentProcess;
	unsigned char stubHookCode[0x64];
	SLIST_ENTRY hookListHeadNode; 
	SLIST_ENTRY memoryListHeadNode; 
	
	static VOID ProcessCallBack(_In_ HANDLE ParentId,_In_ HANDLE ProcessId,_In_ BOOLEAN Create);
	VOID AddPageMemoryNode(PVOID allocateMemory);
	NTSTATUS ReplacePageItem(PULONG64 pageArray, ULONG64 targetValue, ULONG64 newValue);
	NTSTATUS SpliteLargePage(PHardwareHugePde pHardwareHugePde, PHookListNode pHookListNode, ULONG64 funcAddress);
	PHookListNode GetHookListNode(PULONG64 pHardwarePml4e, PULONG64 pHardwarePdpte, PULONG64 pHardwarePde, PULONG64 pHardwarePte, ULONG64 funcAddress);
};