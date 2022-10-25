#pragma once

class MemoryManage
{
public:
	ULONG64 GetPteBase();

	ULONG64 GetPte(ULONG64 virtualAddress);
	ULONG64 GetPde(ULONG64 virtualAddress);
	ULONG64 GetPdpte(ULONG64 virtualAddress);
	ULONG64 GetPml4e(ULONG64 virtualAddress);

	static MemoryManage& Instance();
};