#pragma once

//PML4E
typedef struct _HardwarePml4e
{
	ULONG64 Valid : 1;               
	ULONG64 WriteAndRead : 1;        
	ULONG64 UserAccess : 1;          
	ULONG64 WriteThrough : 1;        
	ULONG64 CacheDisable : 1;        
	ULONG64 Accessed : 1;            
	ULONG64 Dirty : 1;               
	ULONG64 IsPageValid : 1;         
	ULONG64 Global : 1;              
	ULONG64 Ignored0 : 3;			 
	ULONG64 PageFrameNumber : 36;	 
	ULONG64 reserved0 : 4;           
	ULONG64 Ignored1 : 11;			 
	ULONG64 NoExecute : 1;           
}HardwarePml4e, *PHardwarePml4e;

//PDPTE
typedef struct _HardwarePdpte
{
	ULONG64 Valid : 1;               
	ULONG64 WriteAndRead : 1;        
	ULONG64 UserAccess : 1;          
	ULONG64 WriteThrough : 1;        
	ULONG64 CacheDisable : 1;        
	ULONG64 Accessed : 1;            
	ULONG64 Dirty : 1;               
	ULONG64 LargePage : 1;           
	ULONG64 Global : 1;              
	ULONG64 Ignored0 : 3;			 
	ULONG64 PageFrameNumber : 36;	 
	ULONG64 reserved0 : 4;           
	ULONG64 Ignored1 : 11;			 
	ULONG64 NoExecute : 1;           
}HardwarePdpte,*PHardwarePdpte;

//Pde
typedef struct _HardwarePde
{
	ULONG64 Valid : 1;               
	ULONG64 WriteAndRead : 1;        
	ULONG64 UserAccess : 1;          
	ULONG64 WriteThrough : 1;        
	ULONG64 CacheDisable : 1;        
	ULONG64 Accessed : 1;            
	ULONG64 Dirty : 1;               
	ULONG64 LargePage : 1;           
	ULONG64 Global : 1;              
	ULONG64 Ignored0 : 3;			 
	ULONG64 PageFrameNumber : 36;	 
	ULONG64 reserved0 : 4;           
	ULONG64 Ignored1 : 11;			 
	ULONG64 NoExecute : 1;           
}HardwarePde, *PHardwarePde;

//2MB PDE
typedef struct _HardwareHugePde
{
	ULONG64 Valid : 1;               
	ULONG64 WriteAndRead : 1;        
	ULONG64 UserAccess : 1;          
	ULONG64 WriteThrough : 1;        
	ULONG64 CacheDisable : 1;        
	ULONG64 Accessed : 1;            
	ULONG64 Dirty : 1;               
	ULONG64 LargePage : 1;           
	ULONG64 Global : 1;              
	ULONG64 Ignored0 : 3;			 
	ULONG64 IsPageValid : 1;		 
	ULONG64 reserved0 : 8;		     
	ULONG64 PageFrameNumber : 27;	 
	ULONG64 reserved1 : 4;           
	ULONG64 Ignored1 : 11;			 
	ULONG64 NoExecute : 1;           
}HardwareHugePde,*PHardwareHugePde;

//PTE
typedef struct _HardwarePte
{
	ULONG64 Valid : 1;               
	ULONG64 WriteAndRead : 1;        
	ULONG64 UserAccess : 1;          
	ULONG64 WriteThrough : 1;        
	ULONG64 CacheDisable : 1;        
	ULONG64 Accessed : 1;            
	ULONG64 Dirty : 1;               
	ULONG64 IsPageValid : 1;         
	ULONG64 Global : 1;              
	ULONG64 Ignored0 : 3;			 
	ULONG64 PageFrameNumber : 36;	 
	ULONG64 reserved0 : 4;           
	ULONG64 Ignored1 : 11;			 
	ULONG64 NoExecute : 1;           
}HardwarePte,*PHardwarePte;
