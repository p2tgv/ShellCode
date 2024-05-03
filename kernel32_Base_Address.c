#include <intrin.h>
#include <stdint.h>
#include <stdio.h>

#ifdef _WIN64
	#define PEB_OFFSET_FROM_GS 0x60
	#define PEB __readgsqword(PEB_OFFSET_FROM_GS)
	#define LDR_DATA_IN_PEB_OFFSET 24
	#define IN_LOAD_ORDER_MODULE_LIST_OFFSET 16
	#define DLL_BASE_OFFSET 48
#else
	#define PEB_OFFSET_FROM_FS 0x30
	#define PEB __readfsdword(PEB_OFFSET_FROM_FS)
	#define LDR_DATA_IN_PEB_OFFSET 12
	#define IN_LOAD_ORDER_MODULE_LIST_OFFSET 12
	#define DLL_BASE_OFFSET 24
#endif

// The sequence of modules loaded into the process typically follows the order:
// [Executable Image], [ntdll.dll], [kernel32.dll].
#define base_addr *(uintptr_t*)(*(uintptr_t*)(*(uintptr_t*)(*(uintptr_t*)(*(uintptr_t*)(PEB + LDR_DATA_IN_PEB_OFFSET) + IN_LOAD_ORDER_MODULE_LIST_OFFSET))) + DLL_BASE_OFFSET)

int main()
{
    printf("Kernel32.dll Base Address: 0x%p\n", base_addr);
    
    //eax = base + 3C	==> sign
    uintptr_t* eax = (uintptr_t*)(base_addr + 0x3C);
    printf("RVA of PE signature: \t0x%p - 0x%x\n", eax, *eax);
    //eax = base + [eax]
	eax = (uintptr_t*)(base_addr + *eax);
    printf("Address PE signature: \t0x%p - 0x%x\n", eax, *eax);
	//eax = base + 170h
    eax = (uintptr_t*)((unsigned char*)eax + 0x78);
    printf("RVA of Export: \t\t0x%p - 0x%x\n", eax, *eax);
    //eax = base + [eax]
    eax = (uintptr_t*)(base_addr + *eax);
    printf("Address Export Table: \t0x%p - 0x%x\n", eax, *eax);
    //ecx = eax + 24h
	uintptr_t* ecx = (uintptr_t*)((unsigned char*)eax + 0x24);
	printf("RVA of Ordinal: \t0x%p - 0x%x\n", ecx, *ecx);
	//ecx = base_addr + [ecx]
	ecx = (uintptr_t*)(base_addr + *ecx);
	printf("Address RVA of Ordinal: 0x%p - 0x%x\n", ecx, (unsigned short)*ecx);
	//edi = eax + 24h
	uintptr_t* edi = (uintptr_t*)((unsigned char*)eax + 0x20);
	printf("RVA of Name: \t\t0x%p - 0x%x\n", edi, *edi);
	//edi = base_addr + [edi]
	edi = (uintptr_t*)(base_addr + *edi);
	printf("Address RVA of Name: \t0x%p - 0x%x\n", edi, *edi);
	//edx = eax + 1ch
	uintptr_t* edx = (uintptr_t*)((unsigned char*)eax + 0x1c);
	printf("RVA of Address: \t0x%p - 0x%x\n", edx, *edx);
	//edx = base_addr + [edx]
	edx = (uintptr_t*)(base_addr + *edx);
	printf("Address RVA of Address: 0x%p - 0x%x\n", edx, *edx);
	//edx = eax + 14h
	int nums = *(uintptr_t*)((unsigned char*)eax + 0x14);
	printf("Number functions: 0x%x - %d\n", nums, nums);
	
	uintptr_t* var12 = ecx;
	uintptr_t* var16 = edi;
	uintptr_t* var20 = edx;
	
	char var4[80];
	do {
		printf("\nFunction Name (Blank to Exit)): ");
		gets(var4);
		if (strcmp(var4, "") == 0)
			break;	
		
		int counter = 0;
		while (counter < nums)
		{
			ecx = var12;
			edi = var16;
			edx = var20;
			
			//edi, [edi + eax*4]
			edi = (uintptr_t*)((unsigned char*)edi + counter*4);
			edi = (uintptr_t*)(base_addr + *edi);
			//printf("%d(0x%x).Address of RVA Name: \t0x%p - 0x%x", counter, counter, edi, *edi);
			int i = 0;
			int kt = 1;
			for (i = 0; i < strlen(var4); i++)
			{
				//printf("%d(0x%x).Address: %c - %c\n", counter, *((char *)edi+i), *(var4+i));
				if (*((char *)edi+i)!= *(var4+i))
				{
					kt = 0;
					break;
				}
			}
			
			if (kt)
			{
				printf("\t(counter RVA Name) = %d(0x%x) ==> Found RVA Name %s:\t0x%p\n", counter, counter, var4, edi);
				//eax = ecx + counter*2
				printf("\tAddress base of RVA Ordinal: 0x%p\n", ecx);
				eax = (uintptr_t*)((unsigned char*)ecx + counter*2);
				//counter = [eax]
				printf("\tAddress %s of RVA Ordinal: \n\t\t\t\t\t= (base of RVA Ordinal) + (counter RVA Name)*2:\n", var4);
				printf("\t\t\t\t\t= 0x%p - %d(0x%x)\n", eax, (unsigned short)*eax, (unsigned short)*eax);
				//eax = edx + counter*4
				eax = (uintptr_t*)((unsigned char*)edx + ((unsigned short)*eax)*4);
				printf("\tAddress base of RVA Address: 0x%p\n", edx);
				printf("\tAddress %s of RVA Address: \n\t\t\t\t\t= (base of RVA Address) + (Value %s of RVA Ordinal)*4:\n", var4, var4);
				printf("\t\t\t\t\t= 0x%p - 0x%x\n", eax, *eax);
				//eax = base_addr + [eax]
				eax = (uintptr_t*)(base_addr + *eax);
				printf("\tAddress Func Name %s: 0x%p\n", var4, eax);
				
				break;
			}
			counter++;
		}
	} while (1);
}
