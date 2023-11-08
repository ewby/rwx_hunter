#include <windows.h>
#include <stdio.h>
#include <psapi.h>

int main() 
{
    DWORD aProcesses[1024];
    DWORD cbNeeded = 0; 
    DWORD cProcesses = 0;
    unsigned int i = 0;

    if (!EnumProcesses(aProcesses, sizeof(aProcesses), &cbNeeded)) 
    {
        return 1;
    }

    cProcesses = cbNeeded / sizeof(DWORD);

    for (i = 0; i < cProcesses; i++) 
    {
        if (aProcesses[i] != 0) 
	{
	    HANDLE hProcess = NULL;
	    
	    hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, aProcesses[i]);
            
            if (hProcess != NULL) 
	    {
                HMODULE hMods[1024];
                DWORD cbNeededMods = 0;

                if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeededMods)) 
		{
                    for (unsigned int j = 0; j < (cbNeededMods / sizeof(HMODULE)); j++) 
		    {
                        MODULEINFO modInfo;

                        if (GetModuleInformation(hProcess, hMods[j], &modInfo, sizeof(modInfo))) 
			{
                            MEMORY_BASIC_INFORMATION mbi;
                            unsigned char *addr = (unsigned char*)modInfo.lpBaseOfDll;

                            while ((uintptr_t)addr < (uintptr_t)modInfo.lpBaseOfDll + modInfo.SizeOfImage && VirtualQueryEx(hProcess, addr, &mbi, sizeof(mbi))) 
			    {
                                if (mbi.State == MEM_COMMIT && (mbi.Protect & PAGE_EXECUTE_READWRITE)) 
				{
                                    printf("Process ID: %u, Module Base: %p, RWX Region: %p, Offset: 0x%X\n", 
                                            aProcesses[i], 
                                            modInfo.lpBaseOfDll, 
                                            mbi.BaseAddress, 
                                            (unsigned int)((uintptr_t)mbi.BaseAddress - (uintptr_t)modInfo.lpBaseOfDll));
                                }
                                
                                addr += mbi.RegionSize;
                            }
                        }
                    }
                }
                
                CloseHandle(hProcess);
            }
        }
    }

    return 0;
}

