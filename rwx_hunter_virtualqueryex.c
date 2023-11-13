#include <windows.h>
#include <stdio.h>
#include <psapi.h>

int main() 
{
    DWORD array_processes[1024];
    DWORD bytes_needed_pid = 0;
    DWORD processes_pids = 0;
    unsigned int i = 0;

    if (!EnumProcesses(array_processes, sizeof(array_processes), &bytes_needed_pid))
    {
        return 1;
    }

    processes_pids = bytes_needed_pid / sizeof(DWORD);

    for (i = 0; i < processes_pids; i++)
    {
        if (array_processes[i] != 0)
            {
                HANDLE hProcess = NULL;

                hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, array_processes[i]);
            
                if (hProcess != NULL)
                {
                    HMODULE handle_modules[1024];
                    DWORD bytes_needed_mods = 0;

                    if (EnumProcessModules(hProcess, handle_modules, sizeof(handle_modules), &bytes_needed_mods))
		            {
                        for (unsigned int j = 0; j < (bytes_needed_mods / sizeof(HMODULE)); j++)
		                {
                            MODULEINFO module_info;

                            if (GetModuleInformation(hProcess, handle_modules[j], &module_info, sizeof(module_info)))
			                {
                                MEMORY_BASIC_INFORMATION mbi;
                                unsigned char *addr = (unsigned char*)module_info.lpBaseOfDll;

                                while ((uintptr_t)addr < (uintptr_t)module_info.lpBaseOfDll + module_info.SizeOfImage && VirtualQueryEx(hProcess, addr, &mbi, sizeof(mbi)))
			                    {
                                    if (mbi.State == MEM_COMMIT && (mbi.Protect & PAGE_EXECUTE_READWRITE))
				                    {
                                        printf("Process ID: %u, DLL Base Address: %p, RWX Memory Region: %p, Offset: 0x%X\n",
                                                array_processes[i],
                                                module_info.lpBaseOfDll,
                                                mbi.BaseAddress,
                                                (unsigned int)((uintptr_t)mbi.BaseAddress - (uintptr_t)module_info.lpBaseOfDll));
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

