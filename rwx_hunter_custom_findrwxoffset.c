//
// WIP, i suck at PE parsing but pretty sure you need something like ReadProcessMemory or VirtualQueryEx to be successful with rwx_hunter
//

#include <windows.h>
#include <stdio.h>
#include <psapi.h>
#include <winnt.h>

//
// calculate the offset to the RWX memory region of a DLL
//
DWORD_PTR FindRWXOffset(HMODULE handle_modules)
{
    PIMAGE_DOS_HEADER pDosHeader;
    PIMAGE_NT_HEADERS pNtHeader;
    PIMAGE_SECTION_HEADER pSectionHeader;
    //
    // obtain the base address of the module
    //
    // DWORD_PTR baseAddress = (DWORD_PTR)handle_modules;

    //
    // obtain the IMAGE_DOS_HEADER
    //
    pDosHeader = (PIMAGE_DOS_HEADER)handle_modules;

    printf("base address obtained %p\n", pDosHeader);

    //
    // segfault occurring here, probably handle issues from EnumProcessModules not returning a parsable handle, instead being a reference
    //
    if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
    {
        printf("invalid DOS signature %s", pDosHeader->e_lfanew);
        return 0;
    }
    else
    {
        printf("valid DOS signature, continuing!");
    }

    //
    // calculate the address of IMAGE_NT_HEADERS
    //
    pNtHeader = (PIMAGE_NT_HEADERS)((PBYTE) pDosHeader + pDosHeader->e_lfanew);
    printf("nt headers obtained %p\n", pNtHeader);

    //
    // verify the NT signature
    //
    if (pNtHeader->Signature != IMAGE_NT_SIGNATURE)
    {
	    printf("invalid nt signature");
        return 0; // Invalid PE file
    }

    pSectionHeader = IMAGE_FIRST_SECTION(pNtHeader);
    for (WORD i = 0; i < pNtHeader->FileHeader.NumberOfSections; i++)
    {
        DWORD characteristics = pSectionHeader->Characteristics;
        printf("Section %d characteristics: 0x%X\n", i, characteristics);

        // Check if section has executable, readable, and writable permissions
        if ((characteristics & IMAGE_SCN_MEM_EXECUTE) &&
            (characteristics & IMAGE_SCN_MEM_READ) &&
            (characteristics & IMAGE_SCN_MEM_WRITE))
        {
            DWORD_PTR sectionOffset = pSectionHeader->VirtualAddress;
            DWORD_PTR rwxOffset = handle_modules + sectionOffset;
	        printf("offset: 0x%lu", rwxOffset);
            return rwxOffset;
        }

        pSectionHeader++;
    }

    return 0; // No suitable section found
}

int main() 
{
    //
    // init variables for processes array, bytes returned from EnumProcesses, and the final variable for existing process PIDs
    // 
    DWORD array_processes[1024];
    DWORD bytes_needed_pid; 
    DWORD processes_pids;
    unsigned int i;
    HANDLE hProcess;

    if (!EnumProcesses(array_processes, sizeof(array_processes), &bytes_needed_pid)) 
    {
        return 1;
    }

    //
    // divide returned bytes from EnumProcesses by DWORD which is the type of PID
    //
    processes_pids = bytes_needed_pid / sizeof(DWORD);

    //
    // for loop to iterate over each PID with necessary access rights and get those with RWX memory regions
    //
    for (i = 0; i < processes_pids; i++) 
    {
        //
        // take output of EnumProcesses, select first in array and perform if statement if not 0
        //
        if (array_processes[i] != 0) 
	    {
            //
            // obtain handle to the specified process in process array
            //
            hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, array_processes[i]);

            if (hProcess != NULL) 
	        {
                HMODULE handle_modules[1024];
                DWORD bytes_needed_mods;

                //
                // if hProcess isn't null, enumerate it's modules and receive handles to the modules (handle_modules)
                //
                if (EnumProcessModules(hProcess, handle_modules, sizeof(handle_modules), &bytes_needed_mods))
		        {
                    //
                    // let the printf debugging begin
                    //
                    printf("inside EnumProcessModules\n");
                    for (unsigned int j = 0; j < (bytes_needed_mods / sizeof(HMODULE)); j++)
		            {
                        printf("inside the for loop inside EnumProcessModules\n");
                        printf("printing value of handle_modules %p\n", handle_modules);
                        printf("printing value of handle_modules[j] %p\n", handle_modules[j]);
                        
                        DWORD_PTR rwxOffset = FindRWXOffset(handle_modules[j]);

                        printf("still in the for loop, just after FindRWXOffset function call\n");
                        
			            if (rwxOffset != 0)
			            {
                            printf("Process ID: %u, Module Base: %p, RWX Section Offset: 0x%X\n",
                                   array_processes[i],
                                   handle_modules[j],
                                   (unsigned int)(rwxOffset - (DWORD_PTR)handle_modules[j]));
                        }
                    }
                }

                CloseHandle(hProcess);
            }
            else
            {
                printf("OpenProcess failed. PID: %u, Error Code: %lu\n", array_processes[i], GetLastError());
            }

        }
    }

    return 0;
}
