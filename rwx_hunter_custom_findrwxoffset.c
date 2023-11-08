//
// WIP, trying to get PE parsing to work properly
//

#include <windows.h>
#include <stdio.h>
#include <psapi.h>
#include <winnt.h>

//
// calculate the offset to the RWX memory region of a DLL
//
DWORD_PTR FindRWXOffset(HMODULE hMods)
{
    //
    // obtain the base address of the module
    //

    //
    // obtain the IMAGE_DOS_HEADER
    //
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)hMods;
    
    printf("base address obtained %p\n", hMods);
    
    //
    // calculate the address of IMAGE_NT_HEADERS
    //
    PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)(hMods + dosHeader->e_lfanew);
    printf("nt headers obtained %p\n", ntHeader);

    //
    // verify the NT signature
    //
    if (ntHeader->Signature != IMAGE_NT_SIGNATURE)
    {
	printf("invalid nt signature");
        return 0; // Invalid PE file
    }

    IMAGE_SECTION_HEADER* sectionHeader = IMAGE_FIRST_SECTION(ntHeader);
    for (WORD i = 0; i < ntHeader->FileHeader.NumberOfSections; i++)
    {
        DWORD characteristics = sectionHeader->Characteristics;
        printf("Section %d characteristics: 0x%X\n", i, characteristics);

        // Check if section has executable, readable, and writable permissions
        if ((characteristics & IMAGE_SCN_MEM_EXECUTE) &&
            (characteristics & IMAGE_SCN_MEM_READ) &&
            (characteristics & IMAGE_SCN_MEM_WRITE))
        {
            DWORD_PTR sectionOffset = sectionHeader->VirtualAddress;
            DWORD_PTR rwxOffset = hMods + sectionOffset;
	    printf("offset: 0x%lu", rwxOffset);
            return rwxOffset;
        }

        sectionHeader++;
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
                HMODULE hMods[1024];
                DWORD bytes_needed_mods;

		//
		// if hProcess isn't null, enumerate it's modules and receive handles to the modules (hMods)
		//
                if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &bytes_needed_mods)) 
		{
		    //
		    // let the printf debugging begin
		    //
		    printf("inside EnumProcessModules\n");
                    for (unsigned int j = 0; j < (bytes_needed_mods / sizeof(HMODULE)); j++) 
		    {
			printf("inside the for loop inside EnumProcessModules\n");
			printf("printing value of hMods %lu\n", hMods);
			printf("printing value of hMods[j] %lu\n", hMods[j]);
                        
			DWORD_PTR rwxOffset = FindRWXOffset(hMods[j]);

			printf("still in the for loop, just after FindRWXOffset function call\n");
                        
			if (rwxOffset != 0) 
			{
                            printf("Process ID: %u, Module Base: %p, RWX Section Offset: 0x%X\n",
                                   array_processes[i],
                                   hMods[j],
                                   (unsigned int)(rwxOffset - (DWORD_PTR)hMods[j]));
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
