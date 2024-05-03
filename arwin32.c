#include <windows.h>
#include <stdio.h>

/***************************************
arwin - win32 address resolution program
by steve hanna v.01
   vividmachines.com
   shanna@uiuc.edu
you are free to modify this code
but please attribute me if you
change the code. bugfixes & additions
are welcome please email me!
to compile:
you will need a win32 compiler with
the win32 SDK

this program finds the absolute address
of a function in a specified DLL.
happy shellcoding!
***************************************/

int main(int argc, char** argv)
{
	char lib[80];
	char func[80];
	FARPROC fprc_func;
	HMODULE hmod_libname;
	
	do
	{
		printf("\narwin - win32 address resolution program - by steve hanna - v.01\n");
		printf("Library Name (Blank to Exit)): ");			
		gets(lib);
		if (strcmp(lib, "") == 0) break;
		
		hmod_libname = LoadLibrary(lib);
		if(hmod_libname == NULL)
		{
			printf("Error: could not load library!\n");
			continue;
		}
		do
		{
			printf("   + Function Name (Blank to input LIB)): ");
			gets(func);
			if (strcmp(func, "") == 0)
				break;
			
			fprc_func = GetProcAddress(hmod_libname,func);
			if(fprc_func == NULL)
			{
				printf("   \tError: could find the function in the library!\n");
				continue;
			}	
			printf("   \t%s is located at 0x%08x\n",func,(unsigned int)fprc_func);
		} while (1);
	} while (1);
}
