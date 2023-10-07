#include <iostream>
#include "util.h"
#include "elf_parser.h"
#include "remote_dlsym.h"
#include <sys/mman.h>
#include "test_binso.hpp"
#include <string.h>

int main()
{
    auto raddr = (uintptr_t)mmap(NULL,0x1000000,PROT_READ|PROT_EXEC|PROT_WRITE,MAP_ANONYMOUS|MAP_PRIVATE,0,0);
    raddr &= 0x00FFFFFFFFFFFFFF;
    p1x(raddr);
    
    if(raddr == 0)
    {
        return -1;
    }
    
    auto relf=(u8*)malloc(0x2000000);
	
	
    if(relf)
    {
		auto filedata = (u8*)test_binso::binary_data;
		auto imgsz = elf_get_image_sz(filedata);
        mapelf(getpid(),raddr,filedata,relf);
		memcpy((void*)raddr,relf,imgsz);
		auto vecInit = elf_parse_initsect(filedata,relf);
		
		for(auto initaddr : vecInit)
		{
			p1x(initaddr);
			using initfn = void(*)(void);
			auto fn = (initfn)initaddr;
			fn();
		}
		
        free(relf);
        relf = NULL;
    }
	
	munmap((void*)raddr,0x1000000);
	
	puts("ok!");
    
    return 0;
}  
