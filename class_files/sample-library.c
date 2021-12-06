#include <link.h>
#include <stdlib.h>
#include <stdio.h>
#include <dlfcn.h>
#include <string.h>
#include <sys/mman.h>
#include "plthook.h"
#include "pmparser.h"
//#include "foo.h"

int (*dummy_func_ptr)(char*,...);
int (*printf_ptr)(char*,...);
//void (*dummy_func_ptr);
//void (*printf_ptr);
void (*nanosleep_ptr);
void (*nanosleep_copy_ptr);
unsigned long translation;

/* This function is called instead of recv() called by libfoo.so.1  */
static int my_foo(int var)
{
  puts("puts called");
  (*printf_ptr)("hello\n");
  return 10;
}

int install_hook_function()
{
 //... install hook function
 //... update printf and nanosleep addresses
	printf("inst_hook_func\n");
	plthook_t *plthook;
	if (plthook_open(&plthook, "") != 0){
		return -1;
	}
	if (plthook_replace(plthook, "printf", (void*)dummy_func_ptr, NULL) !=0){
		plthook_close(plthook);
		return -1;
	}
	if(plthook_replace(plthook,"nanosleep", (void*)nanosleep_copy_ptr, NULL) !=0){
		plthook_close(plthook);
		return -1;
	}
	plthook_close(plthook);
    return 0;
}


int print_plt_entries(const char *filename)
{
    plthook_t *plthook;
    unsigned int pos = 0; /* This must be initialized with zero. */
    const char *name;
    void **addr;

    if (plthook_open(&plthook, filename) != 0) {
        printf("plthook_open error: %s\n", plthook_error());
        return -1;
    }
    while (plthook_enum(plthook, &pos, &name, &addr) == 0) {
        printf("%p(%p) %s\n", addr, *addr, name);
	if (strncmp(name,"printf",6) == 0){
		//printf("hello\n");
		printf_ptr = *addr;
	} else if(strncmp(name,"nanosleep",9) == 0){
		nanosleep_ptr = *addr;
	}
    }
    plthook_close(plthook);
    return 0;
}

// Allocates RWX memory of given size and returns a pointer to it. On failure,
// prints out the error and returns NULL.
void* alloc_executable_memory(void *addr,size_t size) {
  void* ptr = mmap(addr, size,
                   PROT_READ | PROT_WRITE | PROT_EXEC,
                   MAP_SHARED | MAP_ANONYMOUS, -1, 0);
  if (ptr == (void*)-1) {
    //perror("mmap");
    return NULL;
  }
  return ptr;
}

/*
 MSB           LSB
 _      _      _
 PF_R   PF_W   PF_X
text segment
	- p_type = PT_LOAD
	- p_flags = PF_X && !PF_W
data segment
	- p_type = PT_LOAD
	- p_flags = PF_W && !PF_X
*/
 static int
 callback(struct dl_phdr_info *info, size_t size, void *data)
 {
     int j;
     int segment_flags;
     int flags_mask = 3; // mask for PF_W and PF_X
     int segment_type;

    printf("name=%s (%d segments)\n", info->dlpi_name,
         info->dlpi_phnum);
    printf("address=%10p\n",(void *)(info->dlpi_addr));

    // Declare variables
    char *libc_text_copy_ptr;
    char *libc_text_ptr;
    char *libc_data_ptr;
    unsigned long toAdd = 0;
    unsigned long libc_total_copy_size = 0;
    unsigned long text_size = 0;
    unsigned long data_size = 0;
    unsigned long data_segment_offset = 0;
    unsigned long lea_opcode;
    unsigned long *lea_opcode_ptr;
    unsigned long data_copy_begin = 0;
    unsigned long data_copy_end = 0;

    char *test_ptr;
    unsigned long *test_data_address;
    unsigned long test_data_pointer;
    unsigned long mask;

    // Initialize variables
    libc_text_copy_ptr = (char *)0;
    libc_text_ptr = (char *)0;
    libc_data_ptr = (char *)0;


    // looping through segments within shared libraries and categorizing them
    // as text/code segments or data segments
    for (j = 0; j < info->dlpi_phnum; j++)
 	if (info->dlpi_phdr[j].p_type == 1){
 		segment_flags = info->dlpi_phdr[j].p_flags;
 		segment_type = segment_flags & flags_mask;
		
 		if (segment_type == 1){
         		printf("\t\t header %2d: address=%10p: memsize=%lu: type=text segment\n", j,
              (void *) (info->dlpi_addr + info->dlpi_phdr[j].p_vaddr),info->dlpi_phdr[j].p_memsz);
 		} else if (segment_type == 2){
 			printf("\t\t header %2d: address=%10p: memsize=%1lu: type=data segment\n", j,
              (void *) (info->dlpi_addr + info->dlpi_phdr[j].p_vaddr),info->dlpi_phdr[j].p_memsz);
 		}

		                                   
 		if (strncmp(info->dlpi_name,"/lib/x86_64-linux-gnu/libc.so.6",31) == 0){
 			if (segment_type == 1){
 				text_size = info->dlpi_phdr[j].p_memsz;
 				libc_text_ptr = (char *)info->dlpi_addr + info->dlpi_phdr[j].p_vaddr;

				data_size = info->dlpi_phdr[j+1].p_memsz;
 				libc_data_ptr = (char *)info->dlpi_addr + info->dlpi_phdr[j+1].p_vaddr;
				data_segment_offset = libc_data_ptr - libc_text_ptr;
				libc_total_copy_size = data_size + (unsigned long)data_segment_offset;	
				
				libc_text_copy_ptr = (char *) alloc_executable_memory(0,libc_total_copy_size);
 				memcpy(libc_text_copy_ptr,libc_text_ptr,text_size);
				memcpy((libc_text_copy_ptr+data_segment_offset),libc_data_ptr,data_size);

				translation = libc_text_ptr-libc_text_copy_ptr;
				unsigned long printf_offset = 0;
				// dummy_func and nanosleep_copy
 				printf_offset = ((char*)printf_ptr - libc_text_ptr);
 				dummy_func_ptr = (int*)libc_text_copy_ptr + printf_offset; 
				unsigned long nanosleep_offset = 0;
				nanosleep_offset = ((char*)nanosleep_ptr - libc_text_ptr);
				nanosleep_copy_ptr = libc_text_copy_ptr + nanosleep_offset;

				test_ptr = (char*)(libc_data_ptr);;
				unsigned long i = 0;
				int lea_count = 0;
				unsigned long data_begin;
				unsigned long data_end;
				unsigned long text_begin;
				unsigned long text_end;
				text_begin = (unsigned long)libc_text_ptr;
				text_end = (unsigned long)(libc_text_ptr + text_size);
				data_begin = (unsigned long)(libc_text_ptr + data_segment_offset);
				data_end = (unsigned long)(libc_text_ptr + data_segment_offset + data_size);
				data_copy_begin = (unsigned long)(libc_text_copy_ptr + data_segment_offset);
				data_copy_end = (unsigned long)(libc_text_copy_ptr + data_segment_offset + data_size);
				//printf("Text begin: %lx\n",text_begin);
				//printf("Text end:   %lx\n",text_end);
				printf("Data begin: %lx\n",data_begin);
				printf("Data end:   %lx\n",data_end);
				printf("Data copy begin: %lx\n",data_copy_begin);
				printf("Data copy end:   %lx\n",data_copy_end);
				test_ptr = (char *)data_copy_begin;
				for (i=0;i<data_size;i++){
					test_data_address = (unsigned long*)(test_ptr+i);
					test_data_pointer = *(test_data_address);
					if (test_data_pointer > data_begin && test_data_pointer < data_end) {
						*(test_data_address) = test_data_pointer - translation;
						test_data_pointer = *(test_data_address);
						printf("Data segment address: %p, value: %lx\n",test_data_address,test_data_pointer);
					} else if (test_data_pointer > text_begin && test_data_pointer < text_end) {
						*(test_data_address) = test_data_pointer - translation;
						test_data_pointer = *(test_data_address);
						printf("Data segment address: %p, value: %lx\n",test_data_address,test_data_pointer);
					}
					
				}
				
 			}
 		}
 	}
    return 0;
 }

/*
 * hello()
 *
 * Hello world function exported by the sample library.
 *
 */

void hello()
{
	printf("I just got loaded\n");
}

int printProcessMemory()
{
    int pid=-1; //-1 to use the running process id, use pid>0 to list the map of another process
  procmaps_iterator* maps = pmparser_parse(pid);
    if(maps==NULL){
        printf ("[map]: cannot parse the memory map of %d\n",pid);
        return -1;
    }

    //iterate over areas
    procmaps_struct* maps_tmp=NULL;
    
    while( (maps_tmp = pmparser_next(maps)) != NULL){
        pmparser_print(maps_tmp,0);
        printf("\n~~~~~~~~~~~~~~~~~~~~~~~~~\n"); 
    }

    //mandatory: should free the list
    pmparser_free(maps);
    return 0;
}

/*
 * loadMsg()
 *
 * This function is automatically called when the sample library is injected
 * into a process. It calls hello() to output a message indicating that the
 * library has been loaded.
 *
 */

__attribute__((constructor))
void loadMsg()
{
    //printProcessMemory();
	print_plt_entries("");
	printf("____________________\n");
	//print_plt_entries("name=/lib/x86_64-linux-gnu/libc.so.6");
	dl_iterate_phdr(callback, NULL);
	printf("Address of printf is :%p\n", printf);
	printf("Address of dummy ptr is :%p\n",dummy_func_ptr);
	printf("Address of my_foo is :%p\n",my_foo);
	printf("Starting plt part\n");
	//printf("Address of function foo is :%p\n", foo);
	print_plt_entries("");
	install_hook_function();
	print_plt_entries("");
	hello();
}
__attribute__((destructor))
void loadMsgs()
{
	printf("Goodbye\n");
    //printProcessMemory();
	print_plt_entries("");
	//printf("____________________");
	//print_plt_entries("name=/lib/x86_64-linux-gnu/libc.so.6");
	//dl_iterate_phdr(callback, NULL);
	//printf("Address of printf is :%p\n", printf);
	//printf("Address of dummy ptr is :%p\n",dummy_func_ptr);
	//printf("Address of my_foo is :%p\n",my_foo);
	//printf("Starting plt part\n");
	//printf("Address of function foo is :%p\n", foo);
	//print_plt_entries("");
	//install_hook_function();
	//print_plt_entries("");
	//hello();
	printf("Goodbye\n");
}