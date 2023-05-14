#include <inc/memlayout.h>
#include <kern/kheap.h>
#include <kern/memory_manager.h>

//2022: NOTE: All kernel heap allocations are multiples of PAGE_SIZE (4KB)

//uint32 my_page_and_frame_size=PAGE_SIZE

//int K_arr[((KERNEL_HEAP_MAX-KERNEL_HEAP_START))/PAGE_SIZE];
struct K_MALLOC_ALLOCATE{
	int counter;
	uint32 *address;
};
//1024 -1 1023

struct K_MALLOC_ALLOCATE K_arr[((KERNEL_HEAP_MAX-KERNEL_HEAP_START))/PAGE_SIZE];
int any_page_size=PAGE_SIZE;
int Z=-1;
int MY_indx = 0;
uint32 *global=(uint32*)KERNEL_HEAP_START;
void* kmalloc(unsigned int size)
{
	int Free_AREA = 0;
	int Address_of_end_allocation;
 	int ST_ADDRESS_ALLOCATION=Z;
	int MY_Count = 0;
	int i=(uint32)global;
	while( i < KERNEL_HEAP_MAX )
	{
		uint32 *ptr = NULL;
		//get_frame_info ==> Used to get both the page table
		//				 ==> and the frame of the given virtual address
		struct Frame_Info *frame_info_ptr = get_frame_info(ptr_page_directory, (void*)i, &ptr);
		if(frame_info_ptr == NULL)
		{
			Free_AREA += any_page_size;
			 MY_Count++;
		}
		else
		{
			//10 11 12
			// 13
			if(Free_AREA >= size )
			{
				//نهايه المساحه الفاضيه
				Address_of_end_allocation = i;
				// بدايه المساحه اللي فاضيه
				ST_ADDRESS_ALLOCATION = Address_of_end_allocation - ( MY_Count*any_page_size);
				break;
		     }
			Free_AREA = 0;
			 MY_Count = 0;
		}
		i += any_page_size;
	}
	if(Free_AREA >= size )
	{
		Address_of_end_allocation = i;
		ST_ADDRESS_ALLOCATION = Address_of_end_allocation - ( MY_Count*any_page_size);
	}
//Z=-1
	if(ST_ADDRESS_ALLOCATION==Z)
	{
		int j;
		 MY_Count=0;
	Free_AREA=0;
	for(j = (uint32)KERNEL_HEAP_START; j < (uint32)global; j += any_page_size)
		{
			uint32 *pointer = NULL;
			struct Frame_Info *frame_info_ptr = get_frame_info(ptr_page_directory, (void*)j, &pointer);
			if(frame_info_ptr == NULL)
			{
				Free_AREA += PAGE_SIZE;
				 MY_Count++;
			}
			else
			{
				if(Free_AREA >= size )
				{
					Address_of_end_allocation = j;
					ST_ADDRESS_ALLOCATION = Address_of_end_allocation - ( MY_Count*any_page_size);
					break;
			     }
				Free_AREA = 0;
				 MY_Count= 0;
			}
		}
		if(Free_AREA >= size )
		{
			Address_of_end_allocation = j;
			ST_ADDRESS_ALLOCATION = Address_of_end_allocation - ( MY_Count*any_page_size);
		}
		if(ST_ADDRESS_ALLOCATION== Z)
		{

			return NULL;

		}

	}


    //save start address, allocated size

    int end_address = ST_ADDRESS_ALLOCATION + size;
    int A = ST_ADDRESS_ALLOCATION;
	while( A < end_address  )
	{
		struct Frame_Info *frame_info_ptr = NULL;
		allocate_frame(&frame_info_ptr);
		map_frame(ptr_page_directory, frame_info_ptr,(void*)A ,PERM_PRESENT|PERM_WRITEABLE);
		A += any_page_size;
	}

	K_arr[MY_indx].address = (uint32*)ST_ADDRESS_ALLOCATION;
		K_arr[MY_indx].counter = ROUNDUP(size, PAGE_SIZE);
		MY_indx++;
		global=(uint32*)ROUNDUP(end_address,any_page_size);
	return (void *)ST_ADDRESS_ALLOCATION;
}


void kexpand(uint32 newSize)
{
	int extentedsize;
	extentedsize = newSize-K_arr[MY_indx-1].counter;


	int extendedsize_pages=ROUNDUP(extentedsize,PAGE_SIZE);
	uint32 j=(uint32) K_arr[MY_indx-1].address+K_arr[MY_indx-1].counter;
	int end=j+extentedsize;
	while(j<end)
	{

		struct Frame_Info *frame_info_ptr = NULL;
		allocate_frame(&frame_info_ptr);
		map_frame(ptr_page_directory, frame_info_ptr,(void*)j ,PERM_PRESENT|PERM_WRITEABLE);
		j+= any_page_size;


	}
K_arr[MY_indx-1].counter=newSize;

}

void kfree(void* virtual_address)
{
	int i=0;
			int my_index;// my_index =3
			while(i<MY_indx)
			{
				if((void *)K_arr[i].address==virtual_address)
				{
					my_index=i;
					break;
				}


				i++;
			}
			// end
			//...
			//...
			//...
			//start
			uint32 end=(uint32)virtual_address+ROUNDDOWN(K_arr[my_index].counter,PAGE_SIZE);

			for(uint32 i=(uint32)virtual_address;i<end ;i+=PAGE_SIZE )
			{
				unmap_frame(ptr_page_directory,(uint32 *)i);


			}
			int number=K_arr[my_index].counter/PAGE_SIZE;
			K_arr[my_index ]=K_arr[MY_indx-1];
			MY_indx--;

}

unsigned int kheap_virtual_address(unsigned int physical_address)
{
	uint32 mycount = KERNEL_HEAP_START ;
			while(mycount<(uint32)global)
			{
				//pointer to page table
				uint32* P_P_t;
				struct Frame_Info* frame_info = NULL;
				frame_info = get_frame_info(ptr_page_directory, (void*)mycount, &P_P_t);
				if(frame_info != NULL)
				{
					uint32 searched_phiscal_adderss = to_physical_address(frame_info);
					if(searched_phiscal_adderss == physical_address)
					return mycount;
				}
				 mycount+=PAGE_SIZE;
			}
		return 0;
}

unsigned int kheap_physical_address(unsigned int virtual_address)
{

	//from assiment 2 and 3
	//هعمل بوينتر يشاور علي page table
		uint32* needed_pointer = NULL;
		//كده انا عملت البوينتر
		get_page_table(ptr_page_directory, (void*)virtual_address, &needed_pointer);
		//كده انا شاورت علي page table بتاعي بالبوينتر
// P M F offset>>12
		//هروح اجيب الاندكس بتاع الادرس ده
		int ind=PTX(virtual_address);
		uint32 x=0x00000fff;
		uint32 offset=virtual_address & x;
		//طبعا ال الانتري فيها P , M ,f#,offset
		//فلازم اعمل شيفت رايت ب 12 علشان اجيب رقم الفريم
		int framnumber=needed_pointer[ind]>>12;
		//خلاص كده جيب (Phiscal address )
		return ((framnumber) * PAGE_SIZE)+(offset);
		//PA (F# *pagesize) +offset

}

