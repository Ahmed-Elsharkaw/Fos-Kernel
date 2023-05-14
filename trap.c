#include <inc/mmu.h>
#include <inc/x86.h>
#include <inc/assert.h>

#include <kern/memory_manager.h>
#include <kern/trap.h>
#include <kern/console.h>
#include <kern/command_prompt.h>
#include <kern/user_environment.h>
#include <kern/file_manager.h>
#include <kern/syscall.h>
#include <kern/sched.h>
#include <kern/kclock.h>
#include <kern/trap.h>

extern void __static_cpt(uint32 *ptr_page_directory, const uint32 virtual_address, uint32 **ptr_page_table);

void __page_fault_handler_with_buffering(struct Env * curenv, uint32 fault_va);
void page_fault_handler(struct Env * curenv, uint32 fault_va);
void table_fault_handler(struct Env * curenv, uint32 fault_va);

static struct Taskstate ts;

//2014 Test Free(): Set it to bypass the PAGE FAULT on an instruction with this length and continue executing the next one
// 0 means don't bypass the PAGE FAULT
uint8 bypassInstrLength = 0;


/// Interrupt descriptor table.  (Must be built at run time because
/// shifted function addresses can't be represented in relocation records.)
///

struct Gatedesc idt[256] = { { 0 } };
struct Pseudodesc idt_pd = {
		sizeof(idt) - 1, (uint32) idt
};
extern  void (*PAGE_FAULT)();
extern  void (*SYSCALL_HANDLER)();
extern  void (*DBL_FAULT)();

extern  void (*ALL_FAULTS0)();
extern  void (*ALL_FAULTS1)();
extern  void (*ALL_FAULTS2)();
extern  void (*ALL_FAULTS3)();
extern  void (*ALL_FAULTS4)();
extern  void (*ALL_FAULTS5)();
extern  void (*ALL_FAULTS6)();
extern  void (*ALL_FAULTS7)();
//extern  void (*ALL_FAULTS8)();
//extern  void (*ALL_FAULTS9)();
extern  void (*ALL_FAULTS10)();
extern  void (*ALL_FAULTS11)();
extern  void (*ALL_FAULTS12)();
extern  void (*ALL_FAULTS13)();
//extern  void (*ALL_FAULTS14)();
//extern  void (*ALL_FAULTS15)();
extern  void (*ALL_FAULTS16)();
extern  void (*ALL_FAULTS17)();
extern  void (*ALL_FAULTS18)();
extern  void (*ALL_FAULTS19)();


extern  void (*ALL_FAULTS32)();
extern  void (*ALL_FAULTS33)();
extern  void (*ALL_FAULTS34)();
extern  void (*ALL_FAULTS35)();
extern  void (*ALL_FAULTS36)();
extern  void (*ALL_FAULTS37)();
extern  void (*ALL_FAULTS38)();
extern  void (*ALL_FAULTS39)();
extern  void (*ALL_FAULTS40)();
extern  void (*ALL_FAULTS41)();
extern  void (*ALL_FAULTS42)();
extern  void (*ALL_FAULTS43)();
extern  void (*ALL_FAULTS44)();
extern  void (*ALL_FAULTS45)();
extern  void (*ALL_FAULTS46)();
extern  void (*ALL_FAULTS47)();



static const char *trapname(int trapno)
{
	static const char * const excnames[] = {
			"Divide error",
			"Debug",
			"Non-Maskable Interrupt",
			"Breakpoint",
			"Overflow",
			"BOUND Range Exceeded",
			"Invalid Opcode",
			"Device Not Available",
			"Double Fault",
			"Coprocessor Segment Overrun",
			"Invalid TSS",
			"Segment Not Present",
			"Stack Fault",
			"General Protection",
			"Page Fault",
			"(unknown trap)",
			"x87 FPU Floating-Point Error",
			"Alignment Check",
			"Machine-Check",
			"SIMD Floating-Point Exception"
	};

	if (trapno < sizeof(excnames)/sizeof(excnames[0]))
		return excnames[trapno];
	if (trapno == T_SYSCALL)
		return "System call";
	return "(unknown trap)";
}


void
idt_init(void)
{
	extern struct Segdesc gdt[];

	// LAB 3: Your code here.
	//initialize idt
	SETGATE(idt[T_PGFLT], 0, GD_KT , &PAGE_FAULT, 0) ;
	SETGATE(idt[T_SYSCALL], 0, GD_KT , &SYSCALL_HANDLER, 3) ;
	SETGATE(idt[T_DBLFLT], 0, GD_KT , &DBL_FAULT, 0) ;


	SETGATE(idt[T_DIVIDE   ], 0, GD_KT , &ALL_FAULTS0, 3) ;
	SETGATE(idt[T_DEBUG    ], 1, GD_KT , &ALL_FAULTS1, 3) ;
	SETGATE(idt[T_NMI      ], 0, GD_KT , &ALL_FAULTS2, 3) ;
	SETGATE(idt[T_BRKPT    ], 1, GD_KT , &ALL_FAULTS3, 3) ;
	SETGATE(idt[T_OFLOW    ], 1, GD_KT , &ALL_FAULTS4, 3) ;
	SETGATE(idt[T_BOUND    ], 0, GD_KT , &ALL_FAULTS5, 3) ;
	SETGATE(idt[T_ILLOP    ], 0, GD_KT , &ALL_FAULTS6, 3) ;
	SETGATE(idt[T_DEVICE   ], 0, GD_KT , &ALL_FAULTS7, 3) ;
	//SETGATE(idt[T_DBLFLT   ], 0, GD_KT , &ALL_FAULTS, 3) ;
	//SETGATE(idt[], 0, GD_KT , &ALL_FAULTS, 3) ;
	SETGATE(idt[T_TSS      ], 0, GD_KT , &ALL_FAULTS10, 3) ;
	SETGATE(idt[T_SEGNP    ], 0, GD_KT , &ALL_FAULTS11, 3) ;
	SETGATE(idt[T_STACK    ], 0, GD_KT , &ALL_FAULTS12, 3) ;
	SETGATE(idt[T_GPFLT    ], 0, GD_KT , &ALL_FAULTS13, 3) ;
	//SETGATE(idt[T_PGFLT    ], 0, GD_KT , &ALL_FAULTS, 3) ;
	//SETGATE(idt[ne T_RES   ], 0, GD_KT , &ALL_FAULTS, 3) ;
	SETGATE(idt[T_FPERR    ], 0, GD_KT , &ALL_FAULTS16, 3) ;
	SETGATE(idt[T_ALIGN    ], 0, GD_KT , &ALL_FAULTS17, 3) ;
	SETGATE(idt[T_MCHK     ], 0, GD_KT , &ALL_FAULTS18, 3) ;
	SETGATE(idt[T_SIMDERR  ], 0, GD_KT , &ALL_FAULTS19, 3) ;


	SETGATE(idt[IRQ0_Clock], 0, GD_KT , &ALL_FAULTS32, 3) ;
	SETGATE(idt[33], 0, GD_KT , &ALL_FAULTS33, 3) ;
	SETGATE(idt[34], 0, GD_KT , &ALL_FAULTS34, 3) ;
	SETGATE(idt[35], 0, GD_KT , &ALL_FAULTS35, 3) ;
	SETGATE(idt[36], 0, GD_KT , &ALL_FAULTS36, 3) ;
	SETGATE(idt[37], 0, GD_KT , &ALL_FAULTS37, 3) ;
	SETGATE(idt[38], 0, GD_KT , &ALL_FAULTS38, 3) ;
	SETGATE(idt[39], 0, GD_KT , &ALL_FAULTS39, 3) ;
	SETGATE(idt[40], 0, GD_KT , &ALL_FAULTS40, 3) ;
	SETGATE(idt[41], 0, GD_KT , &ALL_FAULTS41, 3) ;
	SETGATE(idt[42], 0, GD_KT , &ALL_FAULTS42, 3) ;
	SETGATE(idt[43], 0, GD_KT , &ALL_FAULTS43, 3) ;
	SETGATE(idt[44], 0, GD_KT , &ALL_FAULTS44, 3) ;
	SETGATE(idt[45], 0, GD_KT , &ALL_FAULTS45, 3) ;
	SETGATE(idt[46], 0, GD_KT , &ALL_FAULTS46, 3) ;
	SETGATE(idt[47], 0, GD_KT , &ALL_FAULTS47, 3) ;



	// Setup a TSS so that we get the right stack
	// when we trap to the kernel.
	ts.ts_esp0 = KERNEL_STACK_TOP;
	ts.ts_ss0 = GD_KD;

	// Initialize the TSS field of the gdt.
	gdt[GD_TSS >> 3] = SEG16(STS_T32A, (uint32) (&ts),
			sizeof(struct Taskstate), 0);
	gdt[GD_TSS >> 3].sd_s = 0;

	// Load the TSS
	ltr(GD_TSS);

	// Load the IDT
	asm volatile("lidt idt_pd");
}

void print_trapframe(struct Trapframe *tf)
{
	cprintf("TRAP frame at %p\n", tf);
	print_regs(&tf->tf_regs);
	cprintf("  es   0x----%04x\n", tf->tf_es);
	cprintf("  ds   0x----%04x\n", tf->tf_ds);
	cprintf("  trap 0x%08x %s - %d\n", tf->tf_trapno, trapname(tf->tf_trapno), tf->tf_trapno);
	cprintf("  err  0x%08x\n", tf->tf_err);
	cprintf("  eip  0x%08x\n", tf->tf_eip);
	cprintf("  cs   0x----%04x\n", tf->tf_cs);
	cprintf("  flag 0x%08x\n", tf->tf_eflags);
	cprintf("  esp  0x%08x\n", tf->tf_esp);
	cprintf("  ss   0x----%04x\n", tf->tf_ss);
}

void print_regs(struct PushRegs *regs)
{
	cprintf("  edi  0x%08x\n", regs->reg_edi);
	cprintf("  esi  0x%08x\n", regs->reg_esi);
	cprintf("  ebp  0x%08x\n", regs->reg_ebp);
	cprintf("  oesp 0x%08x\n", regs->reg_oesp);
	cprintf("  ebx  0x%08x\n", regs->reg_ebx);
	cprintf("  edx  0x%08x\n", regs->reg_edx);
	cprintf("  ecx  0x%08x\n", regs->reg_ecx);
	cprintf("  eax  0x%08x\n", regs->reg_eax);
}

static void trap_dispatch(struct Trapframe *tf)
{
	// Handle processor exceptions.
	// LAB 3: Your code here.

	if(tf->tf_trapno == T_PGFLT)
	{
		//print_trapframe(tf);
		if(isPageReplacmentAlgorithmLRU())
		{
			//cprintf("===========Table WS before updating time stamp========\n");
			//env_table_ws_print(curenv) ;
			update_WS_time_stamps();
		}
		fault_handler(tf);
	}
	else if (tf->tf_trapno == T_SYSCALL)
	{
		uint32 ret = syscall(tf->tf_regs.reg_eax
				,tf->tf_regs.reg_edx
				,tf->tf_regs.reg_ecx
				,tf->tf_regs.reg_ebx
				,tf->tf_regs.reg_edi
				,tf->tf_regs.reg_esi);
		tf->tf_regs.reg_eax = ret;
	}
	else if(tf->tf_trapno == T_DBLFLT)
	{
		panic("double fault!!");
	}
	else if (tf->tf_trapno == IRQ0_Clock)
	{
		clock_interrupt_handler() ;
	}

	else
	{
		// Unexpected trap: The user process or the kernel has a bug.
		//print_trapframe(tf);
		if (tf->tf_cs == GD_KT)
		{
			panic("unhandled trap in kernel");
		}
		else {
			//env_destroy(curenv);
			return;
		}
	}
	return;
}

void trap(struct Trapframe *tf)
{
	kclock_stop();

	int userTrap = 0;
	if ((tf->tf_cs & 3) == 3) {
		assert(curenv);
		curenv->env_tf = *tf;
		tf = &(curenv->env_tf);
		userTrap = 1;
	}
	if(tf->tf_trapno == IRQ0_Clock)
	{
//		uint16 cnt0 = kclock_read_cnt0() ;
//		cprintf("CLOCK INTERRUPT: Counter0 Value = %d\n", cnt0 );

		if (userTrap)
		{
			assert(curenv);
			curenv->nClocks++ ;
		}
	}
	else if (tf->tf_trapno == T_PGFLT){
		//2016: Bypass the faulted instruction
		if (bypassInstrLength != 0){
			if (userTrap){
				curenv->env_tf.tf_eip = (uint32*)((uint32)(curenv->env_tf.tf_eip) + bypassInstrLength);
				env_run(curenv);
			}
			else{
				tf->tf_eip = (uint32*)((uint32)(tf->tf_eip) + bypassInstrLength);
				kclock_resume();
				env_pop_tf(tf);
			}
		}
	}
	trap_dispatch(tf);
	if (userTrap)
	{
		assert(curenv && curenv->env_status == ENV_RUNNABLE);
		env_run(curenv);
	}
	/* 2019
	 * If trap from kernel, then return to the called kernel function using the passed param "tf" not the user one that's stored in curenv
	 */
	else
	{
		env_pop_tf((tf));
	}
}

void setPageReplacmentAlgorithmLRU(){_PageRepAlgoType = PG_REP_LRU;}
void setPageReplacmentAlgorithmCLOCK(){_PageRepAlgoType = PG_REP_CLOCK;}
void setPageReplacmentAlgorithmFIFO(){_PageRepAlgoType = PG_REP_FIFO;}
void setPageReplacmentAlgorithmModifiedCLOCK(){_PageRepAlgoType = PG_REP_MODIFIEDCLOCK;}

uint32 isPageReplacmentAlgorithmLRU(){if(_PageRepAlgoType == PG_REP_LRU) return 1; return 0;}
uint32 isPageReplacmentAlgorithmCLOCK(){if(_PageRepAlgoType == PG_REP_CLOCK) return 1; return 0;}
uint32 isPageReplacmentAlgorithmFIFO(){if(_PageRepAlgoType == PG_REP_FIFO) return 1; return 0;}
uint32 isPageReplacmentAlgorithmModifiedCLOCK(){if(_PageRepAlgoType == PG_REP_MODIFIEDCLOCK) return 1; return 0;}

void enableModifiedBuffer(uint32 enableIt){_EnableModifiedBuffer = enableIt;}
uint32 isModifiedBufferEnabled(){  return _EnableModifiedBuffer ; }

void enableBuffering(uint32 enableIt){_EnableBuffering = enableIt;}
uint32 isBufferingEnabled(){  return _EnableBuffering ; }

void setModifiedBufferLength(uint32 length) { _ModifiedBufferLength = length;}
uint32 getModifiedBufferLength() { return _ModifiedBufferLength;}


void detect_modified_loop()
{
	struct  Frame_Info * slowPtr = LIST_FIRST(&modified_frame_list);
	struct  Frame_Info * fastPtr = LIST_FIRST(&modified_frame_list);


	while (slowPtr && fastPtr) {
		fastPtr = LIST_NEXT(fastPtr); // advance the fast pointer
		if (fastPtr == slowPtr) // and check if its equal to the slow pointer
		{
			cprintf("loop detected in modiflist\n");
			break;
		}

		if (fastPtr == NULL) {
			break; // since fastPtr is NULL we reached the tail
		}

		fastPtr = LIST_NEXT(fastPtr); //advance and check again
		if (fastPtr == slowPtr) {
			cprintf("loop detected in modiflist\n");
			break;
		}

		slowPtr = LIST_NEXT(slowPtr); // advance the slow pointer only once
	}
	cprintf("finished modi loop detection\n");
}

void fault_handler(struct Trapframe *tf)
{
	int userTrap = 0;
	if ((tf->tf_cs & 3) == 3) {
		userTrap = 1;
	}
	//print_trapframe(tf);
	uint32 fault_va;

	// Read processor's CR2 register to find the faulting address
	fault_va = rcr2();

	//2017: Check stack overflow for Kernel
	if (!userTrap)
	{
		if (fault_va < KERNEL_STACK_TOP - KERNEL_STACK_SIZE && fault_va >= USER_LIMIT)
			panic("Kernel: stack overflow exception!");
	}
	//2017: Check stack underflow for User
	else
	{
		if (fault_va >= USTACKTOP)
			panic("User: stack underflow exception!");
	}

	//get a pointer to the environment that caused the fault at runtime
	struct Env* faulted_env = curenv;

	//check the faulted address, is it a table or not ?
	//If the directory entry of the faulted address is NOT PRESENT then
	if ( (curenv->env_page_directory[PDX(fault_va)] & PERM_PRESENT) != PERM_PRESENT)
	{
		// we have a table fault =============================================================
		//		cprintf("[%s] user TABLE fault va %08x\n", curenv->prog_name, fault_va);
		faulted_env->tableFaultsCounter ++ ;

		table_fault_handler(faulted_env, fault_va);
	}
	else
	{
		// we have normal page fault =============================================================
		faulted_env->pageFaultsCounter ++ ;

//				cprintf("[%08s] user PAGE fault va %08x\n", curenv->prog_name, fault_va);
//				cprintf("\nPage working set BEFORE fault handler...\n");
//				env_page_ws_print(curenv);

		if(isBufferingEnabled())
		{
			__page_fault_handler_with_buffering(faulted_env, fault_va);
		}
		else
		{
			page_fault_handler(faulted_env, fault_va);
		}
//				cprintf("\nPage working set AFTER fault handler...\n");
//				env_page_ws_print(curenv);

	}

	/*************************************************************/
	//Refresh the TLB cache
	tlbflush();
	/*************************************************************/

}


//Handle the table fault
void table_fault_handler(struct Env * curenv, uint32 fault_va)
{
	//panic("table_fault_handler() is not implemented yet...!!");
	//Check if it's a stack page
	uint32* ptr_table;
	if(USE_KHEAP)
	{
		ptr_table = create_page_table(curenv->env_page_directory, (uint32)fault_va);
	}
	else
	{
		__static_cpt(curenv->env_page_directory, (uint32)fault_va, &ptr_table);
	}

}
////////////////////////////////////////
void func_placement(struct Env * curenv, uint32 VIRTUAL_FAULT, uint32 index_replace,uint32 replace_SIDE)
{
	//Returns all permissions bits for the given page
	//(virtual address) in the given environment page directory (ptr_pgdir)
	uint32 permissi_page = pt_get_page_permissions(curenv, VIRTUAL_FAULT);
	uint32 P_B=permissi_page & PERM_BUFFERED;
		if (!P_B)
		{
			struct Frame_Info *new_F_I;
			int result = allocate_frame(&new_F_I);
			if (result != E_NO_MEM)
			{
				permissi_page |= (PERM_PRESENT | PERM_USER | PERM_WRITEABLE);
				result = map_frame(curenv->env_page_directory, new_F_I,(void*)  VIRTUAL_FAULT, permissi_page);
				if (result != E_NO_MEM)
				{
					//read page data from hard disk to memory
					result = pf_read_env_page(curenv, (void*) VIRTUAL_FAULT);
					//if not successfully read then check it's a stack page
					if (result == E_PAGE_NOT_EXIST_IN_PF)
					{
						if ( VIRTUAL_FAULT > USTACKBOTTOM  )
						{
							if(VIRTUAL_FAULT <= USTACKTOP)
								//Add a new environment page with the given virtual address to the page file and initialize it by zeros.
							result = pf_add_empty_env_page(curenv,  VIRTUAL_FAULT, 1);


						}
						else
							return panic("AHMED ALSHARKAWY:INVAILED ADDRESS ");
					}
				}
			}
		}
		else
		{//make the page modified
			uint32 P_M=permissi_page & PERM_MODIFIED;
			uint32 *PT_POINTER = NULL;
			//Sets the permissions given by “permissions_to_set” to “1” in the
			//page table entry of the given page (virtual address), and
			//Clears the permissions given by “permissions_to_clear”.
			//The environment used is the one given by “ptr_env”
			pt_set_page_permissions(curenv, VIRTUAL_FAULT, PERM_PRESENT, PERM_BUFFERED);
			struct Frame_Info *frame_info = get_frame_info(curenv->env_page_directory,(void*) VIRTUAL_FAULT, &PT_POINTER);
			frame_info->isBuffered = 0;
			if (!P_M)
			{
				bufferlist_remove_page(&free_frame_list, frame_info);
			}
			else
			{
				bufferlist_remove_page(&modified_frame_list, frame_info);
			}

			//************************************

	}
		//********************************************************
		if (replace_SIDE  != 0)
		{
			uint32 fault_round_D=ROUNDDOWN(VIRTUAL_FAULT, PAGE_SIZE);
			//Sets the entry number “entry_index” in “e”
			//working set to given virtual address after
			//ROUNDING it 	DOWN to the start of page
			env_page_ws_set_entry(curenv, index_replace,fault_round_D );

		}
		else if(replace_SIDE  == 0)
		{
		uint32 L_WS_INDEX= curenv->page_last_WS_index;
		uint32 WS_size ;

		for (WS_size = curenv->page_WS_max_size;WS_size > 0;WS_size-=1)
			{
			L_WS_INDEX = L_WS_INDEX % (curenv->page_WS_max_size);
			//Returns a value indicating whether the entry at “entry_index”
			//in environment “e” working set is empty
				int empty=env_page_ws_is_entry_empty(curenv, L_WS_INDEX);
				if (empty)
				{
					curenv->page_last_WS_index =( (L_WS_INDEX + 1) % (curenv->page_WS_max_size));
				goto break_loop;
				}

				L_WS_INDEX+=1;
			}

			break_loop:
				env_page_ws_set_entry(curenv, L_WS_INDEX, ROUNDDOWN(VIRTUAL_FAULT, PAGE_SIZE));
		}


	 }

uint32 Virtual_Address_victim;
uint32 index;
void func_replacement(struct Env * current_ENVIROMENT, uint32 fault_virtual_address)
{

			if(isPageReplacmentAlgorithmModifiedCLOCK())
			{
				//modified clock algorithm
				int tru = 1;
				while (tru)
				{

					uint32 start_ind = current_ENVIROMENT->page_last_WS_index;
					uint32 start = start_ind;
					uint32 WS_size;
					for ( WS_size = current_ENVIROMENT->page_WS_max_size;WS_size > 0;WS_size-=1)
					{
						start = (start % current_ENVIROMENT->page_WS_max_size);
						uint32 virtual_Temp = env_page_ws_get_virtual_address(current_ENVIROMENT, start);
						uint32 MY_page_premition = pt_get_page_permissions(current_ENVIROMENT, virtual_Temp);
						uint32 P_M=MY_page_premition & PERM_MODIFIED;
						uint32 P_U=MY_page_premition & PERM_USED;
						if((P_M) == 0)
						{
							if((P_U) == 0)
							{
							Virtual_Address_victim = virtual_Temp;
							index = start;
							current_ENVIROMENT->page_last_WS_index = ((start + 1) % current_ENVIROMENT->page_WS_max_size);
							tru = 0;
							goto outloop;
							}
						}

						start++;
					}
					outloop:
					if (tru == 0)
						break;

					start = start_ind;


					for (WS_size = current_ENVIROMENT->page_WS_max_size;WS_size > 0;WS_size-=1)
					{
						start = (start %current_ENVIROMENT->page_WS_max_size);
						uint32 Tem = env_page_ws_get_virtual_address(current_ENVIROMENT, start);
						uint32 MY_premition = pt_get_page_permissions(current_ENVIROMENT, Tem);
						uint32 MY_Page_Pre_Used=MY_premition & PERM_USED;
						if (MY_Page_Pre_Used == 0)
						{
							Virtual_Address_victim = Tem;
							index = start;
							current_ENVIROMENT->page_last_WS_index = ((start + 1)% current_ENVIROMENT->page_WS_max_size);
							tru = 0;
							break;
						}

						if (tru == 0)
							break;

						pt_set_page_permissions(curenv,Tem, 0, PERM_USED);
						start+=1;
					}

				}
			}

			uint32 *PT_POINTER = NULL;
			struct Frame_Info *F_INFO = get_frame_info(current_ENVIROMENT->env_page_directory,(void*) Virtual_Address_victim, &PT_POINTER);
			F_INFO->isBuffered = 1;
			F_INFO->va = Virtual_Address_victim;
			F_INFO->environment = current_ENVIROMENT;

			pt_set_page_permissions(current_ENVIROMENT, Virtual_Address_victim, PERM_BUFFERED, PERM_PRESENT);

			//check permissions of victim page
			uint32 p_permissions_MODIFIED = pt_get_page_permissions(current_ENVIROMENT, Virtual_Address_victim);
			uint32 P_P_M=p_permissions_MODIFIED& PERM_MODIFIED;

			if (!P_P_M)
			{

				bufferList_add_page(&free_frame_list, F_INFO);

			}
			else
			{
				//add in modified list
				bufferList_add_page(&modified_frame_list, F_INFO);
				if (LIST_SIZE(&modified_frame_list) == getModifiedBufferLength())
				{
					struct Frame_Info *POINTER_FOR_MODIFY;
					LIST_FOREACH(POINTER_FOR_MODIFY, &modified_frame_list)
					{
						int MY_return  = pf_update_env_page(POINTER_FOR_MODIFY->environment,(void*)POINTER_FOR_MODIFY->va, POINTER_FOR_MODIFY);
						pt_set_page_permissions(POINTER_FOR_MODIFY->environment,POINTER_FOR_MODIFY->va, 0, PERM_MODIFIED);
						bufferlist_remove_page(&modified_frame_list,POINTER_FOR_MODIFY);
						bufferList_add_page(&free_frame_list, POINTER_FOR_MODIFY);
					}
			   }
			}


			func_placement(current_ENVIROMENT, fault_virtual_address, index, 1);

}
//Handle the page fault

void page_fault_handler(struct Env * curenv, uint32 fault_va)
{
	//this accourding to documentation
	//Description:
	//Counts the pages loaded in main memory of a given environment
	int WS_Size=env_page_ws_get_size(curenv);
	int MAX_SIZE=curenv->page_WS_max_size;
	if(WS_Size<MAX_SIZE)
	{
		func_placement(curenv,fault_va,0,0);
    }
	else
	{
		func_replacement( curenv,  fault_va);
    }

}

void __page_fault_handler_with_buffering(struct Env * curenv, uint32 fault_va)
{
	// your code is here, remove the panic and write your code
	panic("this function is not required...!!");

}

