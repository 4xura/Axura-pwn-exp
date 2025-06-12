#ifndef KPTI_TRAMPOLINE_H
#define KPTI_TRAMPOLINE_H


/* ============= KPTI Trampoline =============
 * Instead of returning with iretq directly (which fails under KPTI),
 *      we reuse the kernel's legit return path: 
 *          the KPTI trampoline.
 * 
 * This is located in:
 *      swapgs_restore_regs_and_return_to_usermode(),
 *          which properly restores user page tables, executes swapgs, and
 *          returns with iretq safely.
 *          It calls 'SWITCH_TO_USER_CR3' to switch to the user-space page tables
 *
 * Defined at: https://elixir.bootlin.com/linux/v6.10.14/source/arch/x86/entry/entry_64.S#L560
 *
 * We don't care how it restores the regs in exploit, 
 *      but how it handles page isolation!
 *      
 * So, the [KPTI trampoline] will be at:
 *      swapgs_restore_regs_and_return_to_usermode + 22 (0x16)
 *          which is the address of the first mov:
 * 
 * // The 1st mov saves kernel RSP into RDI 
 * .text:FFFFFFFF81200F26                   mov     rdi, rsp
 * // Swith RSP to kernel trampoline stack (per CPU safe: gs:cpu_tss_rw + TSS_sp0)
 * .text:FFFFFFFF81200F29                   mov     rsp, gs:qword_6004
 * // Assign values from kernel stack to trampoline stack
 * .text:FFFFFFFF81200F32                   push    qword ptr [rdi+30h]   // user_ss
 * .text:FFFFFFFF81200F35                   push    qword ptr [rdi+28h]   // user_rsp
 * .text:FFFFFFFF81200F38                   push    qword ptr [rdi+20h]   // user_rflags
 * .text:FFFFFFFF81200F3B                   push    qword ptr [rdi+18h]   // user_cs
 * .text:FFFFFFFF81200F3E                   push    qword ptr [rdi+10h]   // user_rip
 * .text:FFFFFFFF81200F41                   push    qword ptr [rdi]   // preserve kernel stack
 * .text:FFFFFFFF81200F43                   push    rax               // preserve func ret value
 * .text:FFFFFFFF81200F44                   jmp     short loc_FFFFFFFF81200F89
 *   ↓  // Jump to the swapgs ... iretq logic
 * .text:FFFFFFFF81200F89 loc_FFFFFFFF81200F89:
 * .text:FFFFFFFF81200F89                   pop     rax
 * .text:FFFFFFFF81200F8A                   pop     rdi
 * .text:FFFFFFFF81200F8B                   call    cs:off_FFFFFFFF82040088 //swapgs
 *   ↓  // Jump to this native_swapgs code
 * .text.native_swapgs:FFFFFFFF8146D4E0     push    rbp
 * .text.native_swapgs:FFFFFFFF8146D4E1     mov     rbp, rsp
 * .text.native_swapgs:FFFFFFFF8146D4E4     swapgs
 * .text.native_swapgs:FFFFFFFF8146D4E7     pop     rbp
 * .text.native_swapgs:FFFFFFFF8146D4E8     retn
 *   ↓  // Return back to swapgs ... iretq code
 * .text:FFFFFFFF81200F91                   jmp     cs:off_FFFFFFFF82040080
 *   ↓  // native iretq logic
 * .text:FFFFFFFF81200FC0                   test    byte ptr [rsp+arg_18], 4
 * .text:FFFFFFFF81200FC5                   jnz     short loc_FFFFFFFF81200FC9
 * .text:FFFFFFFF81200FC7                   iretq
 *
 * That CR3 reload logic is part of an alternative trampoline path (PTI-aware) 
 *      within this swapgs_restore_regos_and_return_to_usermode asm:
 *
 * .text:FFFFFFFF81200F46                   mov     rdi, cr3
 * .text:FFFFFFFF81200F49                   jmp     short loc_FFFFFFFF81200F7F
 * .text:FFFFFFFF81200F7F                   or      rdi, 1000h
 * .text:FFFFFFFF81200F86                   mov     cr3, rdi
 *
 * We are not taking it unless something like:
 *      jmp .Lpti_restore_regs_and_return_to_usermode
 *          is taken via ALTERNATIVE macros in .S.
 *
 *      When KPTI (PTI mitigation) is enabled, it will jump to: 
 *          .Lpti_restore_regs_and_return_to_usermode
 *              which handles page table isolation before executing swapgs and iretq.
 *
 * Before the KPTI trampoline, the CR3 is set at the start of the asm:
 *
 * SYM_CODE_START_LOCAL(common_interrupt_return)
 * SYM_INNER_LABEL(swapgs_restore_regs_and_return_to_usermode, SYM_L_GLOBAL)
 * ...
 * #ifdef CONFIG_MITIGATION_PAGE_TABLE_ISOLATION
 * ALTERNATIVE "", "jmp .Lpti_restore_regs_and_return_to_usermode", X86_FEATURE_PTI
 * #endif
 */


// chain_kpti_trampoline() is 
// declared in "rop.h", and defined in "rop.c"





#endif  // KPTI_TRAMPOLINE_H
