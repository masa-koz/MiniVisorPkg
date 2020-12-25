;
;   @file GuestAgentAsm.asm
;
;   @brief GuestAgent MASM-written functions.
;
;   @author Satoshi Tanda
;
;   @copyright Copyright (c) 2020 - , Satoshi Tanda. All rights reserved.
;
include AsmCommon.inc

.const

KTRAP_FRAME_SIZE            equ     190h
MACHINE_FRAME_SIZE          equ     28h

.code

extern GuestAgentEntryPoint : proc

AsmGuestAgentEntryPoint proc frame
        ;
        ; Let Windbg reconstruct call stack.
        ;
        .pushframe
        .allocstack KTRAP_FRAME_SIZE - MACHINE_FRAME_SIZE + 100h
        sub     rsp, KTRAP_FRAME_SIZE

        ;
        ; Save registers including flag and XMM registers.
        ;
        PUSHAQ
        pushfq
        sub     rsp, 60h
        movaps  xmmword ptr [rsp +  0h], xmm0
        movaps  xmmword ptr [rsp + 10h], xmm1
        movaps  xmmword ptr [rsp + 20h], xmm2
        movaps  xmmword ptr [rsp + 30h], xmm3
        movaps  xmmword ptr [rsp + 40h], xmm4
        movaps  xmmword ptr [rsp + 50h], xmm5

        ;
        ; GuestAgentEntryPoint(stack);
        ;
        mov     rcx, rsp
        sub     rsp, 20h
        .endprolog
        call    GuestAgentEntryPoint
        add     rsp, 20h

        ;
        ; Restore registers and the stack pointer.
        ;
        movaps  xmm5, xmmword ptr [rsp + 50h]
        movaps  xmm4, xmmword ptr [rsp + 40h]
        movaps  xmm3, xmmword ptr [rsp + 30h]
        movaps  xmm2, xmmword ptr [rsp + 20h]
        movaps  xmm1, xmmword ptr [rsp + 10h]
        movaps  xmm0, xmmword ptr [rsp +  0h]
        add     rsp, 60h
        popfq
        POPAQ
        add     rsp, KTRAP_FRAME_SIZE

        ;
        ; Go back to the hypervisor.
        ;
        vmcall
AsmGuestAgentEntryPoint endp
AsmGuestAgentEntryPointEnd proc
        jmp     $
AsmGuestAgentEntryPointEnd endp

AsmExAllocatePoolWithTag proc
        ;
        ; Those nop instructions are overwritten when a hook is installed.
        ; Original instructions can be copied up to 14+15 bytes. Then, the
        ; NOP+JMP [RIP+0] instructions takes 15 bytes, resulting in up to 44 bytes.
        ;
        repeat 50
        nop
        endm
AsmExAllocatePoolWithTag endp

        end
