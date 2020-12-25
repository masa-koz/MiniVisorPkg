/*!
    @file GuestAgent.h

    @brief GuestAgent code.

    @author Satoshi Tanda

    @copyright Copyright (c) 2020 - , Satoshi Tanda. All rights reserved.
 */
#pragma once
#include "Common.h"

typedef enum _GUEST_AGENT_COMMAND
{
    GuestAgentCommandInitialize,
} GUEST_AGENT_COMMAND;

typedef struct _HOST_GUEST_AGENT_CONTEXT
{
    UINT64 OriginalGuestRip;
    UINT64 OriginalGuestRsp;
    GUEST_AGENT_COMMAND CommandNumber;
    UINT64 Padding;
} HOST_GUEST_AGENT_CONTEXT;
C_ASSERT((sizeof(HOST_GUEST_AGENT_CONTEXT) % 0x10) == 0);

typedef struct _GUEST_AGENT_STACK
{
    union
    {
        //
        //  Low     GuestAgentStackLimit[0]              StackLimit
        //  ^       ...
        //  ^       ...                                  Layout.Context (StackBase)
        //  ^       ...
        //  ^       GuestAgentStackLimit[PAGE_SIZE - 2]
        //  High    GuestAgentStackLimit[PAGE_SIZE - 1]
        //
        DECLSPEC_ALIGN(PAGE_SIZE) UINT8 GuestAgentStackLimit[PAGE_SIZE];
        struct
        {
            //
            // Available for the hypervisor to freely use.
            //
            UINT8 AvailableAsStack[PAGE_SIZE - sizeof(HOST_GUEST_AGENT_CONTEXT)];

            //
            // Set up by the kernel-mode code before starting the hypervisor.
            // The hypervisor never overwrites this contents.
            //
            HOST_GUEST_AGENT_CONTEXT Context;
        } Layout;
    } u;
} GUEST_AGENT_STACK;
