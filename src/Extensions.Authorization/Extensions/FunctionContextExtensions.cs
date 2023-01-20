// ==========================================================================
// Copyright (C) 2023 by NoSuch Company.
// All rights reserved.
// May be used only in accordance with a valid Source Code License Agreement.
//
// Last change: 19/01/2023 @ 7:32 PM
// ==========================================================================

using System.Security.Claims;
using Microsoft.Azure.Functions.Worker;

namespace NoSuchCompany.Azure.Functions.Worker.Extensions.Authorization.Extensions;

public static class FunctionContextExtensions
{
    public static ClaimsPrincipal GetClaimsPrincipal(this FunctionContext functionContext)
    {
        if (!functionContext.Items.ContainsKey(Items.Name))
            return new ClaimsPrincipal();

        return functionContext.Items[Items.Name] as ClaimsPrincipal ?? new ClaimsPrincipal();
    }
}
