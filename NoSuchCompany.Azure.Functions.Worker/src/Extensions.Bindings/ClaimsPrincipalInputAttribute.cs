using Microsoft.Azure.Functions.Worker.Extensions.Abstractions;

namespace NoSuchCompany.Azure.Functions.Worker.Extensions.Bindings;

[AttributeUsage(AttributeTargets.Parameter | AttributeTargets.ReturnValue)]
public sealed class ClaimsPrincipalInputAttribute : InputBindingAttribute
{
}
