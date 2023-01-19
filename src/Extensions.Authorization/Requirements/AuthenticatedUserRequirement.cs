using System.Security.Claims;
using NoSuchCompany.Azure.Functions.Worker.Extensions.Authorization.Policies;

namespace NoSuchCompany.Azure.Functions.Worker.Extensions.Authorization.Requirements;

/// <summary>
/// Defines a requirement to have an authenticated user.
/// </summary>
internal sealed class AuthenticatedUserRequirement : IAuthorizationRequirement
{
    public Task<bool> HandleAsync(ClaimsPrincipal? claimsPrincipal)
    {
        return Task.FromResult(claimsPrincipal is not null && claimsPrincipal.Identities.Any());
    }
}
