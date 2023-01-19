using System.Security.Claims;

namespace NoSuchCompany.Azure.Functions.Worker.Extensions.Authorization.Policies;

/// <summary>
/// Defines a requirement for an authorization.
/// </summary>
public interface IAuthorizationRequirement
{
    Task<bool> HandleAsync(ClaimsPrincipal claimsPrincipal);
}
