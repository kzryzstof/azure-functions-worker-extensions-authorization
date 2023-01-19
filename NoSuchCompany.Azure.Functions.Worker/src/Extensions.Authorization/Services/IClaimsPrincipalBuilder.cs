using System.Security.Authentication;
using System.Security.Claims;

namespace NoSuchCompany.Azure.Functions.Worker.Extensions.Authorization.Services;

/// <summary>
/// Defines a builder of <see cref="ClaimsPrincipal" /> instances.
/// </summary>
public interface IClaimsPrincipalBuilder
{
    /// <summary>
    /// Builds an instance of <see cref="ClaimsPrincipal" /> out of
    /// the specified <paramref name="token" />'s information.
    /// </summary>
    /// <param name="token"></param>
    /// <returns></returns>
    /// <exception cref="ArgumentException">
    /// Thrown if:
    /// - The specified <paramref name="token" /> is not properly formed.
    /// </exception>
    /// <exception cref="AuthenticationException">
    /// Thrown if:
    /// - The specified <paramref name="token" /> could not be validated.
    /// </exception>
    Task<ClaimsPrincipal> GetClaimsPrincipalAsync(string token);
}
