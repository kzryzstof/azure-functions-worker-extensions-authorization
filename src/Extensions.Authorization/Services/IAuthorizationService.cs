using System.Security.Claims;
using Microsoft.Azure.Functions.Worker.Http;

namespace NoSuchCompany.Azure.Functions.Worker.Extensions.Authorization.Services;

/// <summary>
/// Defines the service responsible for authorizing an HTTP request
/// based on the associated policies.
/// </summary>
public interface IAuthorizationService
{
    Task<ClaimsPrincipal> AuthorizeAsync(HttpRequestData httpRequestData);
}
