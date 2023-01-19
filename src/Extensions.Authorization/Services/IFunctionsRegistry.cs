using Microsoft.Azure.Functions.Worker.Http;

namespace NoSuchCompany.Azure.Functions.Worker.Extensions.Authorization.Services;

/// <summary>
/// Defines a registry of Azure Functions.
/// </summary>
internal interface IFunctionsRegistry
{
    /// <summary>
    /// Gets all the policies associated to the specified HTTP request.
    /// </summary>
    /// <param name="httpRequestData"></param>
    /// <returns></returns>
    string[] GetPolicies(HttpRequestData httpRequestData);
}
