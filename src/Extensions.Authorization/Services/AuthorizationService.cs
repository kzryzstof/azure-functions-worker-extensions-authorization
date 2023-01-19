using System.Security;
using System.Security.Authentication;
using System.Security.Claims;
using CommunityToolkit.Diagnostics;
using Microsoft.Azure.Functions.Worker.Http;
using Microsoft.Extensions.Logging;
using NoSuchCompany.Azure.Functions.Worker.Extensions.Authorization.Policies;

namespace NoSuchCompany.Azure.Functions.Worker.Extensions.Authorization.Services;

internal sealed class AuthorizationService : IAuthorizationService
{
    private readonly AuthorizationOptions _authorizationOptions;
    private readonly IClaimsPrincipalBuilder _claimsPrincipalBuilder;
    private readonly IFunctionsRegistry _functionsRegistry;
    private readonly ILogger<AuthorizationService> _logger;

    public AuthorizationService
    (
        ILogger<AuthorizationService> logger,
        IClaimsPrincipalBuilder claimsPrincipalBuilder,
        IFunctionsRegistry functionsRegistry,
        AuthorizationOptions authorizationOptions
    )
    {
        Guard.IsNotNull(logger);
        Guard.IsNotNull(claimsPrincipalBuilder);
        Guard.IsNotNull(functionsRegistry);
        Guard.IsNotNull(authorizationOptions);

        this._logger = logger;
        this._claimsPrincipalBuilder = claimsPrincipalBuilder;
        this._functionsRegistry = functionsRegistry;
        this._authorizationOptions = authorizationOptions;
    }

    /// <summary>
    /// Retrieves and validates the claims passed to the specified <paramref name="httpRequestData" />.
    /// </summary>
    /// <param name="httpRequestData"></param>
    /// <returns></returns>
    /// <exception cref="ArgumentNullException">
    /// Thrown if:
    /// - The <paramref name="httpRequestData" /> is null.
    /// </exception>
    public async Task<ClaimsPrincipal> AuthorizeAsync(HttpRequestData httpRequestData)
    {
        Guard.IsNotNull(httpRequestData);

        //  Gets the policies that must be checked.
        string[] applicablePolicies = this.FindApplicablePolicies(httpRequestData);

        if (applicablePolicies.Length == 0)
        {
            this._logger.LogInformation("No applicable policies have been found. Claims will not be retrieved from the HTTP request");
            return new ClaimsPrincipal();
        }

        //  Retrieves the authenticated user's claims.
        ClaimsPrincipal claimsPrincipal = await this.GetClaimsPrincipalAsync(httpRequestData);

        //  Evaluates the applicable policies.
        foreach (string applicablePolicy in applicablePolicies)
        {
            AuthorizationPolicy authorizationPolicy = this._authorizationOptions.GetPolicy(applicablePolicy);

            if (await authorizationPolicy.EvaluateAsync(claimsPrincipal))
                return claimsPrincipal;
        }

        throw new SecurityException();
    }

    /// <summary>
    /// Gets all the policies applicable to the actual HTTP request.
    /// </summary>
    /// <returns></returns>
    private string[] FindApplicablePolicies(HttpRequestData httpRequestData)
    {
        return this._functionsRegistry.GetPolicies(httpRequestData);
    }

    /// <summary>
    /// Extracts the claims from the specified HTTP request.
    /// </summary>
    /// <param name="httpRequestData"></param>
    /// <returns></returns>
    /// <exception cref="AuthenticationException"></exception>
    private Task<ClaimsPrincipal> GetClaimsPrincipalAsync(HttpRequestData httpRequestData)
    {
        List<string> authorizationHeaders = httpRequestData
            .Headers
            .Where(header => header.Key == "Authorization")
            .SelectMany(header => header.Value)
            .Where(authorizationValue => !string.IsNullOrWhiteSpace(authorizationValue))
            .ToList();

        return this.GetClaimsPrincipalAsync(authorizationHeaders);
    }

    /// <summary>
    /// Extracts the claims from the list of values associated to the authorization header.
    /// </summary>
    /// <param name="authorizationHeaders"></param>
    /// <returns></returns>
    /// <exception cref="AuthenticationException"></exception>
    private Task<ClaimsPrincipal> GetClaimsPrincipalAsync(List<string> authorizationHeaders)
    {
        this._logger.LogInformation("Found '{AuthorizationHeaderCount}' headers with a non empty 'Authorization' key", authorizationHeaders.Count);

        if (!authorizationHeaders.Any())
            throw new AuthenticationException("The Authorization header is missing.");

        int authorizationHeaderValueCount = authorizationHeaders.Count;

        if (authorizationHeaderValueCount != 1)
            throw new AuthenticationException($"The Authorization did not contain only 1 non empty value. Found {authorizationHeaderValueCount}.");

        return this._claimsPrincipalBuilder.GetClaimsPrincipalAsync(authorizationHeaders.First(value => !string.IsNullOrWhiteSpace(value)));
    }
}
