using System.IdentityModel.Tokens.Jwt;
using System.Security.Authentication;
using System.Security.Claims;
using CommunityToolkit.Diagnostics;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;

namespace NoSuchCompany.Azure.Functions.Worker.Extensions.Authorization.Services;

/// <summary>
/// Provides an implementation of <see cref="IClaimsPrincipalBuilder" />.
/// </summary>
internal sealed class ClaimsPrincipalBuilder : IClaimsPrincipalBuilder
{
    private readonly AuthorizationOptions _authorizationOptions;

    public ClaimsPrincipalBuilder(AuthorizationOptions authorizationOptionsOptions)
    {
        Guard.IsNotNull(authorizationOptionsOptions);
        Guard.IsNotNull(authorizationOptionsOptions.DiscoveryEndpoints, nameof(authorizationOptionsOptions.DiscoveryEndpoints));

        this._authorizationOptions = authorizationOptionsOptions;
    }

    /// <summary>
    /// Builds an instance of <see cref="ClaimsPrincipal" /> out of the
    /// specified <paramref name="token" /> after validating it.
    /// </summary>
    /// <param name="token"></param>
    /// <returns></returns>
    /// <exception cref="ArgumentNullException">
    /// Thrown if:
    /// - The specified <paramref name="token" /> is null.
    /// </exception>
    /// <exception cref="ArgumentException">
    /// Thrown if:
    /// - The specified <paramref name="token" /> is empty.
    /// - The specified <paramref name="token" /> is not properly formed.
    /// </exception>
    /// <exception cref="AuthenticationException">
    /// Thrown if:
    /// - The specified <paramref name="token" /> is not valid.
    /// </exception>
    public async Task<ClaimsPrincipal> GetClaimsPrincipalAsync(string token)
    {
        Guard.IsNotNullOrWhiteSpace(token);

        var cleanedBearerToken = token.Replace("Bearer ", "");

        var possibleIssuers = new List<string>();

        var possibleIssuerSigninKeys = new List<SecurityKey>();

        foreach (var discoveryEndpoint in this._authorizationOptions.DiscoveryEndpoints)
        {
            ConfigurationManager<OpenIdConnectConfiguration> configurationManager = new(discoveryEndpoint, new OpenIdConnectConfigurationRetriever());
            var openIdConnectConfiguration = await configurationManager.GetConfigurationAsync();
            possibleIssuers.Add(openIdConnectConfiguration.Issuer);
            possibleIssuerSigninKeys.AddRange(openIdConnectConfiguration.SigningKeys);
        }

        var validationParameters = new TokenValidationParameters
        {
            ValidateAudience = false,
            ValidateIssuer = true,
            ValidIssuers = possibleIssuers,
            ValidateIssuerSigningKey = true,
            IssuerSigningKeys = possibleIssuerSigninKeys,
            RequireExpirationTime = true,
            ValidateLifetime = true,
            RequireSignedTokens = true,
        };

        JwtSecurityTokenHandler securityTokenHandler = new();

        if (!securityTokenHandler.CanReadToken(cleanedBearerToken))
        {
            throw new ArgumentException("Unable to read the token. It is malformed.");
        }

        try
        {
            var claimsPrincipal = securityTokenHandler.ValidateToken(cleanedBearerToken, validationParameters, out var _);

            return claimsPrincipal;
        }
        catch (Exception unhandledException)
        {
            throw new AuthenticationException("The token could not be validated.", unhandledException);
        }
    }
}
