using System.Security.Claims;
using CommunityToolkit.Diagnostics;
using NoSuchCompany.Azure.Functions.Worker.Extensions.Authorization.Policies;

namespace NoSuchCompany.Azure.Functions.Worker.Extensions.Authorization.Requirements;

/// <summary>
/// Defines a requirement for a given <see cref="Claim" />.
/// </summary>
internal sealed class ClaimsAuthorizationRequirement : IAuthorizationRequirement
{
    /// <summary>
    /// Gets the optional list of claim values, which, if present,
    /// the claim must match.
    /// </summary>
    public IEnumerable<string> AllowedValues { get; }

    /// <summary>
    /// Gets the claim type that must be present.
    /// </summary>
    public string ClaimType { get; }

    /// <summary>
    /// Creates a new instance of <see cref="ClaimsAuthorizationRequirement" />.
    /// </summary>
    /// <param name="claimType">The claim type that must be present.</param>
    /// <param name="allowedValues">
    /// The optional list of claim values, which, if present,
    /// the claim must match.
    /// </param>
    public ClaimsAuthorizationRequirement(string claimType, IEnumerable<string> allowedValues)
    {
        Guard.IsNotNullOrWhiteSpace(claimType);

        this.ClaimType = claimType;
        this.AllowedValues = allowedValues;
    }

    /// <summary>
    /// Makes a decision if authorization is allowed based on the claims requirements specified.
    /// </summary>
    /// <param name="claimsPrincipal">The requirement to evaluate.</param>
    public Task<bool> HandleAsync(ClaimsPrincipal? claimsPrincipal)
    {
        if (claimsPrincipal is null)
            return Task.FromResult(false);

        bool found;

        if (!this.AllowedValues.Any())
            found = claimsPrincipal
                .Claims
                .Any(claim => string.Equals(claim.Type, this.ClaimType, StringComparison.OrdinalIgnoreCase));
        else
            found = claimsPrincipal
                .Claims
                .Any(claim => string.Equals(claim.Type, this.ClaimType, StringComparison.OrdinalIgnoreCase) && this.AllowedValues.Contains(claim.Value, StringComparer.Ordinal));

        return Task.FromResult(found);
    }
}
