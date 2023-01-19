using CommunityToolkit.Diagnostics;
using NoSuchCompany.Azure.Functions.Worker.Extensions.Authorization.Requirements;

namespace NoSuchCompany.Azure.Functions.Worker.Extensions.Authorization.Policies;

public sealed class AuthorizationPolicyBuilder
{
    /// <summary>
    /// Gets or sets a list of <see cref="IAuthorizationRequirement" />s which must succeed for
    /// this policy to be successful.
    /// </summary>
    public IList<IAuthorizationRequirement> Requirements { get; }

    internal AuthorizationPolicyBuilder()
    {
        this.Requirements = new List<IAuthorizationRequirement>();
    }

    /// <summary>
    /// Adds the specified <paramref name="requirements" /> to the
    /// <see cref="AuthorizationPolicyBuilder.Requirements" /> for this instance.
    /// </summary>
    /// <param name="requirements">The authorization requirements to add.</param>
    /// <returns>A reference to this instance after the operation has completed.</returns>
    public AuthorizationPolicyBuilder AddRequirements(params IAuthorizationRequirement[] requirements)
    {
        foreach (var req in requirements)
            this.Requirements.Add(req);

        return this;
    }

    /// <summary>
    /// Adds a <see cref="ClaimsAuthorizationRequirement" />
    /// to the current instance.
    /// </summary>
    /// <param name="claimType">The claim type required.</param>
    /// <param name="requiredValues">Values the claim must process one or more of for evaluation to succeed.</param>
    /// <returns>A reference to this instance after the operation has completed.</returns>
    public AuthorizationPolicyBuilder RequireClaim(string claimType, IEnumerable<string> requiredValues)
    {
        Guard.IsNotNullOrWhiteSpace(claimType);

        this.Requirements.Add(new ClaimsAuthorizationRequirement(claimType, requiredValues));

        return this;
    }

    /// <summary>
    /// Adds a <see cref="ClaimsAuthorizationRequirement" />
    /// to the current instance.
    /// </summary>
    /// <param name="claimType">The claim type required, which no restrictions on claim value.</param>
    /// <returns>A reference to this instance after the operation has completed.</returns>
    public AuthorizationPolicyBuilder RequireClaim(string claimType)
    {
        Guard.IsNotNullOrWhiteSpace(claimType);

        this.Requirements.Add(new ClaimsAuthorizationRequirement(claimType, ArraySegment<string>.Empty));

        return this;
    }

    internal AuthorizationPolicy Build()
    {
        return new AuthorizationPolicy(this.Requirements);
    }
}
