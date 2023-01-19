using CommunityToolkit.Diagnostics;
using NoSuchCompany.Azure.Functions.Worker.Extensions.Authorization.Attributes;
using NoSuchCompany.Azure.Functions.Worker.Extensions.Authorization.Policies;
using NoSuchCompany.Azure.Functions.Worker.Extensions.Authorization.Requirements;

namespace NoSuchCompany.Azure.Functions.Worker.Extensions.Authorization;

public sealed class AuthorizationOptions
{
    private readonly Dictionary<string, AuthorizationPolicy> _policies;

    public string[] DiscoveryEndpoints { get; set; } = { "" };

    internal AuthorizationOptions()
    {
        this._policies = new Dictionary<string, AuthorizationPolicy>(StringComparer.OrdinalIgnoreCase)
        {
            {
                AuthorizeAttribute.DefaultPolicy, new AuthorizationPolicy(new AuthenticatedUserRequirement())
            }
        };
    }

    /// <summary>
    /// Allows the definition of a new policy with a set of requirements.
    /// </summary>
    /// <param name="policyName"></param>
    /// <param name="onConfigurePolicy"></param>
    /// <exception cref="ArgumentNullException">
    /// Thrown if:
    /// - The <paramref name="policyName" /> is null.
    /// - The <paramref name="onConfigurePolicy" /> action is null.
    /// </exception>
    /// <exception cref="ArgumentException">
    /// Thrown if:
    /// - The <paramref name="policyName" /> is empty.
    /// </exception>
    public void AddPolicy(string policyName, Action<AuthorizationPolicyBuilder> onConfigurePolicy)
    {
        Guard.IsNotNullOrWhiteSpace(policyName);
        Guard.IsNotNull(onConfigurePolicy);

        var policyBuilder = new AuthorizationPolicyBuilder();

        onConfigurePolicy(policyBuilder);

        this._policies[policyName] = policyBuilder.Build();
    }

    /// <summary>
    /// Gets the policy matching the specified <paramref name="policyName" />.
    /// </summary>
    /// <param name="policyName"></param>
    /// <returns></returns>
    /// <exception cref="ArgumentNullException">
    /// Thrown if:
    /// - The <paramref name="policyName" /> is null.
    /// </exception>
    /// <exception cref="ArgumentException">
    /// Thrown if:
    /// - The <paramref name="policyName" /> is empty.
    /// - There is no policy matching the given <paramref name="policyName" />.
    /// </exception>
    internal AuthorizationPolicy GetPolicy(string policyName)
    {
        Guard.IsNotNullOrWhiteSpace(policyName);

        if (!this._policies.ContainsKey(policyName))
            throw new ArgumentException($"The policy '{policyName}' could not be found.");

        return this._policies[policyName];
    }
}
