using System.Collections.ObjectModel;
using System.Security.Claims;
using CommunityToolkit.Diagnostics;

namespace NoSuchCompany.Azure.Functions.Worker.Extensions.Authorization.Policies;

public sealed class AuthorizationPolicy
{
    private readonly ReadOnlyCollection<IAuthorizationRequirement> _requirements;

    /// <summary>
    /// Gets a readonly list of <see cref="IAuthorizationRequirement" />s which must succeed for
    /// this policy to be successful.
    /// </summary>
    public IReadOnlyList<IAuthorizationRequirement> Requirements => this._requirements;

    public AuthorizationPolicy(IAuthorizationRequirement requirement)
    {
        Guard.IsNotNull(requirement);

        this._requirements = new List<IAuthorizationRequirement> { requirement }.AsReadOnly();
    }

    public AuthorizationPolicy(IEnumerable<IAuthorizationRequirement> requirements)
    {
        Guard.IsNotNull(requirements);

        this._requirements = new List<IAuthorizationRequirement>(requirements).AsReadOnly();
    }

    public async Task<bool> EvaluateAsync(ClaimsPrincipal claimsPrincipal)
    {
        foreach (IAuthorizationRequirement requirement in this.Requirements)
        {
            if (!await requirement.HandleAsync(claimsPrincipal))
                return false;
        }

        return true;
    }
}
