namespace NoSuchCompany.Azure.Functions.Worker.Extensions.Authorization.Attributes;

/// <summary>
/// Defines an attribute used to declare a policy on an Azure Function.
/// </summary>
[AttributeUsage(AttributeTargets.Class | AttributeTargets.Method, AllowMultiple = true)]
public sealed class AuthorizeAttribute : Attribute
{
    internal const string DefaultPolicy = "AuthenticatedUser";

    public string Policy { get; set; } = DefaultPolicy;
}
