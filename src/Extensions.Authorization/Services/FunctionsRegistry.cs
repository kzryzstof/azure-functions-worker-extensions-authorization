using System.Reflection;
using CommunityToolkit.Diagnostics;
using Microsoft.Azure.Functions.Worker;
using Microsoft.Azure.Functions.Worker.Http;
using NoSuchCompany.Azure.Functions.Worker.Extensions.Authorization.Attributes;

namespace NoSuchCompany.Azure.Functions.Worker.Extensions.Authorization.Services;

/// <summary>
/// Provides an implementation of <see cref="IFunctionsRegistry" />.
/// </summary>
internal sealed class FunctionsRegistry : IFunctionsRegistry
{
    private readonly Dictionary<string, string[]> _functionPolicies;

    /// <summary>
    /// Gets the number of functions found.
    /// </summary>
    internal uint FunctionsCount => (uint)this._functionPolicies.Count;

    public FunctionsRegistry(Assembly assembly)
    {
        Guard.IsNotNull(assembly);

        this._functionPolicies = new Dictionary<string, string[]>(StringComparer.CurrentCultureIgnoreCase);

        this.RegisterPolicies(assembly);
    }

    /// <summary>
    /// Gets the policies associated to the specified <paramref name="httpRequestData" />.
    /// </summary>
    /// <param name="httpRequestData"></param>
    /// <returns></returns>
    /// <exception cref="ArgumentNullException">
    /// Thrown if:
    /// - The <paramref name="httpRequestData" /> is null.
    /// </exception>
    public string[] GetPolicies(HttpRequestData httpRequestData)
    {
        Guard.IsNotNull(httpRequestData);

        string functionKey = httpRequestData.FunctionContext.FunctionDefinition.EntryPoint;

        if (!this._functionPolicies.ContainsKey(functionKey))
            return Array.Empty<string>();

        return this._functionPolicies[functionKey];
    }

    /// <summary>
    /// Gets all the Azure Function from the specified <paramref name="assembly" />
    /// and extracts the assigned policies.
    /// </summary>
    /// <returns></returns>
    private void RegisterPolicies(Assembly assembly)
    {
        List<Type> allClasses = assembly
            .GetTypes()
            .Where(type => type.IsClass)
            .ToList();

        foreach (Type existingClass in allClasses)
        {
            //  Extracts the Azure Functions registered in the class.
            List<MethodInfo> methodsWithFunctionAttributes = existingClass.GetMethods()
                .Where(method => method.IsPublic)
                .Where(notNullMethodBase => notNullMethodBase.ReflectedType != null)
                .Where(notNullMethodBase => notNullMethodBase.CustomAttributes.Count() > 1)
                .Where(notNullMethodBase => notNullMethodBase.CustomAttributes.Any(customAttributeData => customAttributeData.AttributeType == typeof(FunctionAttribute)))
                .ToList();

            if (methodsWithFunctionAttributes.Count == 0)
                continue;

            foreach (MethodInfo methodWithFunctionAttribute in methodsWithFunctionAttributes)
            {
                //  Retrieves the AuthorizeAsync attributes on the Azure Function.
                List<CustomAttributeData> authorizedAttributes = methodWithFunctionAttribute
                    .CustomAttributes
                    .Where(customAttributeData => customAttributeData.AttributeType == typeof(AuthorizeAttribute))
                    .Select(customAttributeData => customAttributeData)
                    .ToList();

                if (authorizedAttributes.Count == 0)
                    continue;

                List<string> policies = new();

                foreach (CustomAttributeData authorizedAttribute in authorizedAttributes)
                {
                    CustomAttributeNamedArgument policyNamedArgument = authorizedAttribute.NamedArguments.FirstOrDefault(namedArgument => namedArgument.MemberName == "Policy");

                    if (policyNamedArgument.MemberInfo is null)
                    {
                        policies.Add(AuthorizeAttribute.DefaultPolicy);
                        continue;
                    }

                    policies.Add(policyNamedArgument.TypedValue.Value as string);
                }

                this._functionPolicies.Add($"{methodWithFunctionAttribute.DeclaringType.FullName}.{methodWithFunctionAttribute.Name}".ToLowerInvariant(), policies.ToArray());
            }
        }
    }
}
