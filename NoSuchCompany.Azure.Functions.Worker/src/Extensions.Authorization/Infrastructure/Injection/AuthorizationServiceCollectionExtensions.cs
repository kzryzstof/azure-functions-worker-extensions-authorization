using System.Reflection;
using CommunityToolkit.Diagnostics;
using Microsoft.Azure.Functions.Worker;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using NoSuchCompany.Azure.Functions.Worker.Extensions.Authorization.Infrastructure.Middleware;
using NoSuchCompany.Azure.Functions.Worker.Extensions.Authorization.Policies;
using NoSuchCompany.Azure.Functions.Worker.Extensions.Authorization.Requirements;
using NoSuchCompany.Azure.Functions.Worker.Extensions.Authorization.Services;

namespace NoSuchCompany.Azure.Functions.Worker.Extensions.Authorization.Infrastructure.Injection;

public static class AuthorizationServiceCollectionExtensions
{
    public static IFunctionsWorkerApplicationBuilder UseAuthorization(this IFunctionsWorkerApplicationBuilder functionsWorkerApplicationBuilder)
    {
        functionsWorkerApplicationBuilder.UseMiddleware<AuthorizationMiddleware>();

        return functionsWorkerApplicationBuilder;
    }

    /// <summary>
    /// Registers the services from the application layer.
    /// </summary>
    /// <param name="services"></param>
    /// <param name="onConfigureAuthorizationOptions"></param>
    /// <remarks>
    /// This override is useful if the configuration requires other existing services
    /// such as configuration. The method passes an instance of <see cref="IServiceProvider" />
    /// which allows the retrieval of the needed services.
    /// </remarks>
    public static void AddAuthorization(this IServiceCollection services, Action<IServiceProvider, AuthorizationOptions> onConfigureAuthorizationOptions)
    {
        Guard.IsNotNull(onConfigureAuthorizationOptions);

        AddAuthorization(services, onConfigureAuthorizationOptions, Assembly.GetCallingAssembly());
    }

    /// <summary>
    /// Registers the services from the application layer.
    /// </summary>
    /// <param name="services"></param>
    /// <param name="onConfigureAuthorizationOptions"></param>
    /// <param name="callingAssembly"></param>
    private static void AddAuthorization(this IServiceCollection services, Action<IServiceProvider, AuthorizationOptions> onConfigureAuthorizationOptions, Assembly callingAssembly)
    {
        //  Registers all the project's internal classes.
        services.AddTransient<IClaimsPrincipalBuilder, ClaimsPrincipalBuilder>();
        services.AddTransient<IAuthorizationService, AuthorizationService>();

        //  Registers the Azure Functions and their assigned policies.
        FunctionsRegistry functionsRegistry = new(callingAssembly);
        services.AddSingleton<IFunctionsRegistry>(functionsRegistry);

        //  Registers all the requirements.
        services.AddTransient<IAuthorizationRequirement, ClaimsAuthorizationRequirement>();

        services.AddSingleton(serviceProvider =>
        {
            AuthorizationOptions options = new();

            //  Passes the service around so that policies can be added.
            onConfigureAuthorizationOptions(serviceProvider, options);

            return options;
        });
    }
}
