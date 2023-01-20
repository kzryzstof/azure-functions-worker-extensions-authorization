using System.Net;
using System.Security;
using System.Security.Authentication;
using CommunityToolkit.Diagnostics;
using Microsoft.Azure.Functions.Worker;
using Microsoft.Azure.Functions.Worker.Http;
using Microsoft.Azure.Functions.Worker.Middleware;
using Microsoft.Extensions.Logging;
using NoSuchCompany.Azure.Functions.Worker.Extensions.Authorization.Services;

namespace NoSuchCompany.Azure.Functions.Worker.Extensions.Authorization.Infrastructure.Middleware;

internal sealed class AuthorizationMiddleware : IFunctionsWorkerMiddleware
{
    private readonly IAuthorizationService _authorizationService;
    private readonly ILogger<AuthorizationMiddleware> _logger;

    public AuthorizationMiddleware
    (
        ILogger<AuthorizationMiddleware> logger,
        IAuthorizationService authorizationService
    )
    {
        Guard.IsNotNull(logger);
        Guard.IsNotNull(authorizationService);

        this._logger = logger;
        this._authorizationService = authorizationService;
    }

    public async Task Invoke(FunctionContext context, FunctionExecutionDelegate next)
    {
        try
        {
            var httpRequestData = await context.GetHttpRequestDataAsync();

            if (httpRequestData is null)
            {
                await next(context);
                return;
            }

            try
            {
                var claimsPrincipal = await this._authorizationService.AuthorizeAsync(httpRequestData);

                context.Items.Add(Items.Name, claimsPrincipal);

                await next(context);
            }
            catch (ArgumentNullException argumentNullException)
            {
                this._logger.LogWarning(argumentNullException, "A null argument has been passed: {ExceptionMessage}", argumentNullException.Message);
                InvokeResult(context, httpRequestData.CreateResponse(HttpStatusCode.BadRequest));
            }
            catch (ArgumentException argumentException)
            {
                this._logger.LogWarning(argumentException, "An invalid argument has been passed: {ExceptionMessage}", argumentException.Message);
                InvokeResult(context, httpRequestData.CreateResponse(HttpStatusCode.BadRequest));
            }
            catch (AuthenticationException authenticationException)
            {
                this._logger.LogWarning(authenticationException, "An unauthorized request has been detected: {ExceptionMessage}", authenticationException.Message);
                InvokeResult(context, httpRequestData.CreateResponse(HttpStatusCode.Unauthorized));
            }
            catch (SecurityException securityException)
            {
                this._logger.LogCritical(securityException, "An unauthorized request has been detected: {ExceptionMessage}", securityException.Message);
                InvokeResult(context, httpRequestData.CreateResponse(HttpStatusCode.Forbidden));
            }
            catch (Exception unhandledException)
            {
                this._logger.LogCritical(unhandledException, "An unhandled exception request has been caught: {ExceptionMessage}", unhandledException.Message);
                InvokeResult(context, httpRequestData.CreateResponse(HttpStatusCode.InternalServerError));
            }
        }
        catch (Exception unhandledException)
        {
            this._logger.LogCritical(unhandledException, "Unhandled exception caught: {UnhandledException}", unhandledException.Message);
            throw;
        }
    }

    private static void InvokeResult(FunctionContext context, HttpResponseData response)
    {
        var keyValuePair = context.Features.SingleOrDefault(f => f.Key.Name == "IFunctionBindingsFeature");
        var functionBindingsFeature = keyValuePair.Value;
        var type = functionBindingsFeature.GetType();
        var result = type.GetProperties().Single(p => p.Name == "InvocationResult");
        result.SetValue(functionBindingsFeature, response);
    }
}
