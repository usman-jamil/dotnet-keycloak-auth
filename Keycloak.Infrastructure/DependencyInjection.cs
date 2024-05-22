using System.Security.Claims;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace Keycloak.Infrastructure;

public static class DependencyInjection
{
    public static IServiceCollection AddInfrastructure(
        this IServiceCollection services,
        IConfiguration configuration)
    {
        AddAuthentication(services, configuration);
        AddAuthorization(services);
        
        return services;
    }

    private static void AddAuthentication(IServiceCollection services, IConfiguration configuration)
    {
        services
            .AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
            .AddJwtBearer(opt =>
            {
                opt.Events = new JwtBearerEvents()
                {
                    OnTokenValidated = (context) =>
                    {
                        if (context.Principal?.HasClaim(claim => claim.Type == "realm_access") == true)
                        {
                            var realmAccessClaimValue = context.Principal.Claims
                                .FirstOrDefault(claim => claim.Type == "realm_access")?.Value;

                            if (!string.IsNullOrEmpty(realmAccessClaimValue))
                            {
                                var values = JsonConvert.DeserializeObject<Dictionary<string, object>>(realmAccessClaimValue);
                                if (values != null && values.TryGetValue("roles", out var roles))
                                {
                                    var rolesArray = JArray.FromObject(roles);
                                    var result = rolesArray?.FirstOrDefault(val => val.Value<string>() == "dev-docs-admin");
                                    if (result != null)
                                    {
                                        var claims = new List<Claim>
                                        {
                                            new Claim(ClaimTypes.Role, "admin")
                                        };
                                        var appIdentity = new ClaimsIdentity(claims);
                                        context.Principal?.AddIdentity(appIdentity);
                                    }
                                }
                            }
                        }

                        return Task.CompletedTask;
                    }
                };
            });
        
        services.Configure<AuthenticationOptions>(configuration.GetSection("Authentication"));

        services.ConfigureOptions<JwtBearerOptionsSetup>();

        services.Configure<KeycloakOptions>(configuration.GetSection("Keycloak"));

        services.AddHttpContextAccessor();
    }
    
    private static void AddAuthorization(IServiceCollection services)
    {
        services.AddAuthorizationBuilder()
            .AddPolicy("admin", policy =>
                policy
                    .RequireRole("admin"));

        services.AddAuthorization();
    }
}