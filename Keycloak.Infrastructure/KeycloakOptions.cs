namespace Keycloak.Infrastructure;

public sealed class KeycloakOptions
{
    public string BaseUrl { get; set; } = string.Empty;

    public string TokenUrl { get; set; } = string.Empty;

    public string AuthClientId { get; init; } = string.Empty;

    public string AuthClientSecret { get; init; } = string.Empty;
}
