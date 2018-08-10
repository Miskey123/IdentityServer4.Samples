# Quickstart #6: IdentityServer and ASP.NET Identity

This quickstart uses ASP.NET Identity for identity management.

# How to run
1. `dotnet ef migrations add InitialPersistedGrantDbMigration -c PersistedGrantDbContext -o Data/Migrations/IdentityServer/PersistedGrantDb`
2. `dotnet ef migrations add InitialConfigurationDbMigration -c ConfigurationDbContext -o Data/Migrations/IdentityServer/ConfigurationDb`
3. `dotnet run /seed`

# How can we revoke an access token
Firstly, we should know that Jwt token cannot be revoked. And IdentityServer4 use JWT token as the default token.
So if we want to revoke an access, we must change the access token type.

1. Open the IdentityServerWithAspIdAndEF project, specify the `AccessTokenType` Property of the `Client`:
```
new Client
{
    ClientId = "mvc",
    ClientName = "MVC Client",
    AllowedGrantTypes = GrantTypes.HybridAndClientCredenti
    AccessTokenType = AccessTokenType.Reference,
    //....
}
```
2. Specify the `ApiSecrets` property of the `ApiResource`.
```
public static IEnumerable<ApiResource> GetApiResources()
{
    return new List<ApiResource>
    {
        new ApiResource("api1", "My API"){
            ApiSecrets={new Secret("secret".Sha256())}
        }
    };
}
```
3. Open the Api project, update the token validation configuration. Specify the `ApiSecret` we configured before.
```
services.AddAuthentication("Bearer")
    .AddIdentityServerAuthentication(options =>
    {
        options.Authority = "http://localhost:5000
        options.RequireHttpsMetadata = false;
        options.ApiName = "api1";
        options.ApiSecret = "secret";
    });
```
4. Start the Identity Server, Api and MvcClient by order. After that, 
5. Open `http://localhost:5002/Home/Secure`, because it needs authorized, so it will redirect to the login page, fill in the accout and login. And then you can see the claims and token. Click the `Call API using user token`, you can get the identity information.
6. Open `http://localhost:5000/grants` and click the 'Revoke Access' button, the previous token will be expired.
7. Repeat the 5th step, you will get erorr about 401(Unauthorized).

>http://docs.identityserver.io/en/release/topics/apis.html>