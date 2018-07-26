# Quickstart #6: IdentityServer and ASP.NET Identity

This quickstart uses ASP.NET Identity for identity management.

# How to run
1. `dotnet ef migrations add InitialPersistedGrantDbMigration -c PersistedGrantDbContext -o Data/Migrations/IdentityServer/PersistedGrantDb`
2. `dotnet ef migrations add InitialConfigurationDbMigration -c ConfigurationDbContext -o Data/Migrations/IdentityServer/ConfigurationDb`
3. `dotnet run /seed`