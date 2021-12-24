using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using System;
using System.IdentityModel.Tokens.Jwt;
using System.Text;
using System.Threading.Tasks;

namespace E_Commerce.Services.Identity
{
    public class JwtService
    {
        private readonly SignInManager<IdentityUser> signInManager;
        private readonly IConfiguration configuration;
        public JwtService ( SignInManager<IdentityUser> signInManager, IConfiguration configuration )
        {
            this.signInManager = signInManager;
            this.configuration = configuration;
        }
        public async Task<string> GetToken ( IdentityUser user, TimeSpan expiresIn )
        {
            var principal = await signInManager.CreateUserPrincipalAsync(user);
            if (principal == null) { return null; }
            var signingKey = GetSecurityKey(configuration);
            var token = new JwtSecurityToken(
              expires: DateTime.UtcNow + expiresIn,
              signingCredentials: new SigningCredentials(signingKey, SecurityAlgorithms.HmacSha256),
              claims: principal.Claims
             );
            return new JwtSecurityTokenHandler().WriteToken(token);
        }
        // Validate that our "secrets" are actually secrets and that they match 
        // This will be used by the validator 
        public static TokenValidationParameters GetValidationParameters ( IConfiguration configuration )
        {
            return new TokenValidationParameters
            {
                ValidateIssuerSigningKey = true,
                // This Is Our main goal: Make sure the security key, which comes from configuration is valid 
                IssuerSigningKey = GetSecurityKey(configuration),
                // For simplifying testing 
                ValidateIssuer = false,
                ValidateAudience = false,
            };
        }
        private static SecurityKey GetSecurityKey ( IConfiguration configuration )
        {
            var secret = configuration["JWT:Secret"];
            if (secret == null) { throw new InvalidOperationException("JWT:Secret is missing"); }
            var secretBytes = Encoding.UTF8.GetBytes(secret);
            return new SymmetricSecurityKey(secretBytes);
        }
    }
}
