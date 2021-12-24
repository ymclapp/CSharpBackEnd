using E_Commerce.Models.Identity;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc.ModelBinding;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;

namespace E_Commerce.Services.Identity
{


    public class IdentityUserService : IUserService  //IdentityUserService in steps, but you can name whatever
    {
        private readonly SignInManager<IdentityUser> signInManager;
        private readonly UserManager<IdentityUser> userManager;
        private readonly IHttpContextAccessor httpContextAccessor;
        private readonly IEmailService emailService;
        private readonly JwtService jwtService;

        public IdentityUserService ( SignInManager<IdentityUser> signInManager, UserManager<IdentityUser> userManager, IHttpContextAccessor httpContextAccessor, IEmailService emailService, JwtService jwtService )
        {
            this.signInManager = signInManager;
            this.userManager = userManager;
            this.httpContextAccessor = httpContextAccessor;
            this.emailService = emailService;
            this.jwtService = jwtService;
        }

        public async Task<UserDto> Authenticate ( LoginData data )
        {
            var user = await userManager.FindByNameAsync(data.Username);
            if (!await userManager.CheckPasswordAsync(user, data.Password))
                return null;

            await signInManager.SignInAsync(user, true);
            return await CreateUserDtoAsync(user);
        }

        public async Task<UserDto> Register ( RegisterData data, ModelStateDictionary modelState )
        {
            var user = new IdentityUser
            {
                Email = data.Email,
                UserName = data.Username,
               // FirstName = data.FirstName,
              //  LastName = data.LastName,
                //Password = data.Password,  //NOOOOOOOOOO
            };
            var result = await userManager.CreateAsync(user, data.Password);

            if (result.Succeeded)
            {
                await userManager.AddToRoleAsync(user, "Administrator");
                await emailService.SendEmail(
                    data.Email,
                    "Welcome!",
                    "Welcome!",
                    "<h1>Welcome</h1>"
                    );

                await signInManager.SignInAsync(user, true);
                return await CreateUserDtoAsync(user);
            }
            foreach (var error in result.Errors)
            {
                var errorKey =
                  error.Code.Contains("Password") ? nameof(data.Password) :
                  error.Code.Contains("Email") ? nameof(data.Email) :
                  error.Code.Contains("UserName") ? nameof(data.Username) :
                  "";
                modelState.AddModelError(errorKey, error.Description);
            }
            return null;
        }
        private async Task<UserDto> CreateUserDtoAsync ( IdentityUser user )
        {
            return new UserDto
            {
                UserId = user.Id,
                Email = user.Email,
                Username = user.UserName,
                //FirstName = user.FirstName,
               // LastName = user.LastName,

                Roles = await userManager.GetRolesAsync(user),
            };
        }

        public async Task<UserDto> GetCurrentUser ( )
        {
            var principal = httpContextAccessor.HttpContext.User;
            return await GetUser(principal);
        }

        public async Task<UserDto> GetUser ( ClaimsPrincipal principal )
        {
            var user = await userManager.GetUserAsync(principal);
            return await CreateUserDtoAsync(user);
        }

        public async Task<UserDto> CustomerRegister ( CustomerData data, ModelStateDictionary modelState )
        {
            var user = new IdentityUser
            {
                Email = data.Email,
                UserName = data.Username,
            };
            var result = await userManager.CreateAsync(user, data.Password);

            if (result.Succeeded)
            {
                await userManager.AddToRoleAsync(user, "Customer");
                await emailService.SendEmail(
                    data.Email,
                    "Welcome!",
                    "Welcome!",
                    "<h1>Thank you for choosing our site for your product needs!</h1>"
                    );

                await signInManager.SignInAsync(user, true);
                return await CreateUserDtoAsync(user);
            }
            foreach (var error in result.Errors)
            {
                var errorKey =
                  error.Code.Contains("Password") ? nameof(data.Password) :
                  error.Code.Contains("Email") ? nameof(data.Email) :
                  error.Code.Contains("UserName") ? nameof(data.Username) :
                  "";
                modelState.AddModelError(errorKey, error.Description);
            }
            return null;
        }
        public async Task Logout()
        {
            await signInManager.SignOutAsync();
        }
    }
}
