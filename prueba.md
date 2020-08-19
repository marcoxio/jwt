# 2. Implementing JWTGenerator

## Entity UserData

{% code title="UserData.cs" %}
```csharp
namespace Aplicacion.Security
{
    public class UserData
    {
        public string FullName { get; set; }
        public string Token { get; set; }
        public string Email { get; set; }
        public string Username { get; set; }
        public string Image { get; set; }
    }
}
```
{% endcode %}

## Interfaces

{% code title="IJwtGenerator.cs" %}
```csharp
using System.Collections.Generic;
using Dominio.Entities;

namespace Aplicacion.Interfaces
{
    public interface IJwtGenerator
    {
         string CreateToken(User user, List<string> roles);
    }
}
```
{% endcode %}

## Register User

```csharp
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using Aplicacion.Exceptions;
using Aplicacion.Interfaces;
using Dominio.Entities;
using FluentValidation;
using MediatR;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Persistencia;

namespace Aplicacion.Security
{
    public class Register
    {
        public class Execute : IRequest<UserData>
        {
            public string FullName { get; set; }
            public string Email { get; set; }
            public string Password { get; set; }
            public string Username { get; set; }
        }

         public class ExecuteValidator : AbstractValidator<Execute>{
            public ExecuteValidator(){
                RuleFor(x => x.FullName).NotEmpty();
                RuleFor(x => x.Email).NotEmpty();
                RuleFor(x => x.Password).NotEmpty();
                RuleFor(x => x.Username).NotEmpty();
            }
        }

        public class Handler : IRequestHandler<Execute, UserData>
        {
            private readonly CoursesOnlineContext _context;
            private readonly UserManager<User> _userManager;
            private readonly IJwtGenerator _jwtGenerator;
            public Handler(CoursesOnlineContext context, UserManager<User> userManager, IJwtGenerator jwtGenerator)
            {
                _jwtGenerator = jwtGenerator;
                _userManager = userManager;
                _context = context;

            }

            public async Task<UserData> Handle(Execute request, CancellationToken cancellationToken)
            {
                var exist = await _context.Users.Where(x => x.Email == request.Email).AnyAsync();
                if(exist)
                {
                    throw new HandlerException(HttpStatusCode.BadRequest, new {message ="This email already exists"});
                }

                var existUserName = await _context.Users.Where(x => x.UserName == request.Username).AnyAsync();
                if(existUserName){
                    throw new HandlerException(HttpStatusCode.BadRequest, new {mensaje = "this username already exists"});
                    
                }

                   var user = new User{
                    FullName = request.FullName,
                    Email = request.Email,
                    UserName = request.Username
                };

                var result = await _userManager.CreateAsync(user,request.Password);
                var resultRoles = await _userManager.GetRolesAsync(user);
                var listRoles = new List<string>(resultRoles);
                if(result.Succeeded){
                    return new UserData{
                        FullName = user.FullName,
                        Token = _jwtGenerator.CreateToken(user,listRoles),
                        Username = user.UserName,
                        Email = user.Email
                    };
                }

                throw new Exception("dont add new user");
            }
        }
    }
}
```

## Create Token

```csharp
using System.Collections.Generic;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using Aplicacion.Exceptions;
using Aplicacion.Interfaces;
using Dominio.Entities;
using FluentValidation;
using MediatR;
using Microsoft.AspNetCore.Identity;

namespace Aplicacion.Security
{
    public class Login
    {
        public class Execute : IRequest<UserData>
        {
            public string Email { get; set; }
            public string Password { get; set; }
        }

        public class ExecuteValidation : AbstractValidator<Execute>
        {
            public ExecuteValidation()
            {
                RuleFor(x => x.Email).NotEmpty();
                RuleFor(x => x.Password).NotEmpty();
            }
        }

        public class Handler : IRequestHandler<Execute, UserData>
        {
            private readonly UserManager<User> _userManager;
            private readonly SignInManager<User> _signInManager;
            private readonly IJwtGenerator _jwtGenerator;
            public Handler(UserManager<User> userManager,
            SignInManager<User> signInManager, IJwtGenerator jwtGenerator)
            {
                _jwtGenerator = jwtGenerator;
                _userManager = userManager;
                _signInManager = signInManager;

            }

        public async Task<UserData> Handle(Execute request, CancellationToken cancellationToken)
        {
            var user = await _userManager.FindByEmailAsync(request.Email);
            
            if (user == null)
            {
                throw new HandlerException(HttpStatusCode.Unauthorized);
            }

            var result = await _signInManager.CheckPasswordSignInAsync(user, request.Password, false);
            var resultRoles = await _userManager.GetRolesAsync(user);
            var listRoles = new List<string>(resultRoles);
            if (result.Succeeded)
            {
                return new UserData
                {
                    FullName = user.FullName,
                    Token = _jwtGenerator.CreateToken(user,listRoles),
                    Username = user.UserName,
                    Email = user.Email,
                    Image = null
                };
            }

            throw new HandlerException(HttpStatusCode.Unauthorized);
        }
    }
}
}
```

## JWT Generator

```csharp
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Aplicacion.Interfaces;
using Dominio.Entities;
using Microsoft.IdentityModel.Tokens;

namespace Security
{
    public class JwtGenerator : IJwtGenerator
    {
        public string CreateToken(User user, List<string> roles)
        {
            //in this section  add parameters for read JWT
            var claims = new List<Claim>
            {
                new Claim(JwtRegisteredClaimNames.NameId, user.UserName)
                // new Claim(JwtRegisteredClaimNames.Email, user.Email)
            };

            //Validation list Role
            if (roles != null)
            {
                foreach (var rol in roles)
                {
                    claims.Add(new Claim(ClaimTypes.Role, rol));
                }
            }

            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("This is muy secret word"));
            var credentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha512Signature);

            var tokenDescription = new SecurityTokenDescriptor 
            {
                Subject = new ClaimsIdentity(claims),
                Expires = DateTime.Now.AddDays(30),
                SigningCredentials = credentials
            };

            var tokenHandler = new JwtSecurityTokenHandler();
            var token = tokenHandler.CreateToken(tokenDescription);

            return tokenHandler.WriteToken(token);
        }
    }
}
```

## UserUpdated

{% code title="UserUpdated.cs" %}
```csharp
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using Aplicacion.Exceptions;
using Aplicacion.Interfaces;
using Dominio.Entities;
using FluentValidation;
using MediatR;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Persistencia;

namespace Aplicacion.Security
{
    public class UserUpdated
    {
        public class Execute : IRequest<UserData>
        {
            public string FullName { get; set; }
            public string Email { get; set; }
            public string Password { get; set; }
            public string Username { get; set; }
        }

        public class ExecuteValidator : AbstractValidator<Execute>
        {
            public ExecuteValidator()
            {
                RuleFor(x => x.FullName).NotEmpty();
                RuleFor(x => x.Email).NotEmpty();
                RuleFor(x => x.Password).NotEmpty();
                RuleFor(x => x.Username).NotEmpty();
            }
        }

        public class Handler : IRequestHandler<Execute, UserData>
        {
            private readonly CoursesOnlineContext _context;
            private readonly UserManager<User> _userManager;
            private readonly IJwtGenerator _jwtHandler;
            private IPasswordHasher<User> _passwordHasher;

            public Handler(CoursesOnlineContext context, UserManager<User> userManager, IJwtGenerator jwtHandler, IPasswordHasher<User> passwordHasher)
            {
                _context = context;
                _userManager = userManager;
                _jwtHandler = jwtHandler;
                _passwordHasher = passwordHasher;
            }
            public async Task<UserData> Handle(Execute request, CancellationToken cancellationToken)
            {
                var userIden = await _userManager.FindByNameAsync(request.Username);
                if (userIden == null)
                {
                    throw new HandlerException(HttpStatusCode.NotFound, new { Message = "Dont exist user with username" });
                }

                var result = await _context.Users.Where(x => x.Email == request.Email && x.UserName != request.Username).AnyAsync();
                if (result)
                {
                    throw new HandlerException(HttpStatusCode.InternalServerError, new { mensaje = "This email belong other user" });
                }

                userIden.FullName = request.FullName;
                userIden.PasswordHash = _passwordHasher.HashPassword(userIden, request.Password);
                userIden.Email = request.Email;

                var resultUpdate = await _userManager.UpdateAsync(userIden);
                var resultRoles = await _userManager.GetRolesAsync(userIden);
                var listRoles = new List<string>(resultRoles);

                if (resultUpdate.Succeeded)
                {
                    return new UserData
                    {
                        FullName = userIden.FullName,
                        Username = userIden.UserName,
                        Email = userIden.Email,
                        Token = _jwtHandler.CreateToken(userIden, listRoles)
                    };
                }

                throw new Exception("Dont update user");
            }
        }
    }
}
```
{% endcode %}

## UserController

```csharp
using System.Threading.Tasks;
using Aplicacion.Security;
using Dominio.Entities;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace WebAPI.Controllers
{
    public class UserController : MyControllerBase
    {
        [AllowAnonymous]
        //http:localhost:5000/api/User/login
        [HttpPost("login")]
        public async Task<ActionResult<UserData>> Login(Login.Execute parameters)
        {
            return await Mediator.Send(parameters);
        }

        [HttpPost("register")]
        public async Task<ActionResult<UserData>> Register(Register.Execute parameters)
        {
            return await Mediator.Send(parameters);
        }

        [HttpGet]
        public async Task<ActionResult<UserData>> ReturnUser(){
            return await Mediator.Send(new CurrentUser.Execute());
        }

        [HttpPut]
        public async Task<ActionResult<UserData>> UpdateUser(UserUpdated.Execute parameters){
            return await Mediator.Send(parameters);
        }
    }
}
```

