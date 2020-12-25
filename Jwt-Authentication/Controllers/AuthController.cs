using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using Jwt_Authentication.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;

namespace Jwt_Authentication.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly IConfiguration _config;

        public AuthController(IConfiguration config)
        {
            _config = config;
        }

        [HttpGet]
        public IActionResult Login(string username, string password)
        {
            var user = new UserModel();

            user.UserName = username;
            user.Password = password;

            IActionResult response = Unauthorized();

            var loginUser = AuthenticateUser(user);

            if(loginUser != null)
            {
                var tokenStr = GenerateJWT(loginUser);
                response = Ok(
                    new
                    {
                        token = tokenStr
                    }
                    );
            }

            return response;
        }

        private UserModel AuthenticateUser(UserModel user)
        {
            UserModel u = null;
            if(user.UserName == "gokhansatman" &&  user.Password == "2021")
            {
                u = new UserModel
                {
                    UserName = user.UserName,
                    Email = "abgsatman@gmail.com",
                    Password = user.Password
                };
            }

            return u;
        }

        private string GenerateJWT(UserModel user)
        {
            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config["Jwt:Key"]));
            var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

            var claims = new[]
            {
                new Claim(JwtRegisteredClaimNames.Sub, user.UserName),
                new Claim(JwtRegisteredClaimNames.Email, user.Email),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
            };

            var token = new JwtSecurityToken(
                issuer: _config["Jwt:Issuer"],
                audience: _config["Jwt:Issuer"],
                claims,
                expires: DateTime.Now.AddMinutes(120), //2 hours as default, change it if u want to...
                signingCredentials: credentials
                );

            var encodedToken = new JwtSecurityTokenHandler().WriteToken(token);

            return encodedToken;
        }

        [Authorize]
        [HttpPost("DoLogin")]
        public string DoLogin()
        {
            var identity = HttpContext.User.Identity as ClaimsIdentity;
            IList<Claim> claim = identity.Claims.ToList();

            var userName = claim[0].Value;
            var email = claim[1].Value;

            var result = new StringBuilder();

            result.Append("Your name is ");
            result.Append(userName);

            result.Append(" & ");

            result.Append("Your email is ");
            result.Append(email);

            return result.ToString();
        }

        [Authorize]
        [HttpGet("AnyPage")]
        public string AnyPage()
        {
            return "If you see this line, It means that you have permission to get in here!";
        }
    }
}
