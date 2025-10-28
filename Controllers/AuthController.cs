using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Security.Claims;
using System.Text;
using IdentityEmailDemo.DTOs;
using IdentityEmailDemo.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.Data;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;

namespace IdentityEmailDemo.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly UserManager<IdentityUser> _userManager;

        private readonly IEmailService _emailService;
        private readonly IConfiguration _configuration;

        public AuthController(UserManager<IdentityUser> userManager, IEmailService emailService, IConfiguration configuration)
        {
            _userManager = userManager;
            _emailService = emailService;
            _configuration = configuration;
        }

        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody] RegisterDto model)
        {
            var user = new IdentityUser
            {
                UserName = model.Username,
                Email = model.Email
            };
            var result = await _userManager.CreateAsync(user, model.Password);

            if (!result.Succeeded)
                return BadRequest(result.Errors);

            var token = await _userManager.GenerateEmailConfirmationTokenAsync(user);
            var confirmationLink = Url.Action(nameof(ConfirmEmail), "Auth", new { userId = user.Id, token }, Request.Scheme);

            await _emailService.SendEmailAsync(user.Email, "Confirm your email",
                $"<p>Please confirm your account by clicking <a href='{confirmationLink}'>here<a/>.<p>"
            );

            return Ok("Registration successful! Please check your email to confirm your account.");
        }

        [HttpGet("Confirm-email")]
        public async Task<IActionResult> ConfirmEmail(string userId, string token)
        {
            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
                return BadRequest("Invalid user.");

            var result = await _userManager.ConfirmEmailAsync(user, token);
            if (!result.Succeeded)
                return BadRequest("Email confirmation failed");

            return Ok("Email confirmed successfully!");
        }

        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] LoginDto model)
        {
            var user = await _userManager.FindByNameAsync(model.Username)
                ?? await _userManager.FindByEmailAsync(model.Username);

            if (user == null)
                return Unauthorized("Invalid credentials.");

            if (await _userManager.IsLockedOutAsync(user))
                return Unauthorized("Account locked due to multiple failed login attempts. Please try again later.");

            if (!await _userManager.CheckPasswordAsync(user, model.Password))
            {
                await _userManager.AccessFailedAsync(user);
                return Unauthorized("Invalid username or password");
            }

            await _userManager.ResetAccessFailedCountAsync(user);

            if (!await _userManager.IsEmailConfirmedAsync(user))
                return Unauthorized("Email not confirmed. Please check your inbox to verify your account.");

            if (await _userManager.GetTwoFactorEnabledAsync(user))
                return Ok(new
                {
                    TwoFactorRequired = true,
                    user.Email
                });
                
            var roles = await _userManager.GetRolesAsync(user);

            var token = GenerateJwtToken(user, roles);

            return Ok(new
            {
                message = "Login successful.",
                token,
                user = new
                {
                    user.UserName,
                    user.Email,
                    Roles = roles
                }
            });
        }

        [HttpPost("forgot-password")]
        public async Task<IActionResult> ForgotPassowrd([FromBody] ForgotPasswordDto model)
        {
            var user = await _userManager.FindByEmailAsync(model.Email);
            if (user == null)
                return BadRequest("User not found.");

            var token = await _userManager.GeneratePasswordResetTokenAsync(user);
            var resetLink = Url.Action(nameof(ResetPassword), "Auth", new { token, email = user.Email }, Request.Scheme);

            await _emailService.SendEmailAsync(user.Email!, "Password Reset",
                $"<p>Click <a href='{resetLink}'>here<a/> to reset your password.</p>");

            return Ok("Password reset email sent. Please check your inbox.");
        }

        [HttpPost("reset-password")]
        public async Task<IActionResult> ResetPassword([FromBody] ResetPasswordDto model)
        {
            var user = await _userManager.FindByEmailAsync(model.Email);
            if (user == null)
                return BadRequest("Invalid user.");

            var decodedToken = WebUtility.UrlDecode(model.Token);

            var result = await _userManager.ResetPasswordAsync(user, decodedToken, model.NewPassword);

            if (!result.Succeeded)
                return BadRequest(result.Errors);

            return Ok("Password has been reset successfully.");
        }

        [HttpPost("send-2fa-code")]
        public async Task<IActionResult> SendTwoFactor([FromBody] TwoFactorRequestDto model)
        {
            var user = await _userManager.FindByEmailAsync(model.Email);
            if (user == null)
                return BadRequest("Invalid email.");

            var token = await _userManager.GenerateTwoFactorTokenAsync(user, TokenOptions.DefaultEmailProvider);
            await _emailService.SendEmailAsync(user.Email!, "Your 2FA Code", $"Your verification code is: <b>{token}</b>");

            return Ok("2FA code sent to your email.");
        }

        [HttpPost("verify-2fa-code")]
        public async Task<IActionResult> VerifyTwoFactorCode([FromBody] TwoFactorVerifyDto model)
        {
            var user = await _userManager.FindByEmailAsync(model.Email);
            if (user == null)
                return BadRequest("Invalid user.");

            var isValid = await _userManager.VerifyTwoFactorTokenAsync(user, TokenOptions.DefaultEmailProvider, model.Code);
            if (!isValid)
                return Unauthorized("Invalid verification code.");

            var roles = await _userManager.GetRolesAsync(user);
            var token = GenerateJwtToken(user, roles);

            return Ok(new
            {
                message = "2FA Code successfully verified.",
                token,
                user = new
                {
                    user.UserName,
                    user.Email,
                    Roles = roles
                }
            });
        }

        [Authorize]
        public async Task<IActionResult> EnableTwoFactor()
        {
            var user = await _userManager.GetUserAsync(User);
            if (user == null)
                return Unauthorized();

            await _userManager.SetTwoFactorEnabledAsync(user, true);
            return Ok("Two-factor authentication enabled.");
        }

        [Authorize]
        public async Task<IActionResult> DisableTwoFactor()
        {
            var user = await _userManager.GetUserAsync(User);
            if (user == null)
                return Unauthorized();

            await _userManager.SetTwoFactorEnabledAsync(user, false);
            return Ok("Two-factor authentication disabled.");
        }

        [Authorize]
        [HttpPost("generate-recovery-codes")]
        public async Task<IActionResult> GenerateRecoveryCodes()
        {
            var user = await _userManager.GetUserAsync(User);
            if (user == null)
                return Unauthorized();

            var codes = await _userManager.GenerateNewTwoFactorRecoveryCodesAsync(user, 5);
            return Ok(new
            {
                RecoveryCodes = codes
            });
        }

        private string GenerateJwtToken(IdentityUser user, IList<string> roles)
        {
            var jwtSettings = _configuration.GetSection("JwtSettings");
            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtSettings["Key"]!));

            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.Name, user.UserName!),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
            };

            foreach (var role in roles)
                claims.Add(new Claim(ClaimTypes.Role, role));

            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            var token = new JwtSecurityToken(
                issuer: jwtSettings["Issuer"],
                audience: jwtSettings["Audience"],
                claims: claims,
                expires: DateTime.Now.AddMinutes(Convert.ToDouble(jwtSettings["DurationInMinutes"])),
                signingCredentials: creds
            );

            return new JwtSecurityTokenHandler().WriteToken(token);
        }


    }
}
