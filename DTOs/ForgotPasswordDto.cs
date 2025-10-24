using System;

namespace IdentityEmailDemo.DTOs;

public record ForgotPasswordDto
{
    public required string Email { get; set; }
}
