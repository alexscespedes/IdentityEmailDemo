namespace IdentityEmailDemo;

public record TwoFactorVerifyDto
{
    public required string Email { get; set; }
    public required string Code { get; set; }
}
