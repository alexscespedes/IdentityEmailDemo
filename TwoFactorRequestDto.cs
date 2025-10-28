namespace IdentityEmailDemo;

public record TwoFactorRequestDto
{
    public required string Email { get; set; }
}
