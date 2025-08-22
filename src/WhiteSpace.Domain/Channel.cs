namespace WhiteSpace.Domain;

public class Channel
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public string Name { get; set; } = string.Empty;
    public bool IsPrivate { get; set; }
    public string? Code { get; set; }          // секрет для закрытых каналов
    public Guid OwnerId { get; set; }
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
}