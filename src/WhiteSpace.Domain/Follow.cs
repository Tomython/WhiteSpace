namespace WhiteSpace.Domain;

public class Follow
{
    public Guid FollowerId { get; set; }             // кто подписался
    public Guid FolloweeId { get; set; }             // на кого
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
}