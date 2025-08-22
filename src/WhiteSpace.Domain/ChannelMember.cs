namespace WhiteSpace.Domain;

public class ChannelMember
{
    public Guid ChannelId { get; set; }
    public Guid UserId { get; set; }
    public string Role { get; set; } = "member"; // owner|mod|member
}