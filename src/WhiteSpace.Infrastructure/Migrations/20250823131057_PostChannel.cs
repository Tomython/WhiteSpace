using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace WhiteSpace.Infrastructure.Migrations
{
    /// <inheritdoc />
    public partial class PostChannel : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<Guid>(
                name: "ChannelId",
                table: "Posts",
                type: "TEXT",
                nullable: true);

            migrationBuilder.CreateIndex(
                name: "IX_Posts_ChannelId",
                table: "Posts",
                column: "ChannelId");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropIndex(
                name: "IX_Posts_ChannelId",
                table: "Posts");

            migrationBuilder.DropColumn(
                name: "ChannelId",
                table: "Posts");
        }
    }
}
