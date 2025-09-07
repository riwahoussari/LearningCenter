using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace LearningCenter.Migrations
{
    /// <inheritdoc />
    public partial class changefieldnamefromcreatedattodatejoined : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.RenameColumn(
                name: "CreatedAt",
                schema: "auth",
                table: "Users",
                newName: "DateJoined");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.RenameColumn(
                name: "DateJoined",
                schema: "auth",
                table: "Users",
                newName: "CreatedAt");
        }
    }
}
