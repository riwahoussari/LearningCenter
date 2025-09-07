using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace LearningCenter.Migrations
{
    /// <inheritdoc />
    public partial class removeprofilelinksfromuser : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropForeignKey(
                name: "FK_StudentProfiles_Users_UserId1",
                schema: "lms",
                table: "StudentProfiles");

            migrationBuilder.DropForeignKey(
                name: "FK_TutorProfiles_Users_UserId1",
                schema: "lms",
                table: "TutorProfiles");

            migrationBuilder.DropIndex(
                name: "IX_TutorProfiles_UserId1",
                schema: "lms",
                table: "TutorProfiles");

            migrationBuilder.DropIndex(
                name: "IX_StudentProfiles_UserId1",
                schema: "lms",
                table: "StudentProfiles");

            migrationBuilder.DropColumn(
                name: "StudentProfileId",
                schema: "auth",
                table: "Users");

            migrationBuilder.DropColumn(
                name: "TutorProfileId",
                schema: "auth",
                table: "Users");

            migrationBuilder.DropColumn(
                name: "UserId1",
                schema: "lms",
                table: "TutorProfiles");

            migrationBuilder.DropColumn(
                name: "UserId1",
                schema: "lms",
                table: "StudentProfiles");

            migrationBuilder.CreateIndex(
                name: "IX_TutorProfiles_UserId",
                schema: "lms",
                table: "TutorProfiles",
                column: "UserId");

            migrationBuilder.CreateIndex(
                name: "IX_StudentProfiles_UserId",
                schema: "lms",
                table: "StudentProfiles",
                column: "UserId");

            migrationBuilder.AddForeignKey(
                name: "FK_StudentProfiles_Users_UserId",
                schema: "lms",
                table: "StudentProfiles",
                column: "UserId",
                principalSchema: "auth",
                principalTable: "Users",
                principalColumn: "Id",
                onDelete: ReferentialAction.Cascade);

            migrationBuilder.AddForeignKey(
                name: "FK_TutorProfiles_Users_UserId",
                schema: "lms",
                table: "TutorProfiles",
                column: "UserId",
                principalSchema: "auth",
                principalTable: "Users",
                principalColumn: "Id",
                onDelete: ReferentialAction.Cascade);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropForeignKey(
                name: "FK_StudentProfiles_Users_UserId",
                schema: "lms",
                table: "StudentProfiles");

            migrationBuilder.DropForeignKey(
                name: "FK_TutorProfiles_Users_UserId",
                schema: "lms",
                table: "TutorProfiles");

            migrationBuilder.DropIndex(
                name: "IX_TutorProfiles_UserId",
                schema: "lms",
                table: "TutorProfiles");

            migrationBuilder.DropIndex(
                name: "IX_StudentProfiles_UserId",
                schema: "lms",
                table: "StudentProfiles");

            migrationBuilder.AddColumn<int>(
                name: "StudentProfileId",
                schema: "auth",
                table: "Users",
                type: "integer",
                nullable: false,
                defaultValue: 0);

            migrationBuilder.AddColumn<int>(
                name: "TutorProfileId",
                schema: "auth",
                table: "Users",
                type: "integer",
                nullable: false,
                defaultValue: 0);

            migrationBuilder.AddColumn<string>(
                name: "UserId1",
                schema: "lms",
                table: "TutorProfiles",
                type: "text",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "UserId1",
                schema: "lms",
                table: "StudentProfiles",
                type: "text",
                nullable: true);

            migrationBuilder.CreateIndex(
                name: "IX_TutorProfiles_UserId1",
                schema: "lms",
                table: "TutorProfiles",
                column: "UserId1");

            migrationBuilder.CreateIndex(
                name: "IX_StudentProfiles_UserId1",
                schema: "lms",
                table: "StudentProfiles",
                column: "UserId1");

            migrationBuilder.AddForeignKey(
                name: "FK_StudentProfiles_Users_UserId1",
                schema: "lms",
                table: "StudentProfiles",
                column: "UserId1",
                principalSchema: "auth",
                principalTable: "Users",
                principalColumn: "Id");

            migrationBuilder.AddForeignKey(
                name: "FK_TutorProfiles_Users_UserId1",
                schema: "lms",
                table: "TutorProfiles",
                column: "UserId1",
                principalSchema: "auth",
                principalTable: "Users",
                principalColumn: "Id");
        }
    }
}
