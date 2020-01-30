using System;
using Microsoft.EntityFrameworkCore.Migrations;

namespace MWR.C3.WebController.Migrations
{
    public partial class Initial : Migration
    {
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "Builds",
                columns: table => new
                {
                    Type = table.Column<int>(nullable: false),
                    Arch = table.Column<int>(nullable: false),
                    PublicKey = table.Column<byte[]>(nullable: true),
                    BroadcastKey = table.Column<byte[]>(nullable: true),
                    BuildId = table.Column<ulong>(nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    Commands = table.Column<string>(nullable: true),
                    Peripherals = table.Column<string>(nullable: true),
                    Channels = table.Column<string>(nullable: true),
                    Name = table.Column<string>(nullable: true),
                    Discriminator = table.Column<string>(nullable: false),
                    Connectors = table.Column<string>(nullable: true),
                    RelayCommands = table.Column<string>(nullable: true),
                    StartupCommands = table.Column<string>(nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Builds", x => x.BuildId);
                });

            migrationBuilder.CreateTable(
                name: "Commands",
                columns: table => new
                {
                    GatewayAgentId = table.Column<ulong>(nullable: false),
                    RelayAgentId = table.Column<ulong>(nullable: true),
                    InterfaceId = table.Column<ulong>(nullable: true),
                    DeviceType = table.Column<string>(nullable: true),
                    Id = table.Column<ulong>(nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    Name = table.Column<string>(nullable: false),
                    Data = table.Column<string>(nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Commands", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "Agents",
                columns: table => new
                {
                    AgentId = table.Column<ulong>(nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    BuildId = table.Column<ulong>(nullable: false),
                    Error = table.Column<string>(nullable: true),
                    IsActive = table.Column<bool>(nullable: false),
                    Timestamp = table.Column<int>(nullable: false),
                    Discriminator = table.Column<string>(nullable: false),
                    GatewayAgentId = table.Column<ulong>(nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Agents", x => x.AgentId);
                    table.ForeignKey(
                        name: "FK_Agents_Builds_BuildId",
                        column: x => x.BuildId,
                        principalTable: "Builds",
                        principalColumn: "BuildId",
                        onDelete: ReferentialAction.Cascade);
                    table.ForeignKey(
                        name: "FK_Agents_Agents_GatewayAgentId",
                        column: x => x.GatewayAgentId,
                        principalTable: "Agents",
                        principalColumn: "AgentId",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "Agent",
                columns: table => new
                {
                    ComputerName = table.Column<string>(nullable: true),
                    UserName = table.Column<string>(nullable: true),
                    Domain = table.Column<string>(nullable: true),
                    OsMajorVersion = table.Column<uint>(nullable: false),
                    OsMinorVersion = table.Column<uint>(nullable: false),
                    OsBuildNumber = table.Column<uint>(nullable: false),
                    OsServicePackMajor = table.Column<ushort>(nullable: false),
                    OsServicePackMinor = table.Column<ushort>(nullable: false),
                    OsProductType = table.Column<byte>(nullable: false),
                    ProcessId = table.Column<uint>(nullable: false),
                    IsElevated = table.Column<bool>(nullable: false),
                    RelayAgentId = table.Column<ulong>(nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Agent", x => x.RelayAgentId);
                    table.ForeignKey(
                        name: "FK_Agent_Agents_RelayAgentId",
                        column: x => x.RelayAgentId,
                        principalTable: "Agents",
                        principalColumn: "AgentId",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "Channels",
                columns: table => new
                {
                    AgentId = table.Column<ulong>(nullable: false),
                    InterfaceId = table.Column<ulong>(nullable: false),
                    Hash = table.Column<ulong>(nullable: false),
                    Error = table.Column<string>(nullable: true),
                    IsReturnChannel = table.Column<bool>(nullable: false),
                    IsNegotiationChannel = table.Column<bool>(nullable: false),
                    Jitter = table.Column<string>(nullable: true),
                    StartupCommand = table.Column<string>(nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Channels", x => new { x.AgentId, x.InterfaceId });
                    table.ForeignKey(
                        name: "FK_Channels_Agents_AgentId",
                        column: x => x.AgentId,
                        principalTable: "Agents",
                        principalColumn: "AgentId",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "Connectors",
                columns: table => new
                {
                    AgentId = table.Column<ulong>(nullable: false),
                    InterfaceId = table.Column<ulong>(nullable: false),
                    Hash = table.Column<ulong>(nullable: false),
                    Error = table.Column<string>(nullable: true),
                    StartupCommand = table.Column<string>(nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Connectors", x => new { x.AgentId, x.InterfaceId });
                    table.ForeignKey(
                        name: "FK_Connectors_Agents_AgentId",
                        column: x => x.AgentId,
                        principalTable: "Agents",
                        principalColumn: "AgentId",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "Peripherals",
                columns: table => new
                {
                    AgentId = table.Column<ulong>(nullable: false),
                    InterfaceId = table.Column<ulong>(nullable: false),
                    Hash = table.Column<ulong>(nullable: false),
                    Error = table.Column<string>(nullable: true),
                    Jitter = table.Column<string>(nullable: true),
                    StartupCommand = table.Column<string>(nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Peripherals", x => new { x.AgentId, x.InterfaceId });
                    table.ForeignKey(
                        name: "FK_Peripherals_Agents_AgentId",
                        column: x => x.AgentId,
                        principalTable: "Agents",
                        principalColumn: "AgentId",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "Route",
                columns: table => new
                {
                    AgentId = table.Column<ulong>(nullable: false),
                    OutgoingInterface = table.Column<ulong>(nullable: false),
                    DestinationAgent = table.Column<ulong>(nullable: false),
                    ReceivingInterface = table.Column<ulong>(nullable: false),
                    IsNeighbour = table.Column<bool>(nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Route", x => new { x.AgentId, x.OutgoingInterface, x.DestinationAgent, x.ReceivingInterface });
                    table.ForeignKey(
                        name: "FK_Route_Agents_AgentId",
                        column: x => x.AgentId,
                        principalTable: "Agents",
                        principalColumn: "AgentId",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "IX_Agents_BuildId",
                table: "Agents",
                column: "BuildId");

            migrationBuilder.CreateIndex(
                name: "IX_Agents_GatewayAgentId",
                table: "Agents",
                column: "GatewayAgentId");

            migrationBuilder.CreateIndex(
                name: "IX_Commands_GatewayAgentId",
                table: "Commands",
                column: "GatewayAgentId");
        }

        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "Agent");

            migrationBuilder.DropTable(
                name: "Channels");

            migrationBuilder.DropTable(
                name: "Commands");

            migrationBuilder.DropTable(
                name: "Connectors");

            migrationBuilder.DropTable(
                name: "Peripherals");

            migrationBuilder.DropTable(
                name: "Route");

            migrationBuilder.DropTable(
                name: "Agents");

            migrationBuilder.DropTable(
                name: "Builds");
        }
    }
}
