using System;
using System.Collections.Generic;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Storage.ValueConversion;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace FSecure.C3.WebController.Models
{
    public class C3WebAPIContext : DbContext
    {
        public DbSet<GatewayBuild> GatewayBuilds { get; set; }
        public DbSet<RelayBuild> RelayBuilds { get; set; }
        public DbSet<Build> Builds { get; set; }
        public DbSet<Gateway> Gateways { get; set; }
        public DbSet<Relay> Relays { get; set; }
        public DbSet<Agent> Agents { get; set; }
        public DbSet<Command> Commands { get; set; }

        public DbSet<Channel> Channels { get; set; }
        public DbSet<Peripheral> Peripherals { get; set; }
        public DbSet<Connector> Connectors { get; set; }

        public C3WebAPIContext(DbContextOptions<C3WebAPIContext> options) : base(options)
        {
        }

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            var separatedStringConverter = new ValueConverter<IList<string>, string>(
                    v => string.Join(';', v),
                    v => v.Split(';', StringSplitOptions.RemoveEmptyEntries));

            var jtokenConverter = new ValueConverter<JToken, string>(
                v => JsonConvert.SerializeObject(v),
                v => JToken.Parse(v));

            modelBuilder.Entity<GatewayBuild>()
                .Property(e => e.Connectors)
                .HasConversion(jtokenConverter);

            modelBuilder.Entity<GatewayBuild>()
                .Property(e => e.RelayCommands)
                .HasConversion(jtokenConverter);

            modelBuilder.Entity<Build>()
                .Property(e => e.Commands)
                .HasConversion(jtokenConverter);

            modelBuilder.Entity<Build>()
                .Property(e => e.Channels)
                .HasConversion(jtokenConverter);

            modelBuilder.Entity<Build>()
                .Property(e => e.Peripherals)
                .HasConversion(jtokenConverter);

            modelBuilder.Entity<RelayBuild>()
                .Property(e => e.StartupCommands)
                .HasConversion(jtokenConverter);

            modelBuilder.Entity<Command>()
                .Property(c => c.Data)
                .HasConversion(jtokenConverter);

            modelBuilder.Entity<Channel>()
                .Property(c => c.StartupCommand)
                .HasConversion(jtokenConverter);

            modelBuilder.Entity<Channel>()
                .Property(c => c.Jitter)
                .HasConversion(jtokenConverter);

            modelBuilder.Entity<Connector>()
                .Property(c => c.StartupCommand)
                .HasConversion(jtokenConverter);

            modelBuilder.Entity<Peripheral>()
                .Property(c => c.StartupCommand)
                .HasConversion(jtokenConverter);

            modelBuilder.Entity<Channel>()
                .HasKey(e => new { e.AgentId, e.InterfaceId });

            modelBuilder.Entity<Peripheral>()
                .HasKey(e => new { e.AgentId, e.InterfaceId });

            modelBuilder.Entity<Peripheral>()
                .Property(p => p.Jitter)
                .HasConversion(jtokenConverter);

            modelBuilder.Entity<Connector>()
                .HasKey(e => new { e.AgentId, e.InterfaceId });

            modelBuilder.Entity<Route>()
                .HasKey(route => new
                {
                    route.AgentId,
                    route.OutgoingInterface,
                    route.DestinationAgent,
                    route.ReceivingInterface,
                });

            modelBuilder.Entity<Command>()
                .HasIndex(c => c.GatewayAgentId);
        }
    }
}
