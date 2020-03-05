using Microsoft.EntityFrameworkCore;
using System;
using System.ComponentModel.DataAnnotations.Schema;

namespace FSecure.C3.WebController.Models
{
    [Owned]
    public class HostInfo
    {
        public string ComputerName { get; set; }
        public string UserName{ get; set; }
        public string Domain { get; set; }
        public uint OsMajorVersion { get; set; }
        public uint OsMinorVersion{ get; set; }
        public uint OsBuildNumber { get; set; }
        public ushort OsServicePackMajor { get; set; }
        public ushort OsServicePackMinor { get; set; }
        public byte OsProductType { get; set; }
        public uint ProcessId { get; set; }
        public bool IsElevated { get; set; }

        [NotMapped]
        public string OsVersion
        {
            get
            {
                string productType = 1 == OsProductType ? "Workstation SP:" : "Server SP:";
                return $"Windows {OsMajorVersion}.{OsMinorVersion} {productType} { OsServicePackMajor }.{ OsServicePackMinor} Build {OsBuildNumber}";
            }
        }

    }
}
