using System;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using PECoff;
using Xunit;

public class CertificateConformanceTests
{
    [Fact]
    public void CertificateTable_Detects_Duplicate_RevisionType_Tuples()
    {
        string? fixtures = FindFixturesDirectory();
        Assert.False(string.IsNullOrWhiteSpace(fixtures));
        string validPath = Path.Combine(fixtures!, "minimal", "minimal-x86.exe");
        Assert.True(File.Exists(validPath));

        byte[] source = File.ReadAllBytes(validPath);
        byte[] mutated = BuildPeWithCertificateTable(
            source,
            new CertificateRecord(0x0200, 0x0001, new byte[] { 0x30, 0x82, 0x01, 0x01 }),
            new CertificateRecord(0x0200, 0x0001, new byte[] { 0x30, 0x82, 0x01, 0x02 }));

        string tempFile = Path.GetTempFileName();
        try
        {
            File.WriteAllBytes(tempFile, mutated);
            PECOFF parser = new PECOFF(tempFile);

            Assert.Contains(
                parser.ParseResult.Warnings,
                warning => warning.Contains("SPEC violation: Duplicate WIN_CERTIFICATE", StringComparison.Ordinal));
            Assert.Throws<PECOFFParseException>(() => new PECOFF(tempFile, new PECOFFOptions { StrictMode = true }));
        }
        finally
        {
            File.Delete(tempFile);
        }
    }

    [Fact]
    public void CertificateTable_Reports_X509_And_TsStack_Metadata()
    {
        string? fixtures = FindFixturesDirectory();
        Assert.False(string.IsNullOrWhiteSpace(fixtures));
        string validPath = Path.Combine(fixtures!, "minimal", "minimal-x86.exe");
        Assert.True(File.Exists(validPath));

        byte[] source = File.ReadAllBytes(validPath);
        byte[] x509 = CreateX509CertificateBytes();
        byte[] tsStack = new byte[] { 0x54, 0x53, 0x53, 0x54, 0x01, 0x02, 0x03, 0x04 };
        byte[] mutated = BuildPeWithCertificateTable(
            source,
            new CertificateRecord(0x0200, 0x0001, x509),
            new CertificateRecord(0x0200, 0x0004, tsStack));

        string tempFile = Path.GetTempFileName();
        try
        {
            File.WriteAllBytes(tempFile, mutated);
            PECOFF parser = new PECOFF(tempFile);

            Assert.Equal(2, parser.CertificateEntries.Length);
            CertificateEntry x509Entry = Assert.Single(parser.CertificateEntries, e => e.Type == CertificateTypeKind.X509);
            CertificateEntry tsEntry = Assert.Single(parser.CertificateEntries, e => e.Type == CertificateTypeKind.TsStackSigned);

            Assert.NotNull(x509Entry.TypeMetadata);
            Assert.Equal("X509", x509Entry.TypeMetadata.Kind);
            Assert.True(x509Entry.TypeMetadata.Parsed);
            Assert.False(string.IsNullOrWhiteSpace(x509Entry.TypeMetadata.Subject));

            Assert.NotNull(tsEntry.TypeMetadata);
            Assert.Equal("TsStackSigned", tsEntry.TypeMetadata.Kind);
            Assert.True(tsEntry.TypeMetadata.Parsed);
            Assert.Contains("PayloadBytes=", tsEntry.TypeMetadata.Notes, StringComparison.Ordinal);
            Assert.False(string.IsNullOrWhiteSpace(tsEntry.TypeMetadata.Sha256));

            string json = parser.Result.ToJsonReport(includeBinary: false, indented: false);
            Assert.Contains("\"TypeMetadata\"", json, StringComparison.Ordinal);
            Assert.Contains("TsStackSigned", json, StringComparison.Ordinal);
            Assert.Contains("X509", json, StringComparison.Ordinal);
        }
        finally
        {
            File.Delete(tempFile);
        }
    }

    private readonly struct CertificateRecord
    {
        public ushort Revision { get; }
        public ushort Type { get; }
        public byte[] Payload { get; }

        public CertificateRecord(ushort revision, ushort type, byte[] payload)
        {
            Revision = revision;
            Type = type;
            Payload = payload ?? Array.Empty<byte>();
        }
    }

    private static byte[] BuildPeWithCertificateTable(byte[] source, params CertificateRecord[] records)
    {
        Assert.NotNull(source);
        Assert.NotNull(records);
        Assert.NotEmpty(records);
        Assert.True(TryGetPeLayout(source, out _, out _, out int dataDirectoryStart));

        byte[] table = BuildCertificateTable(records);
        int certOffset = Align8(source.Length);
        byte[] output = new byte[certOffset + table.Length];
        Buffer.BlockCopy(source, 0, output, 0, source.Length);
        Buffer.BlockCopy(table, 0, output, certOffset, table.Length);

        int certDirectoryOffset = dataDirectoryStart + (4 * 8);
        WriteUInt32(output, certDirectoryOffset, (uint)certOffset);
        WriteUInt32(output, certDirectoryOffset + 4, (uint)table.Length);
        return output;
    }

    private static byte[] BuildCertificateTable(CertificateRecord[] records)
    {
        int total = 0;
        for (int i = 0; i < records.Length; i++)
        {
            int entryLength = 8 + records[i].Payload.Length;
            total += Align8(entryLength);
        }

        byte[] table = new byte[total];
        int cursor = 0;
        for (int i = 0; i < records.Length; i++)
        {
            int entryLength = 8 + records[i].Payload.Length;
            WriteUInt32(table, cursor, (uint)entryLength);
            WriteUInt16(table, cursor + 4, records[i].Revision);
            WriteUInt16(table, cursor + 6, records[i].Type);
            if (records[i].Payload.Length > 0)
            {
                Buffer.BlockCopy(records[i].Payload, 0, table, cursor + 8, records[i].Payload.Length);
            }

            cursor += Align8(entryLength);
        }

        return table;
    }

    private static byte[] CreateX509CertificateBytes()
    {
        using RSA rsa = RSA.Create(2048);
        CertificateRequest request = new CertificateRequest(
            "CN=PECOFF-Test",
            rsa,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, false));
        request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, false));
        using X509Certificate2 cert = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(365));
        return cert.Export(X509ContentType.Cert);
    }

    private static int Align8(int value)
    {
        return (value + 7) & ~7;
    }

    private static bool TryGetPeLayout(byte[] data, out int optionalHeaderStart, out bool isPe32Plus, out int dataDirectoryStart)
    {
        optionalHeaderStart = 0;
        isPe32Plus = false;
        dataDirectoryStart = 0;

        if (data == null || data.Length < 0x40)
        {
            return false;
        }

        int peOffset = BitConverter.ToInt32(data, 0x3C);
        if (peOffset <= 0 || peOffset + 4 + 20 + 2 > data.Length)
        {
            return false;
        }

        optionalHeaderStart = peOffset + 4 + 20;
        ushort magic = BitConverter.ToUInt16(data, optionalHeaderStart);
        if (magic == 0x10B)
        {
            isPe32Plus = false;
            dataDirectoryStart = optionalHeaderStart + 0x60;
        }
        else if (magic == 0x20B)
        {
            isPe32Plus = true;
            dataDirectoryStart = optionalHeaderStart + 0x70;
        }
        else
        {
            return false;
        }

        return dataDirectoryStart + (16 * 8) <= data.Length;
    }

    private static void WriteUInt16(byte[] data, int offset, ushort value)
    {
        data[offset] = (byte)(value & 0xFF);
        data[offset + 1] = (byte)((value >> 8) & 0xFF);
    }

    private static void WriteUInt32(byte[] data, int offset, uint value)
    {
        data[offset] = (byte)(value & 0xFF);
        data[offset + 1] = (byte)((value >> 8) & 0xFF);
        data[offset + 2] = (byte)((value >> 16) & 0xFF);
        data[offset + 3] = (byte)((value >> 24) & 0xFF);
    }

    private static string? FindFixturesDirectory()
    {
        string? dir = AppContext.BaseDirectory;
        for (int i = 0; i < 6 && dir != null; i++)
        {
            string candidate = Path.Combine(dir, "PECOFF.Tests", "Fixtures");
            if (Directory.Exists(candidate))
            {
                return candidate;
            }

            dir = Directory.GetParent(dir)?.FullName;
        }

        return null;
    }
}
