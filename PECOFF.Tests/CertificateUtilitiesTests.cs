using System;
using PECoff;
using Xunit;

public class CertificateUtilitiesTests
{
    [Fact]
    public void BuildAuthenticodeStatus_Summarizes_Signers_And_Timestamps()
    {
        Pkcs7SignerInfo timestampSigner = CreateSigner(
            isTimestamp: true,
            hasCodeSigningEku: false,
            hasTimestampEku: true,
            chainStatus: new[] { "TimestampChainOK", "timestampchainok" });
        Pkcs7SignerInfo primarySigner = CreateSigner(
            isTimestamp: false,
            hasCodeSigningEku: true,
            chainStatus: new[] { "UntrustedRoot", "UntrustedRoot" },
            counterSigners: new[] { timestampSigner });

        AuthenticodeStatusInfo status = CertificateUtilities.BuildAuthenticodeStatus(new[] { primarySigner });

        Assert.Equal(1, status.SignerCount);
        Assert.Equal(1, status.TimestampSignerCount);
        Assert.True(status.HasSignature);
        Assert.True(status.SignatureValid);
        Assert.True(status.ChainValid);
        Assert.True(status.HasTimestamp);
        Assert.True(status.TimestampValid);
        Assert.Single(status.ChainStatus);
        Assert.Equal("UntrustedRoot", status.ChainStatus[0]);
        Assert.Single(status.TimestampChainStatus);
        Assert.Equal("TimestampChainOK", status.TimestampChainStatus[0]);
        Assert.Equal(2, status.SignerStatuses.Count);
        Assert.Contains(status.SignerStatuses, s => s.Role == "Primary");
        Assert.Contains(status.SignerStatuses, s => s.Role == "Timestamp");
        Assert.NotNull(status.TrustStore);
        Assert.True(status.TrustStore.Performed);
        Assert.True(status.TrustStore.Verified);
    }

    [Fact]
    public void BuildAuthenticodeStatus_Enforces_Policy()
    {
        Pkcs7SignerInfo signer = CreateSigner(isTimestamp: false, chainValid: false, hasCodeSigningEku: false);

        AuthenticodePolicy policy = new AuthenticodePolicy
        {
            RequireChainValid = true,
            RequireCodeSigningEku = true
        };

        AuthenticodeStatusInfo status = CertificateUtilities.BuildAuthenticodeStatus(new[] { signer }, policy);

        Assert.False(status.PolicyCompliant);
        Assert.Contains(status.PolicyFailures, f => f.Contains("chain", StringComparison.OrdinalIgnoreCase));
        Assert.Contains(status.PolicyFailures, f => f.Contains("code signing", StringComparison.OrdinalIgnoreCase));
        Assert.NotNull(status.TrustStore);
        Assert.False(status.TrustStore.Verified);
    }

    [Fact]
    public void BuildAuthenticodeStatus_Counts_Nested_Timestamps()
    {
        Pkcs7SignerInfo nestedTimestamp = CreateSigner(isTimestamp: true, hasCodeSigningEku: false, hasTimestampEku: true, nestingLevel: 1);
        Pkcs7SignerInfo primarySigner = CreateSigner(isTimestamp: false, hasCodeSigningEku: true, nestedSigners: new[] { nestedTimestamp });

        AuthenticodeStatusInfo status = CertificateUtilities.BuildAuthenticodeStatus(new[] { primarySigner });

        Assert.Equal(1, status.SignerCount);
        Assert.Equal(1, status.TimestampSignerCount);
        Assert.True(status.HasTimestamp);
    }

    private static Pkcs7SignerInfo CreateSigner(
        bool isTimestamp,
        bool chainValid = true,
        bool hasCodeSigningEku = true,
        bool hasTimestampEku = false,
        int nestingLevel = 0,
        Pkcs7SignerInfo[]? counterSigners = null,
        Pkcs7SignerInfo[]? nestedSigners = null,
        string[]? chainStatus = null)
    {
        string[] status = chainStatus ?? (chainValid ? Array.Empty<string>() : new[] { "UntrustedRoot" });
        return new Pkcs7SignerInfo(
            subject: "Signer",
            issuer: "Issuer",
            serialNumber: "01",
            thumbprint: "TP",
            digestAlgorithm: "SHA256",
            signatureAlgorithm: "RSA",
            signerIdentifierType: "IssuerAndSerialNumber",
            signingTime: DateTimeOffset.UtcNow,
            signatureValid: true,
            signatureError: string.Empty,
            chainValid: chainValid,
            chainStatus: status,
            chainElements: Array.Empty<Pkcs7ChainElementInfo>(),
            isTimestampSigner: isTimestamp,
            hasCodeSigningEku: hasCodeSigningEku,
            hasTimestampEku: hasTimestampEku,
            isWithinValidityPeriod: true,
            certificateTransparencyCount: 0,
            certificateTransparencyLogIds: Array.Empty<string>(),
            nestingLevel: nestingLevel,
            counterSigners: counterSigners ?? Array.Empty<Pkcs7SignerInfo>(),
            nestedSigners: nestedSigners ?? Array.Empty<Pkcs7SignerInfo>(),
            rfc3161Timestamps: Array.Empty<Pkcs7TimestampInfo>());
    }
}
