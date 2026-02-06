using System;
using PECoff;
using Xunit;

public class CertificateUtilitiesTests
{
    [Fact]
    public void BuildAuthenticodeStatus_Summarizes_Signers_And_Timestamps()
    {
        Pkcs7SignerInfo timestampSigner = new Pkcs7SignerInfo(
            subject: "Timestamp",
            issuer: "TimestampCA",
            serialNumber: "01",
            thumbprint: "TS",
            digestAlgorithm: "SHA256",
            signatureAlgorithm: "RSA",
            signerIdentifierType: "IssuerAndSerialNumber",
            signingTime: DateTimeOffset.UtcNow,
            signatureValid: true,
            signatureError: string.Empty,
            chainValid: true,
            chainStatus: new[] { "TimestampChainOK", "timestampchainok" },
            isTimestampSigner: true,
            hasCodeSigningEku: false,
            hasTimestampEku: true,
            isWithinValidityPeriod: true,
            counterSigners: Array.Empty<Pkcs7SignerInfo>());

        Pkcs7SignerInfo primarySigner = new Pkcs7SignerInfo(
            subject: "Signer",
            issuer: "IssuerCA",
            serialNumber: "02",
            thumbprint: "SG",
            digestAlgorithm: "SHA256",
            signatureAlgorithm: "RSA",
            signerIdentifierType: "IssuerAndSerialNumber",
            signingTime: DateTimeOffset.UtcNow,
            signatureValid: true,
            signatureError: string.Empty,
            chainValid: true,
            chainStatus: new[] { "UntrustedRoot", "UntrustedRoot" },
            isTimestampSigner: false,
            hasCodeSigningEku: true,
            hasTimestampEku: false,
            isWithinValidityPeriod: true,
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
    }

    [Fact]
    public void BuildAuthenticodeStatus_Enforces_Policy()
    {
        Pkcs7SignerInfo signer = new Pkcs7SignerInfo(
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
            chainValid: false,
            chainStatus: new[] { "UntrustedRoot" },
            isTimestampSigner: false,
            hasCodeSigningEku: false,
            hasTimestampEku: false,
            isWithinValidityPeriod: true,
            counterSigners: Array.Empty<Pkcs7SignerInfo>());

        AuthenticodePolicy policy = new AuthenticodePolicy
        {
            RequireChainValid = true,
            RequireCodeSigningEku = true
        };

        AuthenticodeStatusInfo status = CertificateUtilities.BuildAuthenticodeStatus(new[] { signer }, policy);

        Assert.False(status.PolicyCompliant);
        Assert.Contains(status.PolicyFailures, f => f.Contains("chain", StringComparison.OrdinalIgnoreCase));
        Assert.Contains(status.PolicyFailures, f => f.Contains("code signing", StringComparison.OrdinalIgnoreCase));
    }
}
