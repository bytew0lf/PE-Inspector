using System;
using System.Collections.Generic;
using System.Globalization;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace PECoff
{
    public sealed class Pkcs7SignerInfo
    {
        public string Subject { get; }
        public string Issuer { get; }
        public string SerialNumber { get; }
        public string Thumbprint { get; }
        public string DigestAlgorithm { get; }
        public string SignatureAlgorithm { get; }
        public string SignerIdentifierType { get; }
        public DateTimeOffset? SigningTime { get; }

        public Pkcs7SignerInfo(
            string subject,
            string issuer,
            string serialNumber,
            string thumbprint,
            string digestAlgorithm,
            string signatureAlgorithm,
            string signerIdentifierType,
            DateTimeOffset? signingTime)
        {
            Subject = subject ?? string.Empty;
            Issuer = issuer ?? string.Empty;
            SerialNumber = serialNumber ?? string.Empty;
            Thumbprint = thumbprint ?? string.Empty;
            DigestAlgorithm = digestAlgorithm ?? string.Empty;
            SignatureAlgorithm = signatureAlgorithm ?? string.Empty;
            SignerIdentifierType = signerIdentifierType ?? string.Empty;
            SigningTime = signingTime;
        }
    }

    public static class CertificateUtilities
    {
        public static string GetCertificateExtension(CertificateTypeKind type)
        {
            switch (type)
            {
                case CertificateTypeKind.X509:
                    return ".cer";
                case CertificateTypeKind.PkcsSignedData:
                case CertificateTypeKind.TsStackSigned:
                    return ".p7b";
                default:
                    return ".bin";
            }
        }

        public static string GetPemLabel(CertificateTypeKind type)
        {
            switch (type)
            {
                case CertificateTypeKind.X509:
                    return "CERTIFICATE";
                case CertificateTypeKind.PkcsSignedData:
                case CertificateTypeKind.TsStackSigned:
                    return "PKCS7";
                default:
                    return "BINARY";
            }
        }

        public static string GetCertificateTypeToken(CertificateTypeKind type)
        {
            switch (type)
            {
                case CertificateTypeKind.X509:
                    return "x509";
                case CertificateTypeKind.PkcsSignedData:
                    return "pkcs7";
                case CertificateTypeKind.TsStackSigned:
                    return "tsstack";
                case CertificateTypeKind.Reserved1:
                    return "reserved";
                default:
                    return "unknown";
            }
        }

        public static string ToPem(string label, byte[] data)
        {
            string base64 = Convert.ToBase64String(data ?? Array.Empty<byte>(), Base64FormattingOptions.InsertLineBreaks);
            StringBuilder sb = new StringBuilder();
            sb.Append("-----BEGIN ").Append(label).AppendLine("-----");
            sb.AppendLine(base64);
            sb.Append("-----END ").Append(label).AppendLine("-----");
            return sb.ToString();
        }

        public static bool TryGetPkcs7SignerInfos(
            byte[] data,
            out Pkcs7SignerInfo[] signerInfos,
            out string error)
        {
            signerInfos = Array.Empty<Pkcs7SignerInfo>();
            error = string.Empty;

            if (data == null || data.Length == 0)
            {
                error = "PKCS7 data is empty.";
                return false;
            }

            try
            {
                SignedCms cms = new SignedCms();
                cms.Decode(data);

                if (cms.SignerInfos == null || cms.SignerInfos.Count == 0)
                {
                    return true;
                }

                List<Pkcs7SignerInfo> infos = new List<Pkcs7SignerInfo>();
                foreach (SignerInfo signer in cms.SignerInfos)
                {
                    string subject = string.Empty;
                    string issuer = string.Empty;
                    string serialNumber = string.Empty;
                    string thumbprint = string.Empty;

                    if (signer.Certificate != null)
                    {
                        subject = signer.Certificate.Subject ?? string.Empty;
                        issuer = signer.Certificate.Issuer ?? string.Empty;
                        serialNumber = signer.Certificate.SerialNumber ?? string.Empty;
                        thumbprint = signer.Certificate.Thumbprint ?? string.Empty;
                    }
                    else if (signer.SignerIdentifier != null && signer.SignerIdentifier.Type == SubjectIdentifierType.IssuerAndSerialNumber)
                    {
                        string identifier = signer.SignerIdentifier.Value != null
                            ? signer.SignerIdentifier.Value.ToString() ?? string.Empty
                            : string.Empty;
                        issuer = identifier;
                    }

                    string digestAlgorithm = signer.DigestAlgorithm?.FriendlyName ?? signer.DigestAlgorithm?.Value ?? string.Empty;
                    string signatureAlgorithm = signer.SignatureAlgorithm?.FriendlyName ?? signer.SignatureAlgorithm?.Value ?? string.Empty;
                    string signerIdType = signer.SignerIdentifier?.Type.ToString() ?? string.Empty;
                    DateTimeOffset? signingTime = TryGetSigningTime(signer);

                    infos.Add(new Pkcs7SignerInfo(
                        subject,
                        issuer,
                        serialNumber,
                        thumbprint,
                        digestAlgorithm,
                        signatureAlgorithm,
                        signerIdType,
                        signingTime));
                }

                signerInfos = infos.ToArray();
                return true;
            }
            catch (CryptographicException ex)
            {
                error = ex.Message;
                return false;
            }
            catch (Exception ex)
            {
                error = ex.Message;
                return false;
            }
        }

        private static DateTimeOffset? TryGetSigningTime(SignerInfo signer)
        {
            if (signer == null || signer.SignedAttributes == null)
            {
                return null;
            }

            foreach (CryptographicAttributeObject attr in signer.SignedAttributes)
            {
                if (attr.Oid == null || attr.Oid.Value != "1.2.840.113549.1.9.5")
                {
                    continue;
                }

                if (attr.Values == null || attr.Values.Count == 0)
                {
                    continue;
                }

                try
                {
                    Pkcs9SigningTime signingTime = new Pkcs9SigningTime(attr.Values[0].RawData);
                    return signingTime.SigningTime;
                }
                catch (CryptographicException)
                {
                }
                catch (Exception)
                {
                }
            }

            return null;
        }
    }

    public static class CertificateEntryExtensions
    {
        public static string GetFileExtension(this CertificateEntry entry)
        {
            return CertificateUtilities.GetCertificateExtension(entry.Type);
        }

        public static string GetTypeToken(this CertificateEntry entry)
        {
            return CertificateUtilities.GetCertificateTypeToken(entry.Type);
        }

        public static string GetPemLabel(this CertificateEntry entry)
        {
            return CertificateUtilities.GetPemLabel(entry.Type);
        }

        public static string ToPem(this CertificateEntry entry)
        {
            return CertificateUtilities.ToPem(entry.GetPemLabel(), entry.Data);
        }

        public static bool TryGetPkcs7SignerInfos(
            this CertificateEntry entry,
            out Pkcs7SignerInfo[] signerInfos,
            out string error)
        {
            signerInfos = Array.Empty<Pkcs7SignerInfo>();
            error = string.Empty;

            if (entry == null || entry.Data == null || entry.Data.Length == 0)
            {
                error = "Certificate entry has no data.";
                return false;
            }

            if (entry.Type != CertificateTypeKind.PkcsSignedData &&
                entry.Type != CertificateTypeKind.TsStackSigned)
            {
                error = "Certificate type is not PKCS7.";
                return false;
            }

            return CertificateUtilities.TryGetPkcs7SignerInfos(entry.Data, out signerInfos, out error);
        }
    }
}
