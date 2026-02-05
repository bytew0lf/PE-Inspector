using System;
using System.Collections.Generic;
using System.Globalization;
using System.Formats.Asn1;
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
        public bool SignatureValid { get; }
        public string SignatureError { get; }
        public bool ChainValid { get; }
        public string[] ChainStatus { get; }
        public bool IsTimestampSigner { get; }
        public Pkcs7SignerInfo[] CounterSigners { get; }

        public Pkcs7SignerInfo(
            string subject,
            string issuer,
            string serialNumber,
            string thumbprint,
            string digestAlgorithm,
            string signatureAlgorithm,
            string signerIdentifierType,
            DateTimeOffset? signingTime,
            bool signatureValid,
            string signatureError,
            bool chainValid,
            string[] chainStatus,
            bool isTimestampSigner,
            Pkcs7SignerInfo[] counterSigners)
        {
            Subject = subject ?? string.Empty;
            Issuer = issuer ?? string.Empty;
            SerialNumber = serialNumber ?? string.Empty;
            Thumbprint = thumbprint ?? string.Empty;
            DigestAlgorithm = digestAlgorithm ?? string.Empty;
            SignatureAlgorithm = signatureAlgorithm ?? string.Empty;
            SignerIdentifierType = signerIdentifierType ?? string.Empty;
            SigningTime = signingTime;
            SignatureValid = signatureValid;
            SignatureError = signatureError ?? string.Empty;
            ChainValid = chainValid;
            ChainStatus = chainStatus ?? Array.Empty<string>();
            IsTimestampSigner = isTimestampSigner;
            CounterSigners = counterSigners ?? Array.Empty<Pkcs7SignerInfo>();
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
                    infos.Add(BuildSignerInfo(signer, false));
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

        public static bool TryGetAuthenticodeDigests(
            byte[] data,
            out AuthenticodeDigestInfo[] digests,
            out string error)
        {
            digests = Array.Empty<AuthenticodeDigestInfo>();
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

                byte[] content = cms.ContentInfo.Content;
                if (content == null || content.Length == 0)
                {
                    return false;
                }

                if (!TryParseSpcIndirectData(content, out AuthenticodeDigestInfo digest))
                {
                    return false;
                }

                digests = new[] { digest };
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

        private static bool TryParseSpcIndirectData(byte[] content, out AuthenticodeDigestInfo digestInfo)
        {
            digestInfo = null;
            try
            {
                AsnReader reader = new AsnReader(content, AsnEncodingRules.BER);
                AsnReader sequence = reader.ReadSequence();
                if (sequence.HasData)
                {
                    sequence.ReadEncodedValue(); // SpcAttributeTypeAndOptionalValue
                }

                if (!sequence.HasData)
                {
                    return false;
                }

                AsnReader digestSeq = sequence.ReadSequence();
                AsnReader algSeq = digestSeq.ReadSequence();
                string oid = algSeq.ReadObjectIdentifier();
                if (algSeq.HasData)
                {
                    algSeq.ReadEncodedValue();
                }

                byte[] digest = digestSeq.ReadOctetString();
                string algorithmName = TryGetHashAlgorithmName(oid, out HashAlgorithmName name)
                    ? name.Name ?? oid
                    : oid;

                digestInfo = new AuthenticodeDigestInfo(oid, algorithmName, digest);
                return true;
            }
            catch (Exception)
            {
                return false;
            }
        }

        public static bool TryGetHashAlgorithmName(string oid, out HashAlgorithmName name)
        {
            name = default;
            if (string.IsNullOrWhiteSpace(oid))
            {
                return false;
            }

            switch (oid)
            {
                case "1.3.14.3.2.26":
                    name = HashAlgorithmName.SHA1;
                    return true;
                case "2.16.840.1.101.3.4.2.1":
                    name = HashAlgorithmName.SHA256;
                    return true;
                case "2.16.840.1.101.3.4.2.2":
                    name = HashAlgorithmName.SHA384;
                    return true;
                case "2.16.840.1.101.3.4.2.3":
                    name = HashAlgorithmName.SHA512;
                    return true;
                default:
                    return false;
            }
        }

        private static Pkcs7SignerInfo BuildSignerInfo(SignerInfo signer, bool isTimestamp)
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

            bool signatureValid = false;
            string signatureError = string.Empty;
            try
            {
                signer.CheckSignature(true);
                signatureValid = true;
            }
            catch (CryptographicException ex)
            {
                signatureError = ex.Message;
            }
            catch (Exception ex)
            {
                signatureError = ex.Message;
            }

            bool chainValid = false;
            string[] chainStatus = Array.Empty<string>();
            if (signer.Certificate != null)
            {
                try
                {
                    using (X509Chain chain = new X509Chain())
                    {
                        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
                        chain.ChainPolicy.RevocationFlag = X509RevocationFlag.ExcludeRoot;
                        chain.ChainPolicy.VerificationFlags = X509VerificationFlags.NoFlag;
                        chain.ChainPolicy.VerificationTime = DateTime.UtcNow;

                        chainValid = chain.Build(signer.Certificate);
                        if (chain.ChainStatus != null && chain.ChainStatus.Length > 0)
                        {
                            List<string> statuses = new List<string>();
                            foreach (X509ChainStatus status in chain.ChainStatus)
                            {
                                statuses.Add(status.Status + ": " + status.StatusInformation.Trim());
                            }
                            chainStatus = statuses.ToArray();
                        }
                    }
                }
                catch (Exception ex)
                {
                    chainStatus = new[] { ex.Message };
                }
            }

            List<Pkcs7SignerInfo> countersigners = new List<Pkcs7SignerInfo>();
            if (signer.CounterSignerInfos != null && signer.CounterSignerInfos.Count > 0)
            {
                foreach (SignerInfo counter in signer.CounterSignerInfos)
                {
                    countersigners.Add(BuildSignerInfo(counter, true));
                }
            }

            return new Pkcs7SignerInfo(
                subject,
                issuer,
                serialNumber,
                thumbprint,
                digestAlgorithm,
                signatureAlgorithm,
                signerIdType,
                signingTime,
                signatureValid,
                signatureError,
                chainValid,
                chainStatus,
                isTimestamp,
                countersigners.ToArray());
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
