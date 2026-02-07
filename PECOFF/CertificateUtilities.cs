using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Formats.Asn1;
using System.Linq;
using System.Numerics;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
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
        public IReadOnlyList<Pkcs7ChainElementInfo> ChainElements { get; }
        public bool IsTimestampSigner { get; }
        public bool HasCodeSigningEku { get; }
        public bool HasTimestampEku { get; }
        public bool IsWithinValidityPeriod { get; }
        public int CertificateTransparencyCount { get; }
        public bool HasCertificateTransparency { get; }
        public IReadOnlyList<string> CertificateTransparencyLogIds { get; }
        public int NestingLevel { get; }
        public Pkcs7SignerInfo[] CounterSigners { get; }
        public Pkcs7SignerInfo[] NestedSigners { get; }
        public IReadOnlyList<Pkcs7TimestampInfo> Rfc3161Timestamps { get; }

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
            Pkcs7ChainElementInfo[] chainElements,
            bool isTimestampSigner,
            bool hasCodeSigningEku,
            bool hasTimestampEku,
            bool isWithinValidityPeriod,
            int certificateTransparencyCount,
            string[] certificateTransparencyLogIds,
            int nestingLevel,
            Pkcs7SignerInfo[] counterSigners,
            Pkcs7SignerInfo[] nestedSigners,
            Pkcs7TimestampInfo[] rfc3161Timestamps)
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
            ChainElements = Array.AsReadOnly(chainElements ?? Array.Empty<Pkcs7ChainElementInfo>());
            IsTimestampSigner = isTimestampSigner;
            HasCodeSigningEku = hasCodeSigningEku;
            HasTimestampEku = hasTimestampEku;
            IsWithinValidityPeriod = isWithinValidityPeriod;
            CertificateTransparencyCount = certificateTransparencyCount;
            HasCertificateTransparency = certificateTransparencyCount > 0;
            CertificateTransparencyLogIds = Array.AsReadOnly(certificateTransparencyLogIds ?? Array.Empty<string>());
            NestingLevel = nestingLevel;
            CounterSigners = counterSigners ?? Array.Empty<Pkcs7SignerInfo>();
            NestedSigners = nestedSigners ?? Array.Empty<Pkcs7SignerInfo>();
            Rfc3161Timestamps = Array.AsReadOnly(rfc3161Timestamps ?? Array.Empty<Pkcs7TimestampInfo>());
        }
    }

    public sealed class Pkcs7ChainElementInfo
    {
        public string Subject { get; }
        public string Issuer { get; }
        public string Thumbprint { get; }
        public string[] Status { get; }
        public bool IsSelfSigned { get; }

        public Pkcs7ChainElementInfo(string subject, string issuer, string thumbprint, string[] status, bool isSelfSigned)
        {
            Subject = subject ?? string.Empty;
            Issuer = issuer ?? string.Empty;
            Thumbprint = thumbprint ?? string.Empty;
            Status = status ?? Array.Empty<string>();
            IsSelfSigned = isSelfSigned;
        }
    }

    public sealed class Pkcs7TimestampInfo
    {
        public string Policy { get; }
        public string SerialNumber { get; }
        public string TsaName { get; }
        public DateTimeOffset? GeneratedTime { get; }

        public Pkcs7TimestampInfo(string policy, string serialNumber, string tsaName, DateTimeOffset? generatedTime)
        {
            Policy = policy ?? string.Empty;
            SerialNumber = serialNumber ?? string.Empty;
            TsaName = tsaName ?? string.Empty;
            GeneratedTime = generatedTime;
        }
    }

    public static class CertificateUtilities
    {
        public static AuthenticodeStatusInfo BuildAuthenticodeStatus(Pkcs7SignerInfo[] signers, AuthenticodePolicy policy = null, string filePath = null)
        {
            policy ??= new AuthenticodePolicy();
            if (signers == null || signers.Length == 0)
            {
                bool isPolicyCompliant = !policy.RequireSignature && !policy.RequireSignatureValid &&
                                         !policy.RequireChainValid && !policy.RequireTimestamp &&
                                         !policy.RequireTimestampValid && !policy.RequireCodeSigningEku &&
                                         !policy.RequireCertificateTransparency;
                return new AuthenticodeStatusInfo(
                    0,
                    0,
                    0,
                    0,
                    false,
                    false,
                    false,
                    false,
                    false,
                    Array.Empty<string>(),
                    Array.Empty<string>(),
                    Array.Empty<string>(),
                    BuildWinTrustResult(policy, filePath),
                    !policy.RequireCertificateTransparency,
                    isPolicyCompliant,
                    isPolicyCompliant ? Array.Empty<string>() : new[] { "Missing signature." },
                    Array.Empty<AuthenticodeSignerStatusInfo>(),
                    policy);
            }

            List<string> chainStatus = new List<string>();
            List<string> timestampStatus = new List<string>();
            int signerCount = 0;
            int timestampCount = 0;
            int ctSignerCount = 0;
            HashSet<string> ctLogs = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            bool signatureValid = false;
            bool chainValid = false;
            bool timestampValid = false;
            bool allSignatureValid = true;
            bool allChainValid = true;
            bool allCodeSigningEku = true;
            bool allTimestampValid = true;

            foreach (Pkcs7SignerInfo signer in FlattenSigners(signers))
            {
                if (signer == null)
                {
                    continue;
                }

                if (signer.IsTimestampSigner)
                {
                    timestampCount++;
                    if (signer.SignatureValid && signer.ChainValid)
                    {
                        timestampValid = true;
                    }
                    if (!signer.SignatureValid || !signer.ChainValid)
                    {
                        allTimestampValid = false;
                    }

                    if (signer.ChainStatus != null)
                    {
                        foreach (string status in signer.ChainStatus)
                        {
                            AddStatus(timestampStatus, status);
                        }
                    }
                }
                else
                {
                    signerCount++;
                    if (signer.SignatureValid)
                    {
                        signatureValid = true;
                    }
                    else
                    {
                        allSignatureValid = false;
                    }

                    if (signer.ChainValid)
                    {
                        chainValid = true;
                    }
                    else
                    {
                        allChainValid = false;
                    }

                    if (!signer.HasCodeSigningEku)
                    {
                        allCodeSigningEku = false;
                    }
                    if (signer.HasCertificateTransparency)
                    {
                        ctSignerCount++;
                    }
                    if (policy.EnableCertificateTransparencyLogCheck && signer.CertificateTransparencyLogIds != null)
                    {
                        foreach (string logId in signer.CertificateTransparencyLogIds)
                        {
                            if (!string.IsNullOrWhiteSpace(logId))
                            {
                                ctLogs.Add(logId);
                            }
                        }
                    }

                    if (signer.ChainStatus != null)
                    {
                        foreach (string status in signer.ChainStatus)
                        {
                            AddStatus(chainStatus, status);
                        }
                    }
                }
            }

            bool hasSignature = signerCount > 0;
            bool hasTimestamp = timestampCount > 0;
            bool ctRequiredMet = !policy.RequireCertificateTransparency ||
                                 (signerCount > 0 && ctSignerCount == signerCount);
            if (!hasSignature)
            {
                allSignatureValid = false;
                allChainValid = false;
                allCodeSigningEku = false;
            }
            if (!hasTimestamp)
            {
                allTimestampValid = false;
            }

            List<string> policyFailures = new List<string>();
            bool policyCompliant = true;
            if (policy.RequireSignature && !hasSignature)
            {
                policyCompliant = false;
                policyFailures.Add("Missing signature.");
            }
            if (policy.RequireSignatureValid && !allSignatureValid)
            {
                policyCompliant = false;
                policyFailures.Add("Signature validation failed.");
            }
            if (policy.RequireChainValid && !allChainValid)
            {
                policyCompliant = false;
                policyFailures.Add("Certificate chain validation failed.");
            }
            if (policy.RequireCodeSigningEku && !allCodeSigningEku)
            {
                policyCompliant = false;
                policyFailures.Add("Missing code signing EKU.");
            }
            if (policy.RequireTimestamp && !hasTimestamp)
            {
                policyCompliant = false;
                policyFailures.Add("Missing timestamp.");
            }
            if (policy.RequireTimestampValid && !allTimestampValid)
            {
                policyCompliant = false;
                policyFailures.Add("Timestamp validation failed.");
            }
            if (policy.RequireCertificateTransparency && !ctRequiredMet)
            {
                policyCompliant = false;
                policyFailures.Add("Missing certificate transparency data.");
            }

            List<AuthenticodeSignerStatusInfo> signerStatuses = BuildSignerStatuses(signers);
            return new AuthenticodeStatusInfo(
                signerCount,
                timestampCount,
                ctSignerCount,
                ctLogs.Count,
                hasSignature,
                signatureValid,
                chainValid,
                hasTimestamp,
                timestampValid,
                chainStatus.ToArray(),
                timestampStatus.ToArray(),
                ctLogs.Count == 0 ? Array.Empty<string>() : ctLogs.OrderBy(value => value, StringComparer.Ordinal).ToArray(),
                BuildWinTrustResult(policy, filePath),
                ctRequiredMet,
                policyCompliant,
                policyFailures.ToArray(),
                signerStatuses.ToArray(),
                policy);
        }

        private static List<AuthenticodeSignerStatusInfo> BuildSignerStatuses(Pkcs7SignerInfo[] signers)
        {
            List<AuthenticodeSignerStatusInfo> statuses = new List<AuthenticodeSignerStatusInfo>();
            if (signers == null)
            {
                return statuses;
            }

            foreach (Pkcs7SignerInfo signer in signers)
            {
                AppendSignerStatuses(statuses, signer, "Primary");
            }

            return statuses;
        }

        private static void AppendSignerStatuses(
            List<AuthenticodeSignerStatusInfo> statuses,
            Pkcs7SignerInfo signer,
            string role)
        {
            if (signer == null)
            {
                return;
            }

            string effectiveRole = signer.IsTimestampSigner ? "Timestamp" : role;
            statuses.Add(new AuthenticodeSignerStatusInfo(
                signer.Subject,
                signer.Issuer,
                effectiveRole,
                signer.IsTimestampSigner,
                signer.SignatureValid,
                signer.ChainValid,
                signer.HasCodeSigningEku,
                signer.HasTimestampEku,
                signer.HasCertificateTransparency,
                signer.CertificateTransparencyCount,
                signer.NestingLevel));

            if (signer.CounterSigners != null)
            {
                foreach (Pkcs7SignerInfo counter in signer.CounterSigners)
                {
                    AppendSignerStatuses(statuses, counter, "CounterSignature");
                }
            }

            if (signer.NestedSigners != null)
            {
                foreach (Pkcs7SignerInfo nested in signer.NestedSigners)
                {
                    AppendSignerStatuses(statuses, nested, "Nested");
                }
            }
        }

        private static IEnumerable<Pkcs7SignerInfo> FlattenSigners(Pkcs7SignerInfo[] signers)
        {
            if (signers == null)
            {
                yield break;
            }

            foreach (Pkcs7SignerInfo signer in signers)
            {
                foreach (Pkcs7SignerInfo item in FlattenSigner(signer))
                {
                    yield return item;
                }
            }
        }

        private static IEnumerable<Pkcs7SignerInfo> FlattenSigner(Pkcs7SignerInfo signer)
        {
            if (signer == null)
            {
                yield break;
            }

            yield return signer;

            if (signer.CounterSigners != null)
            {
                foreach (Pkcs7SignerInfo counter in signer.CounterSigners)
                {
                    foreach (Pkcs7SignerInfo item in FlattenSigner(counter))
                    {
                        yield return item;
                    }
                }
            }

            if (signer.NestedSigners != null)
            {
                foreach (Pkcs7SignerInfo nested in signer.NestedSigners)
                {
                    foreach (Pkcs7SignerInfo item in FlattenSigner(nested))
                    {
                        yield return item;
                    }
                }
            }
        }

        private static void AddStatus(List<string> statuses, string status)
        {
            if (string.IsNullOrWhiteSpace(status))
            {
                return;
            }

            foreach (string existing in statuses)
            {
                if (string.Equals(existing, status, StringComparison.OrdinalIgnoreCase))
                {
                    return;
                }
            }

            statuses.Add(status);
        }

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

        public static string GetCertificateRevisionName(ushort revision)
        {
            switch (revision)
            {
                case 0x0100:
                    return "WIN_CERT_REVISION_1_0";
                case 0x0200:
                    return "WIN_CERT_REVISION_2_0";
                default:
                    return "0x" + revision.ToString("X4", CultureInfo.InvariantCulture);
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
            return TryGetPkcs7SignerInfos(data, null, out signerInfos, out error);
        }

        public static bool TryGetPkcs7SignerInfos(
            byte[] data,
            AuthenticodePolicy policy,
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
                    infos.Add(BuildSignerInfo(signer, false, policy, 0));
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

        private static Pkcs7SignerInfo BuildSignerInfo(SignerInfo signer, bool isTimestamp, AuthenticodePolicy policy, int nestingLevel)
        {
            string subject = string.Empty;
            string issuer = string.Empty;
            string serialNumber = string.Empty;
            string thumbprint = string.Empty;
            bool hasCodeSigningEku = false;
            bool hasTimestampEku = false;
            bool isWithinValidity = false;
            int certificateTransparencyCount = 0;
            string[] certificateTransparencyLogIds = Array.Empty<string>();

            if (signer.Certificate != null)
            {
                subject = signer.Certificate.Subject ?? string.Empty;
                issuer = signer.Certificate.Issuer ?? string.Empty;
                serialNumber = signer.Certificate.SerialNumber ?? string.Empty;
                thumbprint = signer.Certificate.Thumbprint ?? string.Empty;
                hasCodeSigningEku = HasEku(signer.Certificate, "1.3.6.1.5.5.7.3.3");
                hasTimestampEku = HasEku(signer.Certificate, "1.3.6.1.5.5.7.3.8");
                certificateTransparencyCount = GetCertificateTransparencyCount(signer.Certificate);
                certificateTransparencyLogIds = GetCertificateTransparencyLogIds(signer.Certificate);
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

            if (signer.Certificate != null)
            {
                DateTimeOffset checkTime = signingTime ?? DateTimeOffset.UtcNow;
                if (signer.Certificate.NotBefore <= checkTime && checkTime <= signer.Certificate.NotAfter)
                {
                    isWithinValidity = true;
                }
            }

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
            List<Pkcs7ChainElementInfo> chainElements = new List<Pkcs7ChainElementInfo>();
            if (signer.Certificate != null)
            {
                try
                {
                    using (X509Chain chain = new X509Chain())
                    {
                        if (policy != null)
                        {
                            if (policy.OfflineChainCheck)
                            {
                                chain.ChainPolicy.DisableCertificateDownloads = true;
                                chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
                            }
                            else
                            {
                                chain.ChainPolicy.RevocationMode = policy.RevocationMode;
                            }
                            chain.ChainPolicy.RevocationFlag = policy.RevocationFlag;
                            chain.ChainPolicy.VerificationFlags = policy.EnableTrustStoreCheck
                                ? X509VerificationFlags.NoFlag
                                : X509VerificationFlags.AllowUnknownCertificateAuthority;
                        }
                        else
                        {
                            chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
                            chain.ChainPolicy.RevocationFlag = X509RevocationFlag.ExcludeRoot;
                            chain.ChainPolicy.VerificationFlags = X509VerificationFlags.NoFlag;
                        }
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

                        foreach (X509ChainElement element in chain.ChainElements)
                        {
                            string subjectName = element.Certificate?.Subject ?? string.Empty;
                            string issuerName = element.Certificate?.Issuer ?? string.Empty;
                            string thumb = element.Certificate?.Thumbprint ?? string.Empty;
                            bool isSelfSigned = !string.IsNullOrWhiteSpace(subjectName) &&
                                                string.Equals(subjectName, issuerName, StringComparison.OrdinalIgnoreCase);
                            List<string> elementStatus = new List<string>();
                            if (element.ChainElementStatus != null && element.ChainElementStatus.Length > 0)
                            {
                                foreach (X509ChainStatus status in element.ChainElementStatus)
                                {
                                    elementStatus.Add(status.Status + ": " + status.StatusInformation.Trim());
                                }
                            }
                            chainElements.Add(new Pkcs7ChainElementInfo(subjectName, issuerName, thumb, elementStatus.ToArray(), isSelfSigned));
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
                    countersigners.Add(BuildSignerInfo(counter, true, policy, nestingLevel));
                }
            }

            List<Pkcs7SignerInfo> nestedSigners = new List<Pkcs7SignerInfo>();
            if (nestingLevel < 3)
            {
                nestedSigners.AddRange(BuildNestedSigners(signer, policy, nestingLevel));
            }

            List<Pkcs7TimestampInfo> rfc3161Timestamps = TryGetRfc3161Timestamps(signer);

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
                chainElements.ToArray(),
                isTimestamp,
                hasCodeSigningEku,
                hasTimestampEku,
                isWithinValidity,
                certificateTransparencyCount,
                certificateTransparencyLogIds,
                nestingLevel,
                countersigners.ToArray(),
                nestedSigners.ToArray(),
                rfc3161Timestamps.ToArray());
        }

        private static List<Pkcs7SignerInfo> BuildNestedSigners(SignerInfo signer, AuthenticodePolicy policy, int nestingLevel)
        {
            List<Pkcs7SignerInfo> nested = new List<Pkcs7SignerInfo>();
            if (signer == null || signer.UnsignedAttributes == null)
            {
                return nested;
            }

            foreach (CryptographicAttributeObject attr in signer.UnsignedAttributes)
            {
                if (attr?.Oid == null || attr.Oid.Value != "1.3.6.1.4.1.311.2.4.1")
                {
                    continue;
                }

                if (attr.Values == null || attr.Values.Count == 0)
                {
                    continue;
                }

                foreach (AsnEncodedData value in attr.Values)
                {
                    if (value?.RawData == null || value.RawData.Length == 0)
                    {
                        continue;
                    }

                    try
                    {
                        SignedCms nestedCms = new SignedCms();
                        nestedCms.Decode(value.RawData);
                        if (nestedCms.SignerInfos == null || nestedCms.SignerInfos.Count == 0)
                        {
                            continue;
                        }

                        foreach (SignerInfo nestedSigner in nestedCms.SignerInfos)
                        {
                            nested.Add(BuildSignerInfo(nestedSigner, false, policy, nestingLevel + 1));
                        }
                    }
                    catch (CryptographicException)
                    {
                    }
                    catch (Exception)
                    {
                    }
                }
            }

            return nested;
        }

        private static List<Pkcs7TimestampInfo> TryGetRfc3161Timestamps(SignerInfo signer)
        {
            List<Pkcs7TimestampInfo> timestamps = new List<Pkcs7TimestampInfo>();
            if (signer == null || signer.UnsignedAttributes == null)
            {
                return timestamps;
            }

            foreach (CryptographicAttributeObject attr in signer.UnsignedAttributes)
            {
                if (attr?.Oid == null || attr.Oid.Value != "1.2.840.113549.1.9.16.2.14")
                {
                    continue;
                }

                if (attr.Values == null || attr.Values.Count == 0)
                {
                    continue;
                }

                foreach (AsnEncodedData value in attr.Values)
                {
                    if (value?.RawData == null || value.RawData.Length == 0)
                    {
                        continue;
                    }

                    if (TryParseRfc3161TimestampInfo(value.RawData, out Pkcs7TimestampInfo info))
                    {
                        timestamps.Add(info);
                    }
                }
            }

            return timestamps;
        }

        private static bool TryParseRfc3161TimestampInfo(byte[] data, out Pkcs7TimestampInfo info)
        {
            info = null;
            if (data == null || data.Length == 0)
            {
                return false;
            }

            try
            {
                SignedCms cms = new SignedCms();
                cms.Decode(data);
                byte[] content = cms.ContentInfo?.Content;
                if (content == null || content.Length == 0)
                {
                    return false;
                }

                AsnReader reader = new AsnReader(content, AsnEncodingRules.BER);
                AsnReader sequence = reader.ReadSequence();
                if (!sequence.HasData)
                {
                    return false;
                }

                sequence.ReadInteger();
                if (!sequence.HasData)
                {
                    return false;
                }

                string policy = sequence.ReadObjectIdentifier();
                if (!sequence.HasData)
                {
                    info = new Pkcs7TimestampInfo(policy, string.Empty, string.Empty, null);
                    return true;
                }

                AsnReader messageImprint = sequence.ReadSequence();
                if (messageImprint.HasData)
                {
                    AsnReader algorithm = messageImprint.ReadSequence();
                    if (algorithm.HasData)
                    {
                        algorithm.ReadObjectIdentifier();
                        if (algorithm.HasData)
                        {
                            algorithm.ReadEncodedValue();
                        }
                    }

                    if (messageImprint.HasData)
                    {
                        messageImprint.ReadOctetString();
                    }
                }

                string serial = string.Empty;
                if (sequence.HasData)
                {
                    BigInteger serialNumber = sequence.ReadInteger();
                    serial = serialNumber.ToString(CultureInfo.InvariantCulture);
                }

                DateTimeOffset? genTime = null;
                if (sequence.HasData)
                {
                    try
                    {
                        genTime = sequence.ReadGeneralizedTime();
                    }
                    catch (AsnContentException)
                    {
                    }
                }

                string tsaName = string.Empty;
                while (sequence.HasData)
                {
                    Asn1Tag tag = sequence.PeekTag();
                    if (tag.TagClass == TagClass.ContextSpecific && tag.TagValue == 0)
                    {
                        AsnReader tsa = sequence.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0));
                        if (tsa.HasData)
                        {
                            Asn1Tag nameTag = tsa.PeekTag();
                            if (nameTag.TagClass == TagClass.ContextSpecific && nameTag.TagValue == 4)
                            {
                                AsnReader directoryName = tsa.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 4));
                                if (directoryName.HasData)
                                {
                                    ReadOnlyMemory<byte> nameBytes = directoryName.ReadEncodedValue();
                                    try
                                    {
                                        X500DistinguishedName name = new X500DistinguishedName(nameBytes.ToArray());
                                        tsaName = name.Name ?? string.Empty;
                                    }
                                    catch (CryptographicException)
                                    {
                                    }
                                }
                            }
                            else
                            {
                                tsa.ReadEncodedValue();
                            }
                        }
                    }
                    else
                    {
                        sequence.ReadEncodedValue();
                    }
                }

                info = new Pkcs7TimestampInfo(policy, serial, tsaName, genTime);
                return true;
            }
            catch (Exception)
            {
                return false;
            }
        }

        private static bool HasEku(X509Certificate2 certificate, string oid)
        {
            if (certificate == null || string.IsNullOrWhiteSpace(oid))
            {
                return false;
            }

            foreach (X509Extension extension in certificate.Extensions)
            {
                if (extension is X509EnhancedKeyUsageExtension eku)
                {
                    foreach (Oid usage in eku.EnhancedKeyUsages)
                    {
                        if (string.Equals(usage.Value, oid, StringComparison.Ordinal))
                        {
                            return true;
                        }
                    }
                }
            }

            return false;
        }

        private static int GetCertificateTransparencyCount(X509Certificate2 certificate)
        {
            if (certificate == null)
            {
                return 0;
            }

            foreach (X509Extension extension in certificate.Extensions)
            {
                if (extension?.Oid?.Value != "1.3.6.1.4.1.11129.2.4.2")
                {
                    continue;
                }

                byte[] raw = extension.RawData;
                if (raw == null || raw.Length == 0)
                {
                    return 0;
                }

                byte[] payload = raw;
                try
                {
                    if (raw[0] == 0x04)
                    {
                        AsnReader reader = new AsnReader(raw, AsnEncodingRules.DER);
                        payload = reader.ReadOctetString();
                    }
                }
                catch (Exception)
                {
                    payload = raw;
                }

                return CountSctEntries(payload);
            }

            return 0;
        }

        private static string[] GetCertificateTransparencyLogIds(X509Certificate2 certificate)
        {
            if (certificate == null)
            {
                return Array.Empty<string>();
            }

            foreach (X509Extension extension in certificate.Extensions)
            {
                if (extension?.Oid?.Value != "1.3.6.1.4.1.11129.2.4.2")
                {
                    continue;
                }

                byte[] raw = extension.RawData;
                if (raw == null || raw.Length == 0)
                {
                    return Array.Empty<string>();
                }

                byte[] payload = raw;
                try
                {
                    if (raw[0] == 0x04)
                    {
                        AsnReader reader = new AsnReader(raw, AsnEncodingRules.DER);
                        payload = reader.ReadOctetString();
                    }
                }
                catch (Exception)
                {
                    payload = raw;
                }

                return ParseSctLogIds(payload);
            }

            return Array.Empty<string>();
        }

        private static int CountSctEntries(byte[] payload)
        {
            if (payload == null || payload.Length < 2)
            {
                return 0;
            }

            int listLength = (payload[0] << 8) | payload[1];
            int limit = Math.Min(payload.Length, listLength + 2);
            int offset = 2;
            int count = 0;

            while (offset + 2 <= limit)
            {
                int entryLength = (payload[offset] << 8) | payload[offset + 1];
                offset += 2;
                if (entryLength <= 0 || offset + entryLength > limit)
                {
                    break;
                }

                count++;
                offset += entryLength;
            }

            return count;
        }

        private static string[] ParseSctLogIds(byte[] payload)
        {
            if (payload == null || payload.Length < 2)
            {
                return Array.Empty<string>();
            }

            int listLength = (payload[0] << 8) | payload[1];
            int limit = Math.Min(payload.Length, listLength + 2);
            int offset = 2;
            HashSet<string> logs = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            while (offset + 2 <= limit)
            {
                int entryLength = (payload[offset] << 8) | payload[offset + 1];
                offset += 2;
                if (entryLength <= 0 || offset + entryLength > limit)
                {
                    break;
                }

                int entryStart = offset;
                if (entryLength >= 33 && entryStart + 33 <= limit)
                {
                    ReadOnlySpan<byte> logId = new ReadOnlySpan<byte>(payload, entryStart + 1, 32);
                    logs.Add(ToHex(logId.ToArray()));
                }

                offset += entryLength;
            }

            return logs.Count == 0
                ? Array.Empty<string>()
                : logs.OrderBy(value => value, StringComparer.Ordinal).ToArray();
        }

        private static string ToHex(byte[] data)
        {
            if (data == null || data.Length == 0)
            {
                return string.Empty;
            }

            StringBuilder sb = new StringBuilder(data.Length * 2);
            foreach (byte b in data)
            {
                sb.Append(b.ToString("X2", CultureInfo.InvariantCulture));
            }
            return sb.ToString();
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

        private static WinTrustResultInfo BuildWinTrustResult(AuthenticodePolicy policy, string filePath)
        {
            if (policy == null || !policy.EnableWinTrustCheck)
            {
                return null;
            }

            if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                return new WinTrustResultInfo("NotSupported", -1, "WinTrust is only available on Windows.");
            }

            if (string.IsNullOrWhiteSpace(filePath) || !File.Exists(filePath))
            {
                return new WinTrustResultInfo("Unavailable", -2, "File not found for WinTrust.");
            }

            return TryGetWinTrustResult(filePath);
        }

        private static WinTrustResultInfo TryGetWinTrustResult(string filePath)
        {
            const uint WTD_UI_NONE = 2;
            const uint WTD_REVOKE_NONE = 0;
            const uint WTD_CHOICE_FILE = 1;
            const uint WTD_STATEACTION_IGNORE = 0;
            const uint WTD_SAFER_FLAG = 0x00000100;

            Guid action = new Guid("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");
            WinTrustFileInfo fileInfo = new WinTrustFileInfo(filePath);
            IntPtr fileInfoPtr = IntPtr.Zero;
            try
            {
                fileInfoPtr = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(WinTrustFileInfo)));
                Marshal.StructureToPtr(fileInfo, fileInfoPtr, false);

                WinTrustData data = new WinTrustData
                {
                    cbStruct = (uint)Marshal.SizeOf(typeof(WinTrustData)),
                    pPolicyCallbackData = IntPtr.Zero,
                    pSIPClientData = IntPtr.Zero,
                    dwUIChoice = WTD_UI_NONE,
                    fdwRevocationChecks = WTD_REVOKE_NONE,
                    dwUnionChoice = WTD_CHOICE_FILE,
                    pInfoStruct = fileInfoPtr,
                    dwStateAction = WTD_STATEACTION_IGNORE,
                    hWVTStateData = IntPtr.Zero,
                    pwszURLReference = IntPtr.Zero,
                    dwProvFlags = WTD_SAFER_FLAG,
                    dwUIContext = 0
                };

                uint result = WinVerifyTrust(IntPtr.Zero, action, ref data);
                if (result == 0)
                {
                    return new WinTrustResultInfo("Valid", 0, "WinTrust signature validation succeeded.");
                }

                string message = GetWinTrustMessage(result);
                return new WinTrustResultInfo("Invalid", unchecked((int)result), message);
            }
            catch (Exception ex)
            {
                return new WinTrustResultInfo("Error", -3, ex.Message);
            }
            finally
            {
                if (fileInfoPtr != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(fileInfoPtr);
                }
            }
        }

        private static string GetWinTrustMessage(uint status)
        {
            switch (status)
            {
                case 0x800B0100: return "No signature was present.";
                case 0x800B0109: return "The certificate chain could not be built.";
                case 0x80096010: return "The signature is invalid.";
                case 0x800B010A: return "The certificate is not trusted.";
                case 0x800B0004: return "The subject is not trusted.";
                case 0x800B0101: return "A required certificate is not within its validity period.";
                default: return "WinTrust error: 0x" + status.ToString("X8", CultureInfo.InvariantCulture);
            }
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private sealed class WinTrustFileInfo
        {
            public uint cbStruct;
            public string pcwszFilePath;
            public IntPtr hFile;
            public IntPtr pgKnownSubject;

            public WinTrustFileInfo(string filePath)
            {
                cbStruct = (uint)Marshal.SizeOf(typeof(WinTrustFileInfo));
                pcwszFilePath = filePath;
                hFile = IntPtr.Zero;
                pgKnownSubject = IntPtr.Zero;
            }
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct WinTrustData
        {
            public uint cbStruct;
            public IntPtr pPolicyCallbackData;
            public IntPtr pSIPClientData;
            public uint dwUIChoice;
            public uint fdwRevocationChecks;
            public uint dwUnionChoice;
            public IntPtr pInfoStruct;
            public uint dwStateAction;
            public IntPtr hWVTStateData;
            public IntPtr pwszURLReference;
            public uint dwProvFlags;
            public uint dwUIContext;
        }

        [DllImport("wintrust.dll", ExactSpelling = true, CharSet = CharSet.Unicode)]
        private static extern uint WinVerifyTrust(
            IntPtr hwnd,
            [MarshalAs(UnmanagedType.LPStruct)] Guid pgActionID,
            ref WinTrustData pWvtData);

        public static CatalogSignatureInfo GetCatalogSignatureInfo(string filePath, AuthenticodePolicy policy)
        {
            policy ??= new AuthenticodePolicy();
            if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                return new CatalogSignatureInfo(
                    supported: false,
                    @checked: false,
                    isSigned: false,
                    trustCheckPerformed: false,
                    trustVerified: false,
                    catalogPath: string.Empty,
                    catalogName: string.Empty,
                    error: "Catalog signature checks are only supported on Windows.",
                    signers: Array.Empty<Pkcs7SignerInfo>(),
                    status: null);
            }

            if (string.IsNullOrWhiteSpace(filePath) || !File.Exists(filePath))
            {
                return new CatalogSignatureInfo(
                    supported: true,
                    @checked: true,
                    isSigned: false,
                    trustCheckPerformed: false,
                    trustVerified: false,
                    catalogPath: string.Empty,
                    catalogName: string.Empty,
                    error: "File not found.",
                    signers: Array.Empty<Pkcs7SignerInfo>(),
                    status: null);
            }

            if (!TryGetCatalogPath(filePath, out string catalogPath, out string error))
            {
                return new CatalogSignatureInfo(
                    supported: true,
                    @checked: true,
                    isSigned: false,
                    trustCheckPerformed: false,
                    trustVerified: false,
                    catalogPath: string.Empty,
                    catalogName: string.Empty,
                    error: error,
                    signers: Array.Empty<Pkcs7SignerInfo>(),
                    status: null);
            }

            Pkcs7SignerInfo[] signers = Array.Empty<Pkcs7SignerInfo>();
            string signerError = string.Empty;
            try
            {
                byte[] catalogBytes = File.ReadAllBytes(catalogPath);
                TryGetPkcs7SignerInfos(catalogBytes, policy, out signers, out signerError);
            }
            catch (Exception ex)
            {
                signerError = ex.Message;
            }

            AuthenticodeStatusInfo status = BuildAuthenticodeStatus(signers, policy, filePath);
            bool trustCheckPerformed = policy.EnableTrustStoreCheck;
            bool trustVerified = trustCheckPerformed && status != null && status.ChainValid;

            string catalogName = Path.GetFileName(catalogPath) ?? string.Empty;
            return new CatalogSignatureInfo(
                supported: true,
                @checked: true,
                isSigned: true,
                trustCheckPerformed: trustCheckPerformed,
                trustVerified: trustVerified,
                catalogPath: catalogPath,
                catalogName: catalogName,
                error: signerError,
                signers: signers,
                status: status);
        }

        private static bool TryGetCatalogPath(string filePath, out string catalogPath, out string error)
        {
            catalogPath = string.Empty;
            error = string.Empty;

            IntPtr hCatAdmin = IntPtr.Zero;
            IntPtr hCatInfo = IntPtr.Zero;
            try
            {
                try
                {
                    if (!CryptCATAdminAcquireContext2(out hCatAdmin, IntPtr.Zero, null, IntPtr.Zero, 0))
                    {
                        error = "CryptCATAdminAcquireContext2 failed.";
                        return false;
                    }
                }
                catch (EntryPointNotFoundException)
                {
                    error = "CryptCATAdminAcquireContext2 is not available on this platform.";
                    return false;
                }

                using FileStream fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                SafeFileHandle handle = fs.SafeFileHandle;
                uint hashSize = 0;
                if (!CryptCATAdminCalcHashFromFileHandle(handle.DangerousGetHandle(), ref hashSize, null, 0))
                {
                    error = "CryptCATAdminCalcHashFromFileHandle failed to size hash.";
                    return false;
                }

                if (hashSize == 0 || hashSize > 1024)
                {
                    error = "Catalog hash size is invalid.";
                    return false;
                }

                byte[] hash = new byte[hashSize];
                if (!CryptCATAdminCalcHashFromFileHandle(handle.DangerousGetHandle(), ref hashSize, hash, 0))
                {
                    error = "CryptCATAdminCalcHashFromFileHandle failed.";
                    return false;
                }

                hCatInfo = CryptCATAdminEnumCatalogFromHash(hCatAdmin, hash, hashSize, 0, IntPtr.Zero);
                if (hCatInfo == IntPtr.Zero)
                {
                    error = "No catalog found for file hash.";
                    return false;
                }

                CATALOG_INFO info = new CATALOG_INFO();
                info.cbStruct = Marshal.SizeOf(typeof(CATALOG_INFO));
                if (!CryptCATCatalogInfoFromContext(hCatInfo, ref info, 0))
                {
                    error = "CryptCATCatalogInfoFromContext failed.";
                    return false;
                }

                catalogPath = info.wszCatalogFile ?? string.Empty;
                return !string.IsNullOrWhiteSpace(catalogPath);
            }
            finally
            {
                if (hCatInfo != IntPtr.Zero && hCatAdmin != IntPtr.Zero)
                {
                    CryptCATAdminReleaseCatalogContext(hCatAdmin, hCatInfo, 0);
                }

                if (hCatAdmin != IntPtr.Zero)
                {
                    CryptCATAdminReleaseContext(hCatAdmin, 0);
                }
            }
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct CATALOG_INFO
        {
            public int cbStruct;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
            public string wszCatalogFile;
        }

        [DllImport("wintrust.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern bool CryptCATAdminAcquireContext2(
            out IntPtr hCatAdmin,
            IntPtr pgSubsystem,
            string pwszHashAlgorithm,
            IntPtr pStrongHashPolicy,
            uint dwFlags);

        [DllImport("wintrust.dll", SetLastError = true)]
        private static extern bool CryptCATAdminCalcHashFromFileHandle(
            IntPtr hFile,
            ref uint pcbHash,
            [Out] byte[] pbHash,
            uint dwFlags);

        [DllImport("wintrust.dll", SetLastError = true)]
        private static extern IntPtr CryptCATAdminEnumCatalogFromHash(
            IntPtr hCatAdmin,
            [In] byte[] pbHash,
            uint cbHash,
            uint dwFlags,
            IntPtr phPrevCatInfo);

        [DllImport("wintrust.dll", SetLastError = true)]
        private static extern bool CryptCATCatalogInfoFromContext(
            IntPtr hCatInfo,
            ref CATALOG_INFO psCatInfo,
            uint dwFlags);

        [DllImport("wintrust.dll", SetLastError = true)]
        private static extern bool CryptCATAdminReleaseCatalogContext(
            IntPtr hCatAdmin,
            IntPtr hCatInfo,
            uint dwFlags);

        [DllImport("wintrust.dll", SetLastError = true)]
        private static extern bool CryptCATAdminReleaseContext(
            IntPtr hCatAdmin,
            uint dwFlags);
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
