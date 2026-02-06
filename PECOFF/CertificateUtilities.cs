using System;
using System.Collections.Generic;
using System.Globalization;
using System.Formats.Asn1;
using System.Numerics;
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
        public IReadOnlyList<Pkcs7ChainElementInfo> ChainElements { get; }
        public bool IsTimestampSigner { get; }
        public bool HasCodeSigningEku { get; }
        public bool HasTimestampEku { get; }
        public bool IsWithinValidityPeriod { get; }
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
        public static AuthenticodeStatusInfo BuildAuthenticodeStatus(Pkcs7SignerInfo[] signers, AuthenticodePolicy policy = null)
        {
            policy ??= new AuthenticodePolicy();
            if (signers == null || signers.Length == 0)
            {
                bool isPolicyCompliant = !policy.RequireSignature && !policy.RequireSignatureValid &&
                                         !policy.RequireChainValid && !policy.RequireTimestamp &&
                                         !policy.RequireTimestampValid && !policy.RequireCodeSigningEku;
                return new AuthenticodeStatusInfo(
                    0,
                    0,
                    false,
                    false,
                    false,
                    false,
                    false,
                    Array.Empty<string>(),
                    Array.Empty<string>(),
                    isPolicyCompliant,
                    isPolicyCompliant ? Array.Empty<string>() : new[] { "Missing signature." });
            }

            List<string> chainStatus = new List<string>();
            List<string> timestampStatus = new List<string>();
            int signerCount = 0;
            int timestampCount = 0;
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

            return new AuthenticodeStatusInfo(
                signerCount,
                timestampCount,
                hasSignature,
                signatureValid,
                chainValid,
                hasTimestamp,
                timestampValid,
                chainStatus.ToArray(),
                timestampStatus.ToArray(),
                policyCompliant,
                policyFailures.ToArray());
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

            if (signer.Certificate != null)
            {
                subject = signer.Certificate.Subject ?? string.Empty;
                issuer = signer.Certificate.Issuer ?? string.Empty;
                serialNumber = signer.Certificate.SerialNumber ?? string.Empty;
                thumbprint = signer.Certificate.Thumbprint ?? string.Empty;
                hasCodeSigningEku = HasEku(signer.Certificate, "1.3.6.1.5.5.7.3.3");
                hasTimestampEku = HasEku(signer.Certificate, "1.3.6.1.5.5.7.3.8");
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
