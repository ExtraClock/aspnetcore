// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Xml;
using System.Xml.Linq;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace Microsoft.AspNetCore.DataProtection.XmlEncryption
{
    /// <summary>
    /// An <see cref="IXmlDecryptor"/> that decrypts XML elements by using the <see cref="EncryptedXml"/> class.
    /// </summary>
    public sealed class EncryptedXmlDecryptor : IInternalEncryptedXmlDecryptor, IXmlDecryptor
    {
        private readonly IInternalEncryptedXmlDecryptor _decryptor;
        private readonly XmlKeyDecryptionOptions _options;

        /// <summary>
        /// Creates a new instance of an <see cref="EncryptedXmlDecryptor"/>.
        /// </summary>
        public EncryptedXmlDecryptor()
            : this(services: null)
        {
        }

        /// <summary>
        /// Creates a new instance of an <see cref="EncryptedXmlDecryptor"/>.
        /// </summary>
        /// <param name="services">An optional <see cref="IServiceProvider"/> to provide ancillary services.</param>
        public EncryptedXmlDecryptor(IServiceProvider services)
        {
            _decryptor = services?.GetService<IInternalEncryptedXmlDecryptor>() ?? this;
            _options = services?.GetService<IOptions<XmlKeyDecryptionOptions>>()?.Value;
        }

        /// <summary>
        /// Decrypts the specified XML element.
        /// </summary>
        /// <param name="encryptedElement">An encrypted XML element.</param>
        /// <returns>The decrypted form of <paramref name="encryptedElement"/>.</returns>
        public XElement Decrypt(XElement encryptedElement)
        {
            if (encryptedElement == null)
            {
                throw new ArgumentNullException(nameof(encryptedElement));
            }

            // <EncryptedData Type="http://www.w3.org/2001/04/xmlenc#Element" xmlns="http://www.w3.org/2001/04/xmlenc#">
            //   ...
            // </EncryptedData>

            // EncryptedXml works with XmlDocument, not XLinq. When we perform the conversion
            // we'll wrap the incoming element in a dummy <root /> element since encrypted XML
            // doesn't handle encrypting the root element all that well.
            var xmlDocument = new XmlDocument();
            xmlDocument.Load(new XElement("root", encryptedElement).CreateReader());
            var elementToDecrypt = (XmlElement)xmlDocument.DocumentElement.FirstChild;

            // Perform the decryption and update the document in-place.
            var encryptedXml = new EncryptedXmlWithCertificateKeys(_options, xmlDocument);
            _decryptor.PerformPreDecryptionSetup(encryptedXml);

            encryptedXml.DecryptDocument();

            // Strip the <root /> element back off and convert the XmlDocument to an XElement.
            return XElement.Load(xmlDocument.DocumentElement.FirstChild.CreateNavigator().ReadSubtree());
        }

        void IInternalEncryptedXmlDecryptor.PerformPreDecryptionSetup(EncryptedXml encryptedXml)
        {
            // no-op
        }

        /// <summary>
        /// Can decrypt the XML key data from an <see cref="X509Certificate2"/> that is not in stored in <see cref="X509Store"/>.
        /// </summary>
        private class EncryptedXmlWithCertificateKeys : EncryptedXml
        {
            private readonly XmlKeyDecryptionOptions _options;
            private readonly XmlDocument m_document;
            private readonly System.Collections.Hashtable m_keyNameMapping;

            public EncryptedXmlWithCertificateKeys(XmlKeyDecryptionOptions options, XmlDocument document)
                : base(document)
            {
                _options = options;
                m_document = document;
                this.m_keyNameMapping = new System.Collections.Hashtable(4);
            }

            
            public override SymmetricAlgorithm GetDecryptionKey(EncryptedData encryptedData, string symmetricAlgorithmUri)
            {
                if (encryptedData == null)
                {
                    throw new ArgumentNullException("encryptedData");
                }
                if (encryptedData.KeyInfo == null)
                {
                    return null;
                }
                var enumerator = encryptedData.KeyInfo.GetEnumerator();
                EncryptedKey encryptedKey = null;
                while (true)
                {
                    if (enumerator.MoveNext())
                    {
                        KeyInfoName current = enumerator.Current as KeyInfoName;
                        if (current == null)
                        {
                            KeyInfoRetrievalMethod method = enumerator.Current as KeyInfoRetrievalMethod;
                            if (method != null)
                            {
                                string idValue = (string)null ?? throw new Exception("1");// System.Security.Cryptography.Xml.Utils.ExtractIdFromLocalUri(method.Uri);
                                encryptedKey = new EncryptedKey();
                                encryptedKey.LoadXml(this.GetIdElement(this.m_document, idValue));
                            }
                            else
                            {
                                KeyInfoEncryptedKey key = enumerator.Current as KeyInfoEncryptedKey;
                                if (key == null)
                                {
                                    continue;
                                }
                                encryptedKey = key.EncryptedKey;
                            }
                        }
                        else
                        {
                            string str = current.Value;
                            if (((SymmetricAlgorithm)this.m_keyNameMapping[str]) != null)
                            {
                                return (SymmetricAlgorithm)this.m_keyNameMapping[str];
                            }
                            XmlNamespaceManager nsmgr = new XmlNamespaceManager(this.m_document.NameTable);
                            nsmgr.AddNamespace("enc", "http://www.w3.org/2001/04/xmlenc#");
                            XmlNodeList list = this.m_document.SelectNodes("//enc:EncryptedKey", nsmgr);
                            if (list != null)
                            {
                                foreach (XmlNode node in list)
                                {
                                    XmlElement element = node as XmlElement;
                                    EncryptedKey key3 = new EncryptedKey();
                                    key3.LoadXml(element);
                                    if ((key3.CarriedKeyName == str) && (key3.Recipient == this.Recipient))
                                    {
                                        encryptedKey = key3;
                                        break;
                                    }
                                }
                            }
                        }
                    }
                    if (encryptedKey == null)
                    {
                        return null;
                    }
                    if (symmetricAlgorithmUri == null)
                    {
                        if (encryptedData.EncryptionMethod == null)
                        {
                            throw new CryptographicException("Cryptography_Xml_MissingAlgorithm");
                        }
                        symmetricAlgorithmUri = encryptedData.EncryptionMethod.KeyAlgorithm;
                    }
                    byte[] buffer = this.DecryptEncryptedKey(encryptedKey);
                    if (buffer == null)
                    {
                        throw new CryptographicException("Cryptography_Xml_MissingDecryptionKey");
                    }
                    SymmetricAlgorithm algorithm = (SymmetricAlgorithm)CryptoConfig.CreateFromName(symmetricAlgorithmUri);
                    if (algorithm == null)
                    {
                        throw new CryptographicException("Cryptography_Xml_MissingAlgorithm");
                    }
                    algorithm.Key = buffer;
                    return algorithm;
                }
            }

            public override byte[] DecryptEncryptedKey(EncryptedKey encryptedKey)
            {
                if (_options != null && _options.KeyDecryptionCertificateCount > 0)
                {
                    var keyInfoEnum = encryptedKey.KeyInfo?.GetEnumerator();
                    if (keyInfoEnum == null)
                    {
                        return null;
                    }

                    while (keyInfoEnum.MoveNext())
                    {
                        if (!(keyInfoEnum.Current is KeyInfoX509Data kiX509Data))
                        {
                            continue;
                        }

                        byte[] key = GetKeyFromCert(encryptedKey, kiX509Data);
                        if (key != null)
                        {
                            return key;
                        }
                    }
                }

                return base.DecryptEncryptedKey(encryptedKey);
            }

            private byte[] GetKeyFromCert(EncryptedKey encryptedKey, KeyInfoX509Data keyInfo)
            {
                var certEnum = keyInfo.Certificates?.GetEnumerator();
                if (certEnum == null)
                {
                    return null;
                }

                while (certEnum.MoveNext())
                {
                    if (!(certEnum.Current is X509Certificate2 certInfo))
                    {
                        continue;
                    }

                    if (!_options.TryGetKeyDecryptionCertificates(certInfo, out var keyDecryptionCerts))
                    {
                        continue;
                    }

                    foreach (var keyDecryptionCert in keyDecryptionCerts)
                    {
                        if (!keyDecryptionCert.HasPrivateKey)
                        {
                            continue;
                        }

                        using (RSA privateKey = keyDecryptionCert.GetRSAPrivateKey())
                        {
                            if (privateKey != null)
                            {
                                var useOAEP = encryptedKey.EncryptionMethod?.KeyAlgorithm == XmlEncRSAOAEPUrl;
                                return DecryptKey(encryptedKey.CipherData.CipherValue, privateKey, useOAEP);
                            }
                        }
                    }
                }

                return null;
            }
        }
    }
}
