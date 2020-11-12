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
                    throw new ArgumentNullException("encryptedData");

                if (encryptedData.KeyInfo == null)
                    return null;
                var keyInfoEnum = encryptedData.KeyInfo.GetEnumerator();
                KeyInfoRetrievalMethod kiRetrievalMethod;
                KeyInfoName kiName;
                KeyInfoEncryptedKey kiEncKey;
                EncryptedKey ek = null;

                while (keyInfoEnum.MoveNext())
                {
                    kiName = keyInfoEnum.Current as KeyInfoName;
                    if (kiName != null)
                    {
                        // Get the decryption key from the key mapping
                        string keyName = kiName.Value;
                        if ((SymmetricAlgorithm)m_keyNameMapping[keyName] != null)
                            return (SymmetricAlgorithm)m_keyNameMapping[keyName];
                        // try to get it from a CarriedKeyName
                        XmlNamespaceManager nsm = new XmlNamespaceManager(m_document.NameTable);
                        nsm.AddNamespace("enc", EncryptedXml.XmlEncNamespaceUrl);
                        XmlNodeList encryptedKeyList = m_document.SelectNodes("//enc:EncryptedKey", nsm);
                        if (encryptedKeyList != null)
                        {
                            foreach (XmlNode encryptedKeyNode in encryptedKeyList)
                            {
                                XmlElement encryptedKeyElement = encryptedKeyNode as XmlElement;
                                EncryptedKey ek1 = new EncryptedKey();
                                ek1.LoadXml(encryptedKeyElement);
                                if (ek1.CarriedKeyName == keyName && ek1.Recipient == this.Recipient)
                                {
                                    ek = ek1;
                                    break;
                                }
                            }
                        }
                        break;
                    }
                    kiRetrievalMethod = keyInfoEnum.Current as KeyInfoRetrievalMethod;
                    if (kiRetrievalMethod != null)
                    {
                        string idref = (string)null ?? throw new Exception("Utils.ExtractIdFromLocalUri(kiRetrievalMethod.Uri)");
                        ek = new EncryptedKey();
                        ek.LoadXml(GetIdElement(m_document, idref));
                        break;
                    }
                    kiEncKey = keyInfoEnum.Current as KeyInfoEncryptedKey;
                    if (kiEncKey != null)
                    {
                        ek = kiEncKey.EncryptedKey;
                        break;
                    }
                }

                // if we have an EncryptedKey, decrypt to get the symmetric key
                if (ek != null)
                {
                    // now process the EncryptedKey, loop recursively 
                    // If the Uri is not provided by the application, try to get it from the EncryptionMethod
                    if (symmetricAlgorithmUri == null)
                    {
                        if (encryptedData.EncryptionMethod == null)
                            throw new CryptographicException("Cryptography_Xml_MissingAlgorithm");
                        symmetricAlgorithmUri = encryptedData.EncryptionMethod.KeyAlgorithm;
                    }
                    byte[] key = DecryptEncryptedKey(ek);
                    if (key == null)
                        throw new CryptographicException("Cryptography_Xml_MissingDecryptionKey");

                    SymmetricAlgorithm symAlg = (SymmetricAlgorithm)CryptoConfig.CreateFromName(symmetricAlgorithmUri);
                    if (symAlg == null)
                    {
                        throw new CryptographicException("Cryptography_Xml_MissingAlgorithm");
                    }
                    symAlg.Key = key;
                    return symAlg;
                }
                return null;
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
