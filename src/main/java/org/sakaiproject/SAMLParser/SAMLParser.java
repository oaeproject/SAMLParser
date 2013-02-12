/*!
 * Copyright 2012 Sakai Foundation (SF) Licensed under the
 * Educational Community License, Version 2.0 (the "License"); you may
 * not use this file except in compliance with the License. You may
 * obtain a copy of the License at
 *
 *     http://www.osedu.org/licenses/ECL-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an "AS IS"
 * BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
 * or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */
package org.sakaiproject.SAMLParser;

import java.io.StringReader;
import java.security.KeyException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.util.ArrayList;
import java.util.List;

import org.opensaml.Configuration;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.EncryptedAssertion;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.encryption.Decrypter;
import org.opensaml.security.SAMLSignatureProfileValidator;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.encryption.DecryptionException;
import org.opensaml.xml.encryption.InlineEncryptedKeyResolver;
import org.opensaml.xml.io.Unmarshaller;
import org.opensaml.xml.io.UnmarshallerFactory;
import org.opensaml.xml.parse.BasicParserPool;
import org.opensaml.xml.security.SecurityHelper;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.security.keyinfo.KeyInfoCredentialResolver;
import org.opensaml.xml.security.keyinfo.StaticKeyInfoCredentialResolver;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.validation.ValidationException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

public class SAMLParser {

    private StaticKeyInfoCredentialResolver skicr;
    private String idpPublicKey;

    public SAMLParser(String idpPublicKey, String spPublicKey, String spPrivateKey) throws CertificateException, KeyException {
        this.idpPublicKey = idpPublicKey;

        // Get the public/private key pairs we need to support.
        List<Credential> credentials = buildCredentials(spPublicKey, spPrivateKey);

        // Setup the Credential resolvers
        skicr = new StaticKeyInfoCredentialResolver(credentials);
    }
    
    public XMLObject parse(String SAMLResponse) throws Exception {
        // Unmarshall the SAML Response into Java SAML Objects.
        Response response = (Response) unmarshall(SAMLResponse);

        // Get the encrypted assertions and replace them with their uncrypted counterparts.
        // It's possible that the response was not encrypted, return as-is in that case.
        List<EncryptedAssertion> encryptedAssertions = response.getEncryptedAssertions();
        if (encryptedAssertions.size() > 0) {
            // Decrypt the assertions.
            for (EncryptedAssertion encryptedAssertion : encryptedAssertions) {
                Assertion assertion = decryptAssertion(skicr, encryptedAssertion);
                response.getDOM().insertBefore(assertion.getDOM(), encryptedAssertion.getDOM());
                response.getDOM().removeChild(encryptedAssertion.getDOM());

                // If we decryted the assertion, it should have a Signature.
                // Validate it.
                validateAssertion(assertion);
            }
        }

        return response;
    }

    private List<Credential> buildCredentials(String spPublicKey, String spPrivateKey) throws CertificateException, KeyException {
        List<Credential> credentials = new ArrayList<Credential>();
        X509Certificate cert = SecurityHelper.buildJavaX509Cert(spPublicKey);
        RSAPrivateKey privateKey = SecurityHelper.buildJavaRSAPrivateKey(spPrivateKey);
        Credential decryptionCredential = SecurityHelper.getSimpleCredential(cert, privateKey);
        credentials.add(decryptionCredential);
        return credentials;
    }

    private void validateAssertion(Assertion assertion) throws ValidationException {
        Signature signature = assertion.getSignature();
        
        // First check if the keys match.
        // Anybody can sign a message..
        String xmlKey = signature.getKeyInfo().getX509Datas().get(0).getX509Certificates().get(0).getValue();
        xmlKey = xmlKey.replace("\n", "");
        if (!xmlKey.equals(idpPublicKey)) {
            throw new ValidationException("The public key that's exposed in this signature doesn't match with the passed in one.");
        }

        // Verify the signature.
        SAMLSignatureProfileValidator validator = new SAMLSignatureProfileValidator();
        validator.validate(assertion.getSignature());
    }

    private Assertion decryptAssertion(KeyInfoCredentialResolver skicr, EncryptedAssertion assertion)
            throws DecryptionException {
        Decrypter decrypter = new Decrypter(null, skicr, new InlineEncryptedKeyResolver());
        return decrypter.decrypt(assertion);
    }

    /**
     * Unmarshall XML to POJOs (These POJOs will be OpenSAML objects.)
     * 
     * @param samlResponse
     * @return The root OpenSAML object.
     * @throws Exception
     */
    private XMLObject unmarshall(String samlResponse) throws Exception {
        BasicParserPool parser = new BasicParserPool();
        parser.setNamespaceAware(true);

        StringReader reader = new StringReader(samlResponse);

        Document doc = parser.parse(reader);
        Element samlElement = doc.getDocumentElement();

        UnmarshallerFactory unmarshallerFactory = Configuration.getUnmarshallerFactory();
        Unmarshaller unmarshaller = unmarshallerFactory.getUnmarshaller(samlElement);
        if (unmarshaller == null) {
            throw new Exception("Failed to unmarshal");
        }

        return unmarshaller.unmarshall(samlElement);
    }
}
