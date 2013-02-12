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

import java.io.StringWriter;

import org.opensaml.DefaultBootstrap;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.util.Base64;
import org.opensaml.xml.util.XMLHelper;

/**
 */
public class App
{
    /**
     * This application takes an input XML string, parses it and decrypts all the embeded EncryptedAssertions 
     * @param args
     * @throws Exception
     */
    public static void main(String[] args) throws Exception
    {
        if (args.length == 0 || args[0].equals("--help") || args[0].equals("-h")) {
            System.err.println("Usage:\n" +
                    "java -jar org.sakaiproject.Hilary.SAMLParser-1.0-SNAPSHOT-jar-with-dependencies.jar idpPublicKey spPublicKey spPrivateKey inputData inputEncoding outputEncoding\n\n" +
                    "Parameters\n" +
                    " * idpPublicKey\n" +
                    "    This is the Identity Provider's public key that can be used to verify signatures in SAML data.\n" +
                    " * spPublicKey\n" +
                    "    This is your Service Provider's public key that the IdP uses to encrypt SAML data.\n" +
                    " * spPrivateKey\n" +
                    "    This is your Service Provider's public key that can be used to decrypt SAML data.\n" +
                    " * inputData\n" +
                    "    The SAML data that needs decrypting (if any.)\n" +
                    " * inputEncoding\n" +
                    "    The encoding format that the inputData is passed in.\n" + 
                    "    Currently only supports 'base64' or 'plain', defaults to 'plain'.\n" +
                    " * outputEncoding\n" +
                    "    The encoding format that the decrypted data should be outputted in.\n" + 
                    "    Currently only supports 'base64' or 'plain', defaults to 'plain'.\n\n" +
                    
                    "Examples:\n" +
                    "    java -jar org.sakaiproject.Hilary.SAMLParser-1.0-SNAPSHOT-jar-with-dependencies.jar <idpPublicKey> <spPublicKey> <spPrivateKey> '<XML data>'\n" +
                    "    java -jar org.sakaiproject.Hilary.SAMLParser-1.0-SNAPSHOT-jar-with-dependencies.jar <idpPublicKey> <spPublicKey> <spPrivateKey> '<base64-encoded XML data>' 'base64'\n" +
                    "    java -jar org.sakaiproject.Hilary.SAMLParser-1.0-SNAPSHOT-jar-with-dependencies.jar <idpPublicKey> <spPublicKey> <spPrivateKey> '<base64-encoded XML data>' 'base64' 'base64'"
            );
            return;
        }
        
        String idpPublicKey = args[0];
        String spPublicKey = args[1];
        String spPrivateKey = args[2];
        String samlResponse = args[3];
        String inputEncoding = (args.length > 4) ? args[4] : "";
        String outputEncoding = (args.length > 5) ? args[5] : "";

        // Bootstrap OpenSAML.
        // This will (for instance) get all the unmarshallers registered.
        DefaultBootstrap.bootstrap();
        
        // Decode the data first if necessary.
        if (inputEncoding.equals("base64")) {
            byte[] decoded = Base64.decode(samlResponse);
            samlResponse = new String(decoded);
        }

        // Parse/decrypt the saml response.
        SAMLParser parser = new SAMLParser(idpPublicKey, spPublicKey, spPrivateKey);
        XMLObject xmlObj = parser.parse(samlResponse);

        // Print the parsed response back out to stdout.
        StringWriter stringWriter = new StringWriter();
        XMLHelper.writeNode(xmlObj.getDOM(), stringWriter);
        
        // Encode the output if requested.
        if (outputEncoding.equals("base64")) {
            String encodedData = Base64.encodeBytes(stringWriter.toString().getBytes());
            System.out.println(encodedData);
        } else {
            System.out.println(stringWriter.toString());
        }
    }
}
