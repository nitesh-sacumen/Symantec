package com.symantec.tree.request.util;
import org.apache.commons.codec.binary.Base64;
import org.forgerock.openam.auth.node.api.NodeProcessException;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import java.io.ByteArrayInputStream;
import java.security.cert.CertificateException;
import java.security.*;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;


public class DeviceHygieneVerification {

    public static String VIP_PROD_ICA_ECC = "-----BEGIN CERTIFICATE-----\n" +
            "MIIClDCCAhqgAwIBAgIQMHvZHLUVvN9GrELIr3/VXjAKBggqhkjOPQQDAzBRMQsw\n" +
            "CQYDVQQGEwJVUzEdMBsGA1UEChMUU3ltYW50ZWMgQ29ycG9yYXRpb24xIzAhBgNV\n" +
            "BAMTGkF1dGhlbnRpY2F0aW9uIEVDQyBSb290IENBMB4XDTE4MDkyNzAwMDAwMFoX\n" +
            "DTM4MDkyNjIzNTk1OVowVzELMAkGA1UEBhMCVVMxHTAbBgNVBAoMFFN5bWFudGVj\n" +
            "IENvcnBvcmF0aW9uMSkwJwYDVQQDDCBWSVAgQXV0aGVudGljYXRpb24gRUNDIERl\n" +
            "dmljZSBDQTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABH/UTO5QmEJMeZoqK4R9\n" +
            "43MM7nbNQamVYTT9Yyw7Mm+QB6PDL9iYiquXG0HgvGcMSPBYbsnKHy0Gp2tHS2SR\n" +
            "Koujgc0wgcowEgYDVR0TAQH/BAgwBgEB/wIBADAOBgNVHQ8BAf8EBAMCAQYwZAYD\n" +
            "VR0fBF0wWzBZoFegVYZTaHR0cDovL3BraS1jcmwuc3ltYXV0aC5jb20vb2ZmbGlu\n" +
            "ZWNhL1N5bWFudGVjQ29ycG9yYXRpb25BdXRoZW50aWNhdGlvbkVDQ1Jvb3RDQS5j\n" +
            "cmwwHQYDVR0OBBYEFPxRzIcKuK+QhwHZ2VcK+O4LAxWrMB8GA1UdIwQYMBaAFCYi\n" +
            "1yc1r1uAcJzj8BEcEeo3YQutMAoGCCqGSM49BAMDA2gAMGUCMQDsSueaAmShlhV3\n" +
            "gs5JE8/Qsgwbuqon/0WZfzQmwIPCken17M3eNmhBSSwhQSSfNysCME4wlfyLSv2W\n" +
            "cSuIxJcUtPFNuoEzUq396E25Ifp9z6b9NsGlDIFFAzvXktTn3735Bg==\n" +
            "-----END CERTIFICATE-----";

    public String mapJwaToJcaSignatureAlgorithm(String jwtSigAlg) {
        switch (jwtSigAlg) {
            case "RS256":
                return "SHA256WithRSA";
            case "ES256":
                return "SHA256withECDSA";
            case "RS384":
                return "SHA384WithRSA";
            case "ES384":
                return "SHA384withECDSA";
            case "RS512":
                return "SHA512WithRSA";
            case "ES512":
                return "SHA512withECDSA";
            default:
                return null;
        }
    }


    private boolean isChainedToCA(X509Certificate cert, X509Certificate caCert) {
        try {
            cert.verify(caCert.getPublicKey());
            return true;
        } catch (CertificateException | InvalidKeyException | SignatureException e) {
            System.out.println("Failed to verify client certificate due to invalid certificate data.");
            return false;
        } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
            System.out.println("Failed to verify client certificate due to incorrect algorithm or provider.");
            return false;
        }
    }


    public String[] validateDHSignatureAndChain(JSONObject jsonObject) throws NodeProcessException{
        String[] result = new String[2];
        try {
            String header = jsonObject.getString("header");
            String payload = jsonObject.getString("payload");
            String signature = jsonObject.getString("signature");

            // Decode URL safe base64 encoded String
            String raw_payload = null;
            String raw_header = null ;
			
				raw_payload = new String(Base64.decodeBase64(payload));
				raw_header = new String(Base64.decodeBase64	(header));
            System.out.println("payload data is " + raw_payload);
            JSONObject headerJsonObject = new JSONObject(raw_header);

            String sigAlg = headerJsonObject.getString("alg");
            JSONArray certArray = headerJsonObject.getJSONArray("x5c");
            String certString = null;
            if (certArray != null && certArray.length() > 0) {
                certString = certArray.getString(0);// as we know we have added only one cert.
            } else {
                throw new NodeProcessException("certArray is null");
            }
            CertificateFactory factory = CertificateFactory.getInstance("X.509");
            byte[] decoded = Base64.decodeBase64(certString);
		
            X509Certificate certificate = (X509Certificate) factory.generateCertificate(new ByteArrayInputStream(decoded));
            PublicKey pubKey = certificate.getPublicKey();
            // 1. Verify signature
            String tbs = header + "." + payload;
            byte[] sigBytes = Base64.decodeBase64(signature);
			
            String jcaSigAlg = mapJwaToJcaSignatureAlgorithm(sigAlg);
            Signature sig = Signature.getInstance(jcaSigAlg);
            sig.initVerify(pubKey);
            sig.update(tbs.getBytes());
            if (!sig.verify(sigBytes)) {
                result[0] = "signature verification failed";
                System.out.println("signature verification failed throw an exception");
            } else {
                result[0] = "signature verification  is successful";
                System.out.println("signature verification  is successful");
            }

            ByteArrayInputStream bis = new ByteArrayInputStream(VIP_PROD_ICA_ECC.getBytes());
            if (!isChainedToCA(certificate, (X509Certificate) factory.generateCertificate(bis))) {
                result[1] = "The certificate chaining Check has been failed";
                System.out.println("The certificate is not chained to the trusted VIP CA failed");
            } else {
                result[1] = "The certificate is chained to the trusted VIP CA.";
                System.out.println("The certificate is chained to the trusted VIP CA.");
            }

        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
            System.out.println("signature verification failed with an exception");
            e.printStackTrace();
            throw new NodeProcessException(e.getLocalizedMessage());
        } catch (CertificateException exp) {
            exp.printStackTrace();
            throw new NodeProcessException(exp.getLocalizedMessage());
        } catch (JSONException exp) {
            exp.printStackTrace();
            throw new NodeProcessException(exp.getLocalizedMessage());
        }

        return result;
    }

}

