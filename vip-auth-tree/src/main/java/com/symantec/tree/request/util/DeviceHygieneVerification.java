package com.symantec.tree.request.util;

import org.apache.commons.codec.binary.Base64;
import org.forgerock.openam.auth.node.api.NodeProcessException;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import org.slf4j.Logger;import org.slf4j.LoggerFactory;
import com.symantec.tree.config.Constants.VIPDR;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.cert.CertificateException;
import java.security.*;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

/**
 * 
 * @author Sacumen (www.sacumen.com)
 * 
 * It verifies Device hygiene against trusted VIP CA Certificate.
 *
 */
public class DeviceHygieneVerification {
	
private Logger logger = LoggerFactory.getLogger(DeviceHygieneVerification.class);


	private String mapJwaToJcaSignatureAlgorithm(String jwtSigAlg) {
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
			logger.debug("Failed to verify client certificate due to invalid certificate data.");
			return false;
		} catch (NoSuchAlgorithmException | NoSuchProviderException e) {
			logger.debug("Failed to verify client certificate due to incorrect algorithm or provider.");
			return false;
		}
	}


	// Validating Device Hygiene 
	public String[] validateDHSignatureAndChain(String header, String payload, String signature)
			throws NodeProcessException{
		String[] result = new String[2];
		try {

			// Decode URL safe base64 encoded String
			String raw_payload;
			String raw_header;

			raw_payload = new String(Base64.decodeBase64(payload));
			raw_header = new String(Base64.decodeBase64(header));
			logger.debug("payload data is " + raw_payload);
			JSONObject headerJsonObject = new JSONObject(raw_header);

			String sigAlg = headerJsonObject.getString("alg");
			JSONArray certArray = headerJsonObject.getJSONArray("x5c");
			String certString;
			if (certArray != null && certArray.length() > 0) {
				certString = certArray.getString(0);// as we know we have added only one cert.
			} else {
				throw new NodeProcessException("certArray is null");
			}
			CertificateFactory factory = CertificateFactory.getInstance("X.509");
			byte[] decoded = Base64.decodeBase64(certString);

			X509Certificate certificate = (X509Certificate) factory
					.generateCertificate(new ByteArrayInputStream(decoded));
			PublicKey pubKey = certificate.getPublicKey();
			// 1. Verify signature
			String tbs = header + "." + payload;
			byte[] sigBytes = Base64.decodeBase64(signature);

			String jcaSigAlg = mapJwaToJcaSignatureAlgorithm(sigAlg);
			Signature sig = Signature.getInstance(jcaSigAlg);
			sig.initVerify(pubKey);
			sig.update(tbs.getBytes());
			if (!sig.verify(sigBytes)) {
				result[0] = VIPDR.DEVICE_HYGIENE_VERIFICATION_FAILURE_MSG;
				logger.error("device verification failed");

			} else {
				result[0] = VIPDR.DEVICE_HYGIENE_VERIFICATION_SUCCESS_MSG;
				logger.info("Device verification successful");

			}

			File f = new File(
					"C:\\prod-hsm-device-ica-ecc-262151-cert-by-offline-root-SymantecCorporationAuthenticationECCRootCA.pem");
			FileInputStream fis;
			byte[] keyBytes;

			try {
				fis = new FileInputStream(f);
				DataInputStream dis = new DataInputStream(fis);
				keyBytes = new byte[(int) f.length()];

				dis.readFully(keyBytes);
				dis.close();

			} catch (IOException e) {
				e.printStackTrace();
				throw new NodeProcessException(e.getLocalizedMessage());
			}
			String temp = new String(keyBytes);

			ByteArrayInputStream bis = new ByteArrayInputStream(temp.getBytes());
			if (!isChainedToCA(certificate, (X509Certificate) factory.generateCertificate(bis))) {
				result[1] = VIPDR.DEVICE_HYGIENE_VERIFICATION_WITH_VIP_FAILURE_MSG;
				logger.error("The certificate is not chained to the trusted VIP CA.");

			} else {
				result[1] = VIPDR.DEVICE_HYGIENE_VERIFICATION_WITH_VIP_SUCCESS_MSG;
				logger.info("The certificate is chained to the trusted VIP CA.");
			}

		} catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
			logger.error("signature verification failed with an exception");
			
			e.printStackTrace();
			throw new NodeProcessException(e.getLocalizedMessage());
		} catch (CertificateException | JSONException exp) {
			logger.error("signature verification failed with an exception");

			exp.printStackTrace();
			throw new NodeProcessException(exp.getLocalizedMessage());
		}

		return result;
	}

}
