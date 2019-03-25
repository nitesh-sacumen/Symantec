package com.symantec.tree.request.util;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.StringReader;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import javax.net.ssl.SSLContext;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.apache.commons.io.IOUtils;
import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.ssl.SSLContexts;
import org.forgerock.openam.auth.node.api.NodeProcessException;
import org.forgerock.openam.utils.AMKeyProvider;
import org.forgerock.security.keystore.KeyStoreBuilder;
import org.w3c.dom.Document;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * 
 * @author Sacumen (www.sacumen.com) <br>
 *         <br>
 *         Utility class to read key-store values to authenticate vip requests.
 *
 */
public class HttpClientUtil {

	private static HttpClientUtil httpClientUtil = null;
	private Logger logger = LoggerFactory.getLogger(HttpClientUtil.class);

	private HttpClientUtil() {
	}

	public static HttpClientUtil getInstance() {
		if (httpClientUtil == null) {
			httpClientUtil = new HttpClientUtil();
		}
		return httpClientUtil;
	}

	/**
	 * This method is used to get key store values form forgerock configurations
	 * 
	 * @return httpClient
	 * @throws NodeProcessException
	 * @throws FileNotFoundException
	 * @throws KeyStoreException
	 * @throws NoSuchAlgorithmException
	 * @throws UnrecoverableKeyException
	 * @throws KeyManagementException
	 */

	private HttpClient getHttpClientForgerock(String keyStoreFile, String keyStorePass)
			throws NodeProcessException, FileNotFoundException {
		logger.info("getting http client");
		HttpClient httpClient;

		AMKeyProvider AM = new AMKeyProvider(false, keyStoreFile, keyStorePass, "JKS", null);

		final KeyStore keyStore = new KeyStoreBuilder().withKeyStoreFile(AM.getKeystoreFilePath())
				.withPassword(AM.getKeystorePass()).withKeyStoreType(AM.getKeystoreType()).build();

		try {

			SSLContext sslContext = SSLContexts.custom().loadKeyMaterial(keyStore, AM.getKeystorePass()).build();
			httpClient = HttpClients.custom().setSSLContext(sslContext).build();
		} catch (KeyStoreException | NoSuchAlgorithmException | KeyManagementException | UnrecoverableKeyException e) {

			logger.error(e.getLocalizedMessage());
			throw new NodeProcessException(e);
		}

		return httpClient;
	}

	public Document executeRequst(String url, String payload) throws NodeProcessException {
		Document doc;
		GetVIPServiceURL vip = GetVIPServiceURL.getInstance();

		HttpPost post = new HttpPost(url);
		post.setHeader("CONTENT-TYPE", "text/xml; charset=ISO-8859-1");
		try {
			HttpClient httpClient = getHttpClientForgerock(vip.getKeyStorePath(), vip.getKeyStorePasswod());
			post.setEntity(new StringEntity(payload));
			HttpResponse response = httpClient.execute(post);
			HttpEntity entity = response.getEntity();
			String body = IOUtils.toString(entity.getContent());

			logger.debug("Response body is " + body);

			DocumentBuilder builder = DocumentBuilderFactory.newInstance().newDocumentBuilder();
			InputSource src = new InputSource();
			src.setCharacterStream(new StringReader(body));
			doc = builder.parse(src);
		} catch (IOException | ParserConfigurationException | SAXException e) {
			logger.error("Not able to process request successfully");
			throw new NodeProcessException(e);
		}

		return doc;
	}

}
