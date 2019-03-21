package com.symantec.tree.request.util;

import java.io.FileNotFoundException;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import javax.net.ssl.SSLContext;
import org.apache.http.client.HttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.ssl.SSLContexts;
import org.forgerock.openam.auth.node.api.NodeProcessException;
import org.forgerock.openam.utils.AMKeyProvider;
import org.forgerock.security.keystore.KeyStoreBuilder;

import com.sun.identity.shared.debug.Debug;

/**
 * 
 * @author Sacumen (www.sacumen.com) <br> <br>
 * Utility class to read key-store values to authenticate vip requests.
 *
 */
public class HttpClientUtil {

	private final Debug debug = Debug.getInstance("VIP");
	private static HttpClientUtil httpClientUtil = null;
	
	private HttpClientUtil() {}
	
	public static HttpClientUtil getInstance(){
	    if(httpClientUtil==null) {
			httpClientUtil = new HttpClientUtil();
		}
		return httpClientUtil;
	}
	
	/**
	 * This method is used to get key store values form forgerock configurations
	 * @return httpClient
	 * @throws NodeProcessException 
	 * @throws FileNotFoundException
	 * @throws KeyStoreException 
	 * @throws NoSuchAlgorithmException 
	 * @throws UnrecoverableKeyException 
	 * @throws KeyManagementException 
	 */
	
	public HttpClient getHttpClientForgerock(String keyStoreFile,String keyStorePass) throws NodeProcessException, FileNotFoundException {
<<<<<<< HEAD
		debug.message("getting http client");
		HttpClient httpClient = null;
=======
		logger.info("getting http client");
		HttpClient httpClient;
>>>>>>> remotes/origin/no_sdk_frank_changes

		AMKeyProvider AM = new AMKeyProvider(false,keyStoreFile, keyStorePass,"JKS", null);
	
		final KeyStore keyStore = new KeyStoreBuilder().withKeyStoreFile(AM.getKeystoreFilePath())
				.withPassword(AM.getKeystorePass()).withKeyStoreType(AM.getKeystoreType()).build();

		try {

			SSLContext sslContext = SSLContexts.custom().loadKeyMaterial(keyStore, AM.getKeystorePass()).build();
			httpClient = HttpClients.custom().setSSLContext(sslContext).build();
		} catch (KeyStoreException |NoSuchAlgorithmException |KeyManagementException|UnrecoverableKeyException e) {
		   throw new NodeProcessException(e);
		}

		return httpClient;
	}
}
