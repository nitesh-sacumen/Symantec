package com.symantec.tree.request.util;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Hashtable;
/**
 * 
 * @author Sacumen (www.sacumen.com) <br> <br>
 * @Description  Getting Service URL for Authentications
 *
 */
public class GetVIPServiceURL {
	private static GetVIPServiceURL getVIPServiceUrl = null;
	final static Hashtable<String,String> serviceUrls = new Hashtable<>();
	private Logger logger = LoggerFactory.getLogger(GetVIPServiceURL.class);

	private String keyStorePath;
	private String keyStorePasswod;
	private String userName;
	
	public String getKeyStorePath() {
		return keyStorePath;
	}

	public void setKeyStorePath(String keyStorePath) {
		this.keyStorePath = keyStorePath;
	}

	public String getKeyStorePasswod() {
		return keyStorePasswod;
	}

	public void setKeyStorePasswod(String keyStorePasswod) {
		this.keyStorePasswod = keyStorePasswod;
	}

	public String getUserName() {
		return userName;
	}

	public void setUserName(String userName) {
		this.userName = userName;
	}


	
	private GetVIPServiceURL(){
	}
	
	public static GetVIPServiceURL getInstance() {
		if(getVIPServiceUrl==null) {
			getVIPServiceUrl = new GetVIPServiceURL();
		}
		return getVIPServiceUrl;
	}
	
	public void setServiceURL(String managementServiceURL, String authenticationServiceURL, String queryServiceURL, String SDKServiceURL) {
		logger.debug("managementServiceURL is "+managementServiceURL);
		logger.debug("AuthenticationServiceURL is "+authenticationServiceURL);
        logger.debug("queryServiceURL is "+queryServiceURL);
        logger.debug("SDKServiceURL is "+SDKServiceURL);

		serviceUrls.put("ManagementServiceURL",managementServiceURL);
		serviceUrls.put("AuthenticationServiceURL",authenticationServiceURL);
		serviceUrls.put("QueryServiceURL", queryServiceURL);
		serviceUrls.put("SDKServiceURL", SDKServiceURL);

	}
}
