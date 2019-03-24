package com.symantec.tree.request.util;

import static com.symantec.tree.config.Constants.AUTHENTICATION_SERVICE_URL;
import static com.symantec.tree.config.Constants.MANAGEMENT_SERVICE_URL;
import static com.symantec.tree.config.Constants.QUERY_SERVICE_URL;
import static com.symantec.tree.config.Constants.SDK_SERVICE_URL;

import org.forgerock.openam.auth.node.api.TreeContext;

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
		serviceUrls.put("ManagementServiceURL",managementServiceURL);
		serviceUrls.put("AuthenticationServiceURL",authenticationServiceURL);
		serviceUrls.put("QueryServiceURL", queryServiceURL);
		serviceUrls.put("SDKServiceURL", SDKServiceURL);

	}
}
