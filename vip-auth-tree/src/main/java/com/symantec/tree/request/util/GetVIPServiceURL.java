package com.symantec.tree.request.util;

import java.util.Hashtable;

import org.forgerock.openam.auth.node.api.NodeProcessException;
import org.forgerock.openam.auth.node.api.TreeContext;
import static com.symantec.tree.config.Constants.*;
/**
 * 
 * @author Sacumen (www.sacumen.com) <br> <br>
 * @Description  Getting Service URL for Authentications
 *
 */
public class GetVIPServiceURL {
	private static GetVIPServiceURL getVIPServiceUrl = null;
	final static Hashtable<String,String> serviceUrls = new Hashtable<>();
	
	private GetVIPServiceURL(){
	}
	
	public static GetVIPServiceURL getInstance() throws NodeProcessException{
		if(getVIPServiceUrl==null) {
			getVIPServiceUrl = new GetVIPServiceURL();
		}
		return getVIPServiceUrl;
	}
	
	public void setServiceURL(TreeContext context) {
		serviceUrls.put("ManagementServiceURL",context.sharedState.get(MANAGEMENT_SERVICE_URL).asString());
		serviceUrls.put("AuthenticationServiceURL",context.sharedState.get(AUTHENTICATION_SERVICE_URL).asString());
		serviceUrls.put("QueryServiceURL", context.sharedState.get(QUERY_SERVICE_URL).asString());
		serviceUrls.put("SDKServiceURL", context.sharedState.get(SDK_SERVICE_URL).asString());

	}
}
