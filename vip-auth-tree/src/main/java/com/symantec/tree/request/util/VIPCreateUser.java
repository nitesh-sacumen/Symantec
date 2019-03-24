package com.symantec.tree.request.util;

import org.apache.commons.io.IOUtils;
import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.InputStreamEntity;
import org.forgerock.openam.auth.node.api.NodeProcessException;
import org.w3c.dom.Document;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

import com.sun.identity.shared.debug.Debug;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringReader;


import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

/**
 * 
 * @author Sacumen (www.sacumen.com) <br> <br>
 * Create user if not exist.
 *
 */
public class VIPCreateUser {

	private final Debug debug = Debug.getInstance("VIP");

	/**
	 * 
	 * @param userId
	 * @return CreateUserRequest payload
	 */
	private String createUserPayload(String userId) {
		debug.message("getting CreateUserRequest payload");
		return "<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" " +
				"xmlns:vip=\"https://schemas.symantec.com/vip/2011/04/vipuserservices\">" +
				"   <soapenv:Header/>" +
				"   <soapenv:Body>" +
				"      <vip:CreateUserRequest>" +
				"               <vip:requestId>" + Math.round(Math.random() * 100000) + "</vip:requestId>" +
				"             <vip:userId>" + userId + "</vip:userId>" +
				"      </vip:CreateUserRequest>" +
				"   </soapenv:Body>" +
				"</soapenv:Envelope>";
	}

	/**
	 * 
	 * @param userId
	 * @return true id user is create, else false
	 * @throws NodeProcessException 
	 * 
	 */
	public boolean createVIPUser(String userId,String key_store,String key_store_pass) throws NodeProcessException {
		    boolean isUserExisted = false;

			String userPayload = createUserPayload(userId);
			Document doc = HttpClientUtil.getInstance().executeRequst(getURL(), userPayload);

			String statusMessage;
			
			statusMessage = doc.getElementsByTagName("statusMessage").item(0).getTextContent();
			
			if ("Success".equals(statusMessage)) {
				isUserExisted = true;
			}

		return isUserExisted;
	}

	/**
	 * 
	 * @return ManagementServiceURL
	 */
	private String getURL() {
		return GetVIPServiceURL.serviceUrls.get("ManagementServiceURL");
	}
}
