package com.symantec.tree.request.util;

import java.io.IOException;
import java.io.StringReader;
import java.util.Random;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.apache.commons.io.IOUtils;
import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.forgerock.openam.auth.node.api.NodeProcessException;
import org.w3c.dom.Document;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

import com.sun.identity.shared.debug.Debug;

/**
 * 
 * @author Sacumen (www.sacumen.com)
 * Executing Confirm Risk request
 *
 */
public class ConfirmRisk {
	private final Debug debug = Debug.getInstance("VIP");
		
	/**
	 * 
	 * @param userName UserId
	 * @param eventID  Event Id evaluated from Evaluate Risk API.
	 * @param key_store keystore.ks file location
	 * @param key_store_pass keystore.ks file password
	 * @return status of Confirm Risk request response
	 * @throws NodeProcessException
	 */
	public String confirmRisk(String userName,String eventID,String key_store,String key_store_pass) throws NodeProcessException {
		String payLoad = getPayload(userName,eventID);
		debug.message("Confirm Risk Request Payload: " + payLoad);
		
		Document doc = HttpClientUtil.getInstance().executeRequst(getURL(), payLoad);

		String status;
		
		status = doc.getElementsByTagName("status").item(0).getTextContent();
					
	    debug.message("Confirm Risk request response code is "+status);
		return status;
	}
	
	/**
	 * 
	 * @param userName UserId
	 * @param eventID Event Id evaluated from Evaluate Risk API.
	 * @return Confirm Risk request payload
	 */
	private String getPayload(String userName,String eventID) {
		debug.message("getting payload for Confirm Risk");
		return "<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" "
		       + "xmlns:vip=\"https://schemas.symantec.com/vip/2011/04/vipuserservices\">" + "<soapenv:Header/>"
		       + "<soapenv:Body>" + "<vip:ConfirmRiskRequest>" + "<vip:requestId>" + new Random().nextInt(10) + 11111
		       + "</vip:requestId>" + "<vip:UserId>" + userName + "</vip:UserId>"
		       + "<vip:EventId>" + eventID + "</vip:EventId>"
		       + "</vip:ConfirmRiskRequest>" + "</soapenv:Body>"
		       + "</soapenv:Envelope>";

	}
	
	/**
	 * 
	 * @return AuthenticationServiceURL
	 */
	private String getURL() {
		return GetVIPServiceURL.serviceUrls.get("AuthenticationServiceURL");
	}
}
