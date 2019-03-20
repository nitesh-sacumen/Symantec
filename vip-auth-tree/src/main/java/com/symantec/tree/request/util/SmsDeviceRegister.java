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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

/**
 * 
 * @author Sacumen (www.sacumen.com) <br> <br>
 * @Description Executing SendOtpRequest
 *
 */
public class SmsDeviceRegister {

	static Logger logger = LoggerFactory.getLogger(SmsDeviceRegister.class);

	/**
	 * 
	 * @param userName
	 * @param credValue
	 * @return true if success, else false
	 * @throws NodeProcessException
	 */
	public Boolean smsDeviceRegister(String userName, String credValue,String key_store,String key_store_pass) throws NodeProcessException {
		//TODO Duplicate code

		HttpPost post = new HttpPost(getURL());

		post.setHeader("CONTENT-TYPE", "text/xml; charset=ISO-8859-1");
		String payLoad = getViewUserPayload(userName, credValue);
		logger.debug("Request Payload: " + payLoad);
		String statusMessage;
		try {
			HttpClient httpClient = HttpClientUtil.getInstance().getHttpClientForgerock(key_store,key_store_pass);
			post.setEntity(new StringEntity(payLoad));

			HttpResponse response = httpClient.execute(post);
			HttpEntity entity = response.getEntity();
			String body = IOUtils.toString(entity.getContent());
			DocumentBuilder builder = DocumentBuilderFactory.newInstance().newDocumentBuilder();
			InputSource src = new InputSource();
			src.setCharacterStream(new StringReader(body));
			Document doc = builder.parse(src);
			statusMessage = doc.getElementsByTagName("statusMessage").item(0).getTextContent();
		} catch (IOException | ParserConfigurationException | SAXException e) {
			throw new NodeProcessException(e);
		}
		if ("success".equalsIgnoreCase(statusMessage)) {
			return true;

		}
		return false;
	}

	/**
	 * 
	 * @param userName
	 * @param credValue
	 * @return SendOtpRequest payoad
	 */
	private static String getViewUserPayload(String userName, String credValue) {
		logger.info("getting SendOtpRequest payload");
		return "<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" "
				+ "xmlns:vip=\"https://schemas.symantec.com/vip/2011/04/vipuserservices\">" + "<soapenv:Header/>"
				+ "<soapenv:Body>" + "<vip:SendOtpRequest>" + "<vip:requestId>" + new Random().nextInt(10) + 11111
				+ "</vip:requestId>" + "" + "<vip:userId>" + userName + "</vip:userId>" + "" + "<vip:smsDeliveryInfo>"
				+ "<vip:phoneNumber>" + credValue + "</vip:phoneNumber>" + "" + "</vip:smsDeliveryInfo>" + ""
				+ "</vip:SendOtpRequest>" + "</soapenv:Body>" + "</soapenv:Envelope>";

	}

	private String getURL() {
		return GetVIPServiceURL.serviceUrls.get("ManagementServiceURL");
	}

}
