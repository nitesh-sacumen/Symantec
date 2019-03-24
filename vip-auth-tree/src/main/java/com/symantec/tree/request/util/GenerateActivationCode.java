package com.symantec.tree.request.util;

import java.io.IOException;
import java.io.StringReader;

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
 * @author Sacumen(www.sacumen.com) <br>
 *         <br>
 * @Desription Getting activation code using GetActivationCode request
 *
 */
public class GenerateActivationCode {
	private final Debug debug = Debug.getInstance("VIP");

	/**
	 * 
	 * @return activation code with status
	 * @throws NodeProcessException
	 */
	public String generateCode(String key_store, String key_store_pass) throws NodeProcessException {
		String activationCode;
		String status;

		String payLoad = createPayload();
		debug.message("Request Payload: " + payLoad);

		Document doc = HttpClientUtil.getInstance().executeRequst(getURL(), payLoad);

		status = doc.getElementsByTagName("ReasonCode").item(0).getTextContent();
		if (doc.getElementsByTagName("ActivationCode").item(0) != null) {
			activationCode = doc.getElementsByTagName("ActivationCode").item(0).getTextContent();
		} else
			activationCode = " ";

		String code = status + "," + activationCode;
		debug.message("Status and TransactionId \t" + code);
		return code;
	}

	/**
	 * 
	 * @return GetActivationCode payload
	 */
	private String createPayload() {
//		logger.info("gtting GetActivationCode payload");
		return "<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:vip=\"http://www"
				+ ".verisign.com/2006/08/vipservice\">" + "   <soapenv:Header/>" + "   <soapenv:Body>"
				+ "      <vip:GetActivationCode Version=\"1.0\" Id=" + "\"" + Math.round(Math.random() * 100000) + "\">"
				+ "        <vip:ACProfile>" + "MOBILEPHONE" + "</vip:ACProfile>" + "      </vip:GetActivationCode>"
				+ "   </soapenv:Body>" + "</soapenv:Envelope>";

	}

	private String getURL() {
		return GetVIPServiceURL.serviceUrls.get("SDKServiceURL");
	}

}