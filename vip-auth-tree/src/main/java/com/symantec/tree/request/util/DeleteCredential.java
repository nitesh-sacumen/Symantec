package com.symantec.tree.request.util;


import org.forgerock.openam.auth.node.api.NodeProcessException;
import org.w3c.dom.Document;
import org.slf4j.Logger;import org.slf4j.LoggerFactory;


/**
 * 
 * @author Sacumen(www.sacumen.com) <br> <br> 
 * @Description Deleting credential id , which is associated with user using
 *         RemoveCredentialRequest
 *
 */
public class DeleteCredential {
private Logger logger = LoggerFactory.getLogger(DeleteCredential.class);

	/**
	 * 
	 * @param userName
	 * @param credId
	 * @param credType
	 * @throws NodeProcessException
	 */
	public void deleteCredential(String userName, String credId, String credType,String key_store,String key_store_pass) throws NodeProcessException {
		String payLoad = getRemoveCredPayload(userName, credId, credType);
		
		logger.info("Request payload is "+payLoad);

		Document doc = HttpClientUtil.getInstance().executeRequst(getURL(), payLoad);
		
		String status = doc.getElementsByTagName("status").item(0).getTextContent();
		
		logger.debug("status of delete cred request response is "+status);
	    
	}

	/**
	 * 
	 * @param userId
	 * @param credId
	 * @param credType
	 * @return RemoveCredentialRequest payload
	 */
	private String getRemoveCredPayload(String userId, String credId, String credType) {
		return "<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" "
				+ "xmlns:vip=\"https://schemas.symantec.com/vip/2011/04/vipuserservices\">" + "   <soapenv:Header/>"
				+ "   <soapenv:Body>" + "      <vip:RemoveCredentialRequest>" + "<vip:requestId>"
				+ Math.round(Math.random() * 100000) + "</vip:requestId>" + "         <vip:userId>" + userId
				+ "</vip:userId>" + "         <vip:credentialId>" + credId + "</vip:credentialId>"
				+ "          <vip:credentialType>" + credType + "</vip:credentialType>      "
				+ "      </vip:RemoveCredentialRequest>" + "   </soapenv:Body>" + "</soapenv:Envelope>";

	}

	/**
	 * 
	 * @return ManagementServiceURL
	 * @throws NodeProcessException 
	 */
	private String getURL() throws NodeProcessException {
		return GetVIPServiceURL.serviceUrls.get("ManagementServiceURL");
	}

}
