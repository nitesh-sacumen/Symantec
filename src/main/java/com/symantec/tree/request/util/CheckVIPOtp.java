package com.symantec.tree.request.util;

import static com.symantec.tree.config.Constants.AUTHENTICATION_FAILED;
import static com.symantec.tree.config.Constants.DISPLAY_ERROR;
import static com.symantec.tree.config.Constants.INVALID_CREDENIALS;
import static com.symantec.tree.config.Constants.OTP_ERROR;
import static com.symantec.tree.config.Constants.SUCCESS_CODE;

import java.util.Random;
import org.forgerock.openam.auth.node.api.Action;
import org.forgerock.openam.auth.node.api.NodeProcessException;
import org.forgerock.openam.auth.node.api.TreeContext;
import org.forgerock.openam.auth.node.api.Action.ActionBuilder;
import org.w3c.dom.Document;

import com.symantec.tree.nodes.VIPOTPCheck.Symantec;

import org.slf4j.Logger;import org.slf4j.LoggerFactory;

/**
 * 
 * @author Sacumen(www.sacumen.com) <br> <br>
 * @Description: Checking OTP with CheckOtpRequest.
 *
 */
public class CheckVIPOtp {

private Logger logger = LoggerFactory.getLogger(CheckVIPOtp.class);

	/**
	 * 
	 * @param userName
	 * @param otpValue
	 * @return status code of response
	 * @throws NodeProcessException
	 */
	public String checkOtp(String userName, String otpValue,String key_store,String key_store_pass) throws NodeProcessException {
        logger.info("Executing check OTP request");

		String payLoad = getViewUserPayload(userName, otpValue);
		
		Document doc = HttpClientUtil.getInstance().executeRequst(getURL(), payLoad);

		String status;
		logger.debug("Request Payload: " + payLoad);

		status = doc.getElementsByTagName("status").item(0).getTextContent();
		return status;

	}

	/**
	 * 
	 * @param userName
	 * @param otpValue
	 * @return CheckOtpRequest payload
	 */
	private String getViewUserPayload(String userName, String otpValue) {
		logger.info("getting CheckOtpRequest payload");
		return "<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" "
				+ "xmlns:vip=\"https://schemas.symantec.com/vip/2011/04/vipuserservices\">" + "   <soapenv:Header/>"
				+ "   <soapenv:Body>" + "      <vip:CheckOtpRequest>" + "<vip:requestId>" + new Random().nextInt(10)
				+ 11111 + "</vip:requestId>" + "<vip:userId>" + userName + "</vip:userId>"
				+ "         <vip:otpAuthData>" + "            <vip:otp>" + otpValue + "</vip:otp>           "
				+ "         </vip:otpAuthData>        " + "      </vip:CheckOtpRequest>" + "   </soapenv:Body>"
				+ "</soapenv:Envelope>";
	}

	/**
	 * 
	 * @return AuthenticationServiceURL
	 * @throws NodeProcessException 
	 */
	private String getURL() throws NodeProcessException {
		return GetVIPServiceURL.serviceUrls.get("AuthenticationServiceURL");
	}
	
	/**
	 * 
	 * @param statusCode
	 * @param context
	 * @return Action Object.
	 */
	public Action sendOutput(String statusCode, TreeContext context) {
		logger.info("Sending Output....");
		
		if (statusCode.equalsIgnoreCase(SUCCESS_CODE)) {
			return goTo(Symantec.TRUE).build();
		}
		
		else if(statusCode.equalsIgnoreCase(INVALID_CREDENIALS) || statusCode.equalsIgnoreCase(AUTHENTICATION_FAILED)) {
				context.sharedState.put(OTP_ERROR, "Entered otp Code is Invalid,Please enter valid OTP");
				return goTo(Symantec.FALSE).build();
		}
		
		else {
			context.sharedState.put(DISPLAY_ERROR, "Your Credentials is disabled, Please contact your administrator.");
			return goTo(Symantec.ERROR).build();
		}
	}
	
	private ActionBuilder goTo(Symantec outcome) {
		return Action.goTo(outcome.name());
	}
	
}