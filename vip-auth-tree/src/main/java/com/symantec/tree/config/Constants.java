package com.symantec.tree.config;

/**
 * 
 * @author Sacumen(www.sacumen.com)
 * 
 *         Constants class which defines constants field which will be used
 *         through out the application
 *
 */
public final class Constants {

	private Constants() {
	}

	public static final String CRED_CHOICE = "SelectedValue";
	public static final String CRED_ID = "CredentialID";
	public static final String SECURE_CODE = "SecurityCode";
	public static final String TXN_ID = "TransactionID";
	public static final String MOB_NUM = "Mobile Number";
	public static final String CONFIRM_CRED_CHOICE = " Cred Choice";
	public static final String PUSH_ERROR = "Push Auth Error";
	public static final String CREDENTIAL_ID_ERROR = "Credential Id Error";
	public static final String OTP_ERROR = "Invalid OTP";
	public static final String DISPLAY_ERROR = "Failure Error";
	public static final String PHONE_NUMBER_ERROR = "Invalid Phone Number";
	public static final String KEY_STORE_PATH = "key_store_path";
	public static final String KEY_STORE_PASS = "key_store_pass";
	public static final String AUTHENTICATION_SERVICE_URL = "Authentication_Service_URL";
	public static final String QUERY_SERVICE_URL = "Query_Service_URL";
	public static final String MANAGEMENT_SERVICE_URL = "Management_Service_URL";
	public static final String SDK_SERVICE_URL = "Sdk Service URL";
	public static final String PUSH_DISPLAY_MESSAGE_TEXT = "push_display_message_text";
	public static final String PUSH_DISPLAY_MESSAGE_TITLE = "push_display_message_title";
	public static final String PUSH_DISPLAY_MESSAGE_PROFILE = "push_display_message_profile";

	public static final String STANDARD_OTP = "STANDARD_OTP";
	public static final String ACTIVATION_CODE = "ACTIVATION CODE";

	public static final String NO_CREDENTIALS_REGISTERED = "NoCredentialRegistered";

	public static final String NO_CRED_REGISTERED = "NO_CRED_REGISTERED";
	public static final String VIP_CRED_REGISTERED = "VIP_CRED_REGISTERED";

	public static final String VIP = "VIP";
	public static final String SMS = "SMS";
	public static final String VOICE = "VOICE";
	public static final String SMS_OTP = "SMS_OTP";
	public static final String VOICE_OTP = "VOICE_OTP";
	public static final String SUCCESS_CODE = "0000";
	public static final String USER_DOES_NOT_EXIST = "6003";
	public static final String INVALID_CREDENIALS = "6004";
	public static final String INVALID_PHONE_NUMBER = "6015";
	public static final String SCHEMA_INVALID = "600B";
	public static final String AUTHENTICATION_FAILED = "6009";
	public static final String CREDENTIALS_ALREADY_REGISTERED = "6026";

	/**
	 * 
	 * Status Code for VIP Auth
	 *
	 */
	public final class VIPAuthStatusCode {
		public VIPAuthStatusCode() {
		}

		public static final String SUCCESS_CODE = "6040";
	}

	/**
	 * 
	 * Status codes for VIP SDK
	 *
	 */
	public final class VIPSDKStatusCode {
		public VIPSDKStatusCode() {
		}

		public static final String SUCCESS_CODE = "0000";
	}

	/**
	 * 
	 * Status code for VIP Poll Push Request
	 *
	 */
	public final class VIPPollPush {
		public VIPPollPush() {
		}

		public static final String ACCEPTED = "7000";
		public static final String UNANSWERED = "7001";
		public static final String REJECTED = "7002";
	}

	/**
	 * 
	 * Constants related to VIP IA Flow.
	 *
	 */
	public final class VIPIA {
		public VIPIA() {
		}

		public static final String AUTH_DATA = "AI_Data";
		public static final String MOBILE_AUTH_DATA = "Mobile_AI_Data";
		public static final String EVENT_ID = "EventId";
		public static final String DEVICE_TAG = "DeviceTag";
		public static final String SCORE = "score";
		public static final String REGISTERED = "0000";
		public static final String NOT_REGISTERED = "6009";
		public static final String DEVICE_FINGERPRINT = "deviceFingerprint";
		public static final String DEVICE_FRIENDLY_NAME = "IA_New";
		public static final String TEST_AGENT = "TestAgent";
		public static final String SCRIPT_URL = "sript";

		public static final String DISABLE_LOGIN_BUTTON_SCRIPT = "document.getElementById('loginButton_0').click();";

	}

	/**
	 * 
	 * Constants related to VIP DR Flow.
	 *
	 */
	public final class VIPDR {
		private VIPDR() {

		}

		public static final String VIP_DR_DATA_PAYLOAD = "VIP_DR_Data_Payload";
		public static final String VIP_DR_DATA_HEADER = "VIP_DR_Data_Header";
		public static final String VIP_DR_DATA_SIGNATURE = "VIP_DR_Data_Signature";
		public static final String VIP_DR_CERT_KEY = "Cert_Key";
		public static final String DEVICE_HYGIENE_VERIFICATION_SUCCESS_MSG = "signature verification  is successful";
		public static final String DEVICE_HYGIENE_VERIFICATION_WITH_VIP_SUCCESS_MSG = "The certificate is chained to the trusted VIP CA.";
		public static final String DEVICE_HYGIENE_VERIFICATION_FAILURE_MSG = "signature verification failed";
		public static final String DEVICE_HYGIENE_VERIFICATION_WITH_VIP_FAILURE_MSG = "The certificate chaining Check has been failed";

	}

}
