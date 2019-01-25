package com.symantec.tree.nodes;

import static com.symantec.tree.config.Constants.*;

import java.util.List;
import java.util.ResourceBundle;
import com.symantec.tree.request.util.AddCredential;
import javax.inject.Inject;

import org.forgerock.guava.common.collect.ImmutableList;
import org.forgerock.json.JsonValue;
import org.forgerock.openam.auth.node.api.*;
import org.forgerock.openam.auth.node.api.Action.ActionBuilder;
import org.forgerock.util.i18n.PreferredLocales;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * 
 * @author Sacumen(www.sacumen.com) <br> <br>
 * @category Node
 * @Descrition "VIP AddCred with VerifyCode" node with TRUE,FALSE and ERROR outcome. If
 *             TRUE, it will go to "VIP Add More Creds". If False, go to "VIP
 *             Enter SecurityCode/OTP" and if ERROR, go to "VIP Display Error".
 *
 */
@Node.Metadata(outcomeProvider = VIPVerifyCodeAddCredential.SymantecOutcomeProvider.class, configClass = VIPVerifyCodeAddCredential.Config.class)
public class VIPVerifyCodeAddCredential implements Node {

	static Logger logger = LoggerFactory.getLogger(VIPVerifyCodeAddCredential.class);
	private static final String BUNDLE = "com/symantec/tree/nodes/VIPVerifyCodeAddCredential";

	private AddCredential addCred;
	static int counter=0;

	/**
	 * Configuration for the node.
	 */
	public interface Config {

	}

	/**
	 * Create the node.
	 *
	 */
	@Inject
	public VIPVerifyCodeAddCredential() {
		addCred = new AddCredential();
	}

	/**
	 * Main logic of the node.
	 * @throws NodeProcessException 
	 */
	@Override
	public Action process(TreeContext context) throws NodeProcessException {
		context.sharedState.remove(OTP_ERROR);
		String userName = context.sharedState.get(SharedStateConstants.USERNAME).asString();
		String credValue = context.sharedState.get(CRED_ID).asString();
		String credPhoneNumber = context.sharedState.get(MOB_NUM).asString();
		String otpReceived = context.sharedState.get(SECURE_CODE).asString();
		String key_store = context.sharedState.get(KEY_STORE_PATH).asString();
		String key_store_pass = context.sharedState.get(KEY_STORE_PASS).asString();
		logger.debug("Secure code" + otpReceived);
		String credIdType;
		if (context.sharedState.get(CRED_CHOICE).asString().equalsIgnoreCase(SMS)) {
			credIdType = SMS_OTP;
			String statusCode = addCred.addCredential(userName, credPhoneNumber, credIdType, otpReceived,
					key_store,key_store_pass);
			return sendOutput(statusCode, context);
		} else if (context.sharedState.get(CRED_CHOICE).asString().equalsIgnoreCase(VOICE)) {
			credIdType = VOICE_OTP;
			String statusCode = addCred.addCredential(userName, credPhoneNumber, credIdType, otpReceived,
					key_store,key_store_pass);
			return sendOutput(statusCode, context);
		} else {
			credIdType = STANDARD_OTP;
			String statusCode = addCred.addCredential(userName, credValue, credIdType, otpReceived,key_store,key_store_pass);
			return sendOutput(statusCode, context);
		}
	}
	
	/**
	 * The possible outcomes for the DisplayCredentail.
	 */
	private enum Symantec {
		/**
		 * Successful.
		 */
		TRUE,
		/**
		 * failed.
		 */
		FALSE,
		/**
		 * Disabled.
		 */
		ERROR

	}
	
	private ActionBuilder goTo(Symantec outcome) {
		return Action.goTo(outcome.name());
	}
	
	/**
	 * Defines the possible outcomes from this SymantecOutcomeProvider node.
	 */
	public static class SymantecOutcomeProvider implements OutcomeProvider {
		@Override
		public List<Outcome> getOutcomes(PreferredLocales locales, JsonValue nodeAttributes) {
			ResourceBundle bundle = locales.getBundleInPreferredLocale(VIPVerifyCodeAddCredential.BUNDLE,
					SymantecOutcomeProvider.class.getClassLoader());
			return ImmutableList.of(new Outcome(Symantec.TRUE.name(), bundle.getString("trueOutcome")),
					new Outcome(Symantec.FALSE.name(), bundle.getString("falseOutcome")),
					new Outcome(Symantec.ERROR.name(), bundle.getString("errorOutcome")));
		}
	}

	/**
	 * 
	 * @param statusCode
	 * @param context
	 * @return Action Object
	 */
	private Action sendOutput(String statusCode, TreeContext context) {
		if (statusCode.equalsIgnoreCase(SUCCESS_CODE)) {
			return goTo(Symantec.TRUE).build();
		} else if(statusCode.equalsIgnoreCase(INVALID_CREDENIALS) || statusCode.equalsIgnoreCase(AUTHENTICATION_FAILED)) {
				context.sharedState.put(OTP_ERROR, "Entered otp Code is Invalid,Please enter valid OTP");
				return goTo(Symantec.FALSE).build();
		}
		else {
			context.sharedState.put(DISPLAY_ERROR, "Your Credentials is disabled, Please contact your administrator.");
			return goTo(Symantec.ERROR).build();
		}
	}

}
