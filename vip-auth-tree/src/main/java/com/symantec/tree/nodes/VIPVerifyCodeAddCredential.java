package com.symantec.tree.nodes;

import static com.symantec.tree.config.Constants.*;

import java.util.List;
import java.util.ResourceBundle;
import com.symantec.tree.request.util.AddCredential;
import com.symantec.tree.request.util.CheckVIPOtp;
import com.symantec.tree.request.util.GetVIPServiceURL;

import javax.inject.Inject;
import com.google.common.collect.ImmutableList;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.forgerock.json.JsonValue;
import org.forgerock.openam.auth.node.api.*;
import org.forgerock.util.i18n.PreferredLocales;

/**
 * 
 * @author Sacumen(www.sacumen.com) <br>
 *         <br>
 * @category Node
 * @Descrition "VIP AddCred with VerifyCode" node with TRUE,FALSE and ERROR
 *             outcome. If TRUE, it will go to "VIP Add More Creds". If False,
 *             go to "VIP Enter SecurityCode/OTP" and if ERROR, go to "VIP
 *             Display Error".
 *
 */
@Node.Metadata(outcomeProvider = VIPVerifyCodeAddCredential.SymantecOutcomeProvider.class, configClass = VIPVerifyCodeAddCredential.Config.class)
public class VIPVerifyCodeAddCredential implements Node {

	private Logger logger = LoggerFactory.getLogger(VIPVerifyCodeAddCredential.class);
	private static final String BUNDLE = "com/symantec/tree/nodes/VIPVerifyCodeAddCredential";

	private AddCredential addCred;

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
	 * 
	 * @throws NodeProcessException
	 */
	@Override
	public Action process(TreeContext context) throws NodeProcessException {
		logger.info("VIP verify code");

		context.sharedState.remove(OTP_ERROR);
		String credValue = context.sharedState.get(CRED_ID).asString();
		String credPhoneNumber = context.sharedState.get(MOB_NUM).asString();
		String otpReceived = context.sharedState.get(SECURE_CODE).asString();

		GetVIPServiceURL vip = GetVIPServiceURL.getInstance();

		CheckVIPOtp checkOtp = new CheckVIPOtp();

		logger.debug("Secure code" + otpReceived);

		String credIdType;
		if (context.sharedState.get(CRED_CHOICE).asString().equalsIgnoreCase(SMS)) {
			credIdType = SMS_OTP;
			String statusCode = addCred.addCredential(vip.getUserName(), credPhoneNumber, credIdType, otpReceived,
					vip.getUserName(), vip.getKeyStorePasswod());
			logger.debug("statusCode of addCredential is " + statusCode);

			return checkOtp.sendOutput(statusCode, context);
		} else if (context.sharedState.get(CRED_CHOICE).asString().equalsIgnoreCase(VOICE)) {
			credIdType = VOICE_OTP;
			String statusCode = addCred.addCredential(vip.getUserName(), credPhoneNumber, credIdType, otpReceived,
					vip.getKeyStorePath(), vip.getKeyStorePasswod());
			logger.debug("statusCode of addCredential is " + statusCode);

			return checkOtp.sendOutput(statusCode, context);
		} else {
			credIdType = STANDARD_OTP;
			String statusCode = addCred.addCredential(vip.getUserName(), credValue, credIdType, otpReceived,
					vip.getKeyStorePath(), vip.getKeyStorePasswod());

			logger.debug("statusCode of addCredential is " + statusCode);

			return checkOtp.sendOutput(statusCode, context);
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


}
