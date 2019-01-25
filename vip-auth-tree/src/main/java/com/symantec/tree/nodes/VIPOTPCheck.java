package com.symantec.tree.nodes;

import static com.symantec.tree.config.Constants.*;

import com.symantec.tree.request.util.CheckVIPOtp;
import java.util.List;
import java.util.ResourceBundle;
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
 * @Descrition "VIP Check Symantec OTP" node with TRUE,FALSE and ERROR outcome.
 *             If TRUE, it will go to "Success". If False, go to "VIP Enter SecurityCode/OTP". If Error, go to "Failure".
 *
 */
@Node.Metadata(outcomeProvider = VIPOTPCheck.SymantecOutcomeProvider.class, configClass = VIPOTPCheck.Config.class)
public class VIPOTPCheck implements Node {

	private static final String BUNDLE = "com/symantec/tree/nodes/VIPOTPCheck";
	private final Logger logger = LoggerFactory.getLogger(VIPOTPCheck.class);

	private CheckVIPOtp checkOtp;

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
	public VIPOTPCheck() {
		checkOtp = new CheckVIPOtp();
	}

	/**
	 * Main logic of the node.
	 * 
	 * @throws NodeProcessException
	 */
	@Override
	public Action process(TreeContext context) throws NodeProcessException {

		String userName = context.sharedState.get(SharedStateConstants.USERNAME).asString();
		String otpValue = context.sharedState.get(SECURE_CODE).asString();
		String key_store = context.sharedState.get(KEY_STORE_PATH).asString();
		String key_store_pass = context.sharedState.get(KEY_STORE_PASS).asString();
		String statusCode = checkOtp.checkOtp(userName, otpValue, key_store, key_store_pass);
		return sendOutput(statusCode, context);
	}

	private ActionBuilder goTo(Symantec outcome) {
		return Action.goTo(outcome.name());
	}

	/**
	 * The possible outcomes for the SymantecVerifyAuth.
	 */
	public enum Symantec {
		/**
		 * Successful authentication.
		 */
		TRUE,
		/**
		 * Authentication failed.
		 */
		FALSE,
		/**
		 * The user has not been answered.
		 */
		ERROR

	}

	/**
	 * Defines the possible outcomes from this SymantecOutcomeProvider node.
	 */
	public static class SymantecOutcomeProvider implements OutcomeProvider {
		@Override
		public List<Outcome> getOutcomes(PreferredLocales locales, JsonValue nodeAttributes) {
			ResourceBundle bundle = locales.getBundleInPreferredLocale(VIPOTPCheck.BUNDLE,
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
	 * @return Action Object.
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
