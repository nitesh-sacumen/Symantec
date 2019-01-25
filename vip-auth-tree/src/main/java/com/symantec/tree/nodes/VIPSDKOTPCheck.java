package com.symantec.tree.nodes;

import static com.symantec.tree.config.Constants.*;

import com.google.inject.assistedinject.Assisted;
import com.symantec.tree.request.util.SDKCheckVIPOtp;

import java.util.List;
import java.util.ResourceBundle;
import javax.inject.Inject;
import org.forgerock.guava.common.collect.ImmutableList;
import org.forgerock.json.JsonValue;
import org.forgerock.openam.annotations.sm.Attribute;
import org.forgerock.openam.auth.node.api.*;
import org.forgerock.openam.auth.node.api.Action.ActionBuilder;
import org.forgerock.util.i18n.PreferredLocales;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * 
 * @author Symantec
 * @category Node
 * @Descrition "VIP SDK Check Symantec OTP" node with TRUE,FALSE and ERROR outcome.
 *
 */
@Node.Metadata(outcomeProvider = VIPSDKOTPCheck.SymantecOutcomeProvider.class, configClass = VIPSDKOTPCheck.Config.class)
public class VIPSDKOTPCheck implements Node {

	private static final String BUNDLE = "com/symantec/tree/nodes/VIPSDKOTPCheck";
	private final Logger logger = LoggerFactory.getLogger(VIPSDKOTPCheck.class);

	private SDKCheckVIPOtp checkOtp;
	private final Config config;


	/**
	 * Configuration for the node.
	 */
	public interface Config {
		@Attribute(order = 100, requiredValue = true)
		String Key_Store_Path();


		@Attribute(order = 200, requiredValue = true)
		String Key_Store_Password();
		
		@Attribute(order = 300, requiredValue = true)
		String Authentication_Service_URL();
	}

	/**
	 * Create the node.
	 *
	 */
	@Inject
	public VIPSDKOTPCheck(@Assisted Config config,SDKCheckVIPOtp checkOtp) {
		this.config = config;
		this.checkOtp = checkOtp;
	}

	/**
	 * Main logic of the node.
	 * @throws NodeProcessException 
	 */
	@Override
	public Action process(TreeContext context) throws NodeProcessException {
		String userName = context.sharedState.get(SharedStateConstants.USERNAME).asString();
		String otpValue = context.sharedState.get(SECURE_CODE).asString();
		System.out.println("otp value is "+otpValue);
		String statusCode = checkOtp.checkOtp(userName, otpValue,config.Key_Store_Path(),config.Key_Store_Password(),config.Authentication_Service_URL());
		System.out.println("Check OTP statusCode is" + statusCode);
		return sendOutput(statusCode,context);

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
			ResourceBundle bundle = locales.getBundleInPreferredLocale(VIPSDKOTPCheck.BUNDLE,
					SymantecOutcomeProvider.class.getClassLoader());
			return ImmutableList.of(new Outcome(Symantec.TRUE.name(), bundle.getString("trueOutcome")),
					new Outcome(Symantec.FALSE.name(), bundle.getString("falseOutcome")),
					new Outcome(Symantec.ERROR.name(), bundle.getString("errorOutcome")));
		}
	}

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
