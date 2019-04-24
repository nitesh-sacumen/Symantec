package com.symantec.tree.nodes;

import static com.symantec.tree.config.Constants.*;

import com.symantec.tree.request.util.CheckVIPOtp;
import com.symantec.tree.request.util.GetVIPServiceURL;

import java.util.List;
import java.util.ResourceBundle;
import javax.inject.Inject;
import com.google.common.collect.ImmutableList;
import org.slf4j.Logger;import org.slf4j.LoggerFactory;

import org.forgerock.json.JsonValue;
import org.forgerock.openam.auth.node.api.*;
import org.forgerock.util.i18n.PreferredLocales;

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
    private Logger logger = LoggerFactory.getLogger(VIPOTPCheck.class);

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
	    logger.info("executing CheckOtpRequest");
        
		String otpValue = context.sharedState.get(SECURE_CODE).asString();
		GetVIPServiceURL vip = GetVIPServiceURL.getInstance();

		String statusCode = checkOtp.checkOtp(vip.getUserName(), otpValue,vip.getKeyStorePath(),vip.getKeyStorePasswod());
		
		logger.debug("Check OTP request status is "+statusCode);
		
		//Making decision based on CheckOtpRequest response
		return checkOtp.sendOutput(statusCode, context);
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
		 * Authentication failed.s
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
	

}
