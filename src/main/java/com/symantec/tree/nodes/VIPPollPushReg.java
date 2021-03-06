package com.symantec.tree.nodes;

import com.symantec.tree.config.Constants.VIPPollPush;
import com.symantec.tree.request.util.AuthPollPush;
import com.symantec.tree.request.util.DeleteCredential;
import com.symantec.tree.request.util.GetVIPServiceURL;

import java.util.List;
import java.util.ResourceBundle;
import javax.inject.Inject;
import org.forgerock.util.Strings;
import com.google.common.collect.ImmutableList;
import org.slf4j.Logger;import org.slf4j.LoggerFactory;

import org.forgerock.json.JsonValue;
import org.forgerock.openam.auth.node.api.Action;
import org.forgerock.openam.auth.node.api.Action.ActionBuilder;
import org.forgerock.openam.auth.node.api.Node;
import org.forgerock.openam.auth.node.api.NodeProcessException;
import org.forgerock.openam.auth.node.api.OutcomeProvider;
import org.forgerock.openam.auth.node.api.TreeContext;
import org.forgerock.util.i18n.PreferredLocales;
import static com.symantec.tree.config.Constants.*;
/**
 * 
 * @author Sacumen (www.sacumen.com) <br> <br>
 * @category Node
 * @Descrition "VIP Poll Push Reg" node with TRUE,FALSE, UNANSWERED and ERROR outcome.
 * If TRUE, it will go to "Success".
 * If False, go to "Failure".
 * If Error, go to "VIP Enter SecurityCode/OTP".
 * If Unanswered, go to "polling wait node".
 *
 */
@Node.Metadata(outcomeProvider = VIPPollPushReg.SymantecOutcomeProvider.class, configClass = VIPPollPushReg.Config.class)
public class VIPPollPushReg implements Node {
	
    private Logger logger = LoggerFactory.getLogger(VIPPollPushReg.class);
	private static final String BUNDLE = "com/symantec/tree/nodes/VIPPollPushReg";

	private AuthPollPush pollPush;

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
	public VIPPollPushReg() {
		pollPush = new AuthPollPush();
	}

	/**
	 * Main logic of the node.
	 */
	public Action process(TreeContext context) {
		logger.info("Entered into ValidaePush porcess method");
		return verifyAuth(context);

	}

	/**
	 * 
	 * @param context
	 * @return Action
	 */
	private Action verifyAuth(TreeContext context) {
		logger.info("Entered into verifyAuth method");
		String credId = context.sharedState.get(CRED_ID).asString();
		String credType = STANDARD_OTP;
		JsonValue newSharedState = context.sharedState.copy();
		GetVIPServiceURL vip = GetVIPServiceURL.getInstance();

		try {

			String result = pollPush.authPollPush(context.sharedState.get(TXN_ID).asString(),vip.getKeyStorePath(),vip.getKeyStorePasswod());
			
			logger.debug("status of authPollPush request response is "+result);

			if (result != null) {

				if (!Strings.isNullOrEmpty(result)) {

					if (result.equalsIgnoreCase(VIPPollPush.ACCEPTED)) {
						logger.info("Push is ACCEPTED");
						return goTo(Symantec.TRUE).replaceSharedState(newSharedState).build();

					} else if (result.equalsIgnoreCase(VIPPollPush.UNANSWERED)) {
						logger.info("Push is UNANSWERED");
						return goTo(Symantec.UNANSWERED).replaceSharedState(newSharedState).build();

					} else if (result.equalsIgnoreCase(VIPPollPush.REJECTED)) {
						logger.info("Push is REJECTED");
						deleteCredential(vip.getUserName(), credId, credType,context);
						return goTo(Symantec.FALSE).replaceSharedState(newSharedState).build();

					} else {
						logger.info("OTP_ERROR..");
						deleteCredential(vip.getUserName(), credId, credType,context);
						context.sharedState.put(OTP_ERROR,"Not able to send push, Please enter Security Code");
						return goTo(Symantec.ERROR).build();

					}

				}
			}

		} catch (Exception e) {
			logger.error(e.getMessage());
		}

		return goTo(Symantec.FALSE).replaceSharedState(newSharedState).build();

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
		 * Authentication Error.
		 */
		ERROR,
		/**
		 * The user has not been answered.
		 */
		UNANSWERED

	}

	/**
	 * Defines the possible outcomes from this SymantecOutcomeProvider node.
	 */
	public static class SymantecOutcomeProvider implements OutcomeProvider {
		@Override
		public List<Outcome> getOutcomes(PreferredLocales locales, JsonValue nodeAttributes) {
			ResourceBundle bundle = locales.getBundleInPreferredLocale(VIPPollPushReg.BUNDLE,
					SymantecOutcomeProvider.class.getClassLoader());
			return ImmutableList.of(new Outcome(Symantec.TRUE.name(), bundle.getString("trueOutcome")),
					new Outcome(Symantec.FALSE.name(), bundle.getString("falseOutcome")),
					new Outcome(Symantec.ERROR.name(), bundle.getString("errorOutcome")),
					new Outcome(Symantec.UNANSWERED.name(), bundle.getString("unansweredOutcome")));
		}
	}

	private void deleteCredential(String userName, String credId, String credType,TreeContext context) throws NodeProcessException {
		logger.debug("deleting credential");
		DeleteCredential delCred = new DeleteCredential();
		GetVIPServiceURL vip = GetVIPServiceURL.getInstance();

		delCred.deleteCredential(userName, credId, credType,vip.getKeyStorePath(),vip.getKeyStorePasswod());
	}

}
