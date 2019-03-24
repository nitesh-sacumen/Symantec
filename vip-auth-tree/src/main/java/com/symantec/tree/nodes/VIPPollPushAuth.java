package com.symantec.tree.nodes;

import com.symantec.tree.config.Constants.VIPPollPush;
import com.symantec.tree.request.util.AuthPollPush;
import com.symantec.tree.request.util.GetVIPServiceURL;

import java.util.List;
import java.util.ResourceBundle;
import javax.inject.Inject;
import org.forgerock.util.Strings;
import com.google.common.collect.ImmutableList;
import com.sun.identity.shared.debug.Debug;

import org.forgerock.json.JsonValue;
import org.forgerock.openam.auth.node.api.Action;
import org.forgerock.openam.auth.node.api.Action.ActionBuilder;
import org.forgerock.openam.auth.node.api.Node;
import org.forgerock.openam.auth.node.api.OutcomeProvider;
import org.forgerock.openam.auth.node.api.TreeContext;
import org.forgerock.util.i18n.PreferredLocales;
import static com.symantec.tree.config.Constants.*;

/**
 * 
 * @author Sacumen(www.sacumen.com) <br> <br>
 * @category Node
 * @Descrition "VIP Poll Push Auth" node with TRUE,FALSE, UNANSWERED and ERROR outcome.
 * If TRUE, it will go to "Success".
 * If False, go to "Failure".
 * If Error, go to "VIP OTPAuth Creds".
 * If Unanswered, go to "polling wait node".
 *
 */
@Node.Metadata(outcomeProvider = VIPPollPushAuth.SymantecOutcomeProvider.class, configClass = VIPPollPushAuth.Config.class)
public class VIPPollPushAuth implements Node {

	private final Debug debug = Debug.getInstance("VIP");
	private static final String BUNDLE = "com/symantec/tree/nodes/VIPPollPushAuth";

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
	public VIPPollPushAuth() {
		pollPush = new AuthPollPush();
	}

	/**
	 * Main logic of the node.
	 */
	public Action process(TreeContext context) {
		return verifyAuth(context);
	}

	/**
	 * 
	 * @param context
	 * @return next action.
	 */
	private Action verifyAuth(TreeContext context) {
		debug.message("Entered into verifyAuth method");
		JsonValue newSharedState = context.sharedState.copy();
		GetVIPServiceURL vip = GetVIPServiceURL.getInstance();

		try {
            
			//Executing PollPushStatusRequest
			String result = pollPush.authPollPush(context.sharedState.get(TXN_ID).asString(),vip.getKeyStorePath(),vip.getKeyStorePasswod());

			//Making decision based on PollPushStatusRequest response
			if (result != null) {

				if (!Strings.isNullOrEmpty(result)) {

					if (result.equalsIgnoreCase(VIPPollPush.ACCEPTED)) {
						return goTo(Symantec.TRUE).replaceSharedState(newSharedState).build();

					} else if (result.equalsIgnoreCase(VIPPollPush.UNANSWERED)) {
						return goTo(Symantec.UNANSWERED).replaceSharedState(newSharedState).build();

					} else if (result.equalsIgnoreCase(VIPPollPush.REJECTED)) {
						return goTo(Symantec.FALSE).replaceSharedState(newSharedState).build();

					} else {
						context.sharedState.put(PUSH_ERROR,"You have not approved push, Please select other option for authentication");
						return goTo(Symantec.ERROR).build();

					}

				}
			}

		} catch (Exception e) {
			debug.error(e.getMessage());
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
			ResourceBundle bundle = locales.getBundleInPreferredLocale(VIPPollPushAuth.BUNDLE,
					SymantecOutcomeProvider.class.getClassLoader());
			return ImmutableList.of(new Outcome(Symantec.TRUE.name(), bundle.getString("trueOutcome")),
					new Outcome(Symantec.FALSE.name(), bundle.getString("falseOutcome")),
					new Outcome(Symantec.ERROR.name(), bundle.getString("errorOutcome")),
					new Outcome(Symantec.UNANSWERED.name(), bundle.getString("unansweredOutcome")));
		}
	}
}
