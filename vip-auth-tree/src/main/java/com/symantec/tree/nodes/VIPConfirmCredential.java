package com.symantec.tree.nodes;

import javax.inject.Inject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.ConfirmationCallback;
import javax.security.auth.callback.TextOutputCallback;

import org.forgerock.guava.common.collect.ImmutableList;
import org.forgerock.json.JsonValue;
import org.forgerock.openam.auth.node.api.Action;
import org.forgerock.openam.auth.node.api.Node;
import org.forgerock.openam.auth.node.api.OutcomeProvider;
import org.forgerock.openam.auth.node.api.TreeContext;
import org.forgerock.openam.auth.node.api.Action.ActionBuilder;
import org.forgerock.util.i18n.PreferredLocales;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static org.forgerock.openam.auth.node.api.Action.send;

import java.util.ArrayList;
import java.util.List;
import java.util.ResourceBundle;
import static com.symantec.tree.config.Constants.CONFIRM_CRED_CHOICE;

/**
 * 
 * @author Sacumen (www.sacumen.com) <br> <br>
 * @category Node
 * @Descrition "VIP Add More Creds" node with yes and no outcome, If yes, go
 *             to "VIP Display Creds" else false, go to "Success".
 *
 */

@Node.Metadata(outcomeProvider = VIPConfirmCredential.CredsOutcomeProvider.class, configClass =
		VIPConfirmCredential.Config.class)
public class VIPConfirmCredential implements Node {

	private static final String BUNDLE = "com/symantec/tree/nodes/VIPConfirmCredential";
	private final Logger logger = LoggerFactory.getLogger(VIPConfirmCredential.class);

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
	public VIPConfirmCredential() {
	}

	/**
	 * Main logic of the node.
	 */
	@Override
	public Action process(TreeContext context) {

		JsonValue sharedState = context.sharedState;
		String inputChoice = "";

		List<ConfirmationCallback> confirmationCallbacks = context.getCallbacks(ConfirmationCallback.class);

		for (ConfirmationCallback cc : confirmationCallbacks) {
			logger.debug("Option type is:\t" + cc.getOptionType());
			logger.debug("Selected option is:\t" + cc.getSelectedIndex());
			inputChoice = SymantecConfirmCredOutcomeChoice.getChoiceByCode(cc.getSelectedIndex());
			sharedState.put(CONFIRM_CRED_CHOICE, inputChoice);
		}
		logger.debug("Choice value:" + inputChoice);
		switch (inputChoice) {
		case "YES":
			return goTo(SymantecConfirmCredOutcome.YES).replaceSharedState(sharedState).build();
		case "NO":
			return goTo(SymantecConfirmCredOutcome.NO).replaceSharedState(sharedState).build();
		}
		return displayCreds(context);

	}

	/**
	 * 
	 * @param context
	 * @return lsit of callbacks
	 */
	private Action displayCreds(TreeContext context) {
		List<Callback> cbList = new ArrayList<>(2);
		ResourceBundle bundle = context.request.locales.getBundleInPreferredLocale(BUNDLE, getClass().getClassLoader());
		TextOutputCallback textOutputCallback = new TextOutputCallback(0, "Add More Credentials ");
		ConfirmationCallback confirmationCallback = new ConfirmationCallback(bundle.getString("callback.creds"),
				ConfirmationCallback.INFORMATION, new String[] { "YES", "NO" }, 0);
		cbList.add(textOutputCallback);
		cbList.add(confirmationCallback);
		return send(cbList).build();
	}

	private ActionBuilder goTo(SymantecConfirmCredOutcome outcome) {
		return Action.goTo(outcome.name());
	}

	/**
	 * The possible outcomes for the SymantecVerifyAuth.
	 */
	public enum SymantecConfirmCredOutcome {
		/**
		 * selection of VIP.
		 */
		YES,
		/**
		 * selection for SMS.
		 */
		NO,

	}

	/**
	 * Defines the configuration for the outcomes.
	 */
	public enum SymantecConfirmCredOutcomeChoice {

		YES(0, "YES"), NO(1, "NO");

		private int code;
		private String choice;

		SymantecConfirmCredOutcomeChoice(int code, String choice) {
			this.code = code;
			this.choice = choice;
		}

		public static String getChoiceByCode(int code) {
			for (SymantecConfirmCredOutcomeChoice syc : SymantecConfirmCredOutcomeChoice.values()) {
				if (syc.code == code) {
					return syc.choice;
				}
			}
			return "";
		}

	}

	/**
	 * Defines the possible outcomes from this SymantecOutcomeProvider node.
	 */
	public static class CredsOutcomeProvider implements OutcomeProvider {
		@Override
		public List<Outcome> getOutcomes(PreferredLocales locales, JsonValue nodeAttributes) {
			ResourceBundle bundle = locales.getBundleInPreferredLocale(VIPConfirmCredential.BUNDLE,
					CredsOutcomeProvider.class.getClassLoader());
			return ImmutableList.of(new Outcome(SymantecConfirmCredOutcome.YES.name(), bundle.getString("YesOutcome")),
					new Outcome(SymantecConfirmCredOutcome.NO.name(), bundle.getString("NoOutcome")));
		}
	}
}