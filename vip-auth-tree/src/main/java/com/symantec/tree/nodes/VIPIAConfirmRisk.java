package com.symantec.tree.nodes;
import static com.symantec.tree.config.Constants.KEY_STORE_PASS;
import static com.symantec.tree.config.Constants.KEY_STORE_PATH;

import org.forgerock.json.JsonValue;
import org.forgerock.openam.auth.node.api.Action;
import org.forgerock.openam.auth.node.api.Action.ActionBuilder;
import org.forgerock.openam.auth.node.api.Node;
import org.forgerock.openam.auth.node.api.NodeProcessException;
import org.forgerock.openam.auth.node.api.OutcomeProvider;
import org.forgerock.openam.auth.node.api.SharedStateConstants;
import org.forgerock.openam.auth.node.api.TreeContext;
import org.forgerock.util.i18n.PreferredLocales;

import com.google.common.collect.ImmutableList;
import com.sun.identity.shared.debug.Debug;
import com.symantec.tree.config.Constants.VIPIA;
import com.symantec.tree.request.util.ConfirmRisk;

import java.util.List;
import java.util.ResourceBundle;
import javax.inject.Inject;

@Node.Metadata(outcomeProvider = VIPIAConfirmRisk.SymantecOutcomeProvider.class, configClass = VIPIAConfirmRisk.Config.class)
public class VIPIAConfirmRisk implements Node{
	private static final String BUNDLE = "com/symantec/tree/nodes/VIPIAConfirmRisk";
	private final Debug debug = Debug.getInstance("VIP");
	private ConfirmRisk confirmRisk;

	/**
	 * Configuration for the node.
	 */
	public interface Config {
	}

	/**
	 * Create the node.
	 */
	@Inject
	public VIPIAConfirmRisk(ConfirmRisk confirmRisk) {
		this.confirmRisk = confirmRisk;
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
		FALSE

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
			ResourceBundle bundle = locales.getBundleInPreferredLocale(VIPIAConfirmRisk.BUNDLE,
					SymantecOutcomeProvider.class.getClassLoader());
			return ImmutableList.of(new Outcome(Symantec.TRUE.name(), bundle.getString("trueOutcome")),
					new Outcome(Symantec.FALSE.name(), bundle.getString("falseOutcome")));
		}
	}
	
	/**
	 * Main logic of the node
	 * @throws NodeProcessException 
	 */
	@Override
	public Action process(TreeContext context) throws NodeProcessException {
	   JsonValue sharedState = context.sharedState;  
       String status = confirmRisk.confirmRisk(
				sharedState.get(SharedStateConstants.USERNAME).asString(),
				sharedState.get(VIPIA.EVENT_ID).asString(), 
				sharedState.get(KEY_STORE_PATH).asString(),sharedState.get(KEY_STORE_PASS).asString());

		debug.message("status in vip ia registration is "+status);
		
		if(status.equals(VIPIA.REGISTERED)) {
			return goTo(Symantec.TRUE).replaceSharedState(sharedState).build();
		}
		else {
			return goTo(Symantec.FALSE).build();
		}
	}
}
