package com.symantec.tree.nodes;

import java.util.List;
import java.util.ResourceBundle;

import javax.inject.Inject;

import org.forgerock.json.JsonValue;
import org.forgerock.openam.auth.node.api.Action;
import org.forgerock.openam.auth.node.api.Node;
import org.forgerock.openam.auth.node.api.OutcomeProvider;
import org.forgerock.openam.auth.node.api.TreeContext;
import org.forgerock.openam.auth.node.api.Action.ActionBuilder;
import org.forgerock.util.i18n.PreferredLocales;

import com.google.common.collect.ImmutableList;
import com.google.inject.assistedinject.Assisted;
import com.sun.identity.shared.debug.Debug;

@Node.Metadata(outcomeProvider = VIPDRDataOSDecisionNode.SymantecOutcomeProvider.class, configClass =
VIPDRDataOSDecisionNode.Config.class)
public class VIPDRDataOSDecisionNode implements Node{

	private final Debug debug = Debug.getInstance("VIP");
	private static final String BUNDLE = "com/symantec/tree/nodes/VIPDRDataOSDecisionNode";

	
	public interface Config {
		
	}
	
	@Inject
	public VIPDRDataOSDecisionNode() {
	}
	
	/**
	 * The possible outcomes for the SymantecVerifyAuth.
	 */
	private enum Symantec {
		/**
		 * ios device. 
		 */
		iOS,
		/**
		 * android device.
		 */
		ANDROID

	}
	
	private ActionBuilder goTo(Symantec outcome) {
		return Action.goTo(outcome.name());
	}
	
	public Action process(TreeContext context) {

		debug.message("collecting OS Field...");
		JsonValue sharedState = context.sharedState;
		
		if(sharedState.get("os").asString().equalsIgnoreCase("\"iOS\"")) {
			return goTo(Symantec.iOS).build();
		}
		else {
			return goTo(Symantec.ANDROID).build();
		}
		
	}
	
	/**
	 * Defines the possible outcomes from this SymantecOutcomeProvider node.
	 */
	public static class SymantecOutcomeProvider implements OutcomeProvider {
		@Override
		public List<Outcome> getOutcomes(PreferredLocales locales, JsonValue nodeAttributes) {
			ResourceBundle bundle = locales.getBundleInPreferredLocale(VIPDRDataOSDecisionNode.BUNDLE,
					SymantecOutcomeProvider.class.getClassLoader());
			return ImmutableList.of(new Outcome(Symantec.ANDROID.name(), bundle.getString("androidOutcome")),
					new Outcome(Symantec.iOS.name(), bundle.getString("iOSOutcome")));
		}
	}

}
