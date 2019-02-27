package com.symantec.tree.nodes;
import java.util.List;
import java.util.ResourceBundle;

import javax.inject.Inject;

import org.forgerock.json.JsonValue;
import org.forgerock.openam.annotations.sm.Attribute;
import org.forgerock.openam.auth.node.api.Action;
import org.forgerock.openam.auth.node.api.Node;
import org.forgerock.openam.auth.node.api.NodeProcessException;
import org.forgerock.openam.auth.node.api.OutcomeProvider;
import org.forgerock.openam.auth.node.api.TreeContext;
import org.forgerock.openam.auth.node.api.Action.ActionBuilder;
import org.forgerock.util.i18n.PreferredLocales;
import com.google.common.collect.ImmutableList;
import com.google.inject.assistedinject.Assisted;
import com.sun.identity.shared.debug.Debug;
import com.symantec.tree.config.Constants.VIPIA;


@Node.Metadata(outcomeProvider = VIPIARiskScoreDecision.SymantecOutcomeProvider.class, configClass = VIPIARiskScoreDecision.Config.class)
public class VIPIARiskScoreDecision implements Node{
	
	private final Config config;
	private static final String BUNDLE = "com/symantec/tree/nodes/VIPIARiskScoreDecision";
	private final Debug debug = Debug.getInstance("VIP");
	
	
	/**
	 * Configuration for the node.
	 */
	public interface Config {
		@Attribute(order = 100, requiredValue = true)
		default int low_threshold() {
			return 20;
		};
		
		@Attribute(order = 200, requiredValue = true)
		default int high_threshold() {
			return 80;
		};
	}

	/**
	 * 
	 */
	@Inject
	public VIPIARiskScoreDecision(@Assisted Config config) {
		this.config = config;
	}

	/**
	 * The possible outcomes for the DisplayCredentail.
	 */
	private enum Symantec {
		/**
		 * Successful.
		 */
		HIGH,
		/**
		 * failed.
		 */
		MEDIUM,
		/**
		 * Disabled.
		 */
		LOW

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
			ResourceBundle bundle = locales.getBundleInPreferredLocale(VIPIARiskScoreDecision.BUNDLE,
					SymantecOutcomeProvider.class.getClassLoader());
			return ImmutableList.of(new Outcome(Symantec.HIGH.name(), bundle.getString("highScoreOutcome")),
					new Outcome(Symantec.MEDIUM.name(), bundle.getString("mediumScoreOutcome")),
					new Outcome(Symantec.LOW.name(), bundle.getString("lowScoreOutcome")));
		}
	}
	
	/**
	 * Main logic of the node.
	 * 
	 * @throws NodeProcessException
	 */
	@Override
	public Action process(TreeContext context) throws NodeProcessException {
		debug.message("Making Decision based on score......");
		String score = context.transientState.get(VIPIA.SCORE).asString();
		int RiskScore = Integer.parseInt(score);
		
		if (RiskScore<=config.low_threshold()) {
			debug.message("Score is LOW");
			return goTo(Symantec.LOW).build();
		}
		else if((config.low_threshold() < RiskScore)&& (config.high_threshold()<RiskScore)) {
			debug.message("Score is MEDIUM");
			return goTo(Symantec.MEDIUM).build();
		}
		else {
			debug.message("Score is HIGH");
			return goTo(Symantec.HIGH).build();
		}
	}



}
