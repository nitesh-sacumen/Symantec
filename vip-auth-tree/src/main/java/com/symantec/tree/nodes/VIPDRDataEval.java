package com.symantec.tree.nodes;

import javax.inject.Inject;
import org.forgerock.json.JsonValue;
import org.forgerock.openam.annotations.sm.Attribute;
import org.forgerock.openam.auth.node.api.AbstractDecisionNode;
import org.forgerock.openam.auth.node.api.Action;
import org.forgerock.openam.auth.node.api.Node;
import org.forgerock.openam.auth.node.api.TreeContext;
import com.google.inject.assistedinject.Assisted;
import com.sun.identity.shared.debug.Debug;


@Node.Metadata(outcomeProvider = AbstractDecisionNode.OutcomeProvider.class, configClass =
VIPDRDataEval.Config.class)
public class VIPDRDataEval extends AbstractDecisionNode{
	
	private final Config config;
	private final Debug debug = Debug.getInstance("VIP");
	
	/**
	 * Configuration for the node.
	 */
	public interface Config {
		
		@Attribute(order = 100)
        default DRDataFields DRDataFields() {
            return DRDataFields.rootDetected;
        }
	}
	
	 public enum DRDataFields {
		 rootDetected,
		 passcodeDisabled,
		 affected,
		 storageEncryptionDisabled,
		 developerOptionEnabled,
		 unknownSourcesEnabled,
		 untrustedCertificateDetected,
		 arpSpoofingDetected,
		 sslStripDetected,
		 sslMITMDetected,
		 contentTamperDetected,
		 usbDebugEnabled,
		 dnsSpoofDetected,
		 touchIDDisabled,
		 osTamper,
		 malwareDetected,
		 needUpgrade
		 
	    }
	
	
	@Inject
	public VIPDRDataEval(@Assisted Config config) {
		this.config = config;
	}
	
	public Action process(TreeContext context) {

		debug.message("Evaluating DR data...");
		JsonValue sharedState = context.sharedState;

		String value = config.DRDataFields().toString();
		
		debug.message("value coming from configuration is " + value);
		debug.message("value coming from shared state is " + sharedState.get(value).asString());
		
		if(sharedState.get(value).asString().equalsIgnoreCase("\"true\"")) {
			return goTo(true).build();
		}
		else {
			return goTo(false).build();
		}
		
	}
	

}
