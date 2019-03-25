package com.symantec.tree.nodes;

import static org.forgerock.openam.auth.node.api.Action.send;

import java.util.ArrayList;
import java.util.List;
import java.util.ResourceBundle;

import javax.inject.Inject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.TextOutputCallback;
import org.forgerock.util.Strings;
import com.google.common.collect.ImmutableList;
import org.slf4j.Logger;import org.slf4j.LoggerFactory;

import org.forgerock.json.JsonValue;
import org.forgerock.openam.auth.node.api.Action;
import org.forgerock.openam.auth.node.api.Node;
import org.forgerock.openam.auth.node.api.SingleOutcomeNode;
import org.forgerock.openam.auth.node.api.TreeContext;
import static com.symantec.tree.config.Constants.*;

/**
 * 
 * @author Sacumen(www.sacumen.com) <br> <br>
 * @category Node
 * @Descrition "VIP Enter CredentialID" node with single outcome. This node will redirect to "VIP Add Credential".
 *
 */
@Node.Metadata(outcomeProvider = SingleOutcomeNode.OutcomeProvider.class, configClass =
		 VIPEnterCredentialId.Config.class)
public class VIPEnterCredentialId extends SingleOutcomeNode {

	private static final String BUNDLE = "com/symantec/tree/nodes/VIPEnterCredentialId";
    private Logger logger = LoggerFactory.getLogger(VIPEnterCredentialId.class);
	
    /**
	 * Configuration for the node.
	 */
	public interface Config {
	}

	/**
	 * Create the node.
	 */
	@Inject
	public VIPEnterCredentialId() {
	}

	/**
	 * 
	 * @param context
	 * @return sending password call back.
	 */
	private Action collectOTP(TreeContext context) {
		logger.info("Collecting credential id from callback");
		List<Callback> cbList = new ArrayList<>(2);
		ResourceBundle bundle = context.request.locales.getBundleInPreferredLocale(BUNDLE, getClass().getClassLoader());
		NameCallback ncb = new NameCallback(bundle.getString("callback.credId"), "Enter Credential ID");
		TextOutputCallback tcb = new TextOutputCallback(0,"Please Enter your Credential Id");
		cbList.add(tcb);
		cbList.add(ncb);
		return send(ImmutableList.copyOf(cbList)).build();
	}

	/**
	 * Main logic of the node
	 */
	@Override
	public Action process(TreeContext context) {
		logger.info("Collect CredID started");
		JsonValue sharedState = context.sharedState;

		context.sharedState.remove(CREDENTIAL_ID_ERROR);
		return context.getCallback(NameCallback.class).map(NameCallback::getName).map(String::new)
				.filter(password -> !Strings.isNullOrEmpty(password)).map(password -> {
					logger.info("Credential ID has been collected and placed into the Shared State");
					return goToNext().replaceSharedState(sharedState.copy().put(CRED_ID, password)).build();
				}).orElseGet(() -> {
					logger.info("Enter Credential ID");
					return collectOTP(context);
				});
	}
}