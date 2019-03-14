package com.symantec.tree.nodes;

import static org.forgerock.openam.auth.node.api.Action.send;

import java.util.ArrayList;
import java.util.List;
import java.util.ResourceBundle;

import javax.inject.Inject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.TextOutputCallback;
import org.forgerock.util.Strings;
import com.google.common.collect.ImmutableList;
import org.forgerock.json.JsonValue;
import org.forgerock.openam.auth.node.api.Action;
import org.forgerock.openam.auth.node.api.Node;
import org.forgerock.openam.auth.node.api.SingleOutcomeNode;
import org.forgerock.openam.auth.node.api.TreeContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import static com.symantec.tree.config.Constants.*;


/**
 * 
 * @author Sacumen(www.sacumen.com) <br> <br>
 * @category Node
 * @Descrition "VIP Enter SecurityCode/OTP" node with single outcome. This node will redirect to "VIP Check Symantec OTP".
 *
 */
@Node.Metadata(outcomeProvider  = SingleOutcomeNode.OutcomeProvider.class,
               configClass      = VIPEnterOTP.Config.class)
public class VIPEnterOTP extends SingleOutcomeNode {

    private static final String BUNDLE = "com/symantec/tree/nodes/VIPEnterOTP";
    private final Logger logger = LoggerFactory.getLogger(VIPEnterOTP.class);

    /**
     * Configuration for the node.
     */
    public interface Config {}

    /**
     * Create the node.
     */
    @Inject
    public VIPEnterOTP() {
    }

	/**
	 * Main logic of the node
	 */
    @Override
    public Action process(TreeContext context) {
    	logger.info("Collect SecurityCode started");
    	context.sharedState.remove(PHONE_NUMBER_ERROR);
        JsonValue sharedState = context.sharedState;
        return context.getCallback(PasswordCallback.class)
                .map(PasswordCallback::getPassword)
                .map(String::new)
                .filter(password -> !Strings.isNullOrEmpty(password))
                .map(password -> {
                	logger.info("SecureCode has been collected and placed into the Shared State");
                    return goToNext()
                        .replaceSharedState(sharedState.put(SECURE_CODE, password)).build();
                })
                .orElseGet(() -> {
                    return displayCredentials(context);
                });
    }
    
    /**
     * 
     * @param context
     * @return  list of callbacks
     */
    private Action displayCredentials(TreeContext context) {
		List<Callback> cbList = new ArrayList<>(2);
		String outputError = context.sharedState.get(OTP_ERROR).asString();
		if (outputError == null) {
			ResourceBundle bundle = context.request.locales.getBundleInPreferredLocale(BUNDLE, getClass().getClassLoader());
			PasswordCallback pcb = new PasswordCallback(bundle.getString("callback.securecode"), false);
			cbList.add(pcb);
		} else {
			TextOutputCallback tcb = new TextOutputCallback(0, outputError);
			ResourceBundle bundle = context.request.locales.getBundleInPreferredLocale(BUNDLE,
					getClass().getClassLoader());
			PasswordCallback pcb = new PasswordCallback(bundle.getString("callback.securecode"), false);
			cbList.add(tcb);
			cbList.add(pcb);
		}

		return send(ImmutableList.copyOf(cbList)).build();

	}
}