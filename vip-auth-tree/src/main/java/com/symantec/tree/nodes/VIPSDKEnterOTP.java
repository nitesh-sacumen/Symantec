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
import com.google.inject.assistedinject.Assisted;
import com.sun.identity.authentication.callbacks.HiddenValueCallback;
import com.symantec.tree.nodes.VIPRegisterUser.Config;

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
               configClass      = VIPSDKEnterOTP.Config.class)
public class VIPSDKEnterOTP extends SingleOutcomeNode {

    private static final String BUNDLE = "com/symantec/tree/nodes/VIPSDKEnterOTP";
    private final Logger logger = LoggerFactory.getLogger(VIPSDKEnterOTP.class);
	private final Config config;


    /**
     * Configuration for the node.
     */
    public interface Config {}

    /**
     * Create the node.
     */
    @Inject
    public VIPSDKEnterOTP(@Assisted Config config) {
    	this.config = config;
    }

	/**
	 * Main logic of the node
	 */
    @Override
    public Action process(TreeContext context) {
    	System.out.println("Collect SecurityCode started in VIP Enter OTP");
        JsonValue sharedState = context.sharedState;
        return context.getCallback(PasswordCallback.class)
                .map(PasswordCallback::getPassword)
                .map(String::new)
                .filter(password -> !Strings.isNullOrEmpty(password))
                .map(password -> {
                	logger.info("SecureCode has been collected and placed into the Shared State");
                	System.out.println("Security Code: "+password);
                    return goToNext()
                        .replaceSharedState(sharedState.put(SECURE_CODE, password)).build();
                })
                .orElseGet(() -> {
                	logger.info("Enter Credential ID");
                	System.out.println("Enter Credential ID in VIP Enter OTP");

                    return displayCredentials(context);
                });
    }
    
    /**
     * 
     * @param context
     * @return  list of callbacks
     */
    private Action displayCredentials(TreeContext context) {
		List<Callback> cbList = new ArrayList<>();
		String outputError = context.sharedState.get(OTP_ERROR).asString();
		System.out.println("outputError "+ outputError);
		if (outputError == null) {
			System.out.println("no outputError...");
			ResourceBundle bundle = context.request.locales.getBundleInPreferredLocale(BUNDLE, getClass().getClassLoader());
			PasswordCallback pcb = new PasswordCallback(bundle.getString("callback.securecode"), false);
			HiddenValueCallback hcb = new HiddenValueCallback("Enter password");
			cbList.add(pcb);
			cbList.add(hcb);
			
		} else {
			System.out.println("outputError exist..");

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