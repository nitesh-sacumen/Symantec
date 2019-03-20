package com.symantec.tree.nodes;

import static com.symantec.tree.config.Constants.DISPLAY_ERROR;
import static org.forgerock.openam.auth.node.api.Action.send;
import javax.inject.Inject;
import javax.security.auth.callback.TextOutputCallback;
import org.forgerock.openam.auth.node.api.Action;
import org.forgerock.openam.auth.node.api.Node;
import org.forgerock.openam.auth.node.api.SingleOutcomeNode;
import org.forgerock.openam.auth.node.api.TreeContext;
import org.forgerock.util.Strings;
import com.sun.identity.shared.debug.Debug;

/**
 * 
 * @author Sacumen(www.sacumen.com) <br> <br>
 * @category Node
 * @Descrition "VIP DISPLAY ERROR" node with single outcome, which will lead to "login failure".
 *
 */
@Node.Metadata(outcomeProvider  = SingleOutcomeNode.OutcomeProvider.class,
               configClass      = VIPDisplayError.Config.class)
public class VIPDisplayError extends SingleOutcomeNode{
	private final Debug debug = Debug.getInstance("VIP");

	    
	    /**
	     * Configuration for the node.
	     */
	    public interface Config {}

	    /**
	     * Create the node.
	     */
	    @Inject
	    public VIPDisplayError() {
	        }
	    
		private Action displayError(TreeContext context) {
			String outputError=context.sharedState.get(DISPLAY_ERROR).asString();
			TextOutputCallback pcb = new TextOutputCallback(0, outputError);
			return send(pcb).build();
		}
		
		
		/**
	     * This Node method displays Error for maximum attempts of Invalid otp Entered.
	     */
	    @Override
	    public Action process(TreeContext context) {
	    	debug.message("Inside VIP DISPLAY ERROR Page");
	    	return context.getCallback(TextOutputCallback.class).map(TextOutputCallback::getMessage)
	                .map(String::new)
	                .filter(name -> !Strings.isNullOrEmpty(name))
	                .map(name -> {
	                	return goToNext().build();
	                }).orElseGet(() -> {
						debug.message("Displaying Error");
						return displayError(context);
					});
	                	
	    }
	  }
