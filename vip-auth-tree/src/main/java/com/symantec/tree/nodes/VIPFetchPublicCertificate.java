package com.symantec.tree.nodes;

import static org.forgerock.secrets.Purpose.purpose;

import java.util.Optional;

import javax.inject.Inject;

import org.forgerock.openam.annotations.sm.Attribute;
import org.forgerock.openam.auth.node.api.AbstractDecisionNode;
import org.forgerock.openam.auth.node.api.Action;
import org.forgerock.openam.auth.node.api.Node;
import org.forgerock.openam.auth.node.api.NodeProcessException;
import org.forgerock.openam.auth.node.api.TreeContext;
import org.forgerock.openam.core.realms.Realm;
import org.forgerock.openam.secrets.DefaultingPurpose;
import org.forgerock.openam.secrets.Secrets;
import org.forgerock.openam.secrets.SecretsProviderFacade;
import org.forgerock.secrets.NoSuchSecretException;
import org.forgerock.secrets.Purpose;
import org.forgerock.secrets.keys.KeyFormatRaw;
import org.forgerock.secrets.keys.SigningKey;
import org.forgerock.util.promise.Promise;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.inject.assistedinject.Assisted;

@Node.Metadata(outcomeProvider  = AbstractDecisionNode.OutcomeProvider.class,
configClass      = VIPFetchPublicCertificate.Config.class)
public class VIPFetchPublicCertificate extends AbstractDecisionNode{
	 static final String DEFAULT_NODE_SIGNING = "am.default.authentication.nodes.mycustom.signing";
	    static final String CUSTOM_NODE_SIGNING = "am.authentication.nodes.mycustom.%s.signing";
	    private static final Purpose<SigningKey> DEFAULT_SIGNING = purpose(DEFAULT_NODE_SIGNING, SigningKey.class);
	    private static final DefaultingPurpose<SigningKey> CUSTOM_SIGNING =
	            new DefaultingPurpose<>(DEFAULT_SIGNING, CUSTOM_NODE_SIGNING);
	    private final Logger logger = LoggerFactory.getLogger(VIPFetchPublicCertificate.class);
	    private final Config config;
	    private final SecretsProviderFacade secrets;

	    /**
	     * Configuration for the node.
	     */
	    public interface Config {
	        @Attribute(order = 100)
	        Optional<String> secretName();
	    }


	    /**
	     * Create the node using Guice injection. Just-in-time bindings can be used to obtain instances of other classes
	     * from the plugin.
	     *
	     * @param config The service config.
	     * @param realm The realm the node is in.
	     */
	    @Inject
	    public VIPFetchPublicCertificate(@Assisted Config config, @Assisted Realm realm, Secrets secrets) {
	        this.config = config;
	        this.secrets = secrets.getRealmSecrets(realm);
	    }

	    @Override
	    public Action process(TreeContext context) throws NodeProcessException {
	        try {
	            // Obtain the Java Security Key instance
	            Promise<SigningKey, NoSuchSecretException> configuredKey = config.secretName()
	                    .map(name -> secrets.getActiveSecret(CUSTOM_SIGNING, name))
	                    .orElseGet(() -> secrets.getActiveSecret(DEFAULT_SIGNING));
	            java.security.Key key = configuredKey.getOrThrow().export(KeyFormatRaw.INSTANCE);
	            // TODO Do something with the key
	        } catch (InterruptedException e) {
	            Thread.currentThread().interrupt();
	            throw new NodeProcessException(e);
	        } catch (NoSuchSecretException e) {
	            throw new NodeProcessException("Badly configured system - no key for " + config.secretName(), e);
	        }
	        return goTo(false).build();
	    }
}
