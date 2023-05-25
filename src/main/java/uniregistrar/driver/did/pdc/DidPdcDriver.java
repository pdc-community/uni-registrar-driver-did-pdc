package uniregistrar.driver.did.pdc;

import com.danubetech.keyformats.PrivateKey_to_JWK;
import com.danubetech.keyformats.jose.JWK;
import com.vnet.did.protocol.request.CreateDidArgs;
import com.vnet.did.protocol.response.ResponseData;
import com.vnet.did.service.DidService;
import com.vnet.did.service.impl.DidServiceImpl;
import com.vnet.did.util.CredentialsUtils;
import foundation.identity.did.VerificationMethod;
import foundation.identity.jsonld.JsonLDUtils;
import org.apache.commons.lang3.StringUtils;
import org.jetbrains.annotations.NotNull;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.web3j.crypto.Credentials;
import uniregistrar.RegistrationException;
import uniregistrar.driver.AbstractDriver;
import uniregistrar.request.CreateRequest;
import uniregistrar.request.DeactivateRequest;
import uniregistrar.request.UpdateRequest;
import uniregistrar.state.CreateState;
import uniregistrar.state.DeactivateState;
import uniregistrar.state.SetStateFinished;
import uniregistrar.state.UpdateState;

import java.net.URI;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * @Description
 * @Author wqq
 * @Date 2023/5/8 14:15
 */
public class DidPdcDriver extends AbstractDriver {

    private static final Logger log = LoggerFactory.getLogger(DidPdcDriver.class);

    @Override
    public CreateState create(CreateRequest createRequest) throws RegistrationException {
        CreateDidArgs createDidArgs = buildCreateDidArgs();
        String did = createDid(createDidArgs);
        CreateState createState = buildCreateState(did, createDidArgs);
        return createState;
    }

    private CreateDidArgs buildCreateDidArgs() {
        CreateDidArgs createDidArgs = new CreateDidArgs();
        Credentials credentials = CredentialsUtils.create();
        createDidArgs.setPublicKey(credentials.getEcKeyPair().getPublicKey().toString());
        createDidArgs.setPrivateKey(credentials.getEcKeyPair().getPrivateKey().toString());
        return createDidArgs;
    }

    private String createDid(CreateDidArgs createDidArgs) throws RegistrationException {
        DidService didService = new DidServiceImpl();
        ResponseData<String> createDidResult = didService.createDid(createDidArgs);
        Integer errorCode = createDidResult.getErrorCode();
        if (!StringUtils.equals("0", errorCode.toString())) {
            log.error("get did document failed caused by {}", createDidResult.getErrorMessage());
            throw new RegistrationException("get did document failed");
        }
        String did = createDidResult.getResult();
        return did;
    }
    private CreateState buildCreateState(String did, CreateDidArgs createDidArgs) {
        Map<String, Object> secret = buildSecret(did, createDidArgs);
        CreateState createState = CreateState.build();
        SetStateFinished.setStateFinished(createState, did, secret);
        return createState;
    }

    private Map<String, Object> buildSecret(String did, CreateDidArgs createDidArgs) {
        List<Map<String, Object>> jsonVerificationMethods = buildJsonVerificationMethods(did, createDidArgs);
        Map<String, Object> secret = new LinkedHashMap<>();
        secret.put("verificationMethod", jsonVerificationMethods);
        return secret;
    }

    private List<Map<String, Object>> buildJsonVerificationMethods(String did, CreateDidArgs createDidArgs) {
        VerificationMethod verificationMethod = buildVerificationMethod(did, createDidArgs);
        List<Map<String, Object>> jsonVerificationMethods = new ArrayList<>();
        jsonVerificationMethods.add(verificationMethod.getJsonObject());
        return jsonVerificationMethods;
    }

    private VerificationMethod buildVerificationMethod(String did, CreateDidArgs createDidArgs) {
        VerificationMethod verificationMethod = VerificationMethod.builder()
                .id(URI.create(did + "#key-1"))
                .controller(did)
                .type("Secp256k1")
                .build();
        String keyUrl = identifierToKeyUrl(did);
        byte[] privateKeyBytes = createDidArgs.getPrivateKey().getBytes();
        JWK jsonWebKey = privateKeyToJWK(privateKeyBytes, keyUrl);
        JsonLDUtils.jsonLdAdd(verificationMethod, "privateKeyJwk", jsonWebKey.toMap());
        JsonLDUtils.jsonLdAdd(verificationMethod, "purpose", List.of( "authentication", "assertionMethod", "capabilityInvocation", "capabilityDelegation"));
        return verificationMethod;
    }

    private static String identifierToKeyUrl(String identifier) {
        return identifier + "#key-1";
    }

    private static JWK privateKeyToJWK(byte[] privateKeyBytes, String keyUrl) {
        String kid = keyUrl;
        String use = null;
        return PrivateKey_to_JWK.secp256k1PrivateKeyBytes_to_JWK(privateKeyBytes, kid, use);
    }

    @Override
    public UpdateState update(UpdateRequest updateRequest) throws RegistrationException {
        throw new RegistrationException("Not implemented.");
    }

    @Override
    public DeactivateState deactivate(DeactivateRequest deactivateRequest) throws RegistrationException {
        throw new RegistrationException("Not implemented.");
    }
}
