package io.cyphera.nifi;

import io.cyphera.Cyphera;
import org.apache.nifi.annotation.documentation.CapabilityDescription;
import org.apache.nifi.annotation.documentation.Tags;
import org.apache.nifi.components.PropertyDescriptor;
import org.apache.nifi.flowfile.FlowFile;
import org.apache.nifi.processor.*;
import org.apache.nifi.processor.exception.ProcessException;
import org.apache.nifi.processor.util.StandardValidators;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.*;

/**
 * NiFi Processor: Cyphera Protect
 *
 * Protects a field value using format-preserving encryption.
 * Reads the FlowFile content as a string, protects it, writes the result back.
 */
@Tags({"cyphera", "encrypt", "fpe", "format-preserving", "protect", "data-protection"})
@CapabilityDescription("Protects (encrypts) FlowFile content using Cyphera format-preserving encryption. "
        + "The entire FlowFile content is treated as the value to protect. "
        + "Use with policy-based routing to protect specific fields in your data flow.")
public class CypheraProtectProcessor extends AbstractProcessor {

    public static final PropertyDescriptor POLICY_NAME = new PropertyDescriptor.Builder()
            .name("policy-name")
            .displayName("Policy Name")
            .description("The Cyphera policy to use (e.g. 'ssn', 'credit_card'). Must match a policy in cyphera.json.")
            .required(true)
            .addValidator(StandardValidators.NON_EMPTY_VALIDATOR)
            .build();

    public static final Relationship REL_SUCCESS = new Relationship.Builder()
            .name("success")
            .description("FlowFiles that were successfully protected")
            .build();

    public static final Relationship REL_FAILURE = new Relationship.Builder()
            .name("failure")
            .description("FlowFiles that failed protection")
            .build();

    private Cyphera client;

    @Override
    protected void init(ProcessorInitializationContext context) {
        client = CypheraLoader.getInstance();
    }

    @Override
    public Set<Relationship> getRelationships() {
        return Set.of(REL_SUCCESS, REL_FAILURE);
    }

    @Override
    public List<PropertyDescriptor> getSupportedPropertyDescriptors() {
        return List.of(POLICY_NAME);
    }

    @Override
    public void onTrigger(ProcessContext context, ProcessSession session) throws ProcessException {
        FlowFile flowFile = session.get();
        if (flowFile == null) return;

        String policyName = context.getProperty(POLICY_NAME).getValue();

        try {
            // Read content
            byte[] content = new byte[(int) flowFile.getSize()];
            session.read(flowFile, in -> {
                int offset = 0;
                while (offset < content.length) {
                    int read = in.read(content, offset, content.length - offset);
                    if (read < 0) break;
                    offset += read;
                }
            });

            String value = new String(content, StandardCharsets.UTF_8).trim();
            String protectedValue = client.protect(value, policyName);

            // Write protected content
            flowFile = session.write(flowFile, out -> out.write(protectedValue.getBytes(StandardCharsets.UTF_8)));
            session.transfer(flowFile, REL_SUCCESS);
        } catch (Exception e) {
            getLogger().error("Cyphera protect failed: {}", e.getMessage(), e);
            session.transfer(flowFile, REL_FAILURE);
        }
    }
}
