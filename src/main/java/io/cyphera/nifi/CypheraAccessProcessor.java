package io.cyphera.nifi;

import io.cyphera.Cyphera;
import org.apache.nifi.annotation.documentation.CapabilityDescription;
import org.apache.nifi.annotation.documentation.Tags;
import org.apache.nifi.components.PropertyDescriptor;
import org.apache.nifi.flowfile.FlowFile;
import org.apache.nifi.processor.*;
import org.apache.nifi.processor.exception.ProcessException;

import java.nio.charset.StandardCharsets;
import java.util.*;

/**
 * NiFi Processor: Cyphera Access
 *
 * Accesses (decrypts) a protected value using the embedded tag.
 * No policy name needed — the tag identifies the policy.
 */
@Tags({"cyphera", "decrypt", "fpe", "format-preserving", "access", "data-protection"})
@CapabilityDescription("Accesses (decrypts) FlowFile content using Cyphera format-preserving encryption. "
        + "The embedded tag identifies which policy was used — no policy name needed.")
public class CypheraAccessProcessor extends AbstractProcessor {

    public static final Relationship REL_SUCCESS = new Relationship.Builder()
            .name("success")
            .description("FlowFiles that were successfully accessed")
            .build();

    public static final Relationship REL_FAILURE = new Relationship.Builder()
            .name("failure")
            .description("FlowFiles that failed access")
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
        return List.of();
    }

    @Override
    public void onTrigger(ProcessContext context, ProcessSession session) throws ProcessException {
        FlowFile flowFile = session.get();
        if (flowFile == null) return;

        try {
            byte[] content = new byte[(int) flowFile.getSize()];
            session.read(flowFile, in -> {
                int offset = 0;
                while (offset < content.length) {
                    int read = in.read(content, offset, content.length - offset);
                    if (read < 0) break;
                    offset += read;
                }
            });

            String protectedValue = new String(content, StandardCharsets.UTF_8).trim();
            String accessed = client.access(protectedValue);

            flowFile = session.write(flowFile, out -> out.write(accessed.getBytes(StandardCharsets.UTF_8)));
            session.transfer(flowFile, REL_SUCCESS);
        } catch (Exception e) {
            getLogger().error("Cyphera access failed: {}", e.getMessage(), e);
            session.transfer(flowFile, REL_FAILURE);
        }
    }
}
