package org.corzia.oidc.config;

import org.apache.shiro.session.mgt.SimpleSession;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.io.Serializable;

public class PreserveIdSessionIdGeneratorTest {

    @Test
    public void testGenerateId_withExistingId_shouldPreserveId() {
        PreserveIdSessionIdGenerator generator = new PreserveIdSessionIdGenerator();
        SimpleSession session = new SimpleSession();
        String expectedId = "browser123_tab456";
        session.setId(expectedId);

        Serializable actualId = generator.generateId(session);

        Assertions.assertEquals(expectedId, actualId, "Generator should preserve existing session ID");
    }

    @Test
    public void testGenerateId_withoutId_shouldGenerateNewUuid() {
        PreserveIdSessionIdGenerator generator = new PreserveIdSessionIdGenerator();
        SimpleSession session = new SimpleSession();
        // ID is null initially

        Serializable actualId = generator.generateId(session);

        Assertions.assertNotNull(actualId, "Generator should return a non-null ID");
        Assertions.assertTrue(actualId.toString().length() > 0, "Generated ID should not be empty");
        // We expect a UUID, so it should be relatively long
        Assertions.assertTrue(actualId.toString().length() > 20, "Generated ID should look like a UUID");
    }
}
