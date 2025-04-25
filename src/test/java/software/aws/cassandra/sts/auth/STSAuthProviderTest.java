package software.aws.cassandra.sts.auth;

import com.datastax.oss.driver.api.core.auth.AuthenticationException;
import com.datastax.oss.driver.api.core.auth.Authenticator;
import com.datastax.oss.driver.api.core.config.DriverConfig;
import com.datastax.oss.driver.api.core.config.DriverExecutionProfile;
import com.datastax.oss.driver.api.core.context.DriverContext;
import com.datastax.oss.driver.api.core.metadata.EndPoint;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.BeforeEach;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link STSAuthProvider}.
 */
public class STSAuthProviderTest {

    private DriverContext mockContext;
    private DriverConfig mockConfig;
    private DriverExecutionProfile mockProfile;

    @BeforeEach
    public void setup() {
        mockContext = mock(DriverContext.class);
        mockConfig = mock(DriverConfig.class);
        mockProfile = mock(DriverExecutionProfile.class);

        when(mockContext.getSessionName()).thenReturn("testSession");
        when(mockContext.getConfig()).thenReturn(mockConfig);
        when(mockConfig.getDefaultProfile()).thenReturn(mockProfile);
    }


    @Test
    public void testConstructorInitialization() {
        STSAuthProvider provider = new STSAuthProvider(mockContext);
        // Verify provider was initialized correctly (if you have getters)
    }

    @Test
    public void testNewAuthenticatorCreation() {
        STSAuthProvider provider = new STSAuthProvider(mockContext);
        EndPoint mockEndpoint = mock(EndPoint.class);

        Authenticator authenticator = provider.newAuthenticator(mockEndpoint, "TestAuthenticator");

        assertNotNull(authenticator);
        assertTrue(authenticator instanceof STSAuthenticator);
    }

    @Test
    public void testOnMissingChallengeThrowsException() {
        STSAuthProvider provider = new STSAuthProvider(mockContext);
        EndPoint mockEndpoint = mock(EndPoint.class);

        assertThrows(AuthenticationException.class, ()->provider.onMissingChallenge(mockEndpoint));
    }

    @Test
    public void testOnMissingChallengeExceptionMessage() {
        STSAuthProvider provider = new STSAuthProvider(mockContext);
        EndPoint mockEndpoint = mock(EndPoint.class);

        Exception e = assertThrows(AuthenticationException.class, ()->provider.onMissingChallenge(mockEndpoint));
        assertTrue(e.getMessage().contains("AWS STS authenticator requires a challenge from the endpoint."));
    }

    @Test
    public void testCloseDoesNotThrowException() throws Exception {
        STSAuthProvider provider = new STSAuthProvider(mockContext);
        provider.close();
    }
}
