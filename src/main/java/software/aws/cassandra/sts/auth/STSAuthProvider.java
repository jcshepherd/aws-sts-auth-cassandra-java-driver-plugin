package software.aws.cassandra.sts.auth;

import com.datastax.oss.driver.api.core.auth.AuthProvider;
import com.datastax.oss.driver.api.core.auth.AuthenticationException;
import com.datastax.oss.driver.api.core.auth.Authenticator;
import com.datastax.oss.driver.api.core.config.DriverExecutionProfile;
import com.datastax.oss.driver.api.core.context.DriverContext;
import com.datastax.oss.driver.api.core.metadata.EndPoint;
import edu.umd.cs.findbugs.annotations.NonNull;

/**
 * Implementation of{@link com.datastax.oss.driver.api.core.auth.AuthProvider} to enable client
 * authentication to Cassandra nodes using signed AWS STS GetCallerIdentity requests.
 */
public class STSAuthProvider implements AuthProvider {

    private final String logPrefix;
    private final DriverExecutionProfile config;

    public STSAuthProvider(DriverContext context) {
        logPrefix = context.getSessionName();
        this.config = context.getConfig().getDefaultProfile();
    }

    @NonNull
    @Override
    public Authenticator newAuthenticator(@NonNull EndPoint endPoint, @NonNull String authenticator)
            throws AuthenticationException {
        return new STSAuthenticator();
    }

    @Override
    public void onMissingChallenge(@NonNull EndPoint endPoint) throws AuthenticationException {
        throw new AuthenticationException(
                endPoint, "AWS STS authenticator requires a challenge from the endpoint. None was sent");
    }

    @Override
    public void close() throws Exception {
        // No resources to close.
    }
}
