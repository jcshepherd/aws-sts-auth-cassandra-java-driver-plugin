package software.aws.cassandra.sts.auth;

import java.io.UnsupportedEncodingException;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLEncoder;
import java.util.HashMap;
import java.util.Map;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.AwsCredentialsProvider;
import software.amazon.awssdk.regions.Region;

import java.nio.Buffer;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Random;
import java.util.concurrent.ExecutionException;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

/**
 * Unit tests for {@link STSAuthenticator}.
 */
public class STSAuthenticatorTest {

    /**
     * Mock credentials provider for testing purposes.
     */
    private MockCredentialsProvider mockCredentialsProvider;

    /** Predictably generate "random" nonces for testing purposes. */
    private static final Random RND = new Random();

    private static final Map<String, Map<String, String>> AUTH_PARAMS;

    static {
        AUTH_PARAMS = new HashMap<>();
        Map<String, String> US_EAST_REQ_1 = new HashMap<>();
        US_EAST_REQ_1.put("Region", "us-east-1");
        US_EAST_REQ_1.put("AccessKey", newAccessKey());
        AUTH_PARAMS.put("US_EAST_REQ_1", US_EAST_REQ_1);

        Map<String, String> US_WEST_REQ_1 = new HashMap<>();
        US_WEST_REQ_1.put("Region", "us-west-2");
        US_WEST_REQ_1.put("AccessKey", newAccessKey());
        AUTH_PARAMS.put("US_WEST_REQ_1", US_WEST_REQ_1);

        Map<String, String> US_WEST_REQ_2 = new HashMap<>();
        US_WEST_REQ_2.put("Region", "us-west-2");
        US_WEST_REQ_2.put("AccessKey", newAccessKey());
        AUTH_PARAMS.put("US_WEST_REQ_2", US_WEST_REQ_2);

        Map<String, String> EU_WEST_REQ_1 = new HashMap<>();
        EU_WEST_REQ_1.put("Region", "eu-west-1");
        EU_WEST_REQ_1.put("AccessKey", newAccessKey());
        AUTH_PARAMS.put("EU_WEST_REQ_1", EU_WEST_REQ_1);
    }

    /** Provides mock AWS credentials for testing purposes. */
    private static class MockCredentialsProvider implements AwsCredentialsProvider {

        String accessKey;
        String otherKey;

        public MockCredentialsProvider() {
            this(newAccessKey());
        }

        public MockCredentialsProvider(String accessKey) {
            this.accessKey = accessKey;
            this.otherKey = newAccessKey();
        }

        @Override
        public AwsBasicCredentials resolveCredentials() {
            return AwsBasicCredentials.create("accessKey", "secretKey");
        }
    }

    @BeforeEach
    public void setup() {
        mockCredentialsProvider = new MockCredentialsProvider();
    }

    @AfterEach
    public void teardown() {
        mockCredentialsProvider = null;
    }

    /**
     * Validates that the authenticator produces the correct response to a node's initial AUTHENTICATE message.
     */
    @Test
    public void testInitialResponse() throws Exception {
        STSAuthenticator authenticator = new STSAuthenticator(mockCredentialsProvider, Region.US_EAST_1);
        ByteBuffer initialResponse = authenticator.initialResponse().toCompletableFuture().get();

        // Verify the initial response contains "AWSSTS\0\0"
        byte[] expected = "AWSSTS\0\0".getBytes(StandardCharsets.UTF_8);
        byte[] actual = new byte[initialResponse.remaining()];
        initialResponse.get(actual);

        assertArrayEquals(expected, actual);
    }


    /**
     * Test authentication flow with mocked credentials: confirm that a valid URL is returned, that it has the
     * appropriate region, endpoint and nonce. This exercises several combinations of regions, access keys,
     * etc., to ensure nothing is being accidentally retained across authentication attempts.
     */
    @Test
    public void testCredentialsProvider() throws InterruptedException, ExecutionException, UnsupportedEncodingException {
        for (Map.Entry<String, Map<String, String>> params: AUTH_PARAMS.entrySet()) {
            String test = params.getKey();
            String accessKey = params.getValue().get("AccessKey");
            String region = params.getValue().get("Region");
            byte[] nonce = newNonce(16);
            STSAuthenticator authenticator = new STSAuthenticator(new MockCredentialsProvider(accessKey), Region.of(region));
            ByteBuffer buffer = authenticator.evaluateChallenge(newAuthChallenge(nonce)).toCompletableFuture().get();
            String challengeResponse = StandardCharsets.UTF_8.decode(buffer).toString();

            URL url = null;

            try {
                url = new URL(challengeResponse);
            } catch (MalformedURLException e) {
                fail("Invalid URL format: " + challengeResponse + " for test " + test);
            }

            assertTrue(url.getProtocol().startsWith("https"), test);
            assertTrue(url.getHost().startsWith("sts." + region), test);
            assertTrue(url.getHost().endsWith("amazonaws.com"), test);
            String encodedNonce = new String(encodeNonce(nonce), StandardCharsets.US_ASCII);
            String httpEncodedNonce = URLEncoder.encode(encodedNonce, StandardCharsets.UTF_8.toString());
            assertTrue(url.getQuery().contains("X-C8-Nonce=" + httpEncodedNonce), test);
        }
    }

    /**
     * Validates that the authenticator correctly fails if the node-provided nonce is less than the expected length.
     */
    @Test
    public void testEvaluateChallengeWithInvalidNonce() {
        STSAuthenticator authenticator = new STSAuthenticator(mockCredentialsProvider, Region.US_EAST_1);

        // Create an invalid nonce challenge
        ByteBuffer challenge = newAuthChallenge(12);

        assertThrows(IllegalArgumentException.class, () -> {
            authenticator.evaluateChallenge(challenge).toCompletableFuture().get();
        });
    }


    /**
     * Validates that the authenticator correctly fails if the node-provided nonce is less than the expected length.
     * <p>
     * Test is currently disabled. A server passing a oversized nonce should lead to an authn failure because the
     * client will return a truncated nonce to the server. But it'd be nice to fail on this client-side.
     */
    @Disabled
    @Test
    public void testEvaluateChallengeWithInvalidLongNonce() {
        STSAuthenticator authenticator = new STSAuthenticator(mockCredentialsProvider, Region.US_WEST_2);

        // Create an invalid nonce challenge
        ByteBuffer challenge = newAuthChallenge(19);

        assertThrows(IllegalArgumentException.class, () -> {
            authenticator.evaluateChallenge(challenge).toCompletableFuture().get();
        });
    }

    /**
     * Creates and returns a ByteBuffer containing a mock nonce challenge.
     * @param lengthInBytes Length of the nonce, in bytes.
     * @return A ByteBuffer containing a mock nonce challenge.
     */
    private static ByteBuffer newAuthChallenge(int lengthInBytes) {
        return newAuthChallenge(newNonce(lengthInBytes));
    }

    /**
     * Creates and returns a ByteBuffer containing a mock nonce challenge.
     * @param nonce The nonce to use in the challenge.
     * @return A ByteBuffer containing a mock nonce challenge.
     */
    private static ByteBuffer newAuthChallenge(byte[] nonce) {
        byte[] encodedNonce = Base64.getEncoder().encode(nonce);
        ByteBuffer buffer = ByteBuffer.allocate(STSAuthenticator.NONCE_KEY.length + encodedNonce.length);
        buffer.put(STSAuthenticator.NONCE_KEY);
        return (ByteBuffer) ((Buffer) buffer.put(encodedNonce).flip());
    }

    /**
     * Encodes a nonce in Base64 format.
     * @param nonce The nonce to encode.
     * @return The Base64-encoded nonce.
     */
    private byte[] encodeNonce(byte[] nonce) {
        return Base64.getEncoder().encode(nonce);
    }

    /**
     * Creates and returns a fixed-length nonce of random bytes.
     * @param length Length of the nonce, in bytes.
     * @return A randomly generated nonce.
     */
    private static byte[] newNonce(int length) {
        byte[] randomBytes = new byte[length];
        RND.nextBytes(randomBytes);
        return randomBytes;
    }

    /**
     * Creates and returns a new mock "access key".
     * @return A String that can be used as a mock access key.
     */
    private static String newAccessKey() {
        String alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
        StringBuilder sb = new StringBuilder(12);
        Random random = new Random();

        for (int i = 0; i < 12; i++) {
            sb.append(alphabet.charAt(random.nextInt(alphabet.length())));
        }

        return sb.toString();
    }
}
