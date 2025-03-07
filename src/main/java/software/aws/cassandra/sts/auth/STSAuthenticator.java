package software.aws.cassandra.sts.auth;

import java.net.URI;
import java.nio.Buffer;
import java.time.Instant;
import java.util.Base64;

import com.datastax.oss.driver.api.core.auth.Authenticator;
import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.Nullable;
import software.amazon.awssdk.auth.credentials.AwsCredentialsProvider;
import software.amazon.awssdk.auth.credentials.DefaultCredentialsProvider;
import software.amazon.awssdk.auth.signer.Aws4Signer;
import software.amazon.awssdk.auth.signer.params.Aws4PresignerParams;
import software.amazon.awssdk.http.SdkHttpFullRequest;
import software.amazon.awssdk.http.SdkHttpMethod;
import software.amazon.awssdk.regions.Region;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;

/**
 * Client/driver-side support for authenticating to a Cassandra node using the client's AWS IAM credentials. Note
 * that the "nonce" provided by the node in its AUTH_CHALLENGE must be included in the signed request, as the
 * "X-C8-Nonce" query parameter.
 */
public class STSAuthenticator implements Authenticator {

    private static final byte[] STS_INITIAL_RESPONSE_BYTES = "AWSSTS\0\0".getBytes(StandardCharsets.UTF_8);

    private static final ByteBuffer STS_INITIAL_RESPONSE;

    /** Header for passing back the node-provide "nonce" in the signed GetCallerIdentity request. */
    private static final String NONCE_QUERY_PARAM = "X-C8-Nonce";

    /** Expected key for the node-provided nonce in its AUTH_CHALLENGE message to this client. */
    static final byte[] NONCE_KEY = "nonce=".getBytes(StandardCharsets.UTF_8);

    /** Expected length of the nonce, in bytes (16 byte nonce, Base-64 encoded). */
    private static final int EXPECTED_NONCE_LENGTH_BYTES = 24;

    /*
     * One-time initialization of the initial response bytebuffer. According to the driver docs, it's
     * safe to reuse a read-only buffer, and in our case, the initial response has no sensitive
     * information.
     */
    static {
        ByteBuffer initialResponse = ByteBuffer.allocate(STS_INITIAL_RESPONSE_BYTES.length);
        initialResponse.put(STS_INITIAL_RESPONSE_BYTES);
        // Certain byte buffer operations (e.g. flip(), clear()) will fail at runtime if the code
        // is compiled with a newer JDK (> 8) but run against an older JRE. Preemptively casting
        // to Buffer avoids the runtime failures by ensuring the base class method is always invoked.
        ((Buffer)initialResponse).flip();
        STS_INITIAL_RESPONSE = initialResponse.asReadOnlyBuffer();
    }

    /**
     * AWS (IAM) credentials provider for this authenticator instance. If not specified uses the
     * DefaultCredentialsProvider.
     */
    private AwsCredentialsProvider credentialsProvider;

    /**
     * The AWS region for the STS region that the node will call to authenticate this client. This
     * is often the same region as the client itself, but may be different when clients are calling
     * across regions. If not specified, defaults to US_WEST_2.
     *
     * TODO - This seems bogus on several levels. Should the node be telling the client what region to use?
     */
    private Region region;

    public STSAuthenticator() {
        this.credentialsProvider = DefaultCredentialsProvider.create();
        this.region = Region.US_WEST_2;
    }

    public STSAuthenticator(AwsCredentialsProvider credentialsProvider, Region region) {
        this.credentialsProvider = credentialsProvider;
        this.region = region;
    }

    /**
     * We respond to AUTHENTICATE with a short token that confirms we intend to authenticate using STS.
     */
    @NonNull
    @Override
    public CompletionStage<ByteBuffer> initialResponse() {
        return CompletableFuture.completedFuture(STS_INITIAL_RESPONSE);
    }

    /**
     * The node has sent an AUTH_CHALLENGE with a nonce: our AUTH_RESPONSE is an AWS STS GetCallerIdentity request,
     * signed with the IAM credentials for the IAM principal (user, role, etc.) that we wish to authenticate as,
     * with the node-provided nonce included as the "X-C8-Nonce" param (which must be included in the signature).
     * @param challenge Expect a node-provided, Base64-encoded 16 byte nonce.
     * @return A signed GetCallerIdentity request.
     */
    @NonNull
    @Override
    public CompletionStage<ByteBuffer> evaluateChallenge(@Nullable ByteBuffer challenge) {
        byte[] nonce = extractNonce(challenge);

        String signedSTSRequest = generateSignedSTSRequest(nonce, credentialsProvider, region);

        return CompletableFuture.completedFuture(ByteBuffer.wrap(signedSTSRequest.getBytes(StandardCharsets.UTF_8)));
    }

    /**
     * The node has responded with READY: no further action required for authentication.
     */
    @NonNull
    @Override
    public CompletionStage<Void> onAuthenticationSuccess(@Nullable ByteBuffer token) {
        return CompletableFuture.completedFuture(null);
    }

    /**
     * Extracts the node-provided nonce from its AUTH_CHALLENGE payload.
     * @param challenge Expected to be node-provided, Base64-encoded 16-byte nonce, prefixed
     *                  with "nonce=" (NONCE_KEY).
     * @return The nonce, as a decoded byte array.
     */
    private static byte[] extractNonce(ByteBuffer challenge) {
        ByteBuffer view = challenge.duplicate();

        int nonceStart = indexOf(view, NONCE_KEY);

        if (nonceStart < 0) {
            throw new IllegalArgumentException("Expected nonce not found in endpoint challenge");
        }

        nonceStart += NONCE_KEY.length;

        if ((view.remaining() - nonceStart) < EXPECTED_NONCE_LENGTH_BYTES) {
            throw new IllegalArgumentException("Node provided invalid nonce: insufficient data");
        }

        ((Buffer)view).position(nonceStart);

        byte[] nonceBytes = new byte[EXPECTED_NONCE_LENGTH_BYTES];
        int bytesRead = 0;

        while (bytesRead < EXPECTED_NONCE_LENGTH_BYTES && view.hasRemaining()) {
            byte b = view.get();
            if (b == ',') {
                break;
            }

            nonceBytes[bytesRead++] = b;
        }


        if (bytesRead != EXPECTED_NONCE_LENGTH_BYTES) {
            throw new IllegalArgumentException(String.format("Expected nonce with %d bytes: %d bytes found",
                                                             EXPECTED_NONCE_LENGTH_BYTES, bytesRead));
        }

        ((Buffer)challenge).clear();

        try {
            return Base64.getDecoder().decode(nonceBytes);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("Node provided invalid nonce: not Base-64 encoded", e);
        }
    }


    /**
     * Generates a signed GetCallerIdentity request using this client's IAM credentials, and including
     * node-provided nonce.
     * @param nonce The nonce, as a decoded byte array.
     * @param credentialsProvider The AWS credentials provider to use for signing the request.
     * @param region The AWS region to use for signing the request. This is the region of the node, not the region
     *               of the client.
     * @return The signed GetCallerIdentity request.
     */
    private String generateSignedSTSRequest(byte[] nonce, AwsCredentialsProvider credentialsProvider, Region region) {

        SdkHttpFullRequest.Builder requestBuilder = SdkHttpFullRequest.builder()
                .method(SdkHttpMethod.GET)
                .uri(URI.create("https://sts." + region.toString() + ".amazonaws.com"))
                .putRawQueryParameter("Action", "GetCallerIdentity")
                .putRawQueryParameter("Version", "2011-06-15")
                .putRawQueryParameter(NONCE_QUERY_PARAM, Base64.getEncoder().encodeToString(nonce));


        Aws4Signer signer = Aws4Signer.create();
        Aws4PresignerParams signedParams = Aws4PresignerParams.builder()
                .awsCredentials(credentialsProvider.resolveCredentials())
                .signingRegion(region)
                .signingName("sts")
                .expirationTime(Instant.now().plusSeconds(60)) // 15 minutes expiration
                .build();

        SdkHttpFullRequest signedRequest = signer.presign(requestBuilder.build(), signedParams);

        return signedRequest.getUri().toString();
    }

    /**
     * Returns the zero-based index of the first occurrence of the pattern in the buffer. This is a common
     * operation but is implemented directly here to reduce external dependencies.T
     * @param buffer The buffer to search.
     * @param pattern The pattern to search for.
     * @return The zero-based index of the first byte of the first occurrence of the pattern in the buffer,
     *         or -1 if not found.
     */
    private static int indexOf(ByteBuffer buffer, byte[] pattern) {

        if (buffer == null || pattern == null || buffer.remaining() < pattern.length) {
            return -1;
        }

        int bufferLength = buffer.remaining();
        int patternLength = pattern.length;

        for (int i = 0; i <= bufferLength - patternLength; i++) {
            if (buffer.get(i) != pattern[0]) {
                continue;
            }

            boolean found = true;

            for (int j = 0; j < patternLength; j++) {
                if (buffer.get(i + j) != pattern[j]) {
                    found = false;
                    break;
                }
            }

            if (found) {
                return i;
            }
        }

        return -1;
    }
}
