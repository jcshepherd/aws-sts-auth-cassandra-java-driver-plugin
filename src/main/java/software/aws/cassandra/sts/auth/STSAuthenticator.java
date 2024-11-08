package software.aws.cassandra.sts.auth;

import java.net.URI;
import java.nio.Buffer;
import java.time.Instant;
import java.util.Base64;
import java.util.TreeMap;

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
import java.util.Arrays;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;

public class STSAuthenticator implements Authenticator {

    private static final byte[] NONCE_KEY = "nonce=".getBytes(StandardCharsets.UTF_8);

    private static final int EXPECTED_NONCE_LENGTH_BYTES = 24;

    private static final byte[] STS_INITIAL_RESPONSE_BYTES = "AWSSTS\0\0".getBytes(StandardCharsets.UTF_8);

    private static final ByteBuffer STS_INITIAL_RESPONSE;

    static {
        ByteBuffer initialResponse = ByteBuffer.allocate(STS_INITIAL_RESPONSE_BYTES.length);
        initialResponse.put(STS_INITIAL_RESPONSE_BYTES);
        ((Buffer)initialResponse).flip();
        // According to the driver docs, it's safe to reuse a
        // read-only buffer, and in our case, the initial response has
        // no sensitive information
        STS_INITIAL_RESPONSE = initialResponse.asReadOnlyBuffer();
    }

    @NonNull
    @Override
    public CompletionStage<ByteBuffer> initialResponse() {
        // We respond to AUTHENTICATE with a short token that confirms we intend to authenticate using STS.
        return CompletableFuture.completedFuture(STS_INITIAL_RESPONSE);
    }

    @NonNull
    @Override
    public CompletionStage<ByteBuffer> evaluateChallenge(@Nullable ByteBuffer challenge) {
        byte[] nonce = extractNonce(challenge);

        AwsCredentialsProvider credentialsProvider = DefaultCredentialsProvider.create();
        Region region = Region.US_WEST_2;

        String presignedSTSRequest = generatePresignedSTSRequest(nonce, credentialsProvider, region);

        return CompletableFuture.completedFuture(ByteBuffer.wrap(presignedSTSRequest.getBytes(StandardCharsets.UTF_8)));
    }

    @NonNull
    @Override
    public CompletionStage<Void> onAuthenticationSuccess(@Nullable ByteBuffer token) {
        return CompletableFuture.completedFuture(null);
    }

    private static byte[] extractNonce(ByteBuffer challenge) {
        int nonceStart = indexOf(challenge, NONCE_KEY);

        if (nonceStart < 0) {
            throw new IllegalArgumentException("Expected nonce not found in endpoint challenge");
        }

        nonceStart = nonceStart + NONCE_KEY.length;
        int nonceEnd = nonceStart;

        while (nonceEnd < challenge.remaining() && challenge.get(nonceEnd) != ',') {
            nonceEnd++;
        }

        int nonceLength = nonceEnd - nonceStart;

        if (nonceLength != EXPECTED_NONCE_LENGTH_BYTES) {
            throw new IllegalArgumentException("Expected nonce with " + EXPECTED_NONCE_LENGTH_BYTES + " bytes: " +
                                               nonceLength + " bytes found");
        }

        ((Buffer)challenge).clear();
        byte[] nonceBytes = new byte[challenge.remaining()];

        return Arrays.copyOfRange(nonceBytes, nonceStart, nonceEnd);
    }


    private String generatePresignedSTSRequest(byte[] nonce, AwsCredentialsProvider credentialsProvider, Region region) {
        // Convert nonce to Base64
        String encodedNonce = Base64.getEncoder().encodeToString(nonce);

        // Create the request
        TreeMap<String, String> queryParams = new TreeMap<>();
        queryParams.put("Action", "GetCallerIdentity");
        queryParams.put("Version", "2011-06-15");

        SdkHttpFullRequest.Builder requestBuilder = SdkHttpFullRequest.builder()
                .method(SdkHttpMethod.GET)
                .uri(URI.create("https://sts." + region.toString() + ".amazonaws.com"))
                .putRawQueryParameter("Action", "GetCallerIdentity")
                .putRawQueryParameter("Version", "2011-06-15")
                .putRawQueryParameter("X-C8-Nonce", encodedNonce);

        // Set up the signer
        Aws4Signer signer = Aws4Signer.create();
        Aws4PresignerParams presignerParams = Aws4PresignerParams.builder()
                .awsCredentials(credentialsProvider.resolveCredentials())
                .signingRegion(region)
                .signingName("sts")
                .expirationTime(Instant.now().plusSeconds(900)) // 15 minutes expiration
                .build();

        // Sign the request
        SdkHttpFullRequest signedRequest = signer.presign(requestBuilder.build(), presignerParams);

        // Build the final URL
        return signedRequest.getUri().toString();

    }

    private static int indexOf(ByteBuffer buffer, byte[] pattern) {
        //((Buffer) buffer).flip();

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
