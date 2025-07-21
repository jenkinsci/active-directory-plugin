package hudson.plugins.active_directory;

import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import org.kohsuke.accmod.Restricted;
import org.kohsuke.accmod.restrictions.NoExternalUse;
import org.springframework.security.crypto.bcrypt.BCrypt;

import edu.umd.cs.findbugs.annotations.CheckForNull;
import edu.umd.cs.findbugs.annotations.NonNull;
import java.security.SecureRandom;
import java.util.Objects;
import java.util.Set;

@Restricted(NoExternalUse.class)
public final class CacheUtil {
    private static final int BCRYPT_MAX_LENGTH = 72;
    @SuppressFBWarnings("MS_SHOULD_BE_FINAL")
    public static /* non-final for Groovy */ boolean NO_CACHE_AUTH = Boolean.getBoolean(CacheUtil.class.getName() + ".noCacheAuth"); // Groovy console: hudson.plugins.active_directory.CacheUtil.NO_CACHE_AUTH = true
    @SuppressFBWarnings("MS_SHOULD_BE_FINAL")
    public static /* non-final for Groovy */ int BCRYPT_ROUNDS = Integer.getInteger(CacheUtil.class.getName() + ".bcryptLogRounds", 10); // Groovy console: hudson.plugins.active_directory.CacheUtil.BCRYPT_ROUNDS = 20

    private static final SecureRandom RANDOM = new SecureRandom();

    private CacheUtil() {
        // prevent instantiation
    }

    public static @CheckForNull
    CacheKey computeCacheKey(@NonNull String username, @NonNull AbstractActiveDirectoryAuthenticationProvider.Password password, Set<CacheKey> existingKeys) {
        Objects.requireNonNull(username);
        Objects.requireNonNull(password);

        if (password instanceof AbstractActiveDirectoryAuthenticationProvider.UserPassword) {
            if (NO_CACHE_AUTH) {
                // we're not caching authentications
                return null;
            }

            CacheKey existingKey = findExistingKeyForUserAndPasswordInSet(username, ((AbstractActiveDirectoryAuthenticationProvider.UserPassword) password).getPassword(), existingKeys);
            if (existingKey != null) {
                return existingKey;
            }

            String salt = computeSalt();
            final String passwordHash = computeHash(((AbstractActiveDirectoryAuthenticationProvider.UserPassword) password).getPassword(), salt);
            return new CacheKey(username, salt, passwordHash);
        }

        // password is null, this isn't authentication
        return new CacheKey(username);
    }

    private static String computeHash(@NonNull String password, String salt) {
        return BCrypt.hashpw(password, salt);
    }

    private static CacheKey findExistingKeyForUserAndPasswordInSet(String username, String password, Set<CacheKey> existingKeys) {
        for (CacheKey key : existingKeys) {
            if (key.getSalt() == null || key.getPasswordHash() == null) {
                // lookup cache key only
                continue;
            }
            if (!Objects.equals(key.getUsername(), username)) {
                continue;
            }
            // At this point, username matches.
            // Next, truncate the password to 72 bytes due to the length limit of BCrypt, otherwise Spring's impl would throw.
            // TODO We should use an unlimited length password hash here, but realistically this is unlikely to be a problem
            byte[] passwordBytes = password.getBytes(StandardCharsets.UTF_8);
            if (passwordBytes.length > BCRYPT_MAX_LENGTH) {
                passwordBytes = Arrays.copyOfRange(passwordBytes, 0, BCRYPT_MAX_LENGTH);
            }
            if (BCrypt.checkpw(passwordBytes, key.getPasswordHash())) {
                return key;
            }
        }
        return null;
    }

    private static String computeSalt() {
        return BCrypt.gensalt(BCRYPT_ROUNDS);
    }
}
