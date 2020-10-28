package hudson.plugins.active_directory;

import org.kohsuke.accmod.Restricted;
import org.kohsuke.accmod.restrictions.NoExternalUse;

import java.util.Objects;

@Restricted(NoExternalUse.class)
public final class CacheKey {
    private final String username;
    private final String salt;
    private final String passwordHash;

    public CacheKey(String username, String salt, String passwordHash) {
        this.username = username;
        this.salt = salt;
        this.passwordHash = passwordHash;
    }

    public CacheKey(String username) {
        this.username = username;
        this.salt = null;
        this.passwordHash = null;
    }

    public String getUsername() {
        return username;
    }

    public String getSalt() {
        return salt;
    }

    public String getPasswordHash() {
        return passwordHash;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        CacheKey cacheKey = (CacheKey) o;
        return username.equals(cacheKey.username) &&
                Objects.equals(salt, cacheKey.salt) &&
                Objects.equals(passwordHash, cacheKey.passwordHash);
    }

    @Override
    public int hashCode() {
        return Objects.hash(username, salt, passwordHash);
    }
}
