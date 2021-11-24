package hudson.plugins.active_directory;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.github.benmanes.caffeine.cache.LoadingCache;
import com.google.common.base.Optional;
import hudson.security.GroupDetails;
import org.acegisecurity.userdetails.UserDetails;
import org.kohsuke.stapler.DataBoundConstructor;

import java.util.concurrent.TimeUnit;

/**
 * Cache configuration
 */
public class CacheConfiguration<K,V,E extends Exception> {
    private final int size;
    private final int ttl;

    /**
     * The {@link UserDetails} cache.
     */
    private transient final Cache<CacheKey, UserDetails> userCache;

    /**
     * The {@link ActiveDirectoryGroupDetails} cache.
     */
    private transient final Cache<String, Optional<GroupDetails>> groupCache;

    /**
     * CacheConfiguration DataBoundConstructor
     *
     * @param size of the cache in terms of number of elements
     * @param ttl of the cache in terms of seconds
     */
    @DataBoundConstructor
    public CacheConfiguration(int size, int ttl) {
        this.size = Math.max(0, Math.min(size, 1000));
        this.ttl = Math.max(0, Math.min(ttl, 3600));

        this.userCache = Caffeine.newBuilder()
                .maximumSize(getSize())
                .expireAfterWrite(getTtl(), TimeUnit.SECONDS)
                .build();

        this.groupCache = Caffeine.newBuilder()
                .maximumSize(getSize())
                .expireAfterWrite(getTtl(), TimeUnit.SECONDS)
                .build();
    }

    /**
     * Get size of the cache
     *
     * @return the size of the cache
     */
    public int getSize() {
        return size;
    }

    /**
     * Get TTL of the cache
     *
     * @return the ttl of the cache in seconds
     */
    public int getTtl() {
        return ttl;
    }

    /**
     * Get the cache for users
     *
     * @return the cache for users
     */
    public Cache<CacheKey, UserDetails> getUserCache() {
        return userCache;
    }

    /**
     * Get the cache for groups
     *
     * @return the cache for groups
     */
    public Cache<String, Optional<GroupDetails>> getGroupCache() {
        return groupCache;
    }
}
