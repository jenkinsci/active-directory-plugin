package hudson.plugins.active_directory;

import hudson.util.TimeUnit2;
import org.apache.commons.collections.map.LRUMap;

/**
 * Cache.
 *
 * Can't use Guava because Jenkins up to 1.463 bundles Guava 9 where cache is beta (and indeed there was a signature change)
 *
 * @author Kohsuke Kawaguchi
 */
public abstract class Cache<K,V,E extends Exception> {
    private final LRUMap/*<String,GroupCacheEntry>*/ store = new LRUMap(256);

    static class Entry<V> {
        final V value;
        long timestamp = System.currentTimeMillis();

        Entry(V value) {
            this.value = value;
        }

        public boolean isStale() {
            return (System.currentTimeMillis() - timestamp) > TimeUnit2.MINUTES.toMillis(10);
        }
    }

    public synchronized V get(K key) throws E {
        Entry<V> e = (Entry<V>)store.get(key);
        if (e!=null) {
            if (!e.isStale())
                return e.value;
            else
                store.remove(key);
        }

        V val = compute(key);
        store.put(key, new Entry<V>(val));
        return val;
    }

    protected abstract V compute(K key) throws E;
}
