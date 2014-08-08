/*
 * The MIT License
 *
 * Copyright (c) 2008-2014, Kohsuke Kawaguchi, CloudBees, Inc., and contributors
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
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

    /**
     * Computes the value for the given key.
     *
     * @return
     *      If this method returns normally, the result is cached, even if it is null.
     * @throws E
     *      To abort the cache computation. Exception is not cached.
     */
    protected abstract V compute(K key) throws E;
}
