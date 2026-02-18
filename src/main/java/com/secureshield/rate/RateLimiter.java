package com.secureshield.rate;

import java.util.Deque;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedDeque;

public class RateLimiter {
    private static final long WINDOW_MS = 60_000;
    private final int maxRequests;
    private final Map<String, Deque<Long>> requestStore = new ConcurrentHashMap<>();

    public RateLimiter(int maxRequests) {
        this.maxRequests = maxRequests;
    }

    public boolean allow(String key) {
        long now = System.currentTimeMillis();
        Deque<Long> timestamps = requestStore.computeIfAbsent(key, k -> new ConcurrentLinkedDeque<>());

        while (!timestamps.isEmpty() && (now - timestamps.peekFirst()) > WINDOW_MS) {
            timestamps.pollFirst();
        }

        if (timestamps.size() >= maxRequests) {
            return false;
        }

        timestamps.addLast(now);
        return true;
    }
}
