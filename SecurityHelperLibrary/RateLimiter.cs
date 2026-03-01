using System;
using System.Collections.Concurrent;
using System.Collections.Generic;

namespace SecurityHelperLibrary
{
    /// <summary>
    /// Thread-safe rate limiter to prevent brute-force attacks.
    /// Implements token bucket algorithm with automatic cleanup.
    /// </summary>
    public class RateLimiter
    {
        private sealed class AttemptBucket
        {
            public Queue<DateTime> Attempts { get; } = new Queue<DateTime>();

            public object SyncRoot { get; } = new object();
        }

        private readonly int _maxAttempts;
        private readonly TimeSpan _windowDuration;
        private readonly int _maxTrackedIdentifiers;
        private readonly ConcurrentDictionary<string, AttemptBucket> _attemptHistory;
        private readonly object _cleanupLock = new object();
        private DateTime _lastCleanup = DateTime.UtcNow;

        /// <summary>
        /// Initialize rate limiter with attempt limits and time window.
        /// </summary>
        /// <param name="maxAttempts">Maximum allowed attempts in the window (default: 5)</param>
        /// <param name="windowDurationSeconds">Time window in seconds (default: 60)</param>
        /// <param name="maxTrackedIdentifiers">Maximum distinct identifiers tracked in memory (default: 100000)</param>
        public RateLimiter(int maxAttempts = 5, int windowDurationSeconds = 60, int maxTrackedIdentifiers = 100000)
        {
            if (maxAttempts < 1)
                throw new ArgumentOutOfRangeException(nameof(maxAttempts), "Must be at least 1");
            if (windowDurationSeconds < 1)
                throw new ArgumentOutOfRangeException(nameof(windowDurationSeconds), "Must be at least 1");
            if (maxTrackedIdentifiers < 1)
                throw new ArgumentOutOfRangeException(nameof(maxTrackedIdentifiers), "Must be at least 1");

            _maxAttempts = maxAttempts;
            _windowDuration = TimeSpan.FromSeconds(windowDurationSeconds);
            _maxTrackedIdentifiers = maxTrackedIdentifiers;
            _attemptHistory = new ConcurrentDictionary<string, AttemptBucket>();
        }

        /// <summary>
        /// Check if an identifier (IP, username, etc) has exceeded rate limit.
        /// </summary>
        /// <param name="identifier">Unique identifier (IP address, username, etc)</param>
        /// <returns>True if request is allowed, false if rate limit exceeded</returns>
        public bool IsAllowed(string identifier)
        {
            if (string.IsNullOrWhiteSpace(identifier))
                throw new ArgumentNullException(nameof(identifier));

            PeriodicCleanup();
            var now = DateTime.UtcNow;

            if (!TryGetOrCreateBucket(identifier, out var bucket))
                return false;

            lock (bucket.SyncRoot)
            {
                while (bucket.Attempts.Count > 0 && now - bucket.Attempts.Peek() > _windowDuration)
                    bucket.Attempts.Dequeue();

                if (bucket.Attempts.Count >= _maxAttempts)
                    return false;

                bucket.Attempts.Enqueue(now);
                return true;
            }
        }

        /// <summary>
        /// Get remaining attempts for identifier before rate limit.
        /// </summary>
        /// <param name="identifier">Unique identifier</param>
        /// <returns>Number of remaining attempts (0 if limit exceeded)</returns>
        public int GetRemainingAttempts(string identifier)
        {
            if (string.IsNullOrWhiteSpace(identifier))
                throw new ArgumentNullException(nameof(identifier));

            if (!_attemptHistory.TryGetValue(identifier, out var bucket))
                return _maxAttempts;

            int validCount;
            var now = DateTime.UtcNow;
            lock (bucket.SyncRoot)
            {
                while (bucket.Attempts.Count > 0 && now - bucket.Attempts.Peek() > _windowDuration)
                    bucket.Attempts.Dequeue();

                validCount = bucket.Attempts.Count;
            }

            return Math.Max(0, _maxAttempts - validCount);
        }

        /// <summary>
        /// Reset rate limit for specific identifier.
        /// </summary>
        /// <param name="identifier">Unique identifier to reset</param>
        public void Reset(string identifier)
        {
            if (string.IsNullOrWhiteSpace(identifier))
                throw new ArgumentNullException(nameof(identifier));

            _attemptHistory.TryRemove(identifier, out _);
        }

        /// <summary>
        /// Clear all rate limit history.
        /// </summary>
        public void ClearAll()
        {
            _attemptHistory.Clear();
        }

        /// <summary>
        /// Periodic cleanup of expired attempts to prevent memory leaks.
        /// </summary>
        private bool TryGetOrCreateBucket(string identifier, out AttemptBucket bucket)
        {
            if (_attemptHistory.TryGetValue(identifier, out bucket))
                return true;

            if (_attemptHistory.Count >= _maxTrackedIdentifiers)
            {
                PeriodicCleanup(force: true);

                if (_attemptHistory.Count >= _maxTrackedIdentifiers)
                {
                    bucket = null;
                    return false;
                }
            }

            bucket = _attemptHistory.GetOrAdd(identifier, _ => new AttemptBucket());
            return true;
        }

        private void PeriodicCleanup(bool force = false)
        {
            // Cleanup every 5 minutes
            if (!force && DateTime.UtcNow - _lastCleanup < TimeSpan.FromMinutes(5))
                return;

            lock (_cleanupLock)
            {
                if (!force && DateTime.UtcNow - _lastCleanup < TimeSpan.FromMinutes(5))
                    return;

                var now = DateTime.UtcNow;
                var keysToClean = new List<string>();

                foreach (var kvp in _attemptHistory)
                {
                    lock (kvp.Value.SyncRoot)
                    {
                        while (kvp.Value.Attempts.Count > 0 && now - kvp.Value.Attempts.Peek() > _windowDuration)
                            kvp.Value.Attempts.Dequeue();

                        if (kvp.Value.Attempts.Count == 0)
                            keysToClean.Add(kvp.Key);
                    }
                }

                foreach (var key in keysToClean)
                    _attemptHistory.TryRemove(key, out _);

                _lastCleanup = now;
            }
        }

        /// <summary>
        /// Get total number of tracked identifiers.
        /// </summary>
        public int GetTrackedIdentifierCount() => _attemptHistory.Count;
    }
}
