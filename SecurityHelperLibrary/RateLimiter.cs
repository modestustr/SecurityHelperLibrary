using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;

namespace SecurityHelperLibrary
{
    /// <summary>
    /// Thread-safe rate limiter to prevent brute-force attacks.
    /// Implements token bucket algorithm with automatic cleanup.
    /// </summary>
    public class RateLimiter
    {
        private readonly int _maxAttempts;
        private readonly TimeSpan _windowDuration;
        private readonly ConcurrentDictionary<string, List<DateTime>> _attemptHistory;
        private readonly object _cleanupLock = new object();
        private DateTime _lastCleanup = DateTime.UtcNow;

        /// <summary>
        /// Initialize rate limiter with attempt limits and time window.
        /// </summary>
        /// <param name="maxAttempts">Maximum allowed attempts in the window (default: 5)</param>
        /// <param name="windowDurationSeconds">Time window in seconds (default: 60)</param>
        public RateLimiter(int maxAttempts = 5, int windowDurationSeconds = 60)
        {
            if (maxAttempts < 1)
                throw new ArgumentOutOfRangeException(nameof(maxAttempts), "Must be at least 1");
            if (windowDurationSeconds < 1)
                throw new ArgumentOutOfRangeException(nameof(windowDurationSeconds), "Must be at least 1");

            _maxAttempts = maxAttempts;
            _windowDuration = TimeSpan.FromSeconds(windowDurationSeconds);
            _attemptHistory = new ConcurrentDictionary<string, List<DateTime>>();
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

            _attemptHistory.AddOrUpdate(
                identifier,
                key => new List<DateTime> { now },
                (key, attempts) =>
                {
                    // Remove attempts outside the window
                    attempts.RemoveAll(t => now - t > _windowDuration);

                    // Check if limit exceeded BEFORE adding new attempt
                    if (attempts.Count >= _maxAttempts)
                        return attempts; // Don't add, return unchanged to trigger false return

                    // Add current attempt
                    attempts.Add(now);
                    return attempts;
                });

            // Get current attempt count to return result
            var currentAttempts = _attemptHistory[identifier];
            return currentAttempts.Count < _maxAttempts;
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

            if (!_attemptHistory.TryGetValue(identifier, out var attempts))
                return _maxAttempts;

            var validAttempts = attempts
                .Where(t => DateTime.UtcNow - t <= _windowDuration)
                .ToList();

            return Math.Max(0, _maxAttempts - validAttempts.Count);
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
        private void PeriodicCleanup()
        {
            // Cleanup every 5 minutes
            if (DateTime.UtcNow - _lastCleanup < TimeSpan.FromMinutes(5))
                return;

            lock (_cleanupLock)
            {
                if (DateTime.UtcNow - _lastCleanup < TimeSpan.FromMinutes(5))
                    return;

                var now = DateTime.UtcNow;
                var keysToClean = new List<string>();

                foreach (var kvp in _attemptHistory)
                {
                    kvp.Value.RemoveAll(t => now - t > _windowDuration);
                    if (kvp.Value.Count == 0)
                        keysToClean.Add(kvp.Key);
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
