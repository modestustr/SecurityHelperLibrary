using Xunit;
using System;
using System.Threading.Tasks;
using SecurityHelperLibrary;

namespace SecurityHelperLibrary.Tests
{
    public class RateLimiterTests
    {
        [Fact]
        [Trait("Category", "RateLimiting")]
        public void RateLimiter_AllowedWithinLimit()
        {
            var limiter = new RateLimiter(maxAttempts: 3, windowDurationSeconds: 10);

            // First 3 attempts should be allowed
            Assert.True(limiter.IsAllowed("user1"));
            Assert.True(limiter.IsAllowed("user1"));
            Assert.True(limiter.IsAllowed("user1"));

            // 4th attempt should be denied
            Assert.False(limiter.IsAllowed("user1"));
        }

        [Fact]
        [Trait("Category", "RateLimiting")]
        public void RateLimiter_DifferentIdentifiersIsolated()
        {
            var limiter = new RateLimiter(maxAttempts: 2, windowDurationSeconds: 10);

            // User1 uses 2 attempts
            Assert.True(limiter.IsAllowed("user1"));
            Assert.True(limiter.IsAllowed("user1"));
            Assert.False(limiter.IsAllowed("user1"));

            // User2 should have independent limit
            Assert.True(limiter.IsAllowed("user2"));
            Assert.True(limiter.IsAllowed("user2"));
            Assert.False(limiter.IsAllowed("user2"));
        }

        [Fact]
        [Trait("Category", "RateLimiting")]
        public void RateLimiter_GetRemainingAttempts()
        {
            var limiter = new RateLimiter(maxAttempts: 5, windowDurationSeconds: 10);

            Assert.Equal(5, limiter.GetRemainingAttempts("user1"));
            limiter.IsAllowed("user1");
            Assert.Equal(4, limiter.GetRemainingAttempts("user1"));
            limiter.IsAllowed("user1");
            Assert.Equal(3, limiter.GetRemainingAttempts("user1"));
        }

        [Fact]
        [Trait("Category", "RateLimiting")]
        public void RateLimiter_Reset()
        {
            var limiter = new RateLimiter(maxAttempts: 2, windowDurationSeconds: 10);

            limiter.IsAllowed("user1");
            limiter.IsAllowed("user1");
            Assert.False(limiter.IsAllowed("user1"));

            // Reset should clear history
            limiter.Reset("user1");
            Assert.Equal(2, limiter.GetRemainingAttempts("user1"));
            Assert.True(limiter.IsAllowed("user1"));
        }

        [Fact]
        [Trait("Category", "RateLimiting")]
        public void RateLimiter_InvalidInput()
        {
            var limiter = new RateLimiter();

            Assert.Throws<ArgumentNullException>(() => limiter.IsAllowed(null));
            Assert.Throws<ArgumentNullException>(() => limiter.IsAllowed(""));
            Assert.Throws<ArgumentNullException>(() => limiter.GetRemainingAttempts(null));
            Assert.Throws<ArgumentNullException>(() => limiter.Reset(null));
        }

        [Fact]
        [Trait("Category", "RateLimiting")]
        public void RateLimiter_InvalidConfiguration()
        {
            Assert.Throws<ArgumentOutOfRangeException>(() => new RateLimiter(maxAttempts: 0, windowDurationSeconds: 60));
            Assert.Throws<ArgumentOutOfRangeException>(() => new RateLimiter(maxAttempts: 5, windowDurationSeconds: 0));
        }

        [Fact]
        [Trait("Category", "RateLimiting")]
        public void RateLimiter_ClearAll()
        {
            var limiter = new RateLimiter(maxAttempts: 1, windowDurationSeconds: 10);

            limiter.IsAllowed("user1");
            limiter.IsAllowed("user2");
            limiter.IsAllowed("user3");

            Assert.True(limiter.GetTrackedIdentifierCount() > 0);

            limiter.ClearAll();

            Assert.Equal(0, limiter.GetTrackedIdentifierCount());
            Assert.True(limiter.IsAllowed("user1"));
        }

        [Fact]
        [Trait("Category", "RateLimiting")]
        public async void RateLimiter_ThreadSafe()
        {
            var limiter = new RateLimiter(maxAttempts: 100, windowDurationSeconds: 10);
            int successCount = 0;
            int failureCount = 0;
            object lockObj = new object();

            // Parallel attempts from multiple threads
            Task[] tasks = new Task[10];
            for (int t = 0; t < 10; t++)
            {
                tasks[t] = Task.Run(() =>
                {
                    for (int i = 0; i < 20; i++)
                    {
                        if (limiter.IsAllowed("shared-user"))
                        {
                            lock (lockObj) { successCount++; }
                        }
                        else
                        {
                            lock (lockObj) { failureCount++; }
                        }
                    }
                });
            }

            await Task.WhenAll(tasks);

            // 200 total attempts, first 100 succeed, rest fail
            Assert.Equal(100, successCount);
            Assert.Equal(100, failureCount);
        }
    }
}
