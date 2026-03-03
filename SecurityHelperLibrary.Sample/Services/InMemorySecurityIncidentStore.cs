using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;

namespace SecurityHelperLibrary.Sample.Services;

public sealed class SecurityIncidentRecord
{
    public DateTime TimestampUtc { get; set; }
    public string Code { get; set; } = string.Empty;
}

public interface ISecurityIncidentStore
{
    void Add(string incidentCode);
    IReadOnlyCollection<SecurityIncidentRecord> GetRecent(int take);
}

public sealed class InMemorySecurityIncidentStore : ISecurityIncidentStore
{
    private const int MaxItems = 1000;
    private readonly ConcurrentQueue<SecurityIncidentRecord> _records = new ConcurrentQueue<SecurityIncidentRecord>();

    public void Add(string incidentCode)
    {
        if (string.IsNullOrWhiteSpace(incidentCode))
            return;

        _records.Enqueue(new SecurityIncidentRecord
        {
            TimestampUtc = DateTime.UtcNow,
            Code = incidentCode
        });

        while (_records.Count > MaxItems && _records.TryDequeue(out _))
        {
        }
    }

    public IReadOnlyCollection<SecurityIncidentRecord> GetRecent(int take)
    {
        if (take < 1)
            take = 1;
        if (take > MaxItems)
            take = MaxItems;

        return _records
            .Reverse()
            .Take(take)
            .ToArray();
    }
}
