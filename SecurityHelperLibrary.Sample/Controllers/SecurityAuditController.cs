using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using SecurityHelperLibrary.Sample.Services;

namespace SecurityHelperLibrary.Sample.Controllers;

[ApiController]
[Route("api/security-audit")]
[Authorize(Roles = "Admin")]
public class SecurityAuditController : ControllerBase
{
    private readonly ISecurityIncidentStore _incidentStore;

    public SecurityAuditController(ISecurityIncidentStore incidentStore)
    {
        _incidentStore = incidentStore;
    }

    [HttpGet("incidents")]
    public ActionResult<IReadOnlyCollection<SecurityIncidentRecord>> GetIncidents([FromQuery] int take = 100)
    {
        return Ok(_incidentStore.GetRecent(take));
    }
}
