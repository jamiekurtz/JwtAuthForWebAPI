using System.Diagnostics;
using System.Net;
using System.Net.Http;
using System.Security.Claims;
using System.Web.Http;

namespace JwtAuthForWebAPI.SampleSite.Controllers
{
    [Authorize]
    public class ValuesController : ApiController
    {
        [Authorize]
        public string Get()
        {
            return ((ClaimsPrincipal) User).Identity.Name;
        }

        [AllowAnonymous]
        public HttpResponseMessage Post(HttpRequestMessage request)
        {
            var message = request.Content.ReadAsStringAsync().Result;
            Trace.TraceInformation(message);

            return request.CreateResponse(HttpStatusCode.OK);
        }

        [Authorize(Roles = "Administrator")]
        public void Delete(string id)
        {
            Trace.TraceInformation(id);
        }
    }
}