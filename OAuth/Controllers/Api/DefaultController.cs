using LNF.Models.Data;
using LNF.Repository;
using LNF.Repository.Data;
using System.Linq;
using System.Web.Http;

namespace OAuth.Controllers.Api
{
    [Route("api")]
    public class DefaultController : ApiController
    {
        [Route("api")]
        public object Get()
        {
            var c = DA.Current.Query<ClientInfo>().FirstOrDefault(x => x.UserName == User.Identity.Name);

            if (c == null) return null;

            return new
            {
                username = c.UserName,
                firstName = c.FName,
                lastName = c.LName,
                email = c.Email,
                phone = c.Phone,
                roles = c.Roles()
            };
        }
    }
}
