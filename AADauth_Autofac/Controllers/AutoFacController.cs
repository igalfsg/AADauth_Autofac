using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Http;
using AADauth_Autofac.Managers;

namespace AADauth_Autofac.Controllers
{
    public class AutoFacController : ApiController
    {
        private IAutofacManager _managertest;
        public AutoFacController(IAutofacManager managertest)
        {
            _managertest = managertest;
        }
        [Authorize]
        [HttpGet]
        [Route("api/GetTestString")]
        public string GetTest()
        {
            return _managertest.GetResult();
        }
    }
}