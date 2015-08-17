

using System;
using log4net;

namespace JwtAuthForWebAPI.SampleSite
{
    public class Logger : ILogger
    {
        readonly ILog _logger = LogManager.GetLogger("JwtAuthForWebAPI");

        private static Logger instance;

        private Logger() { }

        public static Logger Instance
        {
            get 
            {
                if (instance == null)
                {
                    instance = new Logger();
                }
                return instance;
            }
        }

        public void DebugFormat(string message, params object[] paramList)
        {
            _logger.DebugFormat(message,paramList);
        }

        public void WarnFormat(string message, Exception ex)
        {
            _logger.WarnFormat(message, ex);
        }

        public void ErrorFormat(string message, Exception ex)
        {
            _logger.WarnFormat(message, ex);
        }
    }
}

