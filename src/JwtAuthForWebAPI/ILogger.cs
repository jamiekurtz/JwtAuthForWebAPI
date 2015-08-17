

using System;
using System.Diagnostics;

namespace JwtAuthForWebAPI
{
    public interface ILogger
    {
        void DebugFormat(string message, params object[] paramList);

        void WarnFormat(string message, Exception ex);

        void ErrorFormat(string message, Exception ex);
    }

    public class DefaultLogger : ILogger
    {
        public void DebugFormat(string message, params object[] paramList)
        {
            Trace.TraceInformation(message,paramList);
        }

        public void WarnFormat(string message, Exception ex)
        {
            Trace.TraceWarning(message, ex.Message);
        }

        public void ErrorFormat(string message, Exception ex)
        {
            Trace.TraceError(message, ex.Message);
        }
    }
}

