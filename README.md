JwtAuthForWebAPI
================

Nuget-deployed library for securing your ASP.NET Web API service with with JSON Web Tokens (JWT).




 <configuration>
     <system.diagnostics>
        <switches>
           <add name="JwtAuthForWebAPI" value="Verbose" />
        </switches>
     </system.diagnostics>
 </configuration>


"Developer Command Prompt for VS2012"

makecert -r -n "CN=JwtAuthForWebAPI Example" -sky signature -ss my -sr localmachine

certmgr -add -c -n "JwtAuthForWebAPI Example" -s -r localmachine My -s -r localmachine root

(http://msdn.microsoft.com/en-us/library/bfsktky3(v=vs.110).aspx)


