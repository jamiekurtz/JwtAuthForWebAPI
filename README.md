JwtAuthForWebAPI
================

Nuget-deployed library for securing your ASP.NET Web API service with JSON Web Tokens (JWT).

This library is essentially a DelegatingHandler that creates a new ClaimsPrincipal based on the incoming token and assigns it to the current 
thread. As such, you *must* secure your controllers and/or their actions with the `[Authorize]` attribute - per standard ASP.NET authorization practices. In 
other words, the handler doesn't actually prevent unauthorized access to your site - that's what the `[Authorize]` attribute is for.

The main class to use is the JwtAuthenticationMessageHandler - which just needs to be added to the MessageHandlers collection during Web API start-up. Also,
the handler expects the token to be submitted within the Authorization header, using the Bearer scheme. Further, the token itself, per the 
[JSON Web Token](http://self-issued.info/docs/draft-ietf-oauth-json-web-token.html) protocol, is expected to be represented using the JWS Compact 
Serialized format. This also means that this handler only supports signed JWTs (i.e. JWS), and not encrypted tokens (i.e. JWE). Attempting to use
a JWE will fail.

You can install the NuGet package for this library at https://www.nuget.org/packages/JwtAuthForWebAPI/.

You will also need to add a reference System.IdentityModel - which is included with the 4.5 .NET Framework.


Configuration
-------------

Configure your ASP.NET Web API site with this library by putting the following code (or similar) in your WebApiConfig.Register() method:

    var builder = new SecurityTokenBuilder();
    var jwtHandler = new JwtAuthenticationMessageHandler
    {
        AllowedAudience = "http://www.example.com",
        Issuer = "corp",
        SigningToken = builder.CreateFromCertificate("CN=JwtAuthForWebAPI Example")
    };

    config.MessageHandlers.Add(jwtHandler);

The `AllowedAudience` and `Issuer` property values are arbitrary strings, but must match the same properties on the incoming token. In 
other words, if the incoming token contains different values for either of these properties, token validation will fail.

The `SigningToken` property can be any valid SecurityToken object that can be used to validate the incoming token's signature. To make it
easier to configure, you can use the `SecurityTokenBuilder` object - as shown in the example above. The builder supports using
either an X.509 certificate or a shared key (as either a byte array or a base64-encoded string).

You can also use the `AllowedAudiences` property - in addition to or instead of the `AllowedAudience` property.


Principal Transformation
------------------------

If you'd rather have your own `IPrincipal` created - instead of the default `ClaimsPrincipal` - you can implement your own  
`IPrincipalTransformer`. This allows you transform the default `ClaimsPrincipal` and all of its claims into an `IPrincipal` of your
choosing. Simply set the `PrincipalTransformer` property on the `JwtAuthenticationMessageHandler` instance to your own instance 
of `IPrincipalTransformer`. 

All you need to implement in your own IPrincipalTransformer class is:

	IPrincipal Transform(ClaimsPrincipal principal);


Creating a Development Certificate
----------------------------------

As can be seen in the example code (JwtAuthForWebAPI.SampleClient and JwtAuthForWebAPI.SampleSite), this library supports X.509-based
digital signatures. In order to use run the sample code, you will need to create a self-signed certificate. In production environments, the
certificate would typically be issued by an official certificate authority - e.g. VeriSign, Thawte, GoDaddy, or even an Active Directory 
server. 

To create the certificate used in this sample code:

1. Open the "Developer Command Prompt for VS2012" (as Administrator) from the Windows Start Menu
1. Run the following command to create the certificate:

    `makecert -r -n "CN=JwtAuthForWebAPI Example" -sky signature -ss My -sr localmachine`

1. Then run this command to copy the new self-signed certificate into your machine's Trusted Root store:

    `certmgr /add /c /n "JwtAuthForWebAPI Example" /s /r localmachine My /s /r localmachine root`

At this point, the client and server code will be able to utilize the certificate for token signing and validation.


Logging
-------

You can enable logging for this library by configuring a log4net logger in your web.config file - similar to the sample site's
web.config file. The logger you need to enable is called `JwtAuthForWebAPI.JwtAuthenticationMessageHandler`. You need web.config 
content, as well as the following line in your site startup code:

    log4net.Config.XmlConfigurator.Configure();

Please view the web.config file in the JwtAuthForWebAPI.SampleSite project for an example of setting up the logger.

Testing
-------

1. Run unit tests in the solution's Tests folder.
1. Run integration tests in the JwtAuthForWebAPI.SampleClient project.

The JwtAuthForWebAPI.SampleSite must be running in order to run integration tests. To start the site, you can set it as the startup project and click F5 to start the site; once the site is running you can close the browser.
