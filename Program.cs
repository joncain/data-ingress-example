using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Net;
using System.Web;
using System.IO;
using Jose;
using Newtonsoft.Json;

namespace DataIngressExample
{
    class Program
    {
        private static string baseUrl = "REPLACE_WITH_ICENTRIS_PROVIDED_DOMAIN";
        private static string apiKey = "REPLACE_WITH_ICENTRIS_PROVIDED_KEY";
        private static string apiSecret = "REPLACE_WITH_ICENTRIS_PROVIDED_SECRET";
        private static string accessToken = null;

        static void Main(string[] args)
        {
            try
            {
                // Check system health. If a 200 status is returned the system is healthy.
                Program.httpRequest("/data/v1/health", "GET");
                Console.WriteLine("System is healthy, continue...\n");

                // Generate a JWT
                string jwt = getJwt();
                Console.WriteLine("Refresh Token: " + jwt + "\n");

                // Build authentication request body
                var postBody = new StringBuilder();
                postBody.Append("client_assertion_type=" +  HttpUtility.UrlEncode("urn:ietf:params:oauth:client-assertion-type:jwt-bearer"));
                postBody.Append("&client_assertion=" + HttpUtility.UrlEncode(jwt));

                // Authenticate
                WebHeaderCollection authHeaders = new WebHeaderCollection();
                authHeaders.Add("content-type", "application/x-www-form-urlencoded");
                Program.httpRequest("/auth/v0/access", "POST", authHeaders, postBody.ToString());

                if (Program.accessToken != null)
                {
                    // We have an access token, push an event
                    dynamic payload = new System.Dynamic.ExpandoObject();
                    payload.key = "value";
                    payload.foo = "bar";

                    WebHeaderCollection eventHeaders = new WebHeaderCollection();
                    eventHeaders.Add("content-type", "application/json");
                    eventHeaders.Add("Authorization", "bearer " + Program.accessToken);
                    Program.httpRequest("/data/v1/event/TEST_EVENT_IGNORE", "POST", eventHeaders, JsonConvert.SerializeObject(payload));
                }
            }
            catch (WebException e)
            {
                // A status other than 2xx was returned
                Console.WriteLine("Response: " + e.Message);
            }
            catch (Exception e)
            {
                // An unexpected error occured.
                Console.WriteLine("ERROR: " + e.Message);
            }

            Console.WriteLine("Press any key to exit");
            Console.ReadKey();
        }

        private static void httpRequest(string url, string method, WebHeaderCollection headers = null, string reqBody = null)
        {
            url = "https://" + baseUrl + "" + url;
            Console.WriteLine(method + " " + url); 

            WebRequest req = WebRequest.Create(url);
            req.Method = method;

            if (headers != null)
            {
                req.ContentType = headers["content-type"];
                headers.Remove("content-type");

                if (headers.Count > 0)
                {
                    req.Headers = headers;
                }
            }

            if (reqBody != null)
            {
                Console.WriteLine("\n--- Request Body ---");
                Console.WriteLine(reqBody);
                Console.WriteLine("--- --- ---");

                byte[] reqBytes = Encoding.UTF8.GetBytes(reqBody);
                req.ContentLength = reqBytes.Length;

                Stream reqStream = req.GetRequestStream();
                reqStream.Write(reqBytes, 0, reqBytes.Length);
                reqStream.Close();
            }

            try
            {
                HttpWebResponse res = (HttpWebResponse)req.GetResponse();
                Console.WriteLine("Response Status: " + (int)res.StatusCode);
            }
            catch (WebException e)
            {
                if (((HttpWebResponse)e.Response).StatusCode == HttpStatusCode.Redirect && e.Response.ContentType.Contains("json"))
                {
                    // I expect this to be a response that contains the authentication token. 302 response with an application/json content-type
                    Console.WriteLine("\n--- Response Headers ---");
                    foreach (string k in e.Response.Headers.AllKeys)
                    {
                        Console.WriteLine(k + "=" + e.Response.Headers[k].ToString());
                    }
                    Console.WriteLine("--- --- ---");

                    Console.WriteLine("\n--- Access Token ---");
                    string resBody = readResponse(e.Response);
                    Program.accessToken = JsonConvert.DeserializeObject<Dictionary<string, string>>(resBody)["access_token"];
                    Console.WriteLine(Program.accessToken);
                    Console.WriteLine("--- --- ---");
                }
                else
                {
                    e.Response.Close();
                }
            }
        }

        private static string getJwt()
        {
            var payload = new Dictionary<string, object>();
            payload.Add("jti", System.Guid.NewGuid());
            payload.Add("sub", Program.baseUrl);
            payload.Add("kid", Program.apiKey);
            payload.Add("iat", epoch() + (15 * 60));

            var secretKey = Encoding.UTF8.GetBytes(apiSecret);
            return Jose.JWT.Encode(payload, secretKey, JwsAlgorithm.HS256);
        }

        private static int epoch()
        {
            TimeSpan t = DateTime.UtcNow - new DateTime(1970, 1, 1);
            return (int)t.TotalSeconds;
        }

        private static string readResponse(WebResponse res)
        {
            Stream dataStream = res.GetResponseStream();
            StreamReader reader = new StreamReader(dataStream);
            string resBody = reader.ReadToEnd();
            reader.Close();
            dataStream.Close();
            res.Close();
            return resBody;
        }
    }
}
