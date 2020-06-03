using Microsoft.Rest;
using System.Collections.Generic;
using Microsoft.Azure.Management.ResourceGraph;
using Microsoft.Azure.Management.ResourceGraph.Models;

namespace cumulus {
    public class azureGraphHelper {
        public static object readAzureGraph(string accessToken, string subscriptionId, string query) {
            //*** Need to grant application Delegated user_impersonation against Azure Service management ***
            ServiceClientCredentials serviceClientCreds = new TokenCredentials(accessToken);
            ResourceGraphClient client = new ResourceGraphClient(serviceClientCreds);

            QueryResponse response = client.Resources(new QueryRequest(new List<string>(){ subscriptionId }, query));
            return response.Data;
         }
    }
}