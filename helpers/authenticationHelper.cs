using System;
using System.Threading.Tasks;
using Microsoft.Identity.Client;
using System.Collections.Generic;
using System.Linq;

namespace cumulus {
    public class authenticationHelper {

        public static async Task<string> GetAzureToken(string tenantId, string clientId) {

            string[] scopes = new string[] {"https://graph.microsoft.com/beta/groups/Group.ReadWrite.All","https://graph.microsoft.com/beta/AccessReview.ReadWrite.All","https://graph.microsoft.com/beta/User.ReadWrite.All", "https://graph.microsoft.com/beta/AdministrativeUnit.ReadWrite.All"};

            var _clientApp = PublicClientApplicationBuilder.Create(clientId)
                .WithRedirectUri("http://localhost")
                .WithTenantId(tenantId)
                .Build();

            AuthenticationResult result = null;
            string ResultText = "";
            IEnumerable<IAccount> accounts = await _clientApp.GetAccountsAsync();

            try {
                result = await _clientApp.AcquireTokenSilent(scopes, accounts.FirstOrDefault())
                            .ExecuteAsync();
            }
            catch (MsalUiRequiredException ex) {
                // A MsalUiRequiredException happened on AcquireTokenSilent.
                // This indicates you need to call AcquireTokenInteractive to acquire a token
                System.Diagnostics.Debug.WriteLine($"MsalUiRequiredException: {ex.Message}");

                try {
                    result = await _clientApp.AcquireTokenInteractive(scopes)
                        .ExecuteAsync();
                }
                catch (MsalException msalex) {
                    ResultText = $"Error Acquiring Token:{System.Environment.NewLine}{msalex}";
                    throw new Exception(ResultText);
                }
            }
            catch (Exception ex) {
                ResultText = $"Error Acquiring Token Silently:{System.Environment.NewLine}{ex}";
                throw new Exception(ResultText);
            }

            if (result != null) {
                    //string accessToken = result.AccessToken;
                    // Use the token
                return result.AccessToken;
            } else {
                throw new Exception("Unable to retrieve access token");
            }
        }
    }
}