// PostureIQ — Azure Application Insights Availability (Web) Test
//
// Creates a Standard URL ping test that hits the /health endpoint from multiple
// geographic locations.  Results feed into the App Insights "Availability" blade.
//
// Why this is needed:
//   The "Availability" metric in App Insights is populated exclusively by Web
//   Tests — regular HTTP traffic (even from health probes) does NOT count.
//   Without a Web Test resource the Availability chart will always show zero.

@description('Name for the web test resource')
param name string

@description('Azure region (must match the App Insights resource)')
param location string

@description('Resource ID of the linked Application Insights component')
param appInsightsId string

@description('Full HTTPS URL to probe (e.g., https://myapp.azurecontainerapps.io/health)')
param targetUrl string

@description('Test frequency in seconds (300 = 5 min, 600 = 10 min)')
@allowed([300, 600, 900])
param frequencySeconds int = 300

@description('Timeout in seconds for each probe request')
param timeoutSeconds int = 30

@description('Expected HTTP status code')
param expectedHttpStatusCode int = 200

@description('Enable SSL certificate validation')
param sslCheckEnabled bool = true

@description('Warn if SSL cert expires within this many days')
param sslLifetimeCheckDays int = 7

@description('Geographic test locations (Azure availability-test location IDs)')
param testLocations array = [
  { Id: 'us-il-ch1-azr' }   // Chicago
  { Id: 'us-ca-sjc-azr' }   // San Jose
  { Id: 'us-va-ash-azr' }   // Virginia
  { Id: 'us-fl-mia-edge' }  // Miami
  { Id: 'us-tx-sn1-azr' }   // San Antonio
]

// ── Web Test ──────────────────────────────────────────────
resource webTest 'Microsoft.Insights/webtests@2022-06-15' = {
  name: name
  location: location
  tags: {
    // The hidden-link tag associates this web test with the App Insights
    // resource so that results appear in the Availability blade.
    'hidden-link:${appInsightsId}': 'Resource'
  }
  kind: 'standard'
  properties: {
    SyntheticMonitorId: name
    Name: name
    Enabled: true
    Frequency: frequencySeconds
    Timeout: timeoutSeconds
    Kind: 'standard'
    RetryEnabled: true
    Locations: [for loc in testLocations: {
      Id: loc.Id
    }]
    Request: {
      RequestUrl: targetUrl
      HttpVerb: 'GET'
      ParseDependentRequests: false
    }
    ValidationRules: {
      ExpectedHttpStatusCode: expectedHttpStatusCode
      SSLCheck: sslCheckEnabled
      SSLCertRemainingLifetimeCheck: sslLifetimeCheckDays
    }
  }
}

output id string = webTest.id
output name string = webTest.name
