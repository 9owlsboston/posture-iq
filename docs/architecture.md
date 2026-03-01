# PostureIQ — Architecture

## High-Level Architecture

```mermaid
graph TB
    subgraph Agent["PostureIQ Agent"]

        subgraph Core["Core Components"]
            direction LR
            FastAPI["FastAPI<br/>/health /ready /assess"]
            SDK["Copilot SDK<br/>8 tools + system prompt"]
            Runtime["Agent Runtime<br/>Multi-model · Context mgmt"]
            FastAPI --> SDK -- "JSON-RPC" --> Runtime
        end

        subgraph MiddleRow[" "]
            direction LR

            subgraph Middleware["Middleware Layer"]
                ContentSafety["Content Safety (RAI)"] ~~~ PII["PII Redaction"] ~~~ Tracing["Distributed Tracing"] ~~~ AuditLog["Audit Logger"]
            end

            Middleware -- "intercepts" --> Tools

            subgraph Tools["8 Assessment Tools"]
                SecureScore["query_secure_score"]
                Defender["assess_defender_coverage"]
                Purview["check_purview_policies"]
                Entra["get_entra_config"]
                Remediation["generate_remediation_plan"]
                Scorecard["create_adoption_scorecard"]
                Playbook["get_project479_playbook"]
            end
        end

        Core --> Middleware
    end

    subgraph Azure["Azure Services"]
        direction LR
        ContentSafetyAPI["Azure AI Content Safety<br/>RAI · Prompt injection"]
        AppInsights["App Insights<br/>Traces & metrics"]
        Graph["Microsoft Graph Security API<br/>Secure Score · Defender · Purview · Entra"]
        OpenAI["Azure OpenAI (GPT-4o)<br/>Reasoning & remediation"]
    end

    Middleware --> ContentSafetyAPI
    Middleware --> AppInsights
    Tools --> Graph
    Tools --> OpenAI

    style MiddleRow fill:none,stroke:none
```

## Deployment Architecture

```mermaid
graph TB
    subgraph CICD["GitHub Actions CI/CD"]
        GH["Push to main"]
        OIDC["OIDC Workload<br/>Identity Federation"]
        GH --> OIDC
    end

    OIDC -- "az acr login<br/>(no admin credentials)" --> ACR["Azure Container<br/>Registry (ACR)"]

    subgraph ACA["Azure Container Apps"]
        subgraph Container["PostureIQ Container"]
            P1["Python 3.11 + FastAPI + Copilot SDK"]
            P2["GitHub CLI (agent runtime)"]
            P3["User-Assigned Managed Identity"]
            P4["Scale: 0–5 replicas"]
        end
        Probes["Health Probes<br/>/health (liveness)<br/>/ready (readiness)"]
    end

    ACR -- "AcrPull<br/>(Managed Identity)" --> ACA
    ACA --> KV["Key Vault<br/>(secrets)"]
    ACA --> AI["App Insights"]
    ACA --> CS["Content Safety"]
    ACA --> OAI["Azure OpenAI"]
```

## Auth Flow

```mermaid
graph LR
    subgraph UserAuth["User Authentication"]
        User --> EntraID["Entra ID<br/>(OAuth2)"]
        EntraID --> Agent["PostureIQ Agent"]
    end

    subgraph ServiceAuth["Service Authentication"]
        Agent -- "Managed Identity" --> Azure["Azure Services<br/>(OpenAI, KV, CS, AI)"]
        Agent -- "Delegated Permissions" --> GraphAPI["Graph API"]
    end

    subgraph CICDAuth["CI/CD Authentication"]
        GitHub["GitHub Actions"] -- "OIDC Federation<br/>(zero secrets)" --> EntraApp["Entra ID<br/>App Registration"]
        EntraApp -- "Short-lived token" --> AzureRBAC["Azure RBAC<br/>(Contributor + AcrPush)"]
    end
```
