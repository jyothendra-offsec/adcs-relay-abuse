# AD CS NTLM Relay Lab

A Windows Server 2022 lab report on the interaction between NTLM authentication, Certificate Authority web enrollment, and certificate-based identity. The report records certificate-based authentication as the domain controller account in the lab. That result applies to the documented configuration.

## Read the assessment

Start with the [assessment report](report.md). Read the environment and attack flow first, then check the evidence for each transition. Use the detection and mitigation sections to plan a controlled retest.

| Review question | Evidence to collect |
| --- | --- |
| Can the enrollment endpoint accept relayed authentication? | Effective IIS authentication settings, HTTPS configuration, and Extended Protection policy |
| Which identity received a certificate? | Enrollment request record, requester, template and certificate metadata |
| Did the resulting certificate establish access? | Authentication evidence tied to the requester and the resulting identity |
| Did hardening stop the same path? | Repeat the authorized lab test after changing one control and compare the enrollment outcome |

## Hardening priorities

Review Extended Protection on applicable enrollment endpoints, restrict NTLM where feasible, and review enrollment permissions and template scope. Validate each control on the endpoint where it applies. Review web enrollment, CA audit and domain authentication records together to distinguish an attempted relay from successful issuance and use.

## Usage terms

Original material owned by 0xjyothendra requires written permission for modification or redistribution. Third-party content, assets, and earlier licensed releases retain their applicable terms. See [LICENSE](LICENSE).
