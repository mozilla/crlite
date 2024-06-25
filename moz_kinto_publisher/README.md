# Automatic Publication and Signing

This folder contains a tool to push Intermediate CA Certificates for Intermediate CA Preloading, and CRLite filters (full and stashes) to Kinto, and subsequently to approve them for signature.

The Intermediate CA Certificate data is important metadata for CRLite: namely, it indicates whether a subject certificate originated from an issuer enrolled in the CRLite filter data.

CAs change from being enrolled to unenrolled, and unenrolled to enrolled, from time to time, based on whether there is fresh CRL data for that CA. Those transitions have security effects, particularly if CRLite and the Intermediate CA metadata do not update in lock-step.

## Certificate Authority Enrolling in CRLite

When revocation data becomes available for an issuer, the CRLite data set will start including all observed certificates for that issuer in the filter, including adjusting for false positives. This increases the filter size.

If a client *does not observe* that a issuer had been enrolled, yet the CRLite filter contains that issuer, then:

* The client will have a filter of a larger size than is necessary to avoid false positives.


## Certificate Authority Unenrolling from CRLite

If CRLite cannot obtain fresh revocation data for an issuer, the CRLite data set will stop including the observed certificates for that issuer in the filter. This decreases the filter size.

If a client *does not observe* that a issuer has been unenrolled, yet the CRLite filter *does not contain that issuer*, then:

* The client will have a nonzero chance of false positives on certificates from that issuer.

### Mitigation

If an issuer is to be unenrolled, its observed certificates need to remain in the filter until clients have had an opportunity to update their Intermediate CA Certificate Metadata to show that the issuer is indeed unenrolled.
