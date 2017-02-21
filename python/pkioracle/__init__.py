from cryptography import x509
from collections import defaultdict, Counter
import threading

class CertAuthorityOracle:
  def __init__(self):
    self.fqdnSet = set()
    self.regDomSet = set()
    self.dailyIssuance = Counter()
    self.organization = None

  def logCert(self, fqdns, regdoms, date):
    self.fqdnSet.update(fqdns)
    self.regDomSet.update(regdoms)
    self.dailyIssuance[date] += 1

  def merge(self, aRemote):
    self.fqdnSet.update(aRemote.fqdnSet)
    self.regDomSet.update(aRemote.regDomSet)
    self.dailyIssuance.update(aRemote.dailyIssuance)
    if self.organization is None:
      self.organization = aRemote.organization

  def summarize(self):
    counts = {
      "organization": self.organization,
      "fqdns": len(self.fqdnSet),
      "regDoms": len(self.regDomSet),
      "certsIssued": self.dailyIssuance,
    }
    return counts

class Oracle:
  def __init__(self):
    self.certAuthorities = defaultdict(CertAuthorityOracle)
    self.mutex = threading.RLock()

  def summarize(self):
    data={}
    with self.mutex:
      for k in self.certAuthorities:
        data[k] = self.certAuthorities[k].summarize()

    return data

  def merge(self, aRemote):
    with self.mutex:
      allKeys = set(self.certAuthorities.keys()).union(aRemote.certAuthorities.keys())
      for k in allKeys:
        self.certAuthorities[k].merge(aRemote.certAuthorities[k])

  # Mapping function
  def processCert(self, aPsl, aCert):
    akiext = aCert.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier)
    aki = akiext.value.key_identifier.hex()

    subject = aCert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0]
    fqdns = set([subject.value])

    try:
      san = aCert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
      fqdns.update(san.value.get_values_for_type(x509.DNSName))
    except:
      return

    # Filter out wildcards
    fqdns = set(filter(lambda x: x.startswith("*.")==False, fqdns))

    regdoms = set()
    for fqdn in fqdns:
      regdoms.add(aPsl.suffix(fqdn) or fqdn)

    issueDate = aCert.not_valid_before.date().isoformat()
    with self.mutex:
      if aki not in self.certAuthorities:
        issuerOrg = aCert.issuer.get_attributes_for_oid(x509.oid.NameOID. ORGANIZATION_NAME)[0]

        self.certAuthorities[aki] = CertAuthorityOracle()
        self.certAuthorities[aki].organization = issuerOrg.value

      self.certAuthorities[aki].logCert(fqdns, regdoms, issueDate)

