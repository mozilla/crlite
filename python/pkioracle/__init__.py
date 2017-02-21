from cryptography import x509
from collections import defaultdict, Counter
import jsonpickle
import socket
import threading

class CertAuthorityOracle:
  def __init__(self):
    self.fqdnSet = set()
    self.regDomSet = set()
    self.dailyIssuance = Counter()
    self.continent = Counter()
    self.countryIso = Counter()
    self.organization = None

  def logCert(self, fqdns, regdoms, date):
    self.fqdnSet.update(fqdns)
    self.regDomSet.update(regdoms)
    self.dailyIssuance[date] += 1

  def logGeo(self, continent, countryIso):
    self.continent[continent] += 1
    self.countryIso[countryIso] += 1

  def merge(self, aRemote):
    self.fqdnSet.update(aRemote.fqdnSet)
    self.regDomSet.update(aRemote.regDomSet)
    self.dailyIssuance.update(aRemote.dailyIssuance)
    self.continent.update(aRemote.continent)
    self.countryIso.update(aRemote.countryIso)
    if self.organization is None:
      self.organization = aRemote.organization

  def summarize(self):
    counts = {
      "organization": self.organization,
      "fqdns": len(self.fqdnSet),
      "regDoms": len(self.regDomSet),
      "certsIssued": self.dailyIssuance,
    }
    if len(self.continent) > 0:
      counts["continents"] = self.continent
    if len(self.countryIso) > 0:
      counts["countries"] = self.countryIso

    return counts

class Oracle:
  def __init__(self):
    self.certAuthorities = defaultdict(CertAuthorityOracle)
    self.mutex = threading.RLock()
    self.geoDB = None

  def summarize(self):
    data={}
    with self.mutex:
      for k in self.certAuthorities:
        data[k] = self.certAuthorities[k].summarize()

    return data

  def merge(self, aRemote):
    with self.mutex:
      allKeys = set(self.certAuthorities.keys()).union(aRemote.keys())
      for k in allKeys:
        self.certAuthorities[k].merge(aRemote[k])

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

    # Get continent, country, city
    if self.geoDB:
      ipAddress = None
      for fqdn in fqdns:
        try:
          ipAddress = socket.gethostbyname(fqdn)
        except:
          pass
      if ipAddress:
        result = self.geoDB.city(ipAddress)
        continent = result.continent.name
        countryCode = result.country.iso_code
        with self.mutex:
          self.certAuthorities[aki].logGeo(continent, countryCode)

  def serialize(self):
    return jsonpickle.encode(self.certAuthorities)