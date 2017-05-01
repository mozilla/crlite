from cryptography import x509
from collections import defaultdict, Counter
from IPy import IP
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
      "certsIssuedByIssuanceDay": self.dailyIssuance,
      "certsTotal": sum(self.dailyIssuance.values()),
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

  def summarize(self, stats):
    data={}
    with self.mutex:
      allFqdns = set()
      allRegDoms = set()

      for k in self.certAuthorities:
        data[k] = self.certAuthorities[k].summarize()
        if "certsTotal" in data[k]:
          stats["Total Certificates"] += data[k]["certsTotal"]
        stats["Total Certificate Authorities"] += 1
        allFqdns = allFqdns | self.certAuthorities[k].fqdnSet
        allRegDoms = allRegDoms | self.certAuthorities[k].regDomSet
        # clear heavy memory area memory since statistics were gathered
        self.certAuthorities[k].fqdnSet.clear()
        self.certAuthorities[k].regDomSet.clear()

      stats["Total Unique FQDNs Seen"] = len(allFqdns)
      stats["Total Unique RegDoms Seen"] = len(allRegDoms)

    return data

  def merge(self, aRemote):
    with self.mutex:
      allKeys = set(self.certAuthorities.keys()).union(aRemote.keys())
      for k in allKeys:
        self.certAuthorities[k].merge(aRemote[k])

  def recordCertMetadata(self, metaData):
    if not set(["aki", "issuer", "fqdns", "regdoms"]).issubset(metaData):
      # Can't do anything with this non-BR-compliant cert
      return

    with self.mutex:
      oracle = None
      if metaData["aki"] in self.certAuthorities:
        oracle = self.certAuthorities[metaData["aki"]]
      else:
        oracle = CertAuthorityOracle()
        oracle.organization = metaData["issuer"]
        self.certAuthorities[metaData["aki"]] = oracle

      fqdns = metaData["fqdns"].split(",")
      regDoms = metaData["regdoms"].split(",")

      oracle.logCert(fqdns, regDoms, metaData["issuedate"])
      if set(["continent", "countrycode"]).issubset(metaData):
        oracle.logGeo(metaData["continent"], metaData["countrycode"])

  def getMetadataForCert(self, aPsl, aCert):
    metaData={}
    fqdns=set()

    # Issuance date, organization, and AKI are all required
    try:
      metaData["issuedate"] = aCert.not_valid_before.date().isoformat()
      metaData["issuer"] = aCert.issuer.get_attributes_for_oid(x509.oid.NameOID. ORGANIZATION_NAME)[0].value

      akiext = aCert.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier)
      metaData["aki"] = akiext.value.key_identifier.hex()

      # Get the FQDNs
      subject = aCert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0]
      fqdns.add(subject.value)

    except:
      raise ValueError("BR-required information not in this certificate")

    try:
      san = aCert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
      fqdns.update(san.value.get_values_for_type(x509.DNSName))
    except:
      # SANs are optional, sorta.
      pass

    # Filter out wildcards
    metaData["fqdns"] = ",".join(set(filter(lambda x: x.startswith("*.")==False, fqdns)))

    # Get the registered domains
    regdoms = set()
    for fqdn in fqdns:
      regdoms.add(aPsl.suffix(fqdn) or fqdn)
    metaData["regdoms"] = ",".join(regdoms)

    # Get continent, country, city
    if self.geoDB:
      ipAddress = None
      for fqdn in fqdns:
        try:
          ipAddress = socket.gethostbyname(fqdn)
        except:
          pass
      if ipAddress:
        try:
          if IP(ipAddress).iptype() != "PRIVATE":
            result = self.geoDB.city(ipAddress)
            metaData["ipaddress"] = ipAddress
            metaData["continent"] = result.continent.name
            metaData["countrycode"] = result.country.iso_code
        except:
          pass

    return metaData

  def serialize(self):
    return jsonpickle.encode(self.certAuthorities)