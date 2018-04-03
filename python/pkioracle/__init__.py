from cryptography import x509
from collections import defaultdict, Counter
from IPy import IP
import pickle
import jsonpickle
import socket
import threading
import sys, traceback
import binascii

if sys.version_info[0] < 3 or (sys.version_info[0] == 3 and sys.version_info[1] < 1):
   raise Exception("Must be using Python 3.1 or later")


class CertAuthorityOracle:
  def __init__(self):
    self.fqdnSet = set()
    self.regDomSet = set()
    self.wildcardSet = set()
    self.spkis = set()
    self.dailyIssuance = Counter()
    self.continent = Counter()
    self.countryIso = Counter()
    self.organization = None

  def logCert(self, spki, fqdns, regdoms, wildcards, date):
    self.spkis.add(spki)
    self.fqdnSet.update(fqdns)
    self.regDomSet.update(regdoms)
    self.wildcardSet.update(wildcards)
    self.dailyIssuance[date] += 1

  def isLogged(self, spki):
    return spki in self.spkis

  def logGeo(self, continent, countryIso):
    self.continent[continent] += 1
    self.countryIso[countryIso] += 1

  def merge(self, aRemote):
    self.fqdnSet.update(aRemote.fqdnSet)
    self.regDomSet.update(aRemote.regDomSet)
    self.wildcardSet.update(aRemote.wildcardSet)
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
      "wildcards": len(self.wildcardSet),
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
    self.offsets = defaultdict(int)

  def summarize(self, stats):
    data={}
    with self.mutex:
      allFqdns = set()
      allRegDoms = set()
      allWildcards = set()

      for k in self.certAuthorities:
        data[k] = self.certAuthorities[k].summarize()
        if "certsTotal" in data[k]:
          stats["Total Certificates"] += data[k]["certsTotal"]
        stats["Total Certificate Authorities"] += 1
        allFqdns = allFqdns | self.certAuthorities[k].fqdnSet
        allRegDoms = allRegDoms | self.certAuthorities[k].regDomSet
        allWildcards = allWildcards | self.certAuthorities[k].wildcardSet
        # clear heavy memory area memory since statistics were gathered
        self.certAuthorities[k].fqdnSet.clear()
        self.certAuthorities[k].regDomSet.clear()
        self.certAuthorities[k].wildcardSet.clear()

      stats["Total Unique FQDNs Seen"] = len(allFqdns)
      stats["Total Unique RegDoms Seen"] = len(allRegDoms)
      stats["Total Unique Wildcards Seen"] = len(allWildcards)

    return data

  def loadAndMerge(self, path):
    try:
      with open(path, 'rb') as f:
        self.merge(pickle.load(f))
    except:
      t,v,s = sys.exc_info()
      print("Failed to open file on disk: {} {}".format(t, v))
      traceback.print_exception(t,v,s, file=sys.stdout)
      raise

  def merge(self, aRemote):
    with self.mutex:
      allKeys = set(self.certAuthorities.keys()).union(aRemote.keys())
      for k in allKeys:
        # Compat change from jsonpickle to pickle
        if isinstance(k, bytes):
          left=k.decode('utf8')
          self.certAuthorities[left].merge(aRemote[k])
        else:
          left = k
          if k.startswith("b'") and k.endswith("'"):
            left = k[2:-1]
          self.certAuthorities[left].merge(aRemote[k])

  def recordGeodata(self, aki, geodata):
    with self.mutex:
      oracle = None
      if aki not in self.certAuthorities:
        raise Exception("How did we miss an AKI?")
      oracle = self.certAuthorities[aki]
      if not set(["continent", "countrycode"]).issubset(geodata):
        raise Exception("Invalid geodata")
      oracle.logGeo(geodata["continent"], geodata["countrycode"])

  def recordCertMetadata(self, metaData):
    mandatorySet = set(["aki", "issuer", "fqdns", "regdoms", "wildcards"])
    if not mandatorySet.issubset(metaData):
      # Can't do anything with this non-BR-compliant cert
      raise ValueError("Can't handle non-BR-compliant cert (missing field {}): {}".format(mandatorySet.difference(metaData), metaData))

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
      wildcards = metaData["wildcards"].split(",")

      if oracle.isLogged(metaData["spki"]):
        return

      oracle.logCert(metaData["spki"], fqdns, regDoms, wildcards, metaData["issuedate"])
      if set(["continent", "countrycode"]).issubset(metaData):
        oracle.logGeo(metaData["continent"], metaData["countrycode"])

  @staticmethod
  def getFirstAttibute(attributeObj, oid):
    result = attributeObj.get_attributes_for_oid(oid)
    if len(result) == 0:
      raise ValueError("empty set of resulting attributes for {}: {}".format(oid, result))
    return result[0].value

  def getMetadataForCert(self, aPsl, aCert):
    metaData={}
    fqdns=set()

    # Issuance date, organization, and AKI are all required
    try:
      metaData["issuedate"] = aCert.not_valid_before.date().isoformat()
      metaData["issuer"] = self.getFirstAttibute(aCert.issuer, x509.oid.NameOID.ORGANIZATION_NAME)

      akiext = aCert.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier)
      metaData["aki"] = binascii.hexlify(akiext.value.key_identifier).decode('utf8')

      spki = aCert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier)
      metaData["spki"] = binascii.hexlify(spki.value.digest).decode('utf8')

      # Get the FQDNs
      fqdns.add(self.getFirstAttibute(aCert.subject, x509.oid.NameOID.COMMON_NAME))

    except x509.extensions.ExtensionNotFound as e:
      raise ValueError(e)

    try:
      san = aCert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
      fqdns.update(san.value.get_values_for_type(x509.DNSName))
    except:
      # SANs are optional, sorta.
      pass

    # Filter wildcards
    metaData["wildcards"] = ",".join(set(filter(lambda x: x.startswith("*.")==True, fqdns)))

    # Get the registered domains
    regdoms = set()
    for fqdn in fqdns:
      regdoms.add(aPsl.suffix(fqdn) or fqdn)
    metaData["regdoms"] = ",".join(regdoms)

    # All FQDNs, including wildcards
    metaData["fqdns"] = ",".join(fqdns)

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

  def setOffsets(self, offsets):
    self.offsets = offsets

  def serialize(self, fp):
    return pickle.dump(self.certAuthorities, fp)

  def serializeOffsets(self):
    return jsonpickle.encode(self.offsets)
