import sqlite3, sys

if sys.version_info[0] < 3 or (sys.version_info[0] == 3 and sys.version_info[1] < 1):
   raise Exception("Must be using Python 3.1 or later")

class StatisticStorage:
  def __init__(self, dbPath=None):
    self.conn = sqlite3.connect(dbPath)
    self.conn.row_factory = sqlite3.Row
    # Ensure tables exist
    StatisticStorage.ensureTablesExist(self.conn)

  @staticmethod
  def ensureTablesExist(conn):
    c = conn.cursor()
    c.execute("CREATE TABLE IF NOT EXISTS timeline ("
                "issuerID integer not null REFERENCES issuers (issuerID),"
                "datestamp date not null, certsIssued integer not null,"
                "certsActive integer null, fqdnsActive integer null,"
                "regDomainsActive integer null, wildcardsActive integer null,"
                "CONSTRAINT 'issuerdatestamp' UNIQUE (issuerID, datestamp))")
    c.execute("CREATE TABLE IF NOT EXISTS issuers ("
                "issuerID integer primary key, aki string not null, name string not null,"
                "CONSTRAINT 'issuerakiname' UNIQUE (aki, name))")
    c.execute("CREATE TABLE IF NOT EXISTS firefoxpageloadstls ("
                "datestamp date primary key, countTLS integer not null, countPageloads integer not null,"
                "timeAdded datetime not null)")
    conn.commit()

  @staticmethod
  def columnNamesEqualValues(colNames):
    return map(lambda x: "{x}=:{x}".format(x=x), colNames)

  @staticmethod
  def makeInsertQuery(tablename=None, data={}):
    return "INSERT INTO {} ({}) VALUES ({})".format(tablename, ", ".join(data.keys()), ", ".join(map(lambda x: ":"+x, data.keys())))

  def upsert(self, tablename=None, pk=None, data={}):
    ins_query = StatisticStorage.makeInsertQuery(tablename=tablename, data=data)
    c = self.conn.cursor()
    try:
      c.execute(ins_query, data)
      # print("{}: {}".format(ins_query, data))
    except sqlite3.IntegrityError as ie:
      # If that fails, and pk is not None, do an UPDATE using the pk
      if pk is not None:
        pk_set = set(pk)
        update_items = set(data)-pk_set
        data_clause = ", ".join(StatisticStorage.columnNamesEqualValues(update_items))
        where_clause = " AND ".join(StatisticStorage.columnNamesEqualValues(pk))
        up_query = "UPDATE {} SET {} WHERE {}".format(tablename, data_clause, where_clause)
        # print(up_query)
        c.execute(up_query, data)
        # print("{}: {}".format(up_query, data))
      else:
        raise ie
    self.conn.commit()

  def getIssuerID(self, **kwargs):
    if kwargs['name'] is None or kwargs['aki'] is None:
      raise ValueError("Neither Name or AKI can be none")
    c = self.conn.cursor()
    sel_query = "SELECT issuerID FROM issuers WHERE {}".format(" AND ".join(StatisticStorage.columnNamesEqualValues(kwargs)))
    c.execute(sel_query, kwargs)
    row = c.fetchone()
    if row is not None:
      return row['issuerId']

    ins_query = StatisticStorage.makeInsertQuery(tablename="issuers", data=kwargs)
    c.execute(ins_query, kwargs)
    return c.lastrowid

  def updateCertTimeline(self, **kwargs):
    self.upsert(tablename="timeline", pk=['issuerID', 'datestamp'], data=kwargs)

  def updatePageloadTLS(self, **kwargs):
    self.upsert(tablename="firefoxpageloadstls", pk=['datestamp'], data=kwargs)
