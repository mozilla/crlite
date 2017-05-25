
def processS3(bucket):
  # response = client.list_objects_v2(
  #   Bucket=bucket,
  #   MaxKeys=1024,
  #   # StartAfter='string',
  # )

  # print(response)
  # for obj in response['Contents']:
  #   print(obj)

  for obj in s3.Bucket(bucket).objects.filter(Prefix="cert/"):
    # print(obj)
    parts = obj.key.split("/")
    year = int(parts[1])
    dayOfYear = int(parts[2])

    # Is this expired (check by looking the path so we don't have to continue
    # to load)
    now = time.gmtime()
    if (year < now.tm_year) or (year == now.tm_year and dayOfYear < now.tm_yday):
      counter["Expired"] += 1
      continue

    # OK, not expired yet!
    # Grab the metadata, because let's assume we've already processed the cert
    headObj = client.head_object(Bucket=obj.bucket_name, Key=obj.key)
    try:
      # print("Trying {}".format(headObj))
      oracle.processCertMetadata(headObj['Metadata'])

      counter["Metadata Up-to-Date"] += 1
    except KeyError as missingKey:
      # I guess we haven't processed the cert yet, so let's process it.
      dlObj = obj.get()
      der_data = dlObj['Body'].read()
      try:
        cert = x509.load_der_x509_certificate(der_data, default_backend())
        metaData = oracle.getMetadataForCert(psl, cert)
        # print("Updating metadata for {} to {}".format(obj.key, metaData))
        # Save back that metadata
        result = obj.copy_from(CopySource={'Bucket':obj.bucket_name, 'Key':obj.key},
                               Metadata=metaData, MetadataDirective="REPLACE")

        counter["Metadata Updated"] += 1
      except ValueError as e:
        # Problem parsing the certifiate
        problemFd.write("{}\t{}\t{}\n".format(obj.key, obj, e))
        counter["Certificate Parse Errors"] += 1

    counter["Total Certificates Processed"] += 1
