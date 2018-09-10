#!/usr/bin/python3
#
# This Python script shows how to make download a support bundle using the
# basic REST API calls (including a POST call) on an NSX Manager Server.
#
# More information on the NSX Manager REST API is here:
# http://pubs.vmware.com/nsx-63/topic/com.vmware.ICbase/PDF/nsx_63_api.pdf
# https://pubs.vmware.com/NSX-6/topic/com.vmware.ICbase/PDF/nsx_604_api.pdf

import base64
import ssl
import urllib.request

username = 'admin'
password = '#zgx@jGJ'
nsxManager = '10.217.91.251'

def nsxSetup(username, password):
   '''Setups up Python's urllib library to communicate with the
      NSX Manager.  Uses TLS 1.2 and no certification for demo
      purposes.
      Returns the authorization field you need to put in the
      request header.
   '''

   context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
   context.verify_mode = ssl.CERT_NONE
   httpsHandler = urllib.request.HTTPSHandler(context = context)

   manager = urllib.request.HTTPPasswordMgrWithDefaultRealm()
   authHandler = urllib.request.HTTPBasicAuthHandler(manager)

   # The opener will be used for for all urllib calls, from now on.
   opener = urllib.request.build_opener(httpsHandler, authHandler)
   urllib.request.install_opener(opener)

   basicAuthString = '%s:%s' % (username, password)
   field = base64.b64encode(basicAuthString.encode('ascii'))
   #Debugging: print('Basic %s' % str(field,'utf-8'))
   return 'Basic %s' % str(field,'utf-8')

def nsxGetBundle(host, authorizationField):
   '''Get the bundle from the NSX Manager.
      This requires two REST hits.  The first returns the location of the
      bundle, and the second returns the bundle itself.
      bundleLocation is the URL of the full location of the bundle
      bundleName is the file name (last component) of the bundle location
   '''
   request = urllib.request.Request(
                'https://%s/api/1.0/appliance-management/techsupportlogs/NSX' % host,
                method='POST',
                headers={'Authorization': authorizationField})
   response = urllib.request.urlopen(request)

   # The first REST hit returns the location in the 'Location' field in the
   # response header, not as text in the body.
   bundleLocation = response.info()['Location']
   #Debugging: print(response.info()['Location'])
   bundleName = bundleLocation.split("/")[-1]

   request = urllib.request.Request('https://%s/%s' % (host,bundleLocation),
             method='GET',
             headers={'Authorization': authorizationField})
   response = urllib.request.urlopen(request)

   print('Got bundle: %s' % bundleName)
   # binary mode is important here.  This is a *.gz file, so binary.
   with open(bundleName,'wb') as bundleFile:
      bundleFile.write(response.read())

print('Getting support bundle from %s.  This might take a few minutes.' %
      nsxManager)
authorizationField = nsxSetup(username,password)
nsxGetBundle(nsxManager, authorizationField)
