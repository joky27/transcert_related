#!/usr/bin/env python
import os
import subprocess
import sys

def process_openssl (filename):
    with open(filename, 'r') as result:
        buf = result.read()
        
        index1 = 0
        start = buf.find('-----START VERIFYING', index1)
        end = buf.find('-----END VERIFYING', start+1)      
        
        while start >= 0 and end>=0:    
            buf1 = buf[start:end]
            
            header_end = buf1.find('.pem')
            header = buf1[0:header_end+4]
                        
            body = buf1[header_end+5: end]
            
            result = header
            
            obtain_message=False
            if(body.find('unable to load certificate')>=0):
                result=result+ '-----reject for parsing errors'
                obtain_message=True
            if body.find('error 7 at 0 depth lookup:certificate signature failure')>=0:
                result=result+ '-----reject for error 7 at 0 depth lookup:certificate signature failure'
                obtain_message=True
            if(body.find('error 18 at 0 depth lookup:self signed certificate')>=0):
                result=result+ '-----reject for error 18 at 0 depth lookup:self signed certificate'
                obtain_message=True
            if body.find('error 10 at 0 depth lookup:certificate has expired')>=0:
                result=result+ '-----reject for error 10 at 0 depth lookup:certificate has expired'
                obtain_message=True
            if body.find('error 20 at 0 depth lookup:unable to get local issuer certificate')>=0:
                result=result+ '-----reject for error 20 at 0 depth lookup:unable to get local issuer certificate'
                obtain_message=True
                
            if body.find('error 34 at 0 depth lookup:unhandled critical extension')>=0:
                result=result+ '-----reject for error 34 at 0 depth lookup:unhandled critical extension'
                obtain_message=True
            if(body.find('.pem: OK')>=0):
                result=result+ '-----accept'
                obtain_message=True

            if (not obtain_message):
                result = result+ '-----reject for unexpected reason'
                        
            print result
                        
            index1 = start + 1
            start = buf.find('-----START VERIFYING', index1)
            end = buf.find('-----END VERIFYING', start+1)

def process_polarssl (filename):
    with open(filename, 'r') as result:
        buf = result.read()
        
        index1 = 0
        start = buf.find('-----START VERIFYING', index1)
        end = buf.find('-----END VERIFYING', start+1)      
        
        while start >= 0 and end>=0:    
            buf1 = buf[start:end]
            
            header_end = buf1.find('.pem')
            header = buf1[0:header_end+4]
                        
            body = buf1[header_end+5: end]
            
            result = header

            obtain_message=False            
            if(body.find('Loading the certificate(s) ... failed')>=0):
                result=result+ '-----reject for parsing errors'
                obtain_message=True
            if(body.find('! self-signed or not signed by a trusted CA')>=0):
                result=result+ '-----reject for self-signed or not signed by a trusted CA'
                obtain_message=True
            if body.find('! server certificate has expired')>=0:
                result=result+ '-----reject for server certificate has expired'
                obtain_message=True
            if(body.endswith('ok\n')):
                result=result+ '-----accept'
                obtain_message=True

            if (not obtain_message):
                result = result+ '-----reject for unexpected reason'
                        
            print result
                        
            index1 = start + 1
            start = buf.find('-----START VERIFYING', index1)
            end = buf.find('-----END VERIFYING', start+1)  

def process_gnutls (filename):
    
    with open(filename, 'r') as result:
        buf = result.read()
        
        index1 = 0
        start = buf.find('-----START VERIFYING', index1)
        end = buf.find('-----END VERIFYING', start+1)      
        
        while start >= 0 and end>=0:    
            buf1 = buf[start:end]
            
            header_end = buf1.find('.pem')
            header = buf1[0:header_end+4]
                        
            body = buf1[header_end+5: end]
            
            result = header

            obtain_message=False
            
            if(body.find('error parsing')>=0):
                result=result+ '-----reject for parsing errors'   
                obtain_message=True            
            if(body.find('Chain verification output: Not verified. The certificate is NOT trusted. The certificate issuer is unknown.')>=0):
                result=result+ '-----reject for The certificate issuer is unknown'
                obtain_message=True
            if(body.find('Chain verification output: Not verified. The certificate is NOT trusted. The certificate chain uses expired certificate.')>=0):
                result=result+ '-----reject for expired certificate'
                obtain_message=True
            if(body.find('Chain verification output: Not verified. The certificate is NOT trusted. The signature in the certificate is invalid.')>=0):
                result=result+ '-----reject for invalid signature'
                obtain_message=True
            if(body.find('Chain verification output: Verified. The certificate is trusted.')>=0):
                result=result+ '-----accept'    
                obtain_message=True

            if (not obtain_message):
                result = result+ '-----reject for unexpected reason'
                        
            print result
                        
            index1 = start + 1
            start = buf.find('-----START VERIFYING', index1)
            end = buf.find('-----END VERIFYING', start+1)             

option = int(sys.argv[1])
filename = sys.argv[2]

if(option == 1):
    process_openssl (filename)
elif (option == 2):
    process_polarssl (filename)
elif (option == 4):
    process_gnutls (filename)
else:
    pass
