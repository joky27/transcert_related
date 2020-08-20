import conf
import os
import shutil


def open_polar_accept(filepath,mode):
    flag = False
    with open(filepath, 'r') as result:
        buf = result.read()
        start = buf.find('-----START VERIFYING', 0)
        end = buf.find('-----END VERIFYING', start + 1)
        body = buf[start: end]
        if mode == 0:
            if (body.find('.pem: OK')>=0):
                flag = True
        elif mode == 1:
            if (body.endswith('ok\n')):
                flag = True
        elif mode == 2:
            if (body.find('Chain verification output: Verified. The certificate is trusted.') >= 0):
                flag = True
        else:
            if (body.find('PASS') >=0):
                flag = True
    result.close()
    return flag

def open_polar_parse(filepath,mode):
    #mode =0 is openssl,mode =1 is polarssl,mode=2 is gnutls
    flag = True
    with open(filepath, 'r') as result:
        buf = result.read()
        if mode == 0:
           if (buf.find('unable to load certificate') >= 0):
                flag = False
        elif mode == 1:
           if (buf.find('Loading the certificate(s) ... failed')>=0):
                flag = False
        else:
           if (buf.find('error parsing') >= 0):
                flag = False
    return flag
'''
os.system("sh scripts/verify_openssl_polarssl_gnutls.sh")
####collect openssl & polarssl &gbutls certs in /home/juliazhu/Documents/ssl_experiments/cov_certs # results
# to ../parsing/results#############

pem_names = os.listdir('/home/juliazhu/Documents/ssl_on_the_fly/cov_certs/certs')#to be changed
result_folder = '/home/juliazhu/Documents/ssl_on_the_fly/testing/results/'#to be changed
for pem_name in pem_names:
    pem_id = pem_name.split('.')[0]
    open_path = os.path.join(result_folder,pem_id+'.txt')
    polar_pem_name = pem_id+ '_polarssl.txt'
    polar_path = os.path.join(result_folder,polar_pem_name)
    gnutls_pem_name = pem_id + '_gnutls.txt'
    gnutls_path = os.path.join(result_folder, gnutls_pem_name)
    open_accept = open_polar_accept(open_path,mode=0)
    polar_accept = open_polar_accept(polar_path, mode=1)
    gnutls_accept = open_polar_accept(gnutls_path, mode=2)
    #open_parse = open_polar_parse(open_path,mode=0)
    #polar_parse = open_polar_parse(polar_path,mode=1)
    #gnutls_parse = open_polar_parse(gnutls_path, mode=2)
    if open_accept == True and  polar_accept== True and gnutls_accept == True:
        continue
    elif open_accept == False and polar_accept ==False and gnutls_accept==False:
        #goto  share/allcerts & backup in /home/modify/temp in stat phase
        shutil.move(os.path.join('/home/juliazhu/Documents/ssl_on_the_fly/new_seeds',pem_name),
                    os.path.join('/home/juliazhu/Documents/ssl_on_the_fly/new_seeds/reject/seeds',pem_name))
        if os.path.exists(os.path.join('/home/juliazhu/Documents/ssl_on_the_fly/openssl_leaf',pem_name)):
            shutil.move(os.path.join('/home/juliazhu/Documents/ssl_on_the_fly/openssl_leaf', pem_name),
                        os.path.join('/home/juliazhu/Documents/ssl_on_the_fly/new_seeds/reject/leaf', pem_id+'.pem'))
        if os.path.exists(os.path.join('/home/juliazhu/Documents/ssl_on_the_fly/openssl_root',pem_name)):
            shutil.move(os.path.join('/home/juliazhu/Documents/ssl_on_the_fly/openssl_root', pem_name),
                        os.path.join('/home/juliazhu/Documents/ssl_on_the_fly/new_seeds/reject/root', pem_id+'.pem'))
        os.remove(os.path.join('/home/juliazhu/Documents/ssl_on_the_fly/cov_certs/certs',pem_name))
        if os.path.exists(os.path.join('/home/juliazhu/Documents/ssl_on_the_fly/cov_certs/root', pem_name)):
            os.remove(os.path.join('/home/juliazhu/Documents/ssl_on_the_fly/cov_certs/root', pem_name))
        if os.path.exists(os.path.join('/home/juliazhu/Documents/ssl_on_the_fly/cov_certs/leaf', pem_name)):
            os.remove(os.path.join('/home/juliazhu/Documents/ssl_on_the_fly/cov_certs/leaf', pem_name))
    else:
        #goto  share/allcerts & backup in /home/modify/temp in stat phase
        shutil.move(os.path.join('/home/juliazhu/Documents/ssl_on_the_fly/new_seeds',pem_name),
                    os.path.join('/home/juliazhu/Documents/ssl_on_the_fly/new_seeds/unconsis/seeds',pem_name))
        if os.path.exists(os.path.join('/home/juliazhu/Documents/ssl_on_the_fly/openssl_leaf',pem_name)):
            shutil.move(os.path.join('/home/juliazhu/Documents/ssl_on_the_fly/openssl_leaf', pem_name),
                        os.path.join('/home/juliazhu/Documents/ssl_on_the_fly/new_seeds/unconsis/leaf', pem_id+'.pem'))
        if os.path.exists(os.path.join('/home/juliazhu/Documents/ssl_on_the_fly/openssl_root',pem_name)):
            shutil.move(os.path.join('/home/juliazhu/Documents/ssl_on_the_fly/openssl_root', pem_name),
                        os.path.join('/home/juliazhu/Documents/ssl_on_the_fly/new_seeds/unconsis/root', pem_id+'.pem'))
        os.remove(os.path.join('/home/juliazhu/Documents/ssl_on_the_fly/cov_certs/certs',pem_name))
        if os.path.exists(os.path.join('/home/juliazhu/Documents/ssl_on_the_fly/cov_certs/root', pem_name)):
            os.remove(os.path.join('/home/juliazhu/Documents/ssl_on_the_fly/cov_certs/root', pem_name))
        if os.path.exists(os.path.join('/home/juliazhu/Documents/ssl_on_the_fly/cov_certs/leaf', pem_name)):
            os.remove(os.path.join('/home/juliazhu/Documents/ssl_on_the_fly/cov_certs/leaf', pem_name))

#os.system("rm -rf /home/parsing/certs/*")
os.system("rm -rf /home/juliazhu/Documents/ssl_on_the_fly/testing/results/*")
#REMOVE RELATED FILES
'''