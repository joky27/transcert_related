import os
#the function is to extract the date and chain length of a pem

from OpenSSL import crypto
from datetime import datetime,timedelta
#import modify_distributed
#import modify_distributed
import mucert_util
import shutil

import pandas as pd

def pem_info_extract(pem_filepath):
    cert_chains =load_file(pem_filepath)
    print(len(cert_chains))
    index = 0
    for cert in cert_chains:
        expired = cert.get_notAfter()
        expired_time = datetime.strptime(expired[0:8], '%Y%m%d')
        print("the expired time of the "+str(index)+"cert is "+str(expired_time))
        index += 1

def pem_total(pem_folder):
    pem_filelists = os.listdir(pem_folder)
    for pem_file in pem_filelists:
        pem_filename = pem_file.split('.')[0]
        print("tracing pem content"+str(pem_filename))
        pem_filepath = os.path.join(pem_folder,pem_file)
        pem_info_extract(pem_filepath)

def load_file(pem_filepath):
    chain = []
    with open(pem_filepath, "r") as f:
        buf = f.read()
        index1 = 0
        start = buf.find('-----BEGIN CERTIFICATE-----', index1)
        end = buf.find('-----END CERTIFICATE-----', start)

        while start >= 0:
            buf1 = buf[start:end + 25]
            try:
                seed0 = crypto.load_certificate(crypto.FILETYPE_PEM, buf1)
                chain.insert(0, seed0)
            except:
                print
                ("Skipping: " +pem_filepath)
            index1 = start + 1
            start = buf.find('-----BEGIN CERTIFICATE-----', index1)
            end = buf.find('-----END CERTIFICATE-----', start)
    return chain

def delete_field_X509(cert, field):
    new_cert = crypto.X509()
    new_cert.set_version(2)
    if (not field is "notBefore") and (not cert.get_notBefore() is None):
        new_cert.set_notBefore(cert.get_notBefore())
    if (not field is "notAfter") and (not cert.get_notAfter() is None):
        new_cert.set_notAfter(cert.get_notAfter())
    if (not field is "subject") and (not cert.get_subject() is None):
        new_cert.set_subject(cert.get_subject())
        #print(new_cert.get_subject())
    if (not field is "serial_number") and (not cert.get_serial_number() is None):
        new_cert.set_serial_number(cert.get_serial_number())
        #print(new_cert.get_serial_number())
    if ( not field is "extensions"):
        extensions = []
        for i in range(cert.get_extension_count()):
            extension = cert.get_extension(i)
            extensions.append(extension)
        new_cert.add_extensions(extensions)
    new_cert.set_issuer(cert.get_issuer())
    #print(new_cert.get_notAfter())
    return new_cert

def resign_certificate(origin_pem_filepath,target_pem_filepath):
    #chains = []
    #chain_0 = mucert_util.load_file('certs/8931_medium.pem')[0]
    #chains.append(chain_0)
    chains = mucert_util.load_file(origin_pem_filepath)
    #chains.append(chain_1)

    mucert_util.pkeys = mucert_util.gen_pkeys()
    with open(ca_cert_path, 'rt') as ca_cert_file:#ca_cert_path
        ca_cert = crypto.load_certificate(crypto.FILETYPE_PEM, ca_cert_file.read())
    #read_root CA cert

    with open(ca_cert_path, 'rt') as ca_key_file:
        ca_key = crypto.load_privatekey(crypto.FILETYPE_PEM, \
                                                ca_key_file.read())
    ###########################################################
    expired = (datetime.now() + timedelta(days=150)).strftime("%Y%m%d%H%M%SZ")
    chains[0].set_notAfter(expired)
        ###########################################################
    ################extensions##############################################
    #chains[0].set_subject(mucert_util.load_file('/home/1112.pem')[0].get_subject())
    #chains[0].set_version(2)
    extensions = []
    pick_cert = chains[0]#mucert_util.load_file('certs/162923_unexpire.pem')[1]
    print(pick_cert.get_extension_count())
    #extension_1 = mucert_util.load_file('/home/4.34.200.211.pem')[0].get_extension(3)
    #extension_1.set_critical(mucert_util.load_file('/home/4.34.200.211.pem')[0].get_extension(1).get_critical())
    #extension_2 = mucert_util.load_file('/home/103.243.34.100.pem')[0].get_extension(5)
    #extension_2.set_critical(mucert_util.load_file('/home/4.34.200.211.pem')[0].get_extension(1).get_critical())
    #extensions.append(extension_1)
    #extensions.append(extension_2)


    for i in range(pick_cert.get_extension_count()):  # pick_cert.get_extension_count()-4):
        extension = pick_cert.get_extension(i)
        extension_name = extension.get_short_name()
        if extension_name == b'nsCertType' or extension_name == b'crlDistributionPoints'or\
                extension_name == b'certificatePolicies' or extension_name == b'subjectKeyIdentifier'or \
                extension_name == b'authorityKeyIdentifier' or extension_name ==b'UNDEF':
            continue
        else:
            extension.set_critical(mucert_util.load_file('/home/juliazhu/Documents/ssl_experiments/corpus/4.34.200.211.pem')[0].get_extension(1).
                                   get_critical())
            extensions.append(extension)
    print(len(extensions))

    chains[0] = delete_field_X509(chains[0], "extensions")
    chains[0].add_extensions(extensions)

    hash_for_sign = 'sha256'  # random.choice(hash_for_sign_list)
    chains[0].set_issuer(ca_cert.get_subject())
    #sign by CA
    key = ca_key
    for i in range(0, len(chains)):
            chains[i].set_pubkey(mucert_util.pkeys[i % 3])
            chains[i].sign(key, hash_for_sign)
            key = mucert_util.pkeys[i % 3]
   # print(len(chain_0))
   # print(chain_0[0].get_extension_count())
    certs = []
    #certs.append((key, list(chains)))
    certs.append((key, list(reversed(chains))))
    mucert_util.dump_cert(certs, target_pem_filepath)

#fconf = franken_conf_parse.parse_config(conf.configfile)
def recalculate_chain_length(pem_folder,result_content):
    for row in result_content.itertuples():
        att_openssl = getattr(row, 'openssl_acc')
        if att_openssl == 'T':
             pem_id = getattr(row, 'CA')
             pem_filepath = os.path.join(pem_folder,str(pem_id)+'.pem')
             chains = mucert_util.load_file(pem_filepath)
             if len(chains)>= 2:
                 print(pem_id)

def retrieve_unparsable(seed_folder,root_pem_folder,leaf_pem_folder):
    unparsable_folder = seed_folder+'/unparsable'
    file_cnt = 0
    posix_cnt = 0
    files = os.listdir(unparsable_folder)
    for file in files:
        if file.find('_')> 0:
            posix_cnt +=1
            posix = file.split('.')[0].split('_')[1]
            fileid = file.split('.')[0].split('_')[0]
            if posix == 'root':
                shutil.copy(os.path.join(unparsable_folder,file),os.path.join(root_pem_folder,fileid+'.pem'))
            elif posix == 'leaf':
                shutil.copy(os.path.join(unparsable_folder,file),os.path.join(leaf_pem_folder,fileid+'.pem'))
        else:
            print(file)
            file_cnt += 1
            shutil.copy(os.path.join(unparsable_folder,file),os.path.join(seed_folder,file))

def rename_corpus(filefolder,targetfolder):
    #renmae it to 0-1005.pem and remove undef parts
    filenames = os.listdir(filefolder)
    index = 0
    for filename in filenames:
        remove_undef_part(os.path.join(filefolder,filename),
                  os.path.join(targetfolder,str(index)+'.pem'))
        index += 1


def remove_undef_part(filepath,target_filepath):
    chains = mucert_util.load_file(filepath)
    # chains.append(chain_1)
    mucert_util.pkeys = mucert_util.gen_pkeys()
    with open(ca_cert_path, 'rt') as ca_cert_file:  # ca_cert_path
        ca_cert = crypto.load_certificate(crypto.FILETYPE_PEM, ca_cert_file.read())
    # read_root CA cert

    with open(ca_cert_path, 'rt') as ca_key_file:
        ca_key = crypto.load_privatekey(crypto.FILETYPE_PEM, \
                                        ca_key_file.read())

    ###########################################################
    expired = (datetime.now() + timedelta(days=150)).strftime("%Y%m%d%H%M%SZ")
    chains[0].set_notAfter(expired)
    ###########################################################
    extensions =[]
    for i in range(chains[0].get_extension_count()-1):  # pick_cert.get_extension_count()-4):
             extension = chains[0].get_extension(i)
             extension.set_critical(mucert_util.load_file('/home/4.34.200.211.pem')[0].get_extension(1).
                                    get_critical())
             if extension.get_short_name == b'UNDEF':
                 continue
             else:
                 extensions.append(extension)
            #extension = mucert_util.load_file('/home/5.10.83.6.pem')[0].get_extension(6)
            #extensions.append(extension)
    print(len(extensions))

    chains[0] = delete_field_X509(chains[0], "extensions")
    chains[0].add_extensions(extensions)
    hash_for_sign = 'sha256'  # random.choice(hash_for_sign_list)
    chains[0].set_issuer(ca_cert.get_subject())
    # sign by CA
    key = ca_key
    for i in range(0, len(chains)):
        chains[i].set_pubkey(mucert_util.pkeys[i % 3])
        chains[i].sign(key, hash_for_sign)
        key = mucert_util.pkeys[i % 3]
    certs = []
    certs.append((key, list(chains)))
    #certs.append(list(reversed(chains)))
    mucert_util.dump_cert(certs, target_filepath)
    os.remove(filepath)

#seed_folder = '/home/new_ssl_experiments/control_func/new_seeds'
#root_pem_folder = '/home/new_ssl_experiments/control_func/openssl_root'
#leaf_pem_folder = '/home/new_ssl_experiments/control_func/openssl_leaf'
#retrieve_unparsable(seed_folder,root_pem_folder,leaf_pem_folder)

#pem_folder = '/home/certs/'
#result_content = pd.read_csv('/home/total_results/control_func/result.csv')
#recalculate_chain_length(pem_folder,result_content)
#############################################resign for the certs#######################
#ca_cert_path ='/home/rootCA_key_cert.pem'
#filefolder = '/home/corpus/origin'
#targetfolder ='/home/corpus/critical'
#rename_corpus(filefolder,targetfolder)



def move_critical(home_folder,target_folder,csv_content):
    for row in csv_content.itertuples():
            openssl_acc = getattr(row, 'openssl_acc')
            polarssl_acc = getattr(row, 'polarssl_acc')
            gnutls_acc = getattr(row, 'gnutls_acc')
            file_id = getattr(row, 'CA')
            if openssl_acc == 'T' and polarssl_acc == 'T' and gnutls_acc == 'T':
                 os.remove(os.path.join(home_folder,str(file_id)+'.pem'))
            #if openssl_acc == 'T' and polarssl_acc == 'T' and gnutls_acc == 'T':
            #    shutil.copy(os.path.join(home_folder,str(file_id)+'.pem'),
            #                os.path.join(target_folder,str(file_id)+'.pem'))

#home_folder='/home/certs/corpus_critical'
#target_folder ='/home/certs/corpus_critical/pass_critical'
#csv_content = pd.read_csv('/home/results/corpus_critical/result.csv')
#move_critical(home_folder,target_folder,csv_content)

ca_cert_path ='/home/juliazhu/Documents/ssl_experiments/rootCA_key_cert.pem'
corpus_folder = '/home/juliazhu/Documents/ssl_experiments/corpus'
target_folder ='/home/juliazhu/Documents/ssl_experiments/corpus_critical'


files = os.listdir(corpus_folder)
index = 0
for file in files:
    origin_pem_filepath = os.path.join(corpus_folder,file)
    target_pem_filepath = os.path.join(target_folder,str(index)+'.pem')
    resign_certificate(origin_pem_filepath, target_pem_filepath)
    index += 1

#ca_cert_path ='/home/rootCA_key_cert.pem'
#certs = ['466.pem','688.pem','756.pem']
#home_folder = '/home/corpus/critical'
#target_folder = '/home/corpus/critical/pass_critical'
#for cert in certs:
#    origin_pem_filepath = os.path.join(home_folder,cert)
#    target_pem_filepath= os.path.join(target_folder,cert)
#    resign_certificate(origin_pem_filepath,target_pem_filepath)



#origin_pem_filepath = '/home/corpus/critical/97.pem'#no subject no subaltname
#target_pem_filepath = '/home/97_1.pem'
#resign_certificate(origin_pem_filepath,target_pem_filepath)

########################################################################################
#used to print the pem chain length and expired time for folder
#pem_folder = '/home/extract_pems/4'
#pem_total(pem_folder)
