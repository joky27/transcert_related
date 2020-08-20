# Partially reuse some files in frankencert, see https://github.com/sumanj/frankencert.

from OpenSSL import crypto
import random
import collections
import sys
import os
import franken_conf_parse
import mucert_util
import conf
from datetime import datetime, timedelta
import Queue
import numpy as np
import shutil

#signed_by_CA = False
#certificates = mucert_util.load_dir(conf.input_cert_path)
#mucert_util.pkeys = mucert_util.gen_pkeys()


def get_extension_dict(certs):  # frankencert
    d = collections.defaultdict(dict)
    for cert in certs:
        extensions = get_extensions(cert)
        for i, extension in enumerate(extensions):
            """
            PyOpenSSL's get_short_name return UNKN for all unknown extensions
            This is bad for a mapping, our patched PyOpenSSL code has a 
            get_oid function.
            """
            d[extension.get_oid()][extension.get_data()] = extension
    for k in d.keys():
        d[k] = d[k].values()
    return d


def get_extensions(cert):  # frankencert
    return [cert.get_extension(i) \
            for i in range(0, cert.get_extension_count())]


def generate(certificates, ca_cert, ca_key, fconfig, count=1, \
             extensions=None):  # frankencert
    certs = []

    flip_probability = fconfig["flip_critical_prob"]
    self_signed_probability = fconfig["self_signed_prob"]
    max_depth = fconfig["max_depth"]
    max_extensions = fconfig["max_extensions"]
    public_key_len = fconfig["public_key_len"]

    if extensions is None:
        extensions = get_extension_dict(certificates)

    max_extensions = min(max_extensions, len(extensions.keys()))

    # generate the key pairs once and reuse them for faster
    # frankencert generation
    pkeys = []
    for i in range(max_depth):
        pkey = crypto.PKey()
        pkey.generate_key(crypto.TYPE_RSA, public_key_len)
        pkeys.append(pkey)

    progressbar_size = 10
    if (count > progressbar_size):
        step = count / progressbar_size
    else:
        step = 1
    for i in range(count):
        if (i % step == 0):
            sys.stdout.write(".")
            sys.stdout.flush()

        chain = []
        signing_key = ca_key
        issuer = ca_cert.get_subject()
        key = None
        length = random.randint(1, max_depth)
        if length == 1 and random.random() < self_signed_probability:
            issuer = None
        for j in range(length):
            key, cert = generate_cert(certificates, pkeys[j], signing_key, issuer, \
                                      max_extensions, extensions, fconfig["flip_critical_prob"], \
                                      fconfig["ext_mod_prob"], fconfig["invalid_ts_prob"], \
                                      fconfig["hash_for_sign"], fconfig["randomize_serial"])
            signing_key = key
            issuer = cert.get_subject()
            chain.append(cert)
        certs.append((key, list(reversed(chain))))
    return certs


def generate_cert(certificates, pkey, signing_key, issuer, max_extensions, \
                  extensions, flip_probability, \
                  ext_mod_probability, invalid_ts_probability, \
                  hash_for_sign_list, randomize_serial):  # frankencert

    cert = crypto.X509()

    cert.set_pubkey(pkey)
    pick = random.choice(certificates)

    cert.set_notAfter(pick.get_notAfter())
    pick = random.choice(certificates)
    cert.set_notBefore(pick.get_notBefore())
    if randomize_serial:
        cert.set_serial_number(random.randint(2 ** 128, 2 ** 159))
    else:
        pick = random.choice(certificates)
        cert.set_serial_number(pick.get_serial_number())
    pick = random.choice(certificates)
    cert.set_subject(pick.get_subject())

    if not issuer is None:
        cert.set_issuer(issuer)
    else:
        cert.set_issuer(cert.get_subject())

    # overwrite the timestamps if asked by the user
    if random.random() < invalid_ts_probability:
        if random.random() < 0.5:
            notvalidyet = b(datetime.now() + timedelta(days=1). \
                            strftime("%Y%m%d%H%M%SZ"))
            cert.set_notBefore(notvalidyet)
        else:
            expired = b(datetime.now() - timedelta(days=1). \
                        strftime("%Y%m%d%H%M%SZ"))
            cert.set_notBefore(expired)

            # handle the extensions
    # Currently we chose [0,max] extension types
    # then pick one entry randomly from each type
    # Hacked pyOpenSSL to support poking into the data
    # TODO: Multiple extensions of the same type?
    sample = random.randint(0, max_extensions)
    choices = random.sample(extensions.keys(), sample)
    new_extensions = [random.choice(extensions[name]) for name in choices]
    for extension in new_extensions:
        if random.random() < flip_probability:
            extension.set_critical(1 - extension.get_critical())
        if random.random() < ext_mod_probability:
            randstr = "".join(chr(random.randint(0, 255)) for i in range(7))
            extension.set_data(randstr)
    hash_for_sign = random.choice(hash_for_sign_list.split(','))#random.choice(hash_for_sign_list)
    print(hash_for_sign)
    cert.add_extensions(new_extensions)
    if not issuer is None:
        cert.sign(signing_key, hash_for_sign)
    else:
        cert.sign(pkey, hash_for_sign)
    return pkey, cert


# using a cert in certificates to update a cert in seed_certs
# recursively generate a new seed
def update_certs(filefolder, filename, target_name):
    # may have no chain
    # (1) select one seed file and a pick cert
    chain = mucert_util.load_file(filefolder, filename)  # may have no chain
    pick_file = random.choice(os.listdir(conf.input_cert_path))
    pick_chain = mucert_util.load_file(conf.input_cert_path, pick_file)
    pick_cert = pick_chain[random.randint(0, len(pick_chain) - 1)]
    target_filepath = os.path.join('/home/parsing/certs', target_name)
    #target_filepath = os.path.join(filefolder, target_name)
    with open(conf.ca_cert_path, 'rt') as ca_cert_file:
        ca_cert = crypto.load_certificate(crypto.FILETYPE_PEM, ca_cert_file.read())

    with open(conf.ca_cert_path, 'rt') as ca_key_file:
        ca_private_key = crypto.load_privatekey(crypto.FILETYPE_PEM, \
                                                ca_key_file.read())
    fconf = franken_conf_parse.parse_config(conf.configfile)

    # (2) generate a new seed file
    (updatecerts, operation) = update_cert(chain, pick_cert, certificates, ca_cert, ca_private_key, fconf, None)
    if (updatecerts is None) or len(updatecerts) is not 1:
        return
    mucert_util.dump_cert(updatecerts, target_filepath)
    if os.path.exists(conf.modify_log_path):
        modify_log = mucert_util.load_json(conf.modify_log_path)
    else:
        modify_log = {}
    modify_log[target_name] = {}
    modify_log[target_name]['origin'] = filename
    modify_log[target_name]['operation'] = operation
    modify_log[target_name]['corpus'] = pick_file
    mucert_util.dump_json(modify_log, conf.modify_log_path)


def generate_with_extensions(cert, new_extensions):
    new_cert = crypto.X509()
    if (not cert.get_notBefore() is None):
        new_cert.set_notBefore(cert.get_notBefore())
    if (not cert.get_notAfter() is None):
        new_cert.set_notBefore(cert.get_notAfter())
    if (not cert.get_subject() is None):
        new_cert.set_subject(cert.get_subject())
    if (not cert.get_serial_number() is None):
        new_cert.set_serial_number(cert.get_serial_number())
    new_cert.add_extensions(new_extensions)
    return new_cert


# delete a field from a certificate structure
def delete_field_X509(cert, field):
    new_cert = crypto.X509()
    new_cert.set_version(2)
    if (not field is "notBefore") and (not cert.get_notBefore() is None):
        new_cert.set_notBefore(cert.get_notBefore())
    if (not field is "notAfter") and (not cert.get_notAfter() is None):
        new_cert.set_notBefore(cert.get_notAfter())
    if (not field is "subject") and (not cert.get_subject() is None):
        new_cert.set_subject(cert.get_subject())
    if (not field is "serial_number") and (not cert.get_serial_number() is None):
        new_cert.set_serial_number(cert.get_serial_number())
    if (not field is "extensions"):
        extensions = []
        for i in range(cert.get_extension_count()):
            extension = cert.get_extension(i)
            extensions.append(extension)
        new_cert.add_extensions(extensions)
    return new_cert


# Delete a field from a name subject. We delete a subject field by cloning the subject.
# Notice that a filed may have a length limit.
# define ub_name		32768
# define ub_common_name		64
# define ub_locality_name	128
# define ub_state_name		128
# define ub_organization_name	64
# define ub_organization_unit_name	64
# define ub_title		64
# define ub_email_address	128
def delete_field_X509Name(subject, field):
    new_cert = crypto.X509()
    new_subject = crypto.X509Name(new_cert.get_subject())

    if (not subject.name is None) and (not field is "name"):
        if len(subject.name) <= 32768:
            new_subject.name = subject.name
        else:
            new_subject.name = (subject.name)[:32768]

    if (not subject.title is None) and (not field is "title"):
        if len(subject.title) <= 64:
            new_subject.title = subject.title
        else:
            new_subject.title = (subject.title)[:64]

    if (not subject.countryName is None) and (not field is "countryName"):
        new_subject.countryName = subject.countryName

    if (not subject.stateOrProvinceName is None) and (not field is "stateOrProvinceName"):
        if len(subject.stateOrProvinceName) <= 128:
            new_subject.stateOrProvinceName = subject.stateOrProvinceName
        else:
            new_subject.stateOrProvinceName = (subject.stateOrProvinceName)[:128]

    if (not subject.localityName is None) and (not field is "localityName"):
        if len(subject.localityName) <= 128:
            new_subject.localityName = subject.localityName
        else:
            new_subject.localityName = (subject.localityName)[:128]

    if (not subject.organizationName is None) and (not field is "organizationName"):
        if len(subject.organizationName) <= 64:
            new_subject.organizationName = subject.organizationName
        else:
            new_subject.organizationName = (subject.organizationName)[:64]

    if (not subject.organizationalUnitName is None) and (not field is "organizationalUnitName"):
        if len(subject.organizationalUnitName) <= 64:
            new_subject.organizationalUnitName = subject.organizationalUnitName
        else:
            new_subject.organizationalUnitName = (subject.organizationalUnitName)[:64]

    if (not subject.commonName is None) and (not field is "commonName"):
        if len(subject.commonName) <= 64:
            new_subject.commonName = subject.commonName
        else:
            new_subject.commonName = (subject.commonName)[:64]

    if (not subject.emailAddress is None) and (not field is "emailAddress"):
        if len(subject.emailAddress) <= 128:
            new_subject.emailAddress = subject.emailAddress
        else:
            new_subject.emailAddress = (subject.emailAddress)[:128]
    return new_subject


# using a field of pick_cert to update a cert in chain
def update_cert(chain, pick_cert, certificates, ca_cert, ca_key, fconfig, \
                extensions=None):
    flip_probability = fconfig["flip_critical_prob"]
    sign_mode = 1  # we can sign (1) after or (2)before mutation. We remove the code for signing before mutation.

    # generate the key pairs once and reuse them for faster
    # frankencert generation
    max_depth = fconfig["max_depth"]

    max_extensions = fconfig["max_extensions"]
    if extensions is None:
        extensions = get_extension_dict(certificates)
    max_extensions = min(max_extensions, len(extensions.keys()))

    if len(chain) < 1:
        return None

    which_cert_in_chain = 0
    if len(chain) > 1:
        which_cert_in_chain = random.randint(0, len(chain) - 1)  # select a cert

    which_operation = random.randint(-4, 32)  # select an operation
    subject = chain[which_cert_in_chain].get_subject()

    if which_operation == -4:  # print "<--------------delete notAfter"
        chain[which_cert_in_chain] = delete_field_X509(chain[which_cert_in_chain], "notAfter")
    elif which_operation == -3:  # print "<--------------delete notBefore"
        chain[which_cert_in_chain] = delete_field_X509(chain[which_cert_in_chain], "notBefore")
    elif which_operation == -2:  # print "<--------------delete serial_number"
        chain[which_cert_in_chain] = delete_field_X509(chain[which_cert_in_chain], "serial_number")
    elif which_operation == -1:  # print "<--------------delete subject"
        chain[which_cert_in_chain] = delete_field_X509(chain[which_cert_in_chain], "subject")
    elif which_operation == 0:  # print "<--------------delete extensions"
        chain[which_cert_in_chain] = delete_field_X509(chain[which_cert_in_chain], "extensions")
    if which_operation == 1:  # print "<--------------update notAfter"
        if (not pick_cert.get_notAfter() is None):
            expired = pick_cert.get_notAfter()
            expired_time = datetime.strptime(expired[0:8], '%Y%m%d')
            print(expired_time)
            if (expired_time - datetime.now()).days < 0:
                add_day = random.randint(1, 100)
                expired = (datetime.now() + timedelta(days=add_day)).strftime("%Y%m%d%H%M%SZ")
                print(expired)
            chain[which_cert_in_chain].set_notAfter(expired)
    elif which_operation == 2:  # print "<--------------update notBefore"
        if (not pick_cert.get_notBefore() is None):
            chain[which_cert_in_chain].set_notBefore(pick_cert.get_notBefore())
    elif which_operation == 3:  # print "<--------------update serial_number"
        if (not pick_cert.get_serial_number() is None):
            chain[which_cert_in_chain].set_serial_number(pick_cert.get_serial_number())
    elif which_operation == 4:  # print "<--------------update subject"
        if (not pick_cert.get_subject() is None):
            chain[which_cert_in_chain].set_subject(pick_cert.get_subject())

    # update a field in a subject
    elif which_operation == 5:  # print "<--------------update countryName in subject"
        if not pick_cert.get_subject().countryName is None:
            subject.countryName = pick_cert.get_subject().countryName
        else:
            new_subject = delete_field_X509Name(subject, "countryName")
            chain[which_cert_in_chain].set_subject(new_subject)
    elif which_operation == 6:  # print "<--------------update stateOrProvinceName in subject"
        if not pick_cert.get_subject().stateOrProvinceName is None:
            if len(pick_cert.get_subject().stateOrProvinceName) <= 128:
                subject.stateOrProvinceName = pick_cert.get_subject().stateOrProvinceName
            else:
                subject.stateOrProvinceName = (pick_cert.get_subject().stateOrProvinceName)[:128]
        else:
            new_subject = delete_field_X509Name(subject, "stateOrProvinceName")
            chain[which_cert_in_chain].set_subject(new_subject)
    elif which_operation == 7:  # print "<--------------update localityName in subject"
        if not pick_cert.get_subject().localityName is None:
            if len(pick_cert.get_subject().localityName) <= 128:
                subject.localityName = pick_cert.get_subject().localityName
            else:
                subject.localityName = (pick_cert.get_subject().localityName)[:128]
        else:
            new_subject = delete_field_X509Name(subject, "localityName")
            chain[which_cert_in_chain].set_subject(new_subject)
    elif which_operation == 8:  # print "<--------------update organizationName in subject"
        if not pick_cert.get_subject().organizationName is None:
            if len(pick_cert.get_subject().organizationName) <= 64:
                subject.organizationName = pick_cert.get_subject().organizationName
            else:
                subject.organizationName = (pick_cert.get_subject().organizationName)[:64]
        else:
            new_subject = delete_field_X509Name(subject, "organizationName")
            chain[which_cert_in_chain].set_subject(new_subject)
    elif which_operation == 9:  # print "<--------------update organizationalUnitName in subject"
        if not pick_cert.get_subject().organizationalUnitName is None:
            if len(pick_cert.get_subject().organizationalUnitName) <= 64:
                subject.organizationalUnitName = pick_cert.get_subject().organizationalUnitName
            else:
                subject.organizationalUnitName = (pick_cert.get_subject().organizationalUnitName)[:64]
        else:
            new_subject = delete_field_X509Name(subject, "organizationalUnitName")
            chain[which_cert_in_chain].set_subject(new_subject)
    elif which_operation == 10:  # print "<--------------update commonName in subject"
        if not pick_cert.get_subject().commonName is None:
            if len(pick_cert.get_subject().commonName) <= 64:
                subject.commonName = pick_cert.get_subject().commonName  # "127.0.0.1"
            else:
                subject.commonName = (pick_cert.get_subject().commonName)[:64]  # "127.0.0.1"
        else:
            new_subject = delete_field_X509Name(subject, "commonName")
            chain[which_cert_in_chain].set_subject(new_subject)
    elif which_operation == 11:  # print "<--------------update emailAddress in subject"
        if not pick_cert.get_subject().emailAddress is None:
            if len(pick_cert.get_subject().emailAddress) <= 128:
                subject.emailAddress = pick_cert.get_subject().emailAddress
            else:
                subject.emailAddress = (pick_cert.get_subject().emailAddress)[:128]
        else:
            new_subject = delete_field_X509Name(subject, "emailAddress")
            chain[which_cert_in_chain].set_subject(new_subject)
    elif which_operation == 12:  # print "<--------------update name in subject"
        if not pick_cert.get_subject().name is None:
            if len(pick_cert.get_subject().name) <= 32768:
                subject.name = pick_cert.get_subject().name  # "127.0.0.1"
            else:
                subject.name = (pick_cert.get_subject().name)[:32768]  # "127.0.0.1"
        else:
            new_subject = delete_field_X509Name(subject, "name")
            chain[which_cert_in_chain].set_subject(new_subject)
    elif which_operation == 13:  # print "<--------------update title in subject"
        if not pick_cert.get_subject().title is None:
            if len(pick_cert.get_subject().title) <= 64:
                subject.title = pick_cert.get_subject().title  # "127.0.0.1"
            else:
                subject.title = (pick_cert.get_subject().title)[:64]  # "127.0.0.1"
        else:
            new_subject = delete_field_X509Name(subject, "title")
            chain[which_cert_in_chain].set_subject(new_subject)
        # complete updating a field in a subject

    # delete a field in subject
    elif which_operation == 14:  # print "<--------------delete countryName in subject"
        new_subject = delete_field_X509Name(subject, "countryName")
        chain[which_cert_in_chain].set_subject(new_subject)
    elif which_operation == 15:  # print "<--------------delete stateOrProvinceName in subject"
        new_subject = delete_field_X509Name(subject, "stateOrProvinceName")
        chain[which_cert_in_chain].set_subject(new_subject)
    elif which_operation == 16:  # print "<--------------delete localityName in subject"
        new_subject = delete_field_X509Name(subject, "localityName")
        chain[which_cert_in_chain].set_subject(new_subject)
    elif which_operation == 17:  # print "<--------------delete organizationName in subject"
        new_subject = delete_field_X509Name(subject, "organizationName")
        chain[which_cert_in_chain].set_subject(new_subject)
    elif which_operation == 18:  # print "<--------------delete organizationalUnitName in subject"
        new_subject = delete_field_X509Name(subject, "organizationalUnitName")
        chain[which_cert_in_chain].set_subject(new_subject)
    elif which_operation == 19:  # print "<--------------delete commonName in subject"
        new_subject = delete_field_X509Name(subject, "commonName")
        chain[which_cert_in_chain].set_subject(new_subject)
    elif which_operation == 20:  # print "<--------------delete emailAddress in subject"
        new_subject = delete_field_X509Name(subject, "emailAddress")
        chain[which_cert_in_chain].set_subject(new_subject)
    elif which_operation == 21:  # print "<--------------delete name in subject"
        new_subject = delete_field_X509Name(subject, "name")
        chain[which_cert_in_chain].set_subject(new_subject)
    elif which_operation == 22:  # print "<--------------delete title in subject"
        new_subject = delete_field_X509Name(subject, "title")
        chain[which_cert_in_chain].set_subject(new_subject)
        # complete deletion a field in a subject

    # update one cert in a chain
    elif which_operation == 23:  # print "<--------------append a cert"
        pick_cert.set_issuer(chain[len(chain) - 1].get_subject())
        chain.append(pick_cert)
    elif which_operation == 24:  # print "<--------------insert a cert aftet which_cert_in_chain"
        pick_cert.set_issuer(chain[which_cert_in_chain].get_subject())
        if (which_cert_in_chain < len(chain) - 1):  # not the last one
            chain[which_cert_in_chain + 1].set_issuer(pick_cert.get_subject())
        chain.insert(which_cert_in_chain + 1, pick_cert)
    elif which_operation == 25:  # print "<--------------insert a cert before which_cert_in_chain"
        pick_cert.set_issuer(chain[which_cert_in_chain].get_issuer())
        chain[which_cert_in_chain].set_issuer(pick_cert.get_subject())
        chain.insert(which_cert_in_chain, pick_cert)
    elif which_operation == 26:  # print "<--------------delete a cert at which_cert_in_chain"
        if (len(chain) <= 1):  # we cannot delete the only cert
            pass
        else:
            if (which_cert_in_chain + 1 < len(chain)):
                chain[which_cert_in_chain + 1].set_issuer(chain[which_cert_in_chain].get_issuer())
            del chain[which_cert_in_chain]
    elif which_operation == 27:  # print "<--------------update a cert"
        pick_cert.set_issuer(chain[which_cert_in_chain].get_issuer())
        if (which_cert_in_chain + 1 < len(chain)):
            chain[which_cert_in_chain + 1].set_issuer(pick_cert.get_subject())
        chain[which_cert_in_chain] = pick_cert
        # complete updating one cert in the chain

    # update extension
    elif which_operation == 28:  # print "<--------------append a set of extensions"
        new_extensions = []
        for i in range(pick_cert.get_extension_count()):
            extension = pick_cert.get_extension(i)
            new_extensions.append(extension)
        chain[which_cert_in_chain].add_extensions(new_extensions)
    elif which_operation == 29:  # print "<--------------append one extension"
        new_extensions = []
        count_pick = pick_cert.get_extension_count()

        if (count_pick < 1):
            pass
        else:
            index_pick = 0

            if count_pick > 1:
                index_pick = random.randint(0, count_pick - 1)
            extension = pick_cert.get_extension(index_pick)
            new_extensions.append(extension)

        chain[which_cert_in_chain].add_extensions(new_extensions)
    elif which_operation >= 30 and which_operation <= 32:  # print "<--------------update one extension"
        new_extensions = []
        for i in range(chain[which_cert_in_chain].get_extension_count()):
            extension = chain[which_cert_in_chain].get_extension(i)
            new_extensions.append(extension)

        count_cert = len(new_extensions)
        count_pick = pick_cert.get_extension_count()

        if (count_cert < 1 or count_pick < 1):
            pass
        else:
            index_cert = 0
            index_pick = 0
            if count_cert > 1:
                index_cert = random.randint(0, count_cert - 1)

            if count_pick > 1:
                index_pick = random.randint(0, count_pick - 1)

            if which_operation == 30:
                new_extensions[index_cert] = pick_cert.get_extension(index_pick)
            elif which_operation == 31:  # print "<--------------update critical of one extension"
                new_extensions[index_cert].set_critical(pick_cert.get_extension(index_pick).get_critical())
            elif which_operation == 32:  # print "<--------------update data of one extension"
                new_extensions[index_cert].set_data(pick_cert.get_extension(index_pick).get_data())
            chain[which_cert_in_chain] = generate_with_extensions(chain[which_cert_in_chain], new_extensions)
        # complete updating extensions
    elif which_operation == 33:  # print "<--------------do noting: other operations may be included here"
        pass

    key = None
    if sign_mode == 1:  # ****************mode 1: sign after mutation
        if len(chain) < 1:
            return None

        self_signed_probability = fconfig["self_signed_prob"]
        hash_for_sign_list = fconfig["hash_for_sign"]
        ######sign_algorithms add new requirements#########
        hash_for_sign = random.choice(hash_for_sign_list.split(','))#random.choice(hash_for_sign_list)
        print(hash_for_sign)

        if random.random() >= self_signed_probability:  # sign by CA
            chain[0].set_issuer(ca_cert.get_subject())
            key = ca_key

            for i in range(0, len(chain)):
                chain[i].set_pubkey(mucert_util.pkeys[i % 3])
                chain[i].sign(key, hash_for_sign)
                key = mucert_util.pkeys[i % 3]
        else:
            chain[0].set_issuer(chain[0].get_subject())
            chain[0].set_pubkey(mucert_util.pkeys[0])
            key = mucert_util.pkeys[0]
            chain[0].sign(key, hash_for_sign)
            for i in range(1, len(chain)):
                chain[i].set_pubkey(mucert_util.pkeys[i % 3])
                chain[i].sign(key, hash_for_sign)
                key = mucert_util.pkeys[i % 3]
                # end of mode 1

    certs = []
    certs.append((key, list(reversed(chain))))

    return certs, which_operation



def queue_init(queue_path):
    cov_stat = mucert_util.load_json(conf.statfile)
    cand_nodes = []
    for node in cov_stat.keys():
        if cov_stat[node]['cnt'] < 20:
            cand_nodes.append(node)
    np.save(queue_path,cand_nodes)
    return cand_nodes

def modify_init():
    if os.path.exists(conf.queue_path):
        c_nodes = list(np.load(conf.queue_path))
    else:
        c_nodes = queue_init(conf.queue_path)
    if len(c_nodes) != 0:
        select_node = c_nodes[0]
        c_nodes.pop(0) #delete the data of first position
        np.save(conf.queue_path, c_nodes)
        #cov_stat_log = mucert_util.load_json(conf.statfile)
        ############using folder name to represent the cov#######################
        filelist = os.listdir('/home/modify/'+str(select_node))
        filefolder = '/home/modify/'+str(select_node)
        #########################################################################
        #filelist = cov_stat_log[select_node]['fileids']
        i = 0
        for index in range(100):
             i += 1
             print("starting the " + str(i) + "th modification")
             #filenum = len(os.listdir(conf.seed_filefolder))
             #target_name = str(filenum) + '.pem'
        # randomid = random.randint(0,len(filelist)-1)
             filename = random.choice(filelist)
             #print(filepath)
             total_index = np.load(conf.total_index)[0]
             np.save(conf.total_index,np.array([total_index+1]))
             target_name = str(total_index)+'.pem'
             #target_filepath = os.path.join('/home/parsing/certs',target_name)
             #filename = str(fileid) + '.pem'
             try:
                 update_certs(filefolder, filename, target_name) #directly move to parsing/certs folder
                 #shutil.copy(os.path.join(conf.seed_filefolder,target_name),os.path.join(conf.all_certs_path,target_name))
             except:
                 continue
    else:
        os.remove(conf.queue_path)

def one_file_cov_update(func_set,file_cov,func_cov_code,cov_fileid):
    empty_set = set([])  # used to compare difference set
    func_len = str(len(func_set))
    func_code = func_len + '_0'
    cov_code = func_code
    if func_code not in func_cov_code.keys():
        func_cov_code[func_code] = list(func_set)
        file_cov[cov_fileid] = func_code
    else:
        max_iter = len(func_cov_code.keys())
        for iter_num in range(max_iter):
            cov_code = func_len + '_' + str(iter_num)
            if cov_code in func_cov_code.keys():
                func_set_0 = set(func_cov_code[cov_code])
                if func_set.difference(func_set_0) == empty_set and func_set_0.difference(func_set) == empty_set:
                    file_cov[cov_fileid] = cov_code
                    break
            else:
                func_cov_code[cov_code] = list(func_set)
                file_cov[cov_fileid] = cov_code
                break
    return file_cov,func_cov_code,cov_code


def cov_restat():  # used to collect covs of 100 modified files,and update cov_stat,and
    #add new nodes into the queue and check whether candidate nodes in the queue satisfied 20 files,
    #if so,delete it from the queue
    #update 3 files:cov_stat_0_line.json/file_cov_0_line.json/queue.npy
    ###10/8 newest one:loading the results of /home/share/results and move related files into related filefolder
    cov_files = os.listdir(conf.cov_results_path)
    c_nodes = list(np.load(conf.queue_path))
    c_new_nodes = []
    cov_stat = mucert_util.load_json(conf.statfile)
    file_cov = mucert_util.load_json(conf.file_cov_stat)
    mod_log = mucert_util.load_json(conf.modify_log_path)
    ################
    func_cov_code = mucert_util.load_json(conf.func_code_path) #function_node_encoder
    ################
    home_folder = '/home/modify/'
    for cov_file in cov_files:
        cov_fileid = cov_file.split('.')[0]
        origin_fileid = mod_log[cov_fileid+'.pem']["origin"].split('.')[0]
        origin_line_cov = file_cov[origin_fileid]
        #######func_set_part_code######
        func_set = mucert_util.get_func_set(os.path.join(conf.cov_results_path,cov_file))
        (file_cov, func_cov_code,line_cov) = one_file_cov_update(func_set,file_cov,func_cov_code,cov_fileid)
        ######func set part code######## cov_code is equal to line_cov in line part
        #line_cov = mucert_util.get_line_cov(os.path.join(conf.cov_results_path,cov_file))
        #file_cov[cov_fileid] = line_cov #update file_cov_0_line.json
        #########add new pem files into related folder#############
        cov_folder = home_folder + str(line_cov)
        if not os.path.exists(cov_folder):
            os.mkdir(cov_folder)
        shutil.copy(os.path.join('/home/modify/temp', cov_fileid + '.pem'), os.path.join(cov_folder, cov_fileid + '.pem'))
        print(cov_fileid + ' '+line_cov)
        if str(line_cov) not in cov_stat.keys():
            c_nodes.append(str(line_cov))   #new_nodes
            cov_stat[str(line_cov)]= {}
            cov_stat[str(line_cov)]['transfer_list'] = {}
            cov_stat[str(line_cov)]['cnt'] = 1
            cov_stat[str(line_cov)]['mod_cnt'] = 0
            cov_stat[str(line_cov)]['fileids'] = [str(cov_fileid)]
        else:
            cov_stat[str(line_cov)]['cnt'] += 1
            cov_stat[str(line_cov)]['fileids'].append(str(cov_fileid))
        cov_stat[str(origin_line_cov)]['mod_cnt'] += 1
        if str(line_cov) not in cov_stat[str(origin_line_cov)]['transfer_list'].keys():
                  cov_stat[str(origin_line_cov)]['transfer_list'][str(line_cov)] = 1
        else:
                  cov_stat[str(origin_line_cov)]['transfer_list'][str(line_cov)] += 1
    #update cov_stat_0_line.json
    for node in c_nodes:
        if cov_stat[node]['cnt'] < 20:
            c_new_nodes.append(node)
    mucert_util.dump_json(cov_stat,conf.statfile)
    mucert_util.dump_json(file_cov,conf.file_cov_stat)
    mucert_util.dump_json(func_cov_code,conf.func_code_path) #update func parts
    np.save(conf.queue_path,c_new_nodes)




if __name__ == '__main__':
    mode = sys.argv[1]
    if mode == 'start':
        print("start 1 iteration modification")
        starttime = datetime.now()
        signed_by_CA = False
        certificates = mucert_util.load_dir(conf.input_cert_path)
        mucert_util.pkeys = mucert_util.gen_pkeys()
        modify_init()
        endtime = datetime.now()
        used_time =  (endtime - starttime).seconds
        print("modify finished,total use "+str(used_time)+'s')
    elif mode == 'stat':
        cov_restat()
        print("stat info updated for 1 iteration is finished")


    #fconf = franken_conf_parse.parse_config(conf.configfile)
    #hash_for_sign_list = fconf['hash_for_sign']
    #print(hash_for_sign_list)
    #hash_test = hash_for_sign_list.split(',')
    #print(hash_test)
    #print(hash_test[0])
    #filefolder = '/home'
    #filename = '1008.pem'
    #target_name ='test_7.pem'
    #update_certs(filefolder, filename, target_name)


