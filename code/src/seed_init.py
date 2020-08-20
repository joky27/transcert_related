import pandas as pd
import mucert_util
import os
import shutil
from OpenSSL import crypto
from datetime import datetime,timedelta
import conf





def seed_stat_init(filefolder):
    file_cov={}
    cov_stat={}
    filelists = os.listdir(filefolder)
    for file in filelists:
        fileid = file.split('.')[0]
        (line_cov,branch_cov) = mucert_util.get_cov(os.path.join(filefolder,file))
        cov_key = str((line_cov,branch_cov))
        if cov_key in cov_stat.keys():
            cov_stat[cov_key]['cnt'] += 1
            cov_stat[cov_key]['fileids'].append(fileid)
        else:
            cov_stat[cov_key] = {}
            cov_stat[cov_key]['transfer_list'] = {}
            cov_stat[cov_key]['cnt'] = 1
            cov_stat[cov_key]['mod_cnt'] = 0
            cov_stat[cov_key]['fileids'] =list( [fileid])
        file_cov[fileid] = cov_key
    mucert_util.dump_json(file_cov,conf.file_cov_log)
    mucert_util.dump_json(cov_stat,conf.cov_stat_log)


def seed_func_stat_init(filefolder):
    file_cov = {}
    cov_stat ={}
    func_cov_code={}
    filelists = os.listdir(filefolder)
    for file in filelists:
        fileid = file.split('.')[0]
        func_set = mucert_util.get_func_set(os.path.join(filefolder,file))
        empty_set = set([])  # used to compare difference set
        func_len = str(len(func_set))
        func_code = func_len + '_0'
        cov_code = func_code
        if func_code not in func_cov_code.keys():
            func_cov_code[func_code] = list(func_set)
            file_cov[fileid] = func_code
        else:
            max_iter = len(func_cov_code.keys())
            for iter_num in range(max_iter):
                cov_code = func_len + '_' + str(iter_num)
                if cov_code in func_cov_code.keys():
                    func_set_0 = set(func_cov_code[cov_code])
                    if func_set.difference(func_set_0) == empty_set and func_set_0.difference(func_set) == empty_set:
                        file_cov[fileid] = cov_code
                        break
                else:
                    func_cov_code[cov_code] = list(func_set)
                    file_cov[fileid] = cov_code
                    break
        if func_code in cov_stat.keys():
            cov_stat[func_code]['cnt'] += 1
            cov_stat[func_code]['fileids'].append(fileid)
        else:
            cov_stat[func_code] = {}
            cov_stat[func_code]['transfer_list'] = {}
            cov_stat[func_code]['cnt'] = 1
            cov_stat[func_code]['mod_cnt'] = 0
            cov_stat[func_code]['fileids'] =list( [fileid])
    mucert_util.dump_json(file_cov, conf.file_cov_log)
    mucert_util.dump_json(cov_stat, conf.cov_stat_log)
    mucert_util.dump_json(func_cov_code,conf.func_encoder_log)


def func_seed_stat(file_cov):
    cov_stat = {}
    for fileid in file_cov.keys():
        func_code = file_cov[fileid]
        if func_code in cov_stat.keys():
            cov_stat[func_code]['cnt'] += 1
            cov_stat[func_code]['fileids'].append(fileid)
        else:
            cov_stat[func_code] = {}
            cov_stat[func_code]['transfer_list'] = {}
            cov_stat[func_code]['cnt'] = 1
            cov_stat[func_code]['mod_cnt'] = 0
            cov_stat[func_code]['fileids'] =list( [fileid])
    mucert_util.dump_json(cov_stat, '/home/juliazhu/Documents/ssl_on_the_fly/stats/line/cov_stat_line.json')



cov_folder = '/home/juliazhu/transcert/cov/'
seed_stat_init (cov_folder)
#file_cov = mucert_util.load_json('/home/juliazhu/Documents/ssl_on_the_fly/stats/line/file_cov_line.json')
#func_seed_stat(file_cov)

#used for transform root and leaf pem for openssl
#def cert_split(cert_path,CA_path):

#folder = '/home/corpus/origin'
#ca_cert_path = '/home/rootCA_key_cert.pem'
#target_folder='/home/corpus/new'
#corpus_unexpire_resign(folder,target_folder)
#seed_filefolder = '/home/juliazhu/Documents/ssl_experiments/new_seed'
#target_filefolder= '/home/juliazhu/Documents/ssl_experiments/new_seeds'
#result_content = pd.read_csv('/home/juliazhu/Documents/ssl_experiments/result.csv')
#seed_select(seed_filefolder,result_content,target_filefolder)
#filefolder = '/home/juliazhu/Documents/ssl_experiments/cov/results'
#seed_func_stat_init(filefolder)









