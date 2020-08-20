
'''
#1) the seed filefolder path where to load or generate seed files
HOME_DIR = '/home/juliazhu/PycharmProjects/coverage_guided_fuzzing/'
seed_filefolder = HOME_DIR+'util/results'
input_cert_path = HOME_DIR+'util/test_certs'

#2) get cov scripts filepath
#get cov info for one file and save the temp result in cov_result_filepath
#cov_program_filepath = HOME_DIR+ 'util/lemon_dij_test.cpp' #
#get_seed_cov = HOME_DIR+'src/scripts/batch_exec.sh'
get_one_cov = HOME_DIR+'src/scripts/each_exec.sh'
one_cov_filepath = HOME_DIR+'util/cov/temp.txt'

#3) statistic filepath
stat_folder = HOME_DIR +'util/stat/'
file_cov_log = stat_folder + 'file_cov.json'
cov_stat_log = stat_folder + 'cov_stat.json'
node_id_log = stat_folder + 'nodeid.json'

#4) extra necessary files
ca_cert_path = HOME_DIR + 'util/rootCA_key_cert.pem'
configfile = HOME_DIR + 'util/example_franken.conf'
modify_log_path = HOME_DIR + 'util/stat/mod_log.json'
'''


HOME_DIR ='/home/transcert/'
input_cert_path = HOME_DIR+'utils/corpus/'
seed_filefolder = HOME_DIR+'seeds/'
ca_cert_path = HOME_DIR+'rootCA.pem'
#queue_path = HOME_DIR+'stats/line/queue.npy'#stats/line/queue.npy'
modify_log_path = HOME_DIR +'utils/stats/mod_log.json'#'stats/line/mod_log.json'
configfile=HOME_DIR +'example_franken.conf'
file_cov_log = HOME_DIR + 'utils/stats/file_cov.json'#'stats/control_func/file_cov_func.json'#'stats/line/file_cov_line.json'
cov_stat_log = HOME_DIR + 'utils/stats/cov_stat.json'#'stats/control_func/cov_stat_func.json'#stats/line/cov_stat_line.json
#file_cov_log = HOME_DIR + 'stats/func/file_cov_func.json'
#cov_stat_log = HOME_DIR + 'stats/func/cov_stat_func.json'
#func_encoder_log = HOME_DIR + 'stats/func/func_encoder.json'#func encoder
#cov_certs_path =HOME_DIR + 'cov_certs/certs'
openssl_root = HOME_DIR+'root/'
openssl_leaf = HOME_DIR+'leaf/'
cov_results_path = HOME_DIR + 'utils/cov/'

##on_the_fly_testing ##
test_results_path = HOME_DIR + 'utils/results/'
unconsis_folder = HOME_DIR + 'utils/unconsis/'
unconsis_seed_path = unconsis_folder +'seeds/'
unconsis_root_path = unconsis_folder +'root/'
unconsis_leaf_path = unconsis_folder +'leaf/'

##startegy2
extension_corpus = HOME_DIR +'utils/extension_corpus/'
extension_json = HOME_DIR + 'utils/stats/corpus.json'




