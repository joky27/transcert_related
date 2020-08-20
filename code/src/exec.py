import os
import conf

index_max = 2500#2500
index = 0
while index < index_max:
    try:
        print("----starting the "+str(index)+"th iteration")
        os.system("python modify.py start")
        print("------modify finished-------")
        if (index != 0) and not(os.path.exists(conf.queue_path)):
            break
        #os.system("python parsing_filter.py")
        #print("-----parsing collected-----")
        #############################add one line for control_func####################
        os.system("python parsing_filter.py")
        print("------on-the-fly testing finished-------")
        #############################################################
        os.system("sh scripts/batch_exec.sh")
        print("-----cov collected--------")
        os.system("python modify.py stat")
        print("-----stat finished--------")
        os.system("rm -rf /home/juliazhu/Documents/ssl_on_the_fly/cov/info/*")#/home/modify/temp/* s used to save the certs(parsable) into related folders
        os.system(
            "rm -rf /home/juliazhu/Documents/ssl_on_the_fly/cov/results/*")  # /home/modify/temp/* s used to save the certs(parsable) into related folders
        os.system("rm -rf /home/juliazhu/Documents/ssl_on_the_fly/cov_certs/certs/*")#/home/modify/temp/* s used to save the certs(parsable) into related folders
        os.system("rm -rf /home/juliazhu/Documents/ssl_on_the_fly/cov_certs/root/*")#/home/modify/temp/* s used to save the certs(parsable) into related folders
        os.system("rm -rf /home/juliazhu/Documents/ssl_on_the_fly/cov_certs/leaf/*")#/home/modify/temp/* s used to save the certs(parsable) into related folders
        print("----finishing the " + str(index) + "th iteration----")

        index += 1
    except:
        pass
