firstly, we should fix the filepath in the files:
        scripts/batch_exec.sh
        scripts/exec.sh
        scripts/verify_openssl_polarssl_gnutls_mbedtls
        conf.py


1. we should create a seed corpus: seed test cases that will not trigger any problems and then use the following command to collect coverage and init the graph
       cd scripts
       sh exec.sh
       python ../seed_init.py coverage_filefolder

2. use the following command to create testcases
       python modify.py  iteration_num s1 s2
    -- iteration_num : the number of total iteration(when to stop after *** iterations)
    -- s1 : whether adopt Strategy 1 or not (0 or 1)
    -- s2 : whether adopt Strategy 2 or not ( 0 or 1)

3. use the following command to conduct differential testing and simplify results
        sh scripts/verify_openssl_polarssl_gnutls_matrixssl.sh
        sh simplify_results
        python ../result_combine.py result_folder_path target_simplified_result_path