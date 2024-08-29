How It Works:

    Hosts File: If the -hosts option is used, the script reads the list of IP addresses or hostnames from the specified file.  
    
    Directory Creation: For each host, a directory with the hostname is created, and all forensic data for that host is stored in that directory.  
    
    Passwordless sudo Check: The script attempts to run without a password, but if sudo requires a password, it prompts the user to rerun the script with the password.  
    
    Iterative Data Collection: The script iteratively collects forensic data from each host listed in the file and stores the results in separate directories.  

