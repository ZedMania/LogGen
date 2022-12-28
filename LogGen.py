from EmailSysAlert import AlertMailer
from socket import gethostname
from socket import gethostbyname
import sys
import os
import shutil
import glob



hostname = gethostname() 
ip = gethostbyname(hostname) 
ip_name = ip.replace(".", "")
dir_ex = AlertMailer().get_ex_dir()
folder_name = hostname+"-"+ip_name
folder_path = dir_ex+folder_name

def mrl_e():
        try:
            if os.path.exists(folder_path):
                file_paths = glob.glob(folder_path+"/*.csv")
                most_recent = max(file_paths, key=(os.path.getctime))    
                most_r_logtime = most_recent
            return most_r_logtime
        except:
            most_r_logtime = 0
            return most_r_logtime

if __name__ == '__main__':
    
    if os.path.exists(folder_path): 
        pass
    else:
        os.mkdir(folder_path)
    try:
        AlertMailer().clean_main_dir()
        mhash = AlertMailer().gen_mlist_h()
        mrlt = AlertMailer().get_most_recent_log_event(mrl_e())
        
        try:
            AlertMailer().create_logs(mrlt, mhash)
        except Exception as e:
            AlertMailer().log(e)
        try:
            main_path = AlertMailer().get_ex_dir()
            dir_ = os.scandir(main_path)
            log_dir_path = None     
            log_file_path = None
            for entry in dir_:
                if os.path.isdir(entry) and log_dir_path == None:
                    if os.path.basename(entry) == os.path.basename(folder_path):
                        log_dir_path = os.path.abspath(entry)        
                if os.path.isfile(entry):
                    if os.path.basename(entry).endswith('csv') == True:
                        log_file_path = os.path.abspath(entry)
            shutil.move(log_file_path, folder_path)

        except:
            report = 'No EVR generated'
            AlertMailer().log(report)
            
    except Exception as e:
        AlertMailer().log(e)