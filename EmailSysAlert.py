import socket 
import hashlib
import smtplib 
import ssl
import shutil
import os
import sys
from cryptography import fernet as FN
import time
import win32evtlog
from email.mime.multipart import MIMEMultipart as MM
from email.mime.text import MIMEText as MT
from email.mime.base import MIMEBase as MB
from email import encoders
import csv 
import pandas
import glob
import re
import datetime
import xml.etree.ElementTree as ET
import traceback

class AlertMailer: 
    '''make sure program is ran as admin'''
    def __init__(self):
        
        self.smtp_server = 'smtp.gmail.com'
        self.port = 465
        self.my_email = r'your@email'
#Due to recent changes to in gmail, sign in with the app password setting
        self.my_password = 'yourpassword'
        self.server = 'localhost'
        self.logpath = '\Security'
        self.event_logs_ = r'C:\Windows\System32\winevt\Logs'+self.logpath+'.evtx'
    def get_ip(self):    
        '''returns ip address'''
        host = socket.gethostname()
        ip = socket.gethostbyname(host)
        return ip
    def get_hostname(self):
        '''returns hostname'''
        hostname = socket.gethostname()
        return hostname
        
    def key_gen(self):
        '''returns a private key'''
        key = FN.binascii.hexlify(FN.os.urandom(16))
        return key
    def initalization_vector(self):
        '''returns an IV'''
        IV = FN.binascii.hexlify(FN.os.urandom(8))
        return IV
    def clean_main_dir(self):
        '''removes leftover csv due to crashes'''
        ex_dir = AlertMailer().get_ex_dir()
        scan = os.listdir(ex_dir)
        for x in scan:
            if x.endswith('.csv'):
                os.remove(os.path.join(ex_dir, x))
    
    def AES_file_encryptor(self,file,filename_r,key,IV):
        '''encrypts file'''
        nd = file
        cipher = FN.Cipher(FN.algorithms.AES(key) , FN.modes.CFB(IV))
        encryptor = cipher.encryptor()
        out = encryptor.update(nd)+encryptor.finalize()
        with open(os.path.basename(filename_r),'wb') as fout:
            fout.write(out)
            fout.close()

    def AES_file_decryptor(self,file,key,IV):
        '''decrypts file'''
        nd = file
        cipher = FN.Cipher(FN.algorithms.AES(key) , FN.modes.CFB(IV))
        decryptor = cipher.decryptor()
        final = decryptor.update(nd)+decryptor.finalize()
        return final
        
    def file_name(self):
        '''returns a genrated log name'''
        region_time = AlertMailer().date_format(datetime.datetime.now())
        utc_time = AlertMailer().date_format(datetime.datetime.utcnow())

        output = 'EVR-{}-{}'.format(region_time,utc_time)
        return output
        
    
    def get_csv_mlist(self):
        '''returns file path of the mlist'''
        ex_dir = AlertMailer().get_ex_dir()+'mlist'
        csv = os.path.join(ex_dir, 'mlist.csv')
        return csv
    
    def get_csv_main(self):
        '''returns file path of the csv in main dir'''
        ex_dir = AlertMailer().get_ex_dir()
        csv = glob.glob(ex_dir+'/*.csv')
        return csv[0]
 
    def pandas_r_csv(self):
        '''returns data as a pandas data frame'''  
        data = pandas.read_csv(AlertMailer().get_csv_mlist())
        return data
   
    def clean_mlist(self):
        '''removes null and special characters from mlist and returns a list of all event ids as int'''
        data = AlertMailer().pandas_r_csv()
        id_ = data['Current Event ID'].tolist()
        new_id_list = []
        for x in id_:
            if pandas.isnull(x):
                pass
            elif x == '-':
                pass
            else:
                new_id_list.append(int(x))
                
        new_id_list = sorted(new_id_list)
        return new_id_list

    def create_ml_dic(self,mlist_l):
        '''returns a dictionary of the mlist, use the gen_mlist_h for actual operation'''
        data = mlist_l
        mlist = AlertMailer().clean_mlist()
        ml_dic = {}
        for x in data:
            for y in mlist:
                if str(y) == x[0]:
                    ml_dic[y] = x
                    break
        return ml_dic
            
    def gen_mlist_h(self):
        '''returns dic for mlist'''  
        d = open(AlertMailer().get_csv_mlist() ,'r') 
        read_csv = csv.reader(d)
        data = AlertMailer().create_ml_dic(read_csv)
        d.close()
        return data   

    def get_ex_dir(self):
        '''returns the directory of the script'''
        log_dir_path = sys.argv[0]
        log_dir_path = log_dir_path.split(os.path.basename(sys.argv[0]))[0]
        return log_dir_path    

    def get_log_dir(self):
        '''returns the path of the logs'''
        ex_dir = AlertMailer().get_ex_dir()
        log_dir_path = os.path.join(ex_dir, 'Logs')
        if os.path.exists(log_dir_path) == True:
            return log_dir_path
        else:
            AlertMailer().create_log_dir()
            return log_dir_path
    
    def create_log_dir(self):
        '''create a Log directory if not present'''
        main_path = AlertMailer().get_ex_dir()
        dir_ = os.scandir(main_path)
        log_present = None
        for entry in dir_:
            if os.path.isdir(entry):
                # print(os.path.basename(entry))
                if os.path.basename(entry) == 'Logs':
                    log_present = True
                    break             
                else:
                    log_present = False
        if log_present == True:
            pass
        elif log_present == False:
            join_path = os.path.join(main_path, 'Logs')
            os.mkdir(join_path)

    def move_file(self):
        '''moves csv from main dir to logs'''
        main_path = AlertMailer().get_ex_dir()
        dir_ = os.scandir(main_path)
        log_dir_path = None     
        log_file_path = None
        for entry in dir_:
            if os.path.isdir(entry) and log_dir_path == None:
                if os.path.basename(entry) == 'logs':
                    log_dir_path = os.path.abspath(entry)        
            if os.path.isfile(entry):
                if os.path.basename(entry).endswith('csv') == True:
                    log_file_path = os.path.abspath(entry)
        shutil.move(log_file_path, log_dir_path)
 
    def date_gen(self):
        '''generates a readable date'''
        date = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
        return date
                       
    def checksum(self,encrypted_file):
        '''produces checksums in md5 [0] and sha256 [1]'''
        checksum_f = hashlib.sha256(encrypted_file)
        checksum_f_short = hashlib.md5(encrypted_file)
        return ('md5', checksum_f_short.hexdigest()),('sha256' , checksum_f.hexdigest())
    
    def info_report(self,IV,file_hash):
        '''generates report for email'''
        report = 'IV: {} \nSha256: {}'.format(IV,file_hash)
        return report
    
    def email_gen(self,info_report_,encrypted_file = None):
        '''generates email'''
        mail = MM()
        mail['Subject'] = 'EVR Alert '+ str(AlertMailer().date_gen())
        mail['From'] = self.my_email
        mail['To'] = self.my_email
        main_body = MT(info_report_)
        mail.attach(main_body)
        if encrypted_file != None:
            location = encrypted_file()
            attachment =  open(location,'rb')
            new_at = bytes(attachment.read())
            filename = os.path.basename(location)
            part = MB('application', 'octet-stream')
            part.set_payload(new_at)
            encoders.encode_base64(part)
            part.add_header('Content-Disposition', "attachment; filename= {}".format(filename))
            mail.attach(part)
            attachment.close()
        return mail
             
#potential risk, vunerabilty for mitm attack using starttls 
#using SMTP_SSL with default context encrypts with tls 1.3, verified with wireshark capture

    def send_mail(self,mail):
        '''sends encrypted email using smtp'''
        context = ssl.create_default_context()
        try:
            server = smtplib.SMTP_SSL(self.smtp_server,self.port,context=(context))
            server.login(self.my_email, self.my_password)
            server.sendmail(self.my_email, self.my_email,mail.as_bytes())                   
        except Exception as e:
            print(e)
            print(traceback.format_exc())
        finally:
            server.quit() 
     
    def logs_is_empty(self):
        '''checks logs for entrys returns true or false'''
        path = AlertMailer().get_log_dir()
        if len(os.listdir(path)) == 0:
            return True
        else: 
            return False

    def get_most_recent_log(self):
        ''' returns most recent log with path'''
        try:
            file_paths = glob.glob(AlertMailer().get_log_dir()+"/*.csv")
            most_recent = max(file_paths, key=(os.path.getctime))    
            return most_recent
        except:
            pass
        
    def get_most_recent_log_event(self,most_recent_csv_log):
        '''returns date of most recent event as int'''
        with open(most_recent_csv_log,'r') as file:
            reader = csv.reader(file)
            most_recent_e = 0
            try:
                for x in reader:
                    try:
                        formated_date = AlertMailer().date_format(x[2])
                        formated_date = int(formated_date)
                        if formated_date > most_recent_e:
                            most_recent_e = formated_date
                    except:
                        most_recent_e = 0
            except:
                most_recent_e = 0
            return most_recent_e
    
    def date_format(self,sys_time):
        '''returns system time as string'''
        sys_t = str(sys_time)
        reg = re.split(r'[^0-9]', sys_t)
        new_string = ''.join(reg)    
        return new_string
    
    def create_logs(self,most_rec_log,mlh):
        '''creates logs csv'''
        most_r_logtime = most_rec_log
        mhash = mlh
        query_handle = win32evtlog.EvtQuery(
        'C:\Windows\System32\winevt\Logs\Security.evtx',
        win32evtlog.EvtQueryFilePath)
        read_count = 0
        csv_table = []
        csv_header = ['Event ID','Potential Criticality','Time Created','level','Channel','Process ID','Thread ID','IP','Data','Description']
        csv_table.append(csv_header)
        ip = AlertMailer().get_ip()
        while True:
            events = win32evtlog.EvtNext(query_handle, 100)
            read_count += len(events)
            if len(events) == 0:
                break
            for event in events:      
                xml_content = win32evtlog.EvtRender(event, win32evtlog.EvtRenderEventXml)
                xml = ET.fromstring(xml_content)
                ns = '{http://schemas.microsoft.com/win/2004/08/events/event}'
                event_id = xml.find(f'.//{ns}EventID').text
                ev_id = int(event_id)
                time_created = xml.find(f'.//{ns}TimeCreated').get('SystemTime')
                tc = AlertMailer().date_format(time_created)
                tc = int(tc)
                if ev_id in mhash:
                    if tc > most_r_logtime:
                        potential_crit = mhash[ev_id][2]
                        level = xml.find(f'.//{ns}Level').text
                        channel = xml.find(f'.//{ns}Channel').text
                        execution = xml.find(f'.//{ns}Execution')
                        process_id = execution.get('ProcessID')
                        thread_id = execution.get('ThreadID')
                        data = xml.find(f'.//{ns}EventData')
                        data_dic = {}
                        description = mhash[ev_id][3] 
                        for x in data:
                            data_dic[x.get('Name')] = re.split(r'[\r\t\s\n]',str(x.text))
                        csv_table.append([event_id,potential_crit,time_created,level,channel,process_id,thread_id,ip,data_dic,description])
                else:
                    pass           
        if len(csv_table) > 1:
            with open( AlertMailer().file_name()+'.csv' , 'w',newline='') as f:
                write = csv.writer(f)
                write.writerows(csv_table)
        else:
            pass
              
    def mrl_e(self):
        ''' gets most recent log time if none returns 0 '''
        try:
            most_r_logtime = AlertMailer().get_most_recent_log_event(AlertMailer().get_most_recent_log())                
            return most_r_logtime
        except:
            most_r_logtime = 0
            return most_r_logtime
        
    def get_crash_dir(self):
        '''gets path of crash dir'''
        ex_dir = AlertMailer().get_ex_dir()
        crash_dir = ex_dir+'crashL'
        return crash_dir
    
    def crash_report(self,error,trace):
        '''generates a crash report to the crashL folder'''
        report = '{} \n\n{}\n\n{}'.format(AlertMailer().date_gen(),error,trace)
        name = 'Crash-Log-{}'.format(AlertMailer().date_format(AlertMailer().date_gen()))
        with open(AlertMailer().get_crash_dir()+'/'+name+'.txt' ,'w') as file:
            file.write(report)
            file.close()
            
    def get_sel_dir(self,dir_name):
        ''' retruns path to directory of choice, requires folder name'''
        ex_dir = AlertMailer().get_ex_dir()
        crash_dir = os.path.join(ex_dir,dir_name)
        return crash_dir
    
    def gen_key_file(self):
        '''generates a key for encryption'''
        key = AlertMailer().key_gen()
        key_f = key.decode('utf-8')
        name = 'DailyKey-{}'.format(AlertMailer().date_format(AlertMailer().date_gen()))
        with open(AlertMailer().get_sel_dir('kiv')+'/'+name+'.txt','w') as file:
            file.write(key_f)
            file.close() 
            
    def get_key_file(self):
        '''gets the most recent key file'''
        key_dir = AlertMailer().get_sel_dir('kiv')
        try:
            file_paths = glob.glob(key_dir+"/*.txt")
            most_recent = max(file_paths, key=(os.path.getctime))    
            return most_recent
        except:
            pass
        
    def size_check(self):
        '''determines if the file is greater than 24 MB'''
        most_recent_log = AlertMailer().get_most_recent_log()
        size = os.path.getsize(most_recent_log)/(1024*1024)
        if size < 24:
            return True
        else:
            return False

    def log(self,e):
        '''logs crash as text file at the end of exception as e'''
        tb = traceback.format_exc()
        AlertMailer().crash_report(e, tb)
        sys.exit(1)


    
    