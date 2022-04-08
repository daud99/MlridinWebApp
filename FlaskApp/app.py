import os
import pandas as pd
import re, numpy as np
import pickle

from flask import Flask,request,render_template
#from commons import prediction ,exe_to_tensor , byte_to_tensor, npy_to_tensor
from werkzeug.utils import secure_filename

app = Flask(__name__)
@app.route('/',methods=['GET','POST'])
def hello_world():
    #return 'Hello, World'    
    class_to_detail = {"DosGoldenEye": "Goldeneye dos attack is implemented using dos script from Kali Linux attack. The victim machine is Ubuntu 16. This is an application layer dos attack. The intent is to disrupt the service. This runs by using python script thus can be run on all Linux and Windows platforms. Victim VM gets huge requests of requests with different strings of random internet browsers. The server thinks that there may be different users try-ing to get access thus leading to depleted server resources.",
        "DosHulk": "Hulk is an application layer dos attack tool. Kali Linux and Ubuntu VM are used as attackers and victims. It is an HTTP flood tool that uses unique and obfuscated traf-fic volume. Due to its obfuscation, it is more difficult to detect as compared to other DOS attack tools due to their predictable repeated patterns. The main principle for this tool is to generate a unique pattern at every request so that it can evade any in-trusion detection and prevention systems. This attack causes a high number of pack-ets leading to a high flow count.",
        "DosLOIC": "How does the LOIC work? It works by flooding a target server with TCP, UDP, or HTTP packets with the goal of disrupting service. One attacker using the LOIC can’t generate enough junk traffic to make a serious impact on a target; serious attacks require thousands of users to coordinate a simultaneous attack on the same target. In order to make these coordinated attacks easier, users can use IRC chat channels to run a ‘Hivemind’ version of the LOIC which lets one primary user control several networked secondary computers, creating a voluntary botnet.",
        "DosSlowHttp": "This attack is like slowloris and a kind of stealthier and interactive version. It can also act as a slowloris attack. The attacker machine is kali Linux whereas the victim machine is Ubuntu16. This application layer dos attack tool uses low bandwidth and consumes server resources by concurrent connection pool. As we know that HTTP protocol relies upon completing the request before they get processed. Hence, if the connection speed is slow, the server must be busy waiting for complete requests by the client thus making them inaccessible for legitimate users.",
        "DosSlowloris": "Slowloris attack is done using slowloris.py python script from Kali Linux. Victim machine is ubuntu 16 and ubuntu 12. This attack works by sending partial HTTP re-quests to consume all connections to the webserver which are never completed. Hence, it intends to consume all the system resources thus disrupting system service. The webserver is contacted with a large number of connections and the connections stay for a long time. A specialty of this tool is that although it may take time but, in the end, it wins thus named slowloris because it consumes the sockets one by one.",
        "FTPPatator": "Brute-force attack on FTP protocol is performed using the patator tool. FTP protocol is used for file transfer between clients and servers. It requires a valid username and password. This attack is used to extract the login ID and password of the user to get access to the remote system. The victim is Ubuntu 16 having FTP service running. Username and password files that were used in SSH brute-force attacks are also used here.",
        "SSHPatator": "Patator, a Kali Linux tool is used to perform brute force attacks on SSH protocol. SSH is a protocol that is used to secure multiple services over the internet. Its most common use is to log in from a remote server. Victim VM is Ubuntu 16 having an SSH service running.",
        "SqlInjWeb": "SQL injection is one of the most popular attacks on the internet targeting vulnerable webforms that take unsanitized queries from users. The database layer of the web application is exploited that directly uses user input in the database queries. Major queries include stealing and deletion of database data using queries. The victim is a DVWA application configured on Ubuntu 16 and the attacker machine is Kali Linux. This attack is quite difficult to detect because it contains almost similar traffic to that of normal traffic. Just a small change in user input query can lead to this dan-gerous attack.",
        "XssWeb": "This attack is similar to the SQL injection attack where we inject malicious scripts into the unsanitized user inputs. Once a malicious script is injected, victims will be presented with the malicious script when they access the website. This may result in fraud, malicious script execution, and data theft. DVWA application is used to per-form this attack from Kali Linux OS. This attack is also difficult to detect as in the case of SQL injection.", 
        "heartbleed": "Heartbeat is an important part of TLS protocol. It is used to confirm that the corre-sponding device is online. It is a vulnerability of the OpenSSL library that is imple-mented in the TLS protocol. Heartbeat operates by a technique where a client sends some random payload to the server. Then, server must reply to the client with the same payload. This is called heartbeat request and response. The client also must specify the length of the random payload. Here, comes vulnerability. There is no check on the length and actual payload sent by the client. ",
        "httpWebAttack": "For HTTP brute-force attack, we have configured the DVWA app. Damn Vulnerable Web App (DVWA) is a web application that is vulnerable and used to carry on net-work attacks. In its Brute-force section, we have a webpage that is used to test the network attacks. Patator tool is used to implement this attack. The behavior of this attack is quite similar to the previously mentioned brute-force attacks. ", 
        "portscan": "It is a popular attack that is used in the reconnaissance part of the attack. Attack gathers information about systems using this attack and plans how will they intrude into the system. We can get the information of operating systems, possible vulnera-bilities, running services, and port statuses. In a PortScan attack, the attacker tries to communicate to each port that normally ranges from 0 to 65535 and then interpret from the response whether this port is being used or not thus leading to the detection of weak entry points. It uses different types of scans including syn scan, fin scan, UDP scan, etc. ", 
        "normal": "It is a trojan that gathers information about your pc and sends it to a hacker. It also downloads other malware files in your computer. This trojan is usually downloaded when downloading a key generator or a software crack" 
            }
    if request.method =='GET':
        return render_template('generic.html')
    if request.method=="POST" :
        if 'file' not in request.files:
            return render_template('generic.html',instruction= 'File did not upload')
        
        file = request.files['file']
        filename = file.filename
        form = filename.split('.')[-1]
        if form != 'csv':
            
            return render_template('generic.html',instruction= 'Uploaded file is not CSV')
        #file= file.read()
        if form == 'csv':
            #file.save(os.path.join(app.root_path, 'static/myfiles/logo.pcap'))
            # file.save('/home/ubuntu/Downloads/TCPDUMP_and_CICFlowMeter-master/CICFlowMeters/CICFlowMeter-4.0/bin/data/in/'+str(filename))
            # import os
            # cmd = "cd ~/Downloads/TCPDUMP_and_CICFlowMeter-master/CICFlowMeters/CICFlowMeter-4.0/bin && ./cfm /home/ubuntu/Downloads/TCPDUMP_and_CICFlowMeter-master/CICFlowMeters/CICFlowMeter-4.0/bin/data/in/"+str(filename)+" /home/ubuntu/Downloads/TCPDUMP_and_CICFlowMeter-master/CICFlowMeters/CICFlowMeter-4.0/bin/data/out"
            # os.system(cmd)
            # dirname = os.path.dirname(__file__)
            # filename = os.path.join(dirname, 'csv/file.csv')
            file.save(os.path.join(app.root_path, 'csv/file.csv'))
            df = pd.read_csv(os.path.join(app.root_path, 'csv/file.csv'))
            #data= preprocess(df)
            #results= predict(data)
            print(df)

	
        ndataset=df.drop(['Flow ID','Src IP','Src Port','Dst IP','Dst Port','Protocol','Timestamp'], axis=1)
        # print("Data loaded.\nNow preprocessing\n\n")
        # print("nDataset Shape :"+str(ndataset.shape))
        # print("\nnUnique Labels :"+str((ndataset['Label'].unique())))
        #print("\nData Peak\n")
        #print(ndataset.head(2))
        # Removing whitespaces in column names.
        ncol_names = [col.replace(' ', '') for col in ndataset.columns]
        ndataset.columns = ncol_names
        # print("Column names after removing white spaces\n")
        #ndataset.head(2)
        nlabel_names = ndataset['Label'].unique()
        nlabel_names = [re.sub("[^a-zA-Z ]+", "", l) for l in nlabel_names]
        nlabel_names = [re.sub("[\s\s]", '_', l) for l in nlabel_names]
        nlabel_names = [lab.replace("__", "_") for lab in nlabel_names]
        nlabel_names, len(nlabel_names)	
        #print("\nAfter tokening columns Dataset Peak\n")
        #print(ndataset.head(2))
        # Removing rows that contain NULL values and checking if number of removed rows is equal to the number of null values.
        before = ndataset.shape
        ndataset.dropna(inplace=True)
        after = ndataset.shape
        # print("No. of null rows deleted: "+str((before[0] - after[0])))
        # print("Now is there any null value? :"+str((ndataset.isnull().any().any())))
        # ## Removing *non-finite* values
        ndataset = ndataset.loc[:, ndataset.columns != 'Label'].astype('float64')
        # Checking if all values are finite.
        # print("If values are finite? :"+str((np.all(np.isfinite(ndataset)))))
        # Checking what column/s contain non-finite values.
        nonfinite = [col for col in ndataset if not np.all(np.isfinite(ndataset[col]))]
        # print("Columns that are non finite? :"+str(nonfinite))
        # Replacing infinite values with NaN values.
        ndataset = ndataset.replace([np.inf, -np.inf], np.nan)
        # We can see that now we have Nan values again.
        # print("Are there nan values? How many? :"+str((np.any(np.isnan(ndataset)))))
        # Removing new NaN values.
        ndataset.dropna(inplace=True)
        # print("Shape after dropping NAN values :"+str(ndataset.shape))
        novar = "models/novariance_stack_ensemble_model_9807.sav"
        features_no_variance = pickle.load(open(novar, 'rb'))
        ndataset = ndataset.drop(columns=features_no_variance)

        np.random.seed(76)
        nfeatures = ndataset.loc[:, ndataset.columns != 'Label'].astype('float64')
        sclr= "models/scaler_stack_ensemble_model_9807.sav"	
        scaler = pickle.load(open(sclr,'rb'))
        nfeatures=scaler.transform(nfeatures)
        modl= "models/stack_ensemble_model_9807.sav"
        print(nfeatures)
        model= pickle.load((open(modl,'rb')))
        print(nfeatures)
        # print("\n\nNow testing with preloaded model\n\n")
        npreds_classes = model.predict(nfeatures)
        x= npreds_classes.shape[0]
        labl = "models/LE_stack_ensemble_model_9807.sav"
        LE= pickle.load((open(labl,'rb')))
        names=LE.inverse_transform([0,1,2,3,4,5,6,7,8,9,10,11,12])
        # print("Detection distribution percentage\n")
        # printing the tuples in object directly
        high=0
        L=[]
        for name in enumerate(names):
            y=0
            for i in npreds_classes:
                if i==name[0]:
                    y=y+1
            L.append(((y*100)/(x)))
            #print(high)
            if (y*100)/(x) >= high:
                high= (y*100)/(x)
                predicted_class= name[1]
            if name[1]=='XssWeb' or name[1] =='normal':
                print(name[1]+":\t\t"+str(((y*100)/x))[:6])
            else:
                print(name[1]+":\t"+str(((y*100)/x))[:6])

        #name = predicted_class
        detail = class_to_detail[predicted_class]
        '''
        result= prediction(tensor,'final.pth.tar')
        #print(result)
        name =class_to_malware[result]
        detail = class_to_detail[result]
        '''
        predicted_malware = predicted_class
        #c1,c2,c3,c4,c5,c6,c7,c8,c9,c10,c11,c12,c13=L[0],L[1],L[2],L[3],L[4],L[5],L[6],L[7],L[8],L[9],L[10],L[11],L[12]
        return render_template('result.html',file=filename,malware=predicted_malware,about=detail,c1=str(L[0])[:6],c2=str(L[1])[:6],c3=str(L[2])[:6],c4=str(L[3])[:6],c5=str(L[4])[:6],c6=str(L[5])[:6],c7=str(L[6])[:6],c8=str(L[7])[:6],c9=str(L[8])[:6],c10=str(L[9])[:6],c11=str(L[10])[:6],c12=str(L[11])[:6],c13=str(L[12])[:6])
@app.route('/index.html')
def index():
    return render_template('index.html')

if __name__ == '__main__':
    app.run(debug=False)

    
