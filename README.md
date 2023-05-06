#author: Nikhil Sachdeva
#Title:  A traffic filtering approach to detect and mitigate TCP Syn flood attack.

Run:
python3 controller-final.py   #Take input from dataset and predict DDoS.
python3 results.py            #This will measure give accuracy and result

Other files:
plot.html                     #Genrated with input request and frequency
TCPSYN.csv                    #Standard Dataset to simulate requests with some shuffled values https://data.mendeley.com/datasets/236bd4cjmk
Output.csv                    #Dataset file with labeled values.

Alternatively Run:
sudo python3 controller.py    #This will take request from your ethernet instead of database.
sudo plot.html                #To visualise

