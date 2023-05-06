<h4>author: Nikhil Sachdeva</h4>
<h2>Title:  A traffic filtering approach to detect and mitigate TCP Syn flood attack. </h2>
<h5>
<h3>Run:  </h3>                                                                      
python3 controller-final.py   #Take input from dataset and predict DDoS.<br>
python3 results.py            #This will measure output and give accuracy.<br>
<br>
<h3>Other files:  </h3> 
plot.html                     #Genrated with input request and frequency<br>
TCPSYN.csv                    #Standard Dataset to simulate requests. (https://data.mendeley.com/datasets/236bd4cjmk)<br>
Output.csv                    #Dataset file with labeled values.<br>
<br>
<h3>Alternatively Run: </h3>
<p>
sudo python3 controller.py    #This will take request from your ethernet instead of database.<br>
sudo plot.html                #To visualise<br>
</h5>

<br> 
<h4> Example plot </h4>
<img src="https://github.com/Stratonov16/DDoS/blob/main/Screenshot%20from%202023-05-06%2019-42-46.png">
<p>
The traffic filtering algorithm implemented in this code repository is designed to detect and mitigate TCP SYN flood attacks on fog devices. A SYN flood attack is a type of denial-of-service (DoS) attack in which an attacker sends a large number of SYN requests to a target device, but does not complete the connection process. This can cause the target device to become overwhelmed with half-open connections, making it unable to respond to legitimate traffic.
</p>

The algorithm works by monitoring incoming traffic and analyzing the SYN packets to identify potential SYN flood attacks. When an attack is detected, the algorithm takes steps to mitigate the impact of the attack, such as blocking or rate-limiting traffic from the attacking IP address.
<br>
The implementation of this algorithm in the code repository includes several components, including packet capture, traffic analysis, and traffic mitigation. The code is written in a python and is designed to be easily integrated into existing fog device software stacks.
<br>
