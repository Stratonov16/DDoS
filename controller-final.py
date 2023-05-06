#author: Nikhil Sachdeva    
from scapy.all import *
from scapy.utils import wrpcap
from prettytable import PrettyTable
from collections import Counter
from datetime import datetime
import plotly.graph_objs as go
import pandas as pd
import plotly.offline as pyo
import statistics
import math
import time
from datetime import datetime, timedelta

interval = 0                # seconds
windowSize = 5              # window to calculate expo avg
smoothing_factor = 0.85     #more the value, more the weight to recent values in expo avg
input=[]                    #list to store ip's average list to plot
inputx=[]                   #x axis of plot
avglist=[]                  #list used to store average excluding malicious ip's
expavglist=[]               #store exp avg
thresholdlist=[]            #store threshold
output = []                 #store final labels for ip's 

chunk_size = 35          #read input in batch of 35

# Define Plotly figure layout
layout = go.Layout(title="Packet Count", xaxis=dict(title="Time"), yaxis=dict(title="Count"))

# Define Plotly traces
bar_trace = go.Bar(x=[], y=[], name="Packet Count")
line_trace = go.Scatter(x=[], y=[], name="Exponential Moving Average")
stddev_trace = go.Scatter(x=[], y=[], name="Standard Deviation")

# Define Plotly figure
fig = go.Figure(data=[bar_trace, line_trace, stddev_trace], layout=layout)

#function to calculate exponential average
def exponential_moving_average(data, smoothing_factor):
    ema = data[0]
    for i in range(1, len(data)):
        ema = (smoothing_factor * data[i]) + ((1 - smoothing_factor) * ema)
    return ema

#function that returns 1 if there is DDoS otherwise 0
def isDDoS(value, threshold):
    if(value > threshold):
        return 1
    else:
        return 0
    
#----------------------------------------------------START OF PROGRAM---------------------------------------------#

# Read the CSV file into a Pandas dataframe
df = pd.read_csv('TCPSYN.csv')

# Convert the "Src IP" column to a list of IP addresses
src_ip = df['Src IP'].tolist()

# Iterate through the source IP list in chunks of size chunk_size
for i in range(0, len(src_ip), chunk_size):
    # Initialize empty lists for x and y data
    ipAddr = []  #ip
    freq = []  #frequency

    # Extract the chunk of source IP addresses to process
    srcIP = src_ip[i:i+chunk_size]
    # Count the occurrences of each source IP address in the chunk
    cnt = Counter()
    for ip in srcIP:
        cnt[ip] += 1

    # Create a table of the IP addresses and their counts
    table = PrettyTable(["IP", "Count"])
    for ip, count in cnt.most_common():
        table.add_row([ip, count])

    # Print the table
    #print(table)

    # Add new data to plot
    for ip, count in cnt.most_common():
        if ip not in ipAddr:
            ipAddr.append(ip)
            freq.append(count)
        else:
            index = ipAddr.index(ip)
            freq[index] = count

    #calculate average
    summation = sum(freq)
    n = len(ipAddr)
    average = summation/n
    #print(freq) 

    curtime = datetime.now()
    #append average to list with x axis as curtime
    avglist.append(average)
    input.append(average)
    inputx.append(curtime)
  
    
    #intitialise label for attacker ip's
    labels = []

    if(len(avglist) > windowSize):
        #truncate last window from avlist
        curlist = avglist[-windowSize:]
        #print(curlist)
        #calculate exp average
        expav = exponential_moving_average(curlist, smoothing_factor)
        expavglist.append(expav)

        #calculate standard deviation
        stdev = statistics.stdev(avglist)
        n = len(avglist)
        threshold = 3*stdev/pow(n,0.5) + expav
        thresholdlist.append(threshold)
        DDoS = isDDoS(average, threshold)

        if(DDoS > 0):
            print("------DDOS------")

            #print(threshold)
            #remove average calculated from this dataset as we should not include these values for next calculation
            avglist.pop()   
            #go through freq and if freq[i] > threshold then store ip in attacker's list
            attacker_map = {}  # attackers ip will be stored in this map

            for i in range(len(freq)):
                if freq[i] > threshold:
                    attacker_map[ipAddr[i]] = freq[i]

            # iterate through the source IPs
            for ip in srcIP:
                # check if the IP is in the attacker map
                if ip in attacker_map:
                    labels.append("DDOS")
                else:
                    labels.append("Normal")

        else:  

            #if not DDoS then also mark as normal
            print("-----NORMAL-----")

            for ip in srcIP:
                labels.append("Normal")
    else:
        for ip in srcIP:
            labels.append("Normal")
        
    output.extend(labels)
    # Update Plot
    fig = go.Figure()

    # Bar chart for average
    fig.add_trace(go.Bar(x=inputx, y=input))

    # Line chart for exponential moving average
    if len(expavglist) > 0:
        fig.add_trace(go.Scatter(x=inputx[-len(expavglist):], y=expavglist, mode='lines', name='Exponential Moving Average'))
    #Line chart for exponential moving average
    if len(thresholdlist) > 0:
        fig.add_trace(go.Scatter(x=inputx[-len(thresholdlist):], y=thresholdlist, mode='lines', name='Threshold'))

    # Set layout
    fig.update_layout(title='Packet Count', xaxis_title='Time', yaxis_title='Count')

    # Plot
    pyo.plot(fig, filename='plot.html', auto_open=False)

    # Wait for next interval
    time.sleep(interval)

#----------------------------------------Export labelled IP's to Output.csv----------------------------------------#
df['Output'] = output

df.to_csv('Output.csv', index =True)