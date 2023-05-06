#to visualise use the output type:
#pushd &lt; plot.html; python3 -m http.server 9999; popd;
#firefox 0.0.0.0:9999
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

interval = 5  # seconds
windowSize = 3 # window to calculate expo avg
smoothing_factor = 0.5
avglist=[]
avglistx=[]
expavglist=[]
stddevlist=[]


def isDDoS(value, threshold):
    if(value > threshold):
        return 1
    else:
        return 0
def exponential_moving_average(data, smoothing_factor):
    ema = data[0]
    for i in range(1, len(data)):
        ema = (smoothing_factor * data[i]) + ((1 - smoothing_factor) * ema)
    return ema

# Define Plotly figure layout
layout = go.Layout(title="Packet Count", xaxis=dict(title="Time"), yaxis=dict(title="Count"))

# Define Plotly traces
bar_trace = go.Bar(x=[], y=[], name="Packet Count")
line_trace = go.Scatter(x=[], y=[], name="Exponential Moving Average")
stddev_trace = go.Scatter(x=[], y=[], name="Standard Deviation")

# Define Plotly figure
fig = go.Figure(data=[bar_trace, line_trace, stddev_trace], layout=layout)

while True:
    xData=[]
    yData=[]
    DDoS = 0 #intialise it with zero, if it is 1 then it means ddos is happening
    # Run scapy to capture packets
    exist = os.path.exists("capture.pcap")
    if exist: 
        os.remove("capture.pcap")
    with open("capture.pcap", 'x') as fp:
        pass
    capture_duration = interval
    sniff(filter="tcp", timeout = capture_duration, prn=lambda pkt: wrpcap("capture.pcap", pkt, append=True))

    try:
        packets = rdpcap("capture.pcap")
    except Scapy_Exception as e:
        print("Error: No input in pcap file.")
        continue

    srcIP=[]
    for pkt in packets:
        if IP in pkt:
            try:
                srcIP.append(pkt[IP].src)
            except:
                pass

    #Count
    cnt=Counter()
    for ip in srcIP:
        cnt[ip] += 1

    #Table and Print
    table= PrettyTable(["IP", "Count"])
    for ip, count in cnt.most_common():
        table.add_row([ip, count])
    print(table)

    # Add new data to plot
    for ip, count in cnt.most_common():
        if ip not in xData:
            xData.append(ip)
            yData.append(count)
        else:
            index = xData.index(ip)
            yData[index] = count

    #calculate average
    summation = sum(yData)
    n = len(xData)
    average = summation/n
    print(yData)

    #append average to list with x axis as curtime
    avglist.append(average)
    curtime = datetime.now()
    avglistx.append(curtime)
    

    if(len(avglist) > windowSize):
        #truncate last window from avlist
        curlist = avglist[-windowSize:]
        #print(curlist)
        #calculate exp average
        expav = exponential_moving_average(curlist, smoothing_factor)
        expavglist.append(expav);

        #calculate standard deviation
        stdev = statistics.stdev(avglist)
        n = len(avglist)
        threshold = 3*stdev/pow(n,0.5) + expav
        stddevlist.append(threshold)
        DDoS = isDDoS(expav, threshold)
        if(DDoS > 0):
            1
        #block ips having mean requests > threshold. xData and yData

    # Add standard deviation to plot
    #stdev_line_trace = go.Scatter(x=avglistx, y=expav+stdev, name="Std Dev")
    #fig.add_trace(stdev_line_trace)

    # Update Plotly traces with new data
    bar_trace.x = avglistx
    bar_trace.y = avglist
    line_trace.x = avglistx[-len(expavglist):]
    line_trace.y = expavglist

    # Update Plot
    fig = go.Figure()

    # Bar chart for average
    fig.add_trace(go.Bar(x=avglistx, y=avglist))

    # Line chart for exponential moving average
    if len(expavglist) > 0:
        fig.add_trace(go.Scatter(x=avglistx[-len(expavglist):], y=expavglist, mode='lines', name='Exponential Moving Average'))

    if len(stddevlist) > 0:
        fig.add_trace(go.Scatter(x=avglistx[-len(stddevlist):], y=stddevlist, mode='lines', name='Threshold'))

    # Set layout
    fig.update_layout(title='Packet Count', xaxis_title='Time', yaxis_title='Count')

    # Plot
    pyo.plot(fig, filename='plot.html', auto_open=False)

    # Wait for next interval
    time.sleep(interval)
