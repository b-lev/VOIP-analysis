
# coding: utf-8

# In[53]:

url="https://www.dropbox.com/home?preview=capture1log.pcap"


# In[54]:

get_ipython().system(u'curl -o /home/rufina/Documents/github-dropbox/rename/capture1log.pcap $url')


# In[55]:

ls -l /home/rufina/Documents/github-dropbox/rename/capture1log.pcap


# In[56]:

get_ipython().system(u'md5sum /home/rufina/Documents/github-dropbox/rename/capture1log.pcap')


# In[57]:

get_ipython().system(u'tshark -v')


# In[58]:

get_ipython().system(u'tshark -n -r /home/rufina/Documents/github-dropbox/rename/capture.log -T fields -Eheader=y -e frame.number -e frame.len > frame.len')


# In[59]:

get_ipython().system(u'head -10 frame.len')


# In[9]:

import pandas as pd


# In[10]:

df=pd.read_table("frame.len")


# In[11]:

df


# In[29]:

df["frame.len"].describe()


# In[30]:

get_ipython().magic(u'pylab inline')


# In[31]:

figsize(10,6)


# In[32]:

df["frame.len"].plot(style=".", alpha=0.2)
title("Frame length")
ylabel("bytes")
xlabel("frame number")


# In[33]:

import subprocess
import datetime
import pandas as pd

def read_pcap(filename, fields=[], display_filter="", 
              timeseries=False, strict=False):
    if timeseries:
        fields = ["frame.time_epoch"] + fields
    fieldspec = " ".join("-e %s" % f for f in fields)

    display_filters = fields if strict else []
    if display_filter:
        display_filters.append(display_filter)
    filterspec = "-R '%s'" % " and ".join(f for f in display_filters)

    options = "-r %s -n -T fields -Eheader=y" % filename
    cmd = "tshark %s %s %s" % (options, filterspec, fieldspec)
    proc = subprocess.Popen(cmd, shell = True, 
                                 stdout=subprocess.PIPE)
    if timeseries:
        df = pd.read_table(proc.stdout, 
                        index_col = "frame.time_epoch", 
                        parse_dates=True, 
                        date_parser=datetime.datetime.fromtimestamp)
    else:
        df = pd.read_table(proc.stdout)
    return df


# In[35]:

framelen=read_pcap("/home/rufina/Documents/github-dropbox/rename/capture.log", ["frame.len"], timeseries=True)
framelen


# In[36]:

bytes_per_second=framelen.resample("S", how="sum")


# In[37]:

bytes_per_second.plot()


# In[38]:

fields=["tcp.stream", "ip.src", "ip.dst", "tcp.seq", "tcp.ack", "tcp.window_size", "tcp.len"]
ts=read_pcap("/home/rufina/Documents/github-dropbox/rename/capture.log", fields, timeseries=True, strict=True)
ts


# In[39]:

stream=ts[ts["tcp.stream"] == 10]


# In[40]:

stream


# In[41]:

per_stream=ts.groupby("tcp.stream")
per_stream.head()


# In[42]:

bytes_per_stream = per_stream["tcp.len"].sum()
bytes_per_stream.head()


# In[43]:

bytes_per_stream.plot()


# In[44]:

bytes_per_stream.max()


# In[62]:

biggest_stream=bytes_per_stream.idxmax()
biggest_stream


# In[63]:

bytes_per_stream.ix[biggest_stream]


# In[76]:

get_ipython().system(u'tshark -r /home/rufina/Documents/github-dropbox/rename/capture.log -q -z conv,eth -z conv,ip -z conv,tcp')


# In[68]:

import numpy as np

d = np.genfromtxt('/home/rufina/Desktop/data.txt')

x = (d[:,0])  
y = (d[:,1 ])

print x  
print(y*8)


# In[69]:

import matplotlib.pyplot as plt  
import numpy as np  
x, y = np.loadtxt('/home/rufina/Desktop/data.txt', unpack=True)  
bins = np.arange(60+1)  
totals, edges = np.histogram(x, weights=y, bins=bins)  
counts, edges = np.histogram(x, bins=bins)  

print counts  
print totals*0.008/counts  

plt.plot(totals*0.008/counts, 'r')  
plt.xlabel('time, s')  
plt.ylabel('kbit/s')  
plt.grid(True)  
plt.xlim(0.0, 60.0)  
plt.show()  


# In[51]:

import time

def get_bytes(t, iface='eth0'):
    #with open('/sys/class/net/' + iface + '/statistics/' + t + '_bytes', 'r') as f:
     #   data = f.read();
    #return int(data)
    
def get_bytes(t, file='/home/rufina/Documents/github-dropbox/rename/capture1log.pcap'):
    with open(file + t + '_bytes', 'r') as f:
        data = f.read();
        return int(data)
    


if __name__ == '__main__':
    (tx_prev, rx_prev) = (0, 0)

    while(True):
        tx = get_bytes('tx')
        rx = get_bytes('rx')

        if tx_prev > 0:
            tx_speed = tx - tx_prev
            print('TX: ', tx_speed, 'bps')

        if rx_prev > 0:
            rx_speed = rx - rx_prev
            print('RX: ', rx_speed, 'bps')

        time.sleep(1)

        tx_prev = tx
        rx_prev = rx


# In[ ]:



