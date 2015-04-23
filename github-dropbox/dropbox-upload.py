
# coding: utf-8

# In[1]:

from IPython.display import HTML
HTML('<iframe src=https://www.dropbox.com/home width=600 height=300></iframe>')


# In[2]:

get_ipython().system(u'mkdir -p pcap')


# In[3]:

cd pcap


# In[5]:

url="https://www.dropbox.com/home?preview=session_challenger_dropbox-upload.pcap"


# In[6]:

import urllib
urllib.urlretrieve(url, "/home/rufina/Documents/github-dropbox/rename/dropbox-upload.pcap")


# In[8]:

ls -l /home/rufina/Documents/github-dropbox/rename/session_challenger_dropbox-upload.pcap


# In[9]:

get_ipython().system(u'md5sum /home/rufina/Documents/github-dropbox/rename/session_challenger_dropbox-upload.pcap')


# In[11]:

get_ipython().system(u'tshark -v')


# In[12]:

get_ipython().system(u'tshark -n -r /home/rufina/Documents/github-dropbox/rename/session_challenger_dropbox-upload.pcap -T fields -Eheader=y -e frame.number -e frame.len > frame.len')


# In[13]:

get_ipython().system(u'head -10 frame.len')


# In[14]:

import pandas as pd


# In[15]:

df=pd.read_table("frame.len")


# In[16]:

df


# In[17]:

df["frame.len"].describe()


# In[18]:

get_ipython().magic(u'pylab inline')


# In[19]:

figsize(10,6)


# In[20]:

df["frame.len"].plot(style=".", alpha=0.2)
title("Frame length")
ylabel("bytes")
xlabel("frame number")


# In[21]:

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


# In[22]:

framelen=read_pcap("/home/rufina/Documents/github-dropbox/rename/session_challenger_dropbox-upload.pcap", ["frame.len"], timeseries=True)
framelen


# In[23]:

bytes_per_second=framelen.resample("S", how="sum")


# In[24]:

bytes_per_second.head()


# In[25]:

bytes_per_second.plot()


# In[26]:

fields=["tcp.stream", "ip.src", "ip.dst", "tcp.seq", "tcp.ack", "tcp.window_size", "tcp.len"]
ts=read_pcap("/home/rufina/Documents/github-dropbox/rename/session_challenger_dropbox-upload.pcap", fields, timeseries=True, strict=True)
ts


# In[27]:

stream=ts[ts["tcp.stream"] == 10]


# In[28]:

stream


# In[29]:

print stream.to_string()


# In[30]:

stream["type"] = stream.apply(lambda x: "client" if x["ip.src"] == stream.irow(0)["ip.src"] else "server", axis=1)


# In[31]:

print stream.to_string()


# In[32]:

client_stream=stream[stream.type == "client"]


# In[33]:

client_stream["tcp.seq"].plot(style="r-o")


# In[34]:

client_stream.index = arange(len(client_stream))
client_stream["tcp.seq"].plot(style="r-o")


# In[35]:

per_stream=ts.groupby("tcp.stream")
per_stream.head()


# In[36]:

bytes_per_stream = per_stream["tcp.len"].sum()
bytes_per_stream.head()


# In[37]:

bytes_per_stream.plot()


# In[38]:

bytes_per_stream.max()


# In[39]:

biggest_stream=bytes_per_stream.idxmax()
biggest_stream


# In[40]:

bytes_per_stream.ix[biggest_stream]


# In[ ]:



