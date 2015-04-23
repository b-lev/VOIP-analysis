
# coding: utf-8

# In[7]:

url="https://github.com/rufinachettiar/git/blob/master/shootlog.pcap"


# In[9]:

get_ipython().system(u'curl -o /home/rufina/Documents/github-dropbox/rename/new/git/shootlog.pcap $url')


# In[10]:

ls -l /home/rufina/Documents/github-dropbox/rename/new/git/shootlog.pcap


# In[11]:

get_ipython().system(u'md5sum /home/rufina/Documents/github-dropbox/rename/new/git/shootlog.pcap')


# In[12]:

get_ipython().system(u'tshark -v')


# In[13]:

get_ipython().system(u'tshark -n -r /home/rufina/Documents/github-dropbox/rename/new/git/shoot.log -T fields -Eheader=y -e frame.number -e frame.len > frame.len')


# In[14]:

get_ipython().system(u'head -10 frame.len')


# In[15]:

import pandas as pd


# In[16]:

df=pd.read_table("frame.len")


# In[17]:

df


# In[18]:

df["frame.len"].describe()


# In[19]:

get_ipython().magic(u'pylab inline')


# In[20]:

figsize(10,6)


# In[21]:

df["frame.len"].plot(style=".", alpha=0.2)
title("Frame length")
ylabel("bytes")
xlabel("frame number")


# In[22]:

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


# In[29]:

framelen=read_pcap("/home/rufina/Documents/github-dropbox/rename/new/git/shoot.log", ["frame.len"], timeseries=True)
framelen


# In[30]:

bytes_per_second=framelen.resample("S", how="sum")


# In[31]:

bytes_per_second.head()


# In[32]:

bytes_per_second.plot()


# In[33]:

fields=["tcp.stream", "ip.src", "ip.dst", "tcp.seq", "tcp.ack", "tcp.window_size", "tcp.len"]
ts=read_pcap("/home/rufina/Documents/github-dropbox/rename/new/git/shoot.log", fields, timeseries=True, strict=True)
ts


# In[34]:

stream=ts[ts["tcp.stream"] == 10]


# In[35]:

stream


# In[36]:

per_stream=ts.groupby("tcp.stream")
per_stream.head()


# In[37]:

bytes_per_stream = per_stream["tcp.len"].sum()
bytes_per_stream.head()


# In[38]:

bytes_per_stream.plot()


# In[39]:

bytes_per_stream.max()


# In[40]:

biggest_stream=bytes_per_stream.idxmax()
biggest_stream


# In[41]:

bytes_per_stream.ix[biggest_stream]


# In[ ]:



