# -*- coding: cp1252 -*- 
 
from urllib2 import urlopen 
from json import loads,dumps 
from os.path import isfile 
from urllib import urlretrieve 
from urlparse import urlparse 
from time import time 
from struct import unpack 
from imghdr import what 
from os import remove,rename 
 
#------------------------------------------------------------------------------ 
 
dic={'a':[1,2,3,4,5,6,7,8,9]} 
lists=[1,2,3,10,11,12] 
 
class SpecialTools(object): 
 info=""" 
 dimensions(fname): 
 
 type(fname)=str 
 
 return values: 
 tuple 
 
 
 
 
 dict_appender(dic,key,item): 
 
 type(dic)=dict 
 type(key)=str 
 type(item)=list 
 
 return values: 
 dict 
 
 For dictionaries that contain at least one list as a key item only, this 
 appends all values in 'item' into 'dic'['key'] and returns the new 
 dictionary made. If an element in 'item' exists in 'dic'['key'], it will 
 not be included in the new dictionary. The new dictionary is then 
 returned. 
 
 
 file_dl(link) 
 
 type(link)=str 
 
 return values: 
 str 
 
 class variables used: 
 save_dir 
 
 The link in 'link' is opened then downloaded into a specified directory 
 named 'save_dir' with their name intact. If the content from the link 
 is downloaded, it returns the directory of the file. Otherwise, False. 
 Also, if connection error happening between the server and client, it 
 also returns False. 
 """ 
 
 defaultconfig={ 
 "base_site":"http://www.reddit.com/user/francis_0000a/m/wallpapers", 
 "downloaded":[], 
 "queried":[] 
 } 
 save_dir="D:\F5XS Documents\Pictures\Wallpapers (Organized)\Unsorted" 
 threshold=0.0009765625 
 sc=unichr(0xd7).encode("latin-1") 
 def __init__(self): 
 pass 
 def instant(self,read=False): 
 SpecialTools().config_check() 
 if read==True: 
 print "Redditing..." 
 links=Reddit().instant() 
 print "Redditing completed. Initiating config writing." 
 SpecialTools().config_write("queried",links) 
 SpecialTools().config_check() 
 links=SpecialTools().config_read("queried") 
 for x in links[::-1]: 
 if SpecialTools().splitter(x)[2] in [".jpg",".png","jpeg",".JPG",".PNG",".JPEG"]: 
 save=SpecialTools().file_dl(x) 
 if save!=False: #Somewhere in this, especially the monstrous conditionals, yields anomalies. You slept them out. 
 if SpecialTools().dimensions(save)==False: 
 SpecialTools().config_write("downloaded",[x]) 
 elif ((float(SpecialTools().dimensions(save)[0])/SpecialTools().dimensions(save)[1]>=16./9.*(1-SpecialTools().threshold) and float(SpecialTools().dimensions(save)[0])/SpecialTools().dimensions(save)[1]<=16./9.*(1-self.threshold)) and (SpecialTools().dimensions(save)[0]*SpecialTools().dimensions(save)[1]>=1049088)): 
 print 1 
 placer=(self.splitter(save)[0]+r"16%s9\\"%self.sc+self.splitter(save)[1]+self.splitter(save)[2]).decode('latin-1') 
 rename(save,placer) 
 SpecialTools().config_write("downloaded",[x]) 
 counter+=1 
 elif ((float(SpecialTools().dimensions(save)[0])/SpecialTools().dimensions(save)[1]>=8./5.*(1-self.threshold) and float(SpecialTools().dimensions(save)[0])/SpecialTools().dimensions(save)[1]<=8./5.*(1+self.threshold)) and (SpecialTools().dimensions(save)[0]*SpecialTools().dimensions(save)[1]>=1049088)): 
 print 2 
 placer=(self.splitter(save)[0]+r"8%s5\\"%self.sc+self.splitter(save)[1]+self.splitter(save)[2]).decode('latin-1') 
 rename(save,placer) 
 SpecialTools().config_write("downloaded",[x]) 
 counter+=1 
 else: 
 remove(save) 
 SpecialTools().config_write("downloaded",[x]) 
 SpecialTools().config_check() 
 def config_base(self): 
 try: 
 fdir=open("states.json","r").read() 
 if fdir=="": raise IOError 
 except IOError: 
 fdir=open("states.json","w") 
 fdir.truncate() 
 fdir.write(dumps(self.defaultconfig)) 
 fdir.close() 
 fdir=open("states.json","r").read() 
 return fdir 
 def config_check(self): 
 dic=loads(SpecialTools().config_base()) 
 json=loads(open("states.json","r").read()) 
 fdir=open("states.json","w") 
 fdir.truncate() 
 counter=0 
 phqueried=[] 
 phdownloaded=[] 
 for x in json["queried"]: 
 if not x in phqueried: 
 phqueried.append(x) 
 for x in json["downloaded"]: 
 if not x in phdownloaded: 
 phdownloaded.append(x) 
 json["queried"]=phqueried 
 json["downloaded"]=phdownloaded 
 while counter