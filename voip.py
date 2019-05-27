# Mehenni Sadaoui # 2019

import pyshark
import math
import os
import struct
import numpy as np
import time
import datetime
from dateutil import parser
import statistics as s
import scipy.io.wavfile
import sys
import wave
import ffmpeg 
import subprocess
from subprocess import call
import shutil
import thinkdsp
import thinkplot
import warnings
warnings.filterwarnings('ignore')


#-----------------------declaring the different variables and lists-------------------------------------------------------------------------------------------
#counter for the failed calls
c=0
#delay
delay=0
#jitter
jitter=0
#sum of the jitter 
tj=0
#counter to count the number of packets of the same stream
counter=0
#list containing the sip cause codes
list_sc=[]
#list containing the rtp packets source addresses and destination addresses put together
list=[]
#list containing the rtp packets after selection
listf=[]
#list containing the time stamps
listtime=[]
#list containing the delays
listdelay=[]
#list conataining the sliced timestamps of the same stream 
listtime2=[]
#list containing the length of the packets in bytes
lislength=[]
#list conataining the length of packets that belong to the same stream 
lislength1=[]
#list containing the codecs
listcodec=[]
#list conataining the codec of the same stream
listcodec1=[]
#list that contains the payload of the RTP packets
rtp_list=[]
#list containing the payload of the same stream
rtp_list2=[]
#list containing the jitter values
listjitter=[]


#--------------------create arguments and check if they are entered correctly--------------------------------------------------------------------------

if len(sys.argv) == 3:
   
   #argument that secifies the path to the trace file
   path1 = sys.argv[1]

   #argument that specifies the path to the location where to save the result files
   path2 = sys.argv[2]
 
  
#--------------------creat files and  folders where to save the different results -------------------------------------------------------------------------------------

   #change the directory the location where the result files will be saved
   os.chdir(path2)

   # check if the folder does exist or not
   if  os.path.isdir('voip_app_files'):
             pass

   #if the folder doesnt exist, create it 
   else:
       os.mkdir('voip_app_files')
        
   #geting the name of the pcap file to name the result folders with it 
   a=sys.argv[1]

   #find the position of the last backslash caracter '\' 
   l = a.rfind('\\')  

   #find the position of the extension of the pcap file
   e=str( sys.argv[1]).find('.pcap')

   #get the name of the pcap file
   file_name=str(a) [l+1:e]

   #get the daytime in order to name the folders with it    
   now = datetime.datetime.now()

   dt=(now.strftime("%Y-%m-%d  %Hh%Mm%Ss"))
    
   #create a directory named with the daytime and the name of the pcap file to save the results to it 
   os.mkdir('voip_app_files/'+file_name+' '+dt)

   #create a directory to save the plots
   os.mkdir(path2+'/voip_app_files/'+file_name+' '+dt+'/Plots')

   #create a directory to save the voice outputs(wav files)
   os.mkdir(path2+'/voip_app_files/'+file_name+' '+dt+'/Voice_output')

   #specify the path for the created files
   f_calls=path2+'/voip_app_files/'+file_name+' '+dt+'/Failled_calls.txt'
   my_result=path2+'/voip_app_files/'+file_name+' '+dt+'/Result.txt'
    
   # open the files for writing to them
   output_f= open(f_calls,'w')
   output_r= open(my_result,'w')
 
   print(" ")
   print("Processing the data... ")
   print(" ")


#--------------------read the pcap file and  filter the sip packets in order to get the failed calls-------------------------------------------------------------------

   cap = pyshark.FileCapture(path1,display_filter="sip" )

   for pkt in cap:
           
           # create a list containing the sip cause codes
           list_sc=['404','488','486','408','480','403','603','410','301','404','502','584','501','503','606','404','504','500']

           #get the status code
           result=str( pkt.sip).find('Status-Code')

           sc=str( pkt.sip) [result+13:result+16]
        
           #check if the status code is in the list
           if sc in list_sc:
               
               #counter to print the call number
               c=c+1
              #get the address of the initial speaker
               result1=str( pkt.sip).find('Sent-by Address')

              #get the address of the destination of the call
               result2=str( pkt.sip).find('SIP to address Host Part')

              #print the failed calls info
               print(" Failed call",c,":")
               print(" Src.IP:",str(pkt.sip)[result1+17:result1+32],"Dst.IP:",str(pkt.sip)[result2+26:result2+41],"Status-Code:",sc,"\n")              
                               
              #write the failed calls info into a file
               output_f.write(" Src.IP "+str( pkt.sip) [result1+17:result1+32]+" Dst.IP "+str( pkt.sip) [result2+26:result2+41]+" Status-Code "+sc+"\n") 
               output_f.write("\n")
  
           else:
               pass


#--------------------read the pcap file to filter the rtp packets and get different information from them --------------------------------------------------------------
        
   cap = pyshark.FileCapture(path1, display_filter="rtp")
     
   for pkt in cap:

            #put the source addresses and the destination addresses together and add them into the list 
             list.append("-> Src.IP:" + pkt.ip.src +" Src.port:"+pkt[pkt.transport_layer].srcport+ " Dst.IP:" +pkt.ip.dst+ " Dst.port:"+pkt[pkt.transport_layer].dstport )

            #put the real arrival time into the list (listtime)
             listtime.append(pkt.frame_info.time )

            #put the length of the packets (bytes) in listlength 
             lislength.append(pkt.frame_info.len )

            #get the codec by converting the object to a string and search for the index of the codec
            #in order to slice the string and get the codec                    
             resulta=str( pkt.rtp).find('Payload type')
             resultb=str( pkt.rtp).find('Sequence number')

            #slice the string to get the codec and append it to listcodec
             listcodec.append(str( pkt.rtp) [resulta+13:resultb] ) 
             
             # filter the rtp payload
             try:
                rtp = pkt[3]
                if rtp.payload:
                   
                   #put the payload in a list (rtp_list)
                   rtp_list.append(rtp.payload.split(":"))
                
             except:
                pass

         
   #compairing the elements of the list and adding the elemnts that doesnt match to a new list(listf)
   for el in list:
            if el not in listf:
                listf.append(el)

   for j in range ( len(listf)):

              # get the  values of the same stream
              for k in range ( len(list)):
                  if listf[j]==list[k]:
                  
                     #count the number of packets of the same stream
                     counter=counter+1

                     #append the time stamps of the same stream to listtime2 after slicing the real time in order to get the datetime withou the location
                     #convert the real time from string to datetime
                     listtime2.append( parser.parse(listtime[k][:31])) 

                     #append the length of the packets (bytes) that belong to the same stream to listlength1 and convert them from strings to integers
                     lislength1.append(int(lislength[k]))

                     #append the codec of the same stream to listcodec1 
                     listcodec1.append(listcodec[k])
                  
                     #get only the streams that has a payload
                     if k < len(rtp_list):

                        #get the rtp payload of the same stream
                        rtp_list2.append(rtp_list[k])

                     else:
                         pass
          
#--------------------calculation of the delay and jitter---------------------------------------------------------------------------------------------------------------

              #delay calculation
              #to calculate the delay we need minimum 2 packets

              if counter>=2:

                #counter-1 as when we calculate the delay we will loss one value
                for g in range ( counter-1):

                   #calculation of delay
                   delay=listtime2[g+1]-listtime2[g]

                   #put the delay values in the listdelay after converting datetime to seconds
                   # and converting the strings of seconds to float values for further calculations
                   listdelay.append(float('{:8}'.format( delay.total_seconds()) ))  

                else:
                     pass

              #jiter calculation
              #to calculate the jitter we need minimum 3 packets

              if counter>=3:
               
                for n in range (counter-2):
                 
                    jitter=listdelay[n+1]-listdelay[n]

                    #put the jitter values in the listjitter
                    listjitter.append(jitter)
                
              else:
                    pass

              #calculate the total number of bytes by summing the elements of listlength1 
              bytes = 0
              for num in lislength1:
                bytes += num

#--------------------print the different parameters--------------------------------------------------------------------------------------------------------------------

              #j+1 because j starts from 0 and we need to print starting from 1 
              #print the arrival time of the last packet as follow listtime2[counter-1], counter-1  because the counter starts from 1 and the list indexing starts from 0
              #listcodec1[0] to print the codec in use (as its the same stream, it has the same codec so we just take the first case of the listcodec)
              print (" ")
              # to calculate the mean, min, max, stddev of delay and the jitter we need at least 3 packets, whcih means minimun 2 delay values
              # counter is the number of packets in the same stream  
              if counter<3:

                  print("VOIP.stream",j+1,listf[j]," Start.time:",listtime2[0]," End.time:",listtime2[counter-1]," Codec:",listcodec1[0]," pkts.bytes:",bytes," pkts.no:",counter)

              # to calculate the mean, min, max, stddev of jitter we need at least 4 packets, which means 3 delay values, which means 2 jitter values
              elif counter>=4:

                  print("VOIP.stream",j+1,listf[j]," Start.time:",listtime2[0]," End.time:",listtime2[counter-1]," Codec:",listcodec1[0]," pkts.bytes:",bytes," pkts.no:",counter, " Ifg.Avg:",s.mean(listdelay),"s", " Ifg.stddev:", s.stdev(listdelay),"s"," Ifg.min:",min(listdelay),"s", " Ifg.max:", max(listdelay),"s", " Jitter.Avg:",s.mean(listjitter),"s", " Jitter.stddev:", s.stdev(listjitter),"s"," Jitter.min:",min(listjitter),"s", " Jitter.max:", max(listjitter),"s")

              else:
                  print("VOIP.stream",j+1,listf[j]," Start.time:",listtime2[0]," End.time:",listtime2[counter-1]," Codec:",listcodec1[0]," pkts.bytes:",bytes," pkts.no:",counter, " Ifg.Avg:",s.mean(listdelay),"s", " Ifg.stddev:", s.stdev(listdelay),"s"," Ifg.min:",min(listdelay),"s", " Ifg.max:", max(listdelay),"s","Jitter:",jitter,"s")

              print (" ")
            
#--------------------write to the result files the different parameters-------------------------------------------------------------------------------------------------

              # to calculate the mean, min, max, stddev of delay and the jitter we need at least 3 packets, whcih means minimun 2 delay values
              if counter<3:

                    output_r.write("VOIP.stream"+str(j+1)+str(listf[j])+" Start.time:"+str(listtime2[0])+" End.time:"+str(listtime2[counter-1])+" Codec:"+str(listcodec1[0])+" pkts.bytes:"+str(bytes)+" pkts.no:"+str(counter))
                    output_r.write(" \n")

              # to calculate the mean, min, max, stddev of jitter we need at least 4 packets, which means 3 delay values, which means 2 jitter values
              elif counter>=4:

                  output_r.write("VOIP.stream"+str(j+1)+str(listf[j])+" Start.time:"+str(listtime2[0])+" End.time:"+str(listtime2[counter-1])+" Codec:"+str(listcodec1[0])+" pkts.bytes:"+str(bytes)+" pkts.no:"+str(counter)+" Ifg.Avg:"+str(s.mean(listdelay))+" s"+ " Ifg.stddev:"+str( s.stdev(listdelay))+" s"+" Ifg.min:"+str(min(listdelay))+" s"+ " Ifg.max:"+str( max(listdelay))+" s"+ " Jitter.Avg:"+ str(s.mean(listjitter))+" s"+ " Jitter.stddev:"+ str( s.stdev(listjitter))+" s"+" Jitter.min:"+ str(min(listjitter))+" s"+ " Jitter.max:"+ str( max(listjitter))+" s\n")
                  output_r.write(" \n")

              else:

                   output_r.write("VOIP.stream"+str(j+1)+str(listf[j])+" Start.time:"+str(listtime2[0])+" End.time:"+str(listtime2[counter-1])+" Codec:"+str(listcodec1[0])+" pkts.bytes:"+str(bytes)+" pkts.no:"+str(counter)+" Ifg.Avg:"+str(s.mean(listdelay))+" s"+ " Ifg.stddev:"+str( s.stdev(listdelay))+" s"+" Ifg.min:"+str(min(listdelay))+" s"+ " Ifg.max:"+str( max(listdelay))+" s"+" Jitter:"+str(jitter)+" s\n")
                   output_r.write(" \n")

              
#--------------------create a raw file into which the audio data is saved---------------------------------------------------------------------------------------------------

              #specify the path for the created raw audio
              my_audio=path2+'/voip_app_files/'+file_name+' '+dt+'/output_raw.raw'

              # open a raw file for writing to it
              raw_audio = open(my_audio,'wb')

              # join the indexes of the rtp_list2 and save the output using a bytearray to create the raw audio file
              for rtp_packet in rtp_list2:
                packet = " ".join(rtp_packet)
                audio = bytearray.fromhex(packet)
                raw_audio.write(audio)
           
              #close the raw file to avoid overwriting
              raw_audio.close()
           
              #empty the list in order to put in the the values of the next stream and avoid overwrting
              del rtp_list2[:]

#--------------------reconstract the audio and print the wave form and the spectrum of the audio streams---------------------------------------------------------------
              
              #check if the codec used is G711
              #\r\n\t are escape characters

              if listcodec1[0]==(' ITU-T G.711 PCMA (8)\r\n\t'): 
                  
                  #change directory to the location of the raw file in order to convert it to a wav file
                  os.chdir(path2+'/voip_app_files/'+file_name+' '+dt)

                  #convert the raw file to a wav file using ffmpeg
                  cmds = ['ffmpeg', '-f', 'alaw', '-ar', '8000', '-i', 'output_raw.raw', 'output_wav.wav']
                  subprocess.call(cmds)

                  #ploting the waveform and the spectrum 

                  thinkplot.preplot(rows=2,cols=1 )

                  #Read the wave file
                  data=thinkdsp.read_wave('output_wav.wav')

                  #plot the wavform of the wavefile
                  thinkplot.subplot(1)
                  data.plot()
                  thinkplot.config(title='Wave form',xlabel='Time',ylabel='Amplitude', legend=False)
  
                  #plot the spectrum
                  data_spec=data.make_spectrum()
                  thinkplot.subplot(2)
                  data_spec.plot()
                  thinkplot.config(title='Spectrum',xlabel='Frequency',ylabel='Amplitude', legend=False)

                  #change directory in order to save th plots in the specified directory
                  os.chdir(path2+'/voip_app_files/'+file_name+' '+dt+'/Plots')

                  #save the plots
                  thinkplot.save(root='VoiP.stream '+str(j+1) )

                  #rename and move the wav files to the specified directory
                  shutil.move(path2+'/voip_app_files/'+file_name+' '+dt+'/output_wav.wav', path2+'/voip_app_files/'+file_name+' '+dt+'/Voice_output'+'/ VOIP.stream_'+str(j+1)+'_output_wav.wav')

                  #remove the eps files 
                  os.remove(path2+'/voip_app_files/'+file_name+' '+dt+'/Plots/VoiP.stream '+str(j+1)+'.eps')
              
              #check if the codec used is G722

              elif listcodec1[0]==(' ITU-T G.722 (9)\r\n\t'): 
       
                  #change directory to the location of the raw file in order to convert it to a wav file
                  os.chdir(path2+'/voip_app_files/'+file_name+' '+dt)

                  #convert the raw file to a wav file using ffmpeg
                  cmds = ['ffmpeg', '-f', 'g722', '-i', 'output_raw.raw', 'output_wav.wav']
                  subprocess.call(cmds)

                  #ploting the waveform and the spectrum 

                  thinkplot.preplot(rows=2,cols=1 )

                  #Read the wave file
                  data=thinkdsp.read_wave('output_wav.wav')

                  #plot the wavform of the wavefile
                  thinkplot.subplot(1)
                  data.plot()
                  thinkplot.config(title='Wave form',xlabel='Time',ylabel='Amplitude', legend=False)
  
                  #plot the spectrum
                  data_spec=data.make_spectrum()
                  thinkplot.subplot(2)
                  data_spec.plot()
                  thinkplot.config(title='Spectrum',xlabel='Frequency',ylabel='Amplitude', legend=False)

                  #change directory in order to save th plots in the specified directory
                  os.chdir(path2+'/voip_app_files/'+file_name+' '+dt+'/Plots')

                  #save the plots
                  thinkplot.save(root='VoiP.stream '+str(j+1) )

                  #rename and move the wav files to the specified directory
                  shutil.move(path2+'/voip_app_files/'+file_name+' '+dt+'/output_wav.wav', path2+'/voip_app_files/'+file_name+' '+dt+'/Voice_output'+'/ VOIP.stream_'+str(j+1)+'_output_wav.wav')

                  #remove the eps files
                  os.remove(path2+'/voip_app_files/'+file_name+' '+dt+'/Plots/VoiP.stream '+str(j+1)+'.eps')
   
              
              #check if the codec used is G726

              elif (listcodec1[0][:5])==(' G726'): 
 
                  #change directory to the location of the raw file in order to convert it to a wav file
                  os.chdir(path2+'/voip_app_files/'+file_name+' '+dt)

                  #convert the raw file to a wav file using ffmpeg
                  cmds = ['ffmpeg', '-f', 'g726le',  '-i', 'output_raw.raw', 'output_wav.wav']
                  subprocess.call(cmds)
                  
                  #ploting the waveform and the spectrum 

                  thinkplot.preplot(rows=2,cols=1 )

                  #Read the wave file
                  data=thinkdsp.read_wave('output_wav.wav')

                  #plot the wavform of the wavefile
                  thinkplot.subplot(1)
                  data.plot()
                  thinkplot.config(title='Wave form',xlabel='Time',ylabel='Amplitude', legend=False)
  
                  #plot the spectrum
                  data_spec=data.make_spectrum()
                  thinkplot.subplot(2)
                  data_spec.plot()
                  thinkplot.config(title='Spectrum',xlabel='Frequency',ylabel='Amplitude', legend=False)

                  #change directory in order to save th plots in the specified directory
                  os.chdir(path2+'/voip_app_files/'+file_name+' '+dt+'/Plots')

                  #save the plots
                  thinkplot.save(root='VoiP.stream '+str(j+1) )

                  #rename and move the wav files to the specified directory
                  shutil.move(path2+'/voip_app_files/'+file_name+' '+dt+'/output_wav.wav', path2+'/voip_app_files/'+file_name+' '+dt+'/Voice_output'+'/ VOIP.stream_'+str(j+1)+'_output_wav.wav')

                  #remove the eps files
                  os.remove(path2+'/voip_app_files/'+file_name+' '+dt+'/Plots/VoiP.stream '+str(j+1)+'.eps')


              #check if the codec used is G729
              
              elif listcodec1[0]==(' ITU-T G.729 (18)\r\n\t'): 
    
                  #change directory to the location of the raw file in order to convert it to a wav file
                  os.chdir(path2+'/voip_app_files/'+file_name+' '+dt)

                  #convert the raw file to a wav file using ffmpeg
                  cmds = ['ffmpeg', '-f', 'g729', '-i', 'output_raw.raw', 'output_wav.wav']
                  subprocess.call(cmds)

                  #ploting the waveform and the spectrum 

                  thinkplot.preplot(rows=2,cols=1 )

                  #Read the wave file
                  data=thinkdsp.read_wave('output_wav.wav')

                  #plot the wavform of the wavefile
                  thinkplot.subplot(1)
                  data.plot()
                  thinkplot.config(title='Wave form',xlabel='Time',ylabel='Amplitude', legend=False)
  
                  #plot the spectrum
                  data_spec=data.make_spectrum()
                  thinkplot.subplot(2)
                  data_spec.plot()
                  thinkplot.config(title='Spectrum',xlabel='Frequency',ylabel='Amplitude', legend=False)

                  #change directory in order to save th plots in the specified directory
                  os.chdir(path2+'/voip_app_files/'+file_name+' '+dt+'/Plots')

                  #save the plots
                  thinkplot.save(root='VoiP.stream '+str(j+1) )

                  #rename and move the wav files to the specified directory
                  shutil.move(path2+'/voip_app_files/'+file_name+' '+dt+'/output_wav.wav', path2+'/voip_app_files/'+file_name+' '+dt+'/Voice_output'+'/ VOIP.stream_'+str(j+1)+'_output_wav.wav')

                  #remove the eps files
                  os.remove(path2+'/voip_app_files/'+file_name+' '+dt+'/Plots/VoiP.stream '+str(j+1)+'.eps')


              #check if the codec used is GSM
              
              elif listcodec1[0]==(' GSM 06.10 (3)\r\n\t'): 
    
                  #change directory to the location of the raw file in order to convert it to a wav file
                  os.chdir(path2+'/voip_app_files/'+file_name+' '+dt)

                  #convert the raw file to a wav file using ffmpeg
                  cmds = ['ffmpeg', '-f', 'gsm', '-i', 'output_raw.raw', 'output_wav.wav']
                  subprocess.call(cmds)

                  #ploting the waveform and the spectrum 

                  thinkplot.preplot(rows=2,cols=1 )

                  #Read the wave file
                  data=thinkdsp.read_wave('output_wav.wav')

                  #plot the wavform of the wavefile
                  thinkplot.subplot(1)
                  data.plot()
                  thinkplot.config(title='Wave form',xlabel='Time',ylabel='Amplitude', legend=False)
  
                  #plot the spectrum
                  data_spec=data.make_spectrum()
                  thinkplot.subplot(2)
                  data_spec.plot()
                  thinkplot.config(title='Spectrum',xlabel='Frequency',ylabel='Amplitude', legend=False)

                  #change directory in order to save th plots in the specified directory
                  os.chdir(path2+'/voip_app_files/'+file_name+' '+dt+'/Plots')

                  #save the plots
                  thinkplot.save(root='VoiP.stream '+str(j+1) )

                  #rename and move the wav files to the specified directory
                  shutil.move(path2+'/voip_app_files/'+file_name+' '+dt+'/output_wav.wav', path2+'/voip_app_files/'+file_name+' '+dt+'/Voice_output'+'/ VOIP.stream_'+str(j+1)+'_output_wav.wav')

                  #remove the eps files
                  os.remove(path2+'/voip_app_files/'+file_name+' '+dt+'/Plots/VoiP.stream '+str(j+1)+'.eps')

              else:
           
                  print("Voice can not be reconstructed for this stream")


              #empty the counter 
              counter=0

              #empty the lists in order to put in the the values of the next stream
              del listtime2[:]
              del listdelay[:]
              del lislength1[:]
              del listcodec1[:]
              del listjitter[:]

              #remove the raw file
              os.remove(path2+'/voip_app_files/'+file_name+' '+dt+'/output_raw.raw')
              
   #close the text files
   output_f.close()
   output_r.close()


else:
    
    print("")
    print("please enter Voip.py  followed by two arguments as follow:")
    print("Voip.py argument1  argument2")
    print("argument1 is the path to the pcap file, argument2 is the path to the folder where results will be saved")






   