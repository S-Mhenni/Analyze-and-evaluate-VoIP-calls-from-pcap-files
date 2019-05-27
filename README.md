# Analyze-and-evaluate-VoIP-calls-from-pcap-files

This tool takes pcap files as input, automatically extracts the VoIP streams contained in the files, recontruct the audio, and returns the following:

   -The failed calls, their source and destination IP addresses and their status codes.

   -The VoIP streams contained in the call,  their source and destination IP addresses, source and destination ports,  start and end           times, codec in use, the number of the packets and their size in bytes, the minimum, average, maximum, and standard deviation of           the inter frame gap and jitter.

   -The reconstructed audio that is saved as a WAV file.

   -The plots of the waveform and the spectrum of the voice streams.
     
This tool reconstructs the audio in VoIP calls based on the SIP protocol for the most common codecs (G711,G722,G726,G729,GSM).
For G726 the tool reconstructs the audio when the byte order is little endian, when its big endian the reconstructed audio might be affected.

If other codecs are used then the tool will return only the information stated above without reconstructing the audio.





