# Windump
A Windows tcpdump-esc utility used for monitoring traffic following a specified traffic filter.
<hr>
Windump is a simple-to-use, tcpdump-esc utility used to monitor traffic going through the machine it is running on. It allows for a very flexible filter using WinDivert's filter language in order to inspect specific types of packets. 
<br><br>
I aim to eventually morph this base traffic monitor into a full firewall application to monitor, change, and block packets based on user-defined parameters from reaching the endpoint within the host machne. As of right now, though, the application works fine as a simple command-line monitor. 
<br><br>
For information regarding the filter language in use, refer to <a href="https://www.reqrypt.org/windivert-doc.html#filter_language">here</a> for documentation.
