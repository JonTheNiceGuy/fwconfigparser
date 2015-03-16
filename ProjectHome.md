This is a piece of code written to provide firewall engineers a quick overview of the configuration of their firewalls.

The current version requires you to run the "show run" command on a Pix device and save it to a text file called "process.txt" in the same directory as the PHP script, then run the PHP script (either in the CLI and dump the resulting text to an HTML file or via your web browser), and open it to review the configuration.

It is not complete, as it was required to "scratch an itch", but does provide a quick interface to most of your rules. Each access-list line is also shown in the source code as a comment line.