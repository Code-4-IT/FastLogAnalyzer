# FastLogAnalyzer
Analyzes huge textlog files (several GBs)  with optimal speed, user can select search criteras in .conf file.
The default .conf file included was configured to find attack attempts in log file, like SQL injections or whatever.

This is a superfast log analyzer for huge log files. This initial version is made for Apache webserver log files, using log-format 'Combined' or 'Common'.
But it should be easy to expand it for more log formats. After it finished the search, it present the results in a IP-address sorted list.
