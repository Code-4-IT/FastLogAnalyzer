/*
   MIT License

   Copyright (c) 2017, CRoCS, EnigmaBridge Ltd.

   Permission is hereby granted, free of charge, to any person obtaining a copy
   of this software and associated documentation files (the "Software"), to deal
   in the Software without restriction, including without limitation the rights
   to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
   copies of the Software, and to permit persons to whom the Software is
   furnished to do so, subject to the following conditions:

   The above copyright notice and this permission notice shall be included in all
   copies or substantial portions of the Software.

   THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
   IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
   FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
   AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
   LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
   OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
   SOFTWARE.

   -----------------------------------------------------------------

   LOGSEARCH  Version 1.03

   Analyzes huge web server log files and other types of log file
   Works with 'common' and 'combined' log web server format, see Apache docs

   Code is optimzed for speed and not for readability!

   Display a result for each found search request together with IP:s stats

   Tested under Red Hat Linux and Windows XP 32bit
   Compile with GCC or Visual Express 2008
   gcc -Wall logsearch.c -o logsearch
   gcc -Wall -lm logsearch.c -o logsearch // incuding the math library

History:

V1.03 Initial GitHub release

-----------------------------------------------------------------
*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <ctype.h>

/* ---------- Global structures and vars, to speed things up --------- 

   Why? Passing huge arrays on the stack to different functions will slow things down!!!
   This code must also work with ANSI-C compilers
   */

struct node
{
	int cnt;
	unsigned int ip;
};

struct tags
{
	int cnt;
	char tag[64];
};

/* IPv4 sub Lengths */
static int CIDR_LENGTHS[4]={ 1, 256, 65536, 16777216};

static int NODES	= 64; // Initial NODEs size to store (dynamic size)
static int ip_hits  = 0;
static int searchCnt= 0;
static int skipCnt  = 0;

struct tags **searchTag = NULL;
struct tags **skipTag 	= NULL;

static int MAXLINE=8192;
/* ------------------------------------*/

/* Function Declarations */

int ReadConf(char *fname); // Read config file
int GetWebRequest (char *text, char *src); // Get web server equest from log file
int FastSearchLog(FILE *fp);
// Sort rules
static int intcmpr(const void *a, const void *b);
static int ipcmpr (const void *a, const void *b);

// Conversion functions
unsigned int IP_to_int(char *ipadr);
int int_to_IP(unsigned int ip, char *result);
char *trim(char *s);


/*---------------- MAIN ---------------*/

int main(int argc, char * argv[])
{
	int ret=EXIT_FAILURE;
	// check command line arguments
	if (argc <2)
	{
		fprintf (stderr, "\nLogsearch ver. 1.03 (c) 2023 by Code4Speed\n");
		fprintf (stderr, "Usage: logsearch filename\n");
		fprintf (stderr, "(use file \"logsearch.conf\" to change settings)\n\n");
		fprintf (stderr, "Examples:\n");
		fprintf (stderr, "logsearch access.log\nsearch in logfile \"access.log\" and print result to screen\n\n");
		fprintf (stderr, "logsearch access.log > attempts.txt\nsearch and print result to file \"attempts.txt\"\n");
		return EXIT_FAILURE;
	}

	// read tags and other settings
	if (ReadConf("logsearch.conf") == EXIT_FAILURE) return EXIT_FAILURE;

	FILE *fp;
	fprintf (stdout,"\nProcessing file : %s\n\n", argv[1]);
	fp=fopen(argv[1],"rb");
	if (fp==NULL)
	{
		fprintf (stderr, "File open error: %s\n",argv[1]);
		return EXIT_FAILURE;
	}

	ret = FastSearchLog(fp);
	if (fp!=NULL) fclose(fp);

	return ret;
}
/*--------------------------------------*/

/* Open log file */

int FastSearchLog(FILE *fp)
{
	int n;
	int i;

	unsigned int found;
	unsigned int temp_ip;
	char *line;
	char *lwrline;
	char *sp;

	int nodeCnt;
	int retcode,skip;
	char test_ip[16];

	struct node **iplist = NULL;
	// Allocate us some memory
	iplist = (struct node **)realloc(iplist, (NODES + 1) * sizeof(struct node *));
	if (iplist==NULL)
	{
		fprintf (stderr, "Could not allocate memory!\n");
		return EXIT_FAILURE;
	}

	found=0;
	nodeCnt=0;

	line = calloc(1,MAXLINE+2);
	lwrline = calloc(1,MAXLINE+2);
	// Process the file
	while (fgets(line, MAXLINE , fp) != NULL)
	{
		// Process and search for the request string
		retcode=GetWebRequest(lwrline,line);
		if (retcode==403 || retcode==0) continue;
		//
		// Now we should have clean request string, start the search!
		// skip line if a exclude-tag is found (exclude in logsearch.cnf)
		//
		skip=0;
		for (n=0;n<skipCnt;n++)
		{
			sp = strstr(lwrline, skipTag[n]->tag);
			if (sp != NULL)
			{
				skipTag[n]->cnt++;
				skip=1;
				n=skipCnt;
			}
		}
		if (skip) continue;

		// Search for include tags
		for (n=0;n<searchCnt;n++)
		{
			sp = strstr(lwrline, searchTag[n]->tag);
			if (sp == NULL) continue;

			// We found something!
			searchTag[n]->cnt++;

			// 404s is not that dangerous but still good for analyzing, put them one tab away
			if (retcode == 404) fprintf (stdout, "\t%s",line); // we should not need any CRLF!
			else fprintf (stdout, "%s",line);

			// Find the IP adress
			sp=strstr(line, " ");
			if (sp==NULL)
			{
				fprintf (stderr, "Invalid log format!\n");
				n=searchCnt;
				break;
			}
			line[(int)(sp - line)]=0; // temp storage for IP

			// Save IP if it's new, otherwise increase IP-hit-counter
			temp_ip=IP_to_int(trim(line));
			if (temp_ip == 0) 
			{
				fprintf (stderr, "Invalid IP: #%s#\n",line);
				goto endfile;
			}
			for (i=0;i<nodeCnt;i++)
			{
				if (iplist[i]->ip == temp_ip)
				{
					// Not a new IP, increase counter
					iplist[i]->cnt++;
					// Mark as IP-found and quit loop, quick and dirty
					i=NODES+1;
				}
			}
			// New IP?
			if (i<=NODES)
			{
				// Do we have enough room in memory? If not, allocate more memory
				if (nodeCnt==NODES)
				{
					NODES += nodeCnt;
					iplist = (struct node **)realloc(iplist, (NODES + 1) * sizeof(struct node *));
					if (iplist==NULL)
					{
						fprintf (stderr, "Could not allocate memory!\n");
						goto endfile;
					}
				}
				// Save IP in our list
				iplist[nodeCnt] = (struct node *)malloc(sizeof(struct node));
				iplist[nodeCnt]->ip = temp_ip;
				// First time found!, set hit counter to 1
				iplist[nodeCnt]->cnt = 1;
				// increase our list counter
				nodeCnt++;
			}
			found++;
			// we only need one find per line, stop searchtag-loop to speed things up
			break;
		} // --- end of searchtag loop ---
	} // --- file read loop ---

endfile:

	//
	// Print the results!
	//
	fprintf (stdout,"\n%d tags found!\n",found);
	if (found>0)
	{
		// Sort by hits, most first
		qsort(iplist, nodeCnt, sizeof(*iplist), intcmpr);
		fprintf (stdout,"\n Hits\tIP\n===========================\n");
		for (i=0;i<nodeCnt;i++)
		{
			int_to_IP(iplist[i]->ip,test_ip);
			fprintf(stdout,"%5d\t%s\n",iplist[i]->cnt,test_ip);
		}
		// Sort by IP, view only IPs with more than X hits
		qsort(iplist, nodeCnt, sizeof(*iplist), ipcmpr);
		fprintf (stdout,"\n\nIP with more than %d hits\n===========================\n",ip_hits);
		for (i=0;i<nodeCnt;i++)	if (iplist[i]->cnt > ip_hits)
		{
			int_to_IP(iplist[i]->ip,test_ip);
			fprintf(stdout,"%s\n",test_ip);
		}

		// View searchtags found
		fprintf (stdout,"\n\nSearch tags found\n===========================\n");
		qsort(searchTag, searchCnt, sizeof(*searchTag), intcmpr);
		for (i=0;i<searchCnt;i++) if (searchTag[i]->cnt > 0)
		{
			fprintf(stdout,"%5d\t%s\n",searchTag[i]->cnt,searchTag[i]->tag);
		}

		// View skiptags found
		fprintf (stdout,"\n\nSkipped tags\n===========================\n");
		qsort(skipTag, skipCnt, sizeof(*skipTag), intcmpr);
		for (i=0;i<skipCnt;i++)	if (skipTag[i]->cnt > 0)
		{
			fprintf(stdout,"%5d\t%s\n",skipTag[i]->cnt,skipTag[i]->tag);
		}
	}

	// Flush, free and close, psscchhhhh...
	fflush(stdout);
	free(line);
	free(lwrline);
	for (i=0;i<nodeCnt;i++)   free(iplist[i]);
	for (i=0;i<searchCnt;i++) free(searchTag[i]);
	for (i=0;i<skipCnt;i++)	  free(skipTag[i]);
	if (iplist!=NULL)		free(iplist);
	if (searchTag!=NULL) free(searchTag);
	if (skipTag!=NULL)	free(skipTag);

	return EXIT_SUCCESS;
}

/* Sorting rules/comparison */

static int intcmpr(const void *a, const void *b)
{
	struct node * const *one = a;
	struct node * const *two = b;
	int res;
	int searchint=(int)(*one)->cnt;
	int searchint2=(int)(*two)->cnt;

	if (searchint==searchint2)		 res=0;
	else if (searchint>searchint2) res=-1;
	else if (searchint<searchint2) res=1;

	return res;
}

static int ipcmpr(const void *a, const void *b)
{
	struct node * const *one = a;
	struct node * const *two = b;
	int res;
	unsigned int searchint=(unsigned int)(*one)->ip;
	unsigned int searchint2=(unsigned int)(*two)->ip;

	if (searchint==searchint2)		 res=0;
	else if (searchint>searchint2) res=-1;
	else if (searchint<searchint2) res=1;

	return res;
}

//
// Read include/exclude tags and configuration
//
int ReadConf(char *fname)
{
	FILE *fp;
	int ret=EXIT_SUCCESS;
	int includeNODES=64;
	int skipNODES=64;
	int len;
	char *line = NULL;

	// allocate space!!!!!
	searchTag = (struct tags **)realloc(searchTag, (includeNODES + 1) * sizeof(struct tags *));
	if (searchTag==NULL)
	{
		fprintf (stderr, "Could not allocate memory!\n");
		return EXIT_FAILURE;
	}
	skipTag = (struct tags **)realloc(skipTag, (skipNODES + 1) * sizeof(struct tags *));
	if (skipTag==NULL)
	{
		fprintf (stderr, "Could not allocate memory!\n");
		if (searchTag!=NULL) free(searchTag);
		return EXIT_FAILURE;
	}
	line = calloc(1,MAXLINE+2);
	if (line==NULL)
	{
		fprintf (stderr, "Could not allocate memory!\n");
		if (searchTag!=NULL) free(searchTag);
		if (skipTag!=NULL)	free(skipTag);
		return EXIT_FAILURE;
	}

	// open cnf file
	fp=fopen(fname,"r");
	if (fp==NULL)
	{
		fprintf (stderr, "Could not open tagfile: %s\n",fname);
		if (line!=NULL) free(line);
		if (searchTag!=NULL) free(searchTag);
		if (skipTag!=NULL)	free(skipTag);
		return EXIT_FAILURE;
	}

	while (fgets(line, MAXLINE, fp) != NULL)
	{
		if (line[0] != '#')
		{
			len=strlen(line);
			// Is this the fastest way to skip CRLF?? (must be Win,Mac and Linux compatible!)
			if (line[len-2]<32) line[len-2]=0;
			else if (line[len-1]<32) line[len-1]=0;
			//
			if (len>5)
			{
				if (strstr(line,"ip_hits=")!=NULL) ip_hits=atoi(&line[8]);
				else if (strstr(line,"include=")!=NULL)
				{
					// Do we have enough room in memory? If not, allocate more memory
					if (searchCnt==includeNODES)
					{
						includeNODES += searchCnt;
						searchTag = (struct tags **)realloc(searchTag, (includeNODES + 1) * sizeof(struct tags *));
						if (searchTag==NULL)
						{
							fprintf (stderr, "Could not allocate memory!\n");
							ret=EXIT_FAILURE;
							break;
						}
					}
					// Save tag in our list
					searchTag[searchCnt] = (struct tags *)malloc(sizeof(struct tags));
					strncpy(searchTag[searchCnt]->tag,&line[8],64);
					searchTag[searchCnt]->cnt=0;
					searchCnt++;
				}
				else if (strstr(line,"exclude=")!=NULL)
				{
					// Do we have enough room in memory? If not, allocate more memory
					if (skipCnt==skipNODES)
					{
						skipNODES += skipCnt;
						skipTag = (struct tags **)realloc(skipTag, (includeNODES + 1) * sizeof(struct tags *));
						if (skipTag==NULL)
						{
							fprintf (stderr, "Could not allocate memory!\n");
							ret=EXIT_FAILURE;
							break;
						}
					}
					// Save tag in our list
					skipTag[skipCnt] = (struct tags *)malloc(sizeof(struct tags));
					strncpy(skipTag[skipCnt]->tag,&line[8],64);
					skipTag[skipCnt]->cnt=0;
					skipCnt++;
				}
			}
		}
	}
	fprintf (stdout,"Search-tags read: %d  Exclude-tags read: %d\n",searchCnt,skipCnt);
	fflush(stdout);

	fclose(fp);
	if (line!=NULL) free(line);
	if (ret!=EXIT_SUCCESS && searchTag!=NULL) free(searchTag);
	if (ret!=EXIT_SUCCESS && skipTag!=NULL)	free(skipTag);

	return ret;
}

/*
   This request searcher focuses on processing web server log files
   Offset string at start-GET/POST and cut the string at STOP and make string lowercase
   return server response code or 0 = ERR
   */
int GetWebRequest (char *text, char *src)
{

	static char GETSEARCH[]	="\"GET ";
	static char POSTSEARCH[]="\"POST ";
	static char STOP[]		=" HTTP/1";
	int start=0;
	int retcode=0;
	int i=0,offset=0;
	int len=strlen(src);

	while (i<len)
	{
		if (!start && (i+5)<len)
		{
			// Ok, still searching for start offset (GETSEARCH/POSTSEARCH)
			if (memcmp(&src[i],GETSEARCH,4)==0) start=1;
			else if (memcmp(&src[i],POSTSEARCH,5)==0) start=1;
			i++;
		}
		else if (start)
		{
			// Start already found, look for end (STOP variable)
			if ((i+15)<len && memcmp(&src[i],STOP,7)==0)
			{
				retcode=atoi(&src[i+11]);
				break;
			}
			// Simple lowercase conversion A-Z -> a-z, fastest way
			if (src[i] > 64 && src[i] < 91) 	text[offset] = src[i] + 32;
			else text[offset]=src[i];
			offset++;
		}
		i++;
	}
	text[offset]=0;

	return retcode;
}


/* Convert integer to IP in chars */
int int_to_IP(unsigned int ip, char *result)
{
	if (!ip || ip<CIDR_LENGTHS[3]) return -1;
	char *temp = result;
	sprintf(temp,"%d.%d.%d.%d",(ip >> 24 & 255),(ip >> 16 & 255),(ip >> 8 & 255),(ip & 255));
	return 0;
}

/* Convert IP chars to integer IP */
unsigned int IP_to_int(char *ipadr)
{
	if (ipadr==NULL) return 0;
	int len=strlen(ipadr);
	unsigned int result=0;
	int n=0, cidr=3;
	char temp[4];
	char *token;
	if (len<7) return 0;
	token=strtok(ipadr,".");
	while (token!=NULL)
	{
		strcpy(temp,token);
		n=atoi(temp);
		if (cidr==0) result+=n;
		else result+=(n*(CIDR_LENGTHS[cidr]));
		cidr--;
		token=strtok(NULL,".");
		if (token==NULL) return result;
	}
	if (cidr != -1) return 0;

	return result;
}

/* My own trim function */
char *trim(char *s) 
{
	char *ptr;
	if (!s) return NULL;   
	if (!*s) return s;  
	for (ptr = s + strlen(s) - 1; (ptr >= s) && isspace(*ptr); --ptr);
	ptr[1] = 0;
	return s;
}

