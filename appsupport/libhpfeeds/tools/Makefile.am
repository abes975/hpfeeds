AM_CFLAGS = -I../include -Werror -Wall -g -static
AM_LDFLAGS = -lhpfeeds -L../src

#bin_PROGRAMS = hpclient

#hpclient_LDFLAGS =  ${AM_LDFLAGS}
#hpclient_LDADD = ../src/libhpfeeds.la
#hpclient_SOURCES = hpclient.c

bin_PROGRAMS = client

client_LDFLAGS =  ${AM_LDFLAGS}
client_LDADD = ../src/libhpfeeds.la
client_SOURCES = client.c
