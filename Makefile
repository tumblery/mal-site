mal_site: mal_site.c
        gcc -o mal_site mal_site.c -lpcap

clean:
        rm -f *.o mal_site

