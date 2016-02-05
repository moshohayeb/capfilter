#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

#define FRAMES_PER_FILE	10000

#define PCAP_DIR_NAME	"./pieces/"
#define PCAP_BASE_NAME	"piece"

int32_t fdout;
bool wrote_pcap_hdr;

uint32_t *written;
uint32_t n_written;

typedef struct pcap_hdr_s {
	uint32_t magic_number;   /* magic number */
	uint16_t version_major;  /* major version number */
	uint16_t version_minor;  /* minor version number */
	int32_t  thiszone;       /* GMT to local correction */
	uint32_t sigfigs;        /* accuracy of timestamps */
	uint32_t snaplen;        /* max length of captured packets, in octets */
	uint32_t network;        /* data link type */
} pcap_hdr_t;

typedef struct pcaprec_hdr_s {
	uint32_t ts_sec;         /* timestamp seconds */
	uint32_t ts_usec;        /* timestamp microseconds */
	uint32_t incl_len;       /* number of octets of packet saved in file */
	uint32_t orig_len;       /* actual length of packet */
} pcaprec_hdr_t;

bool
is_written(uint32_t frame)
{
    uint32_t i;

    for (i = 0; i < n_written; i++)
        if (written[i] == frame) return true;

    return false;
}


bool
find_and_write(uint32_t frame)
{
	pcap_hdr_t pcap_hdr;
	pcaprec_hdr_t pcap_rec_hdr;
	uint8_t data[65536];
	int32_t fdin;
	uint32_t fileno, nframe;
	uint32_t i, n_read, n_write, n_size, n_extracted;
	char filename[128];


	// check if the frame has already been written
	if (is_written(frame)) {
		printf("frame(%d) already written\n", frame);
		return true;
	}

	i = 0;
	nframe = frame % FRAMES_PER_FILE;
	fileno = ceil(frame * 1.0 / FRAMES_PER_FILE) - 1; // numbering starts from 00000
	snprintf(filename, 128, "%s/%s-%05d.pcap", PCAP_DIR_NAME, PCAP_BASE_NAME, fileno);

	if (access(filename, F_OK) == -1) {
		printf("file(%s) for frame(%d) does not exist", filename, frame);
		return false;
	}

	fdin = open(filename, O_RDONLY);
	if(fdin == -1) {
		printf("error:(%s)\n", strerror(errno));
		return false;
	}

	n_size = sizeof(pcap_hdr_t);
	n_read = read(fdin, (void *) &pcap_hdr, n_size);
	if(n_read < n_size) {
		printf("fread(%d).pcap_hdr_t = %d\n", n_size, n_read);
		return false;
	}

	if (!wrote_pcap_hdr) {
	    write(fdout, &pcap_hdr, sizeof(pcap_hdr_t));
		wrote_pcap_hdr = true;
	}

	// printf("pcap.hdr, magic=[0x%x] version[%d.%d] thiszone=%d, sigfigs=%d, snaplen=%d, network=%d\n",
	// 	pcap_hdr.magic_number, pcap_hdr.version_major, pcap_hdr.version_minor, pcap_hdr.sigfigs,
	// 	pcap_hdr.thiszone, pcap_hdr.snaplen, pcap_hdr.network);

	printf("frame(%d) @ filename(%s:%d) ", frame, filename, nframe);
	while(1)
	{
		i ++;
		// read pcap record header
		n_size = sizeof(pcaprec_hdr_t);
		n_read = read(fdin, &pcap_rec_hdr, n_size);
		if(n_read < n_size) {
			// reached the end of the file
			printf("not found\n");
			return false;
		}

		if (i != nframe) {
			lseek(fdin, pcap_rec_hdr.incl_len, SEEK_CUR);
			continue;
		}

		// printf("pcap.rec[%03d], timestamp[%d.%d] incl=%d orig=%d\n",
		// 	i, pcap_rec_hdr.ts_sec, pcap_rec_hdr.ts_usec, pcap_rec_hdr.incl_len,  pcap_rec_hdr.orig_len);

		printf("found\n");
		n_read = read(fdin, data, pcap_rec_hdr.incl_len);
		n_write = write(fdout, &pcap_rec_hdr, sizeof(pcaprec_hdr_t));
		n_write = write(fdout, data, n_read);

		written[n_written++] = frame;
		break;
	}

	close(fdin);
	return true;
}


int main(int argc, char const *argv[]) \
{
	uint32_t i;
	uint32_t frame;
	uint32_t wlen;

	const char *fout = argv[1];

	if (argc < 3) {
		printf("usage: %s <outfile> [ <packet#> <packet#> ... ]\n", argv[0]);
		exit(1);
	}

	wlen = argc - 2;
	uint32_t w[wlen];
	for (i = 0; i < wlen; i++)
		w[i] = atoi(argv[i+2]);

	n_written = 0;
	written = calloc(wlen, sizeof(uint32_t));

	fdout = open(fout, O_RDWR | O_CREAT | O_TRUNC, 0644);
	if(fdout == -1) {
		printf("error:(%s)\n", strerror(errno));
		return -1;
	}

	for (i = 0; i < wlen; i++) {
		find_and_write(w[i]);
	}

	close(fdout);
	return 0;
}
