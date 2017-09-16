
/*
 * Feedback collection.
 * The feedbacks are collected for research purpose, and will only be used to improve this tool.
 * Thanks for your understanding and support.
 */


#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#include "globals.h"
#include "logging.h"
#include "socket.h"
#include "helper.h"


#define WORKING_DIR "/tmp/"
#define TMP_LOG_FILE "intangd.log.tmp"
#define TMP_LOG_PATH WORKING_DIR"intangd.log.tmp"
#define COMPRESSED_LOG_PATH "/tmp/intangd.log.tar.gz"

/* Maximum upload size 1MB (before compression) */
#define MAX_UPLOAD_SIZE 1048576

/* When log size exceeds this, don't upload any more */
#define MAX_LOG_SIZE 104857600

extern time_t startup_ts;

static int fb_sock;

static int upload_offset;

static pthread_mutex_t fb_lock;


int init_fb_sock()
{
    if ((fb_sock=socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        log_error("init_fb_sock: cannot create socket");
        return -1;
    }
    struct sockaddr_in dst_addr;
    dst_addr.sin_family = AF_INET;
    dst_addr.sin_port = htons(FEEDBACK_SERVER_PORT);
    dst_addr.sin_addr.s_addr = str2ip(FEEDBACK_SERVER_IP);

    log_info("Connecting to feedback server.");
    if (connect(fb_sock, (struct sockaddr*)&dst_addr, sizeof(dst_addr)) < 0)    {
        log_error("Cannot connect to feedback server. %d", errno);
        return -1;
    }
    log_info("Connected to feedback server.");

    return 0; 
}

int clean_fb_sock()
{
    close(fb_sock);
    return 0;
}

void cut_log()
{
    char buf[MAX_UPLOAD_SIZE];
    long upload_end;
    FILE *fp, *fp2;

    fp = fopen(LOG_FILE, "r");
    fseek(fp, 0, SEEK_END);
    upload_end = ftell(fp);

    int size = (upload_end - upload_offset) <= MAX_UPLOAD_SIZE ? 
        (upload_end - upload_offset) : MAX_UPLOAD_SIZE;

    fseek(fp, upload_offset, SEEK_SET);
    int ret = fread(buf, 1, size, fp);
    upload_offset += ret;

    fp2 = fopen(TMP_LOG_PATH, "w");
    fwrite(buf, 1, ret, fp2);

    fclose(fp);
    fclose(fp2);
}

void compress_log()
{
    char cmd[256];
    sprintf(cmd, "tar zcf %s -C %s %s", COMPRESSED_LOG_PATH, WORKING_DIR, TMP_LOG_FILE);
    system(cmd);
}


int upload_log()
{
    int ret;
    char sndbuf[MAX_PACKET_SIZE];
    FILE *fp;

    while (init_fb_sock() < 0) 
        sleep(10);

    if (upload_offset > MAX_LOG_SIZE) {
        log_warn("The whole log file exceeds 100MB limit, stop uploading...");
        return -1;
    }

    cut_log();

    log_info("Compressing log...");
    compress_log();

    log_info("Uploading log...");

    ret = send(fb_sock, (char*)&startup_ts, sizeof(time_t), 0);
    log_debug("Startup timestamp sent.");

    fp = fopen(COMPRESSED_LOG_PATH, "rb");
    fseek(fp, 0, SEEK_END);
    int size = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    ret = send(fb_sock, (char*)&size, sizeof(int), 0);
    log_debug("Log file size sent. %d", size);

    while ((ret = fread(sndbuf, 1, MAX_PACKET_SIZE, fp)) != 0) {
        log_debug("%d bytes log read.", ret);
        //printf("%s\n", sndbuf);
        
        do {
            ret = send(fb_sock, sndbuf, ret, 0);
            if (ret <= 0) {
                if (ret == 0)
                    log_error("Sent 0 bytes. Connection may be closed.");
                else 
                    log_error("Failed to send. errno: %d", errno);
                close(fb_sock);
                while (init_fb_sock() < 0) 
                    sleep(10);
            }
            else {
                log_info("Sent %d bytes compressed log.", ret);
            }
        } while (ret <= 0);
            
    }
    fclose(fp);

    // destroy the connection after using it
    close(fb_sock);

    return 0;
}



