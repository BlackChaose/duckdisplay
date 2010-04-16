//
// Created by Nik on 01.21.2010.
// email: nikita.s.kalitin@gmail.com
//

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#define MEMSTR 256

/**
 * Execute a command and get the result.
 *
 * @param   command - The system command to run.
 * @return  The string command line output of the command.
 */
void run_cmd(char *command, char (*out)[MEMSTR]) {
    FILE *fptr;
    fptr = popen(command, "r");
    char str[MEMSTR];
    memset(str,0, MEMSTR);
    
    if (fptr == NULL) {
        printf("Failed to run command\n");
        exit(1);
    }

    while (fgets(*out, sizeof(*out), fptr) != NULL) {
        strcat(str, *out);
    }

    strcpy(*out, str);
    pclose(fptr);
    
}

int check_in(char *element, char **list_of_elements) {
    int index = 0;
    while (*(list_of_elements + index) != NULL) {
        if (strcmp(element, *(list_of_elements + index)) == 0) {
            return 1;
        }
        index = index + 1;
    }
    index = 0;
    return 0;
}

char *check_result(int range) {
    if (range == 0) {
        return "clean file";
    } else if (range < 50) {
        return "suspicious file";
    } else if (range >= 50 && range < 100) {
        return "very suspecious file";
    } else if (range >= 100) {
        return "malicious file";
    }
    return "\0";
}

int optim_check(int range) {
    if (range >= 100) {
        return 0;
    }else{
        return 1;
        }
}

void print_char_arr(char (*arr)[256]) {
    int index = 0;
    printf("\n***print arr:***\n");
    while (index < 5 ) {
        printf("%d: %s ", index, arr[index]);
        index = index + 1;
    }
    printf("\n****** %d *******\n", index);
}

int main(int argc, char *argv[]) {
    char md5_sum[32];
    char **p_to_md5sums = (char **) calloc(sizeof(md5_sum), 3);
    *(p_to_md5sums + 0) = "bd9b715e4ea2511e82aa654c3f786067";
    *(p_to_md5sums + 1) = "508b26d054ec49794596b320e3e4d2c7";
    *(p_to_md5sums + 2) = "c1c848ed39f3b68eab0bdf651c51b773";

    char command[1024];

    int cve_range = 0;
    // printf("data array: %s %s \n", *(p_to_md5sums + 0), *(p_to_md5sums + 1));
    char buf[MEMSTR]="";
    /* 0 extension 1 type 2 md5sum 3 md5sum of half file 4 sum of range */
    char check_params[5][256]={"\0","\0","\0","\0","\0"};


    char *res = "\0";
    if (argc == 2) {
        printf("\n\n##################### Start check file #####################\n\n");
        res = argv[1];
        printf("==> checked file: %s \n", res);


        /* get extension*/
        sprintf(command, "FILE=\"%s\"; echo \"${FILE##*.}\" |tr -d \'\n\'", argv[1]);
        run_cmd(command, &buf);
        if (strcmp(buf, "php") == 0) {
            strcpy(check_params[0],"php");
        } else {
            strcpy(check_params[0],buf);
        }
        /* end of get extension*/
        /* get type of file */
        sprintf(command, "/usr/bin/file %s | awk \'{print $2}\' |tr -d \'\n\'", argv[1]);
        run_cmd(command, &buf);
        if (strcmp(buf, "PHP") == 0) {
            strcpy(check_params[1], "php");
        } else {
            strcpy(check_params[1], buf);
        }
        /*END of get type of file*/

        /* check 1*/
        /**
         *
         * FIXME:!!! not correct value/ Must be pdf? but view PHP
         * */
        if (strcmp(check_params[0], check_params[1]) == 0) {
            cve_range = cve_range + 0;
            printf("==> check 1: Ok! (type of file: %s, extension: %s)\n", check_params[1], check_params[0]);
        } else {
            cve_range = cve_range + 50;
            printf("==> check 1: FAIL! (type of file: %s, extension: %s)\n", check_params[1], check_params[0]);
        }
        /*end of check 1*/
        if(optim_check(cve_range)==0){
            printf("result: %s (range: %d)\n", check_result(cve_range), cve_range);
            printf("\n\n############################################################\n\n");
            exit(0);
        }

        /* get md5sum of file */
        sprintf(command, "md5sum %s | awk \'{print $1}\' | tr -d \'\\n\'", argv[1]);
        run_cmd(command, &buf);
        strcpy(check_params[2], buf);
        /*end get md5sum of file*/
        /*check 2 - check md5sum*/
        if (check_in(check_params[2], p_to_md5sums) == 1) {
            cve_range = cve_range + 100;
            printf("==> check 2: FAIL! (md5sum in malware's db)\n");
        } else {
            printf("==> check 2: Ok! (md5sum not in malware's db\n");
        }
        /*end of check2 - check md5sum*/
		
		
     
        printf("result: %s (range: %d)\n", check_result(cve_range), cve_range);

    } else if (argc > 2) {
        printf("Too many arguments supplied.\n");
        exit(1);
    } else {
        printf("One argument expected.\n");
        exit(0);
    }

    free(p_to_md5sums);
    printf("\n\n############################################################\n\n");
    return 0;
}