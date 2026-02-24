#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define MAX_SIZE 100

// 简单的状态机函数
int check_conditions(char *input) {
    int result = 0;
    
    if (strlen(input) < 5) {
        result += 1;
    }
    
    if (input[0] == 'A') {
        result += 2;
    }
    
    if (input[1] == 'B') {
        result += 3;
    }
    
    if (input[2] == 'C') {
        result += 4;
    }
    
    if (input[3] == 'D') {
        result += 5;
    }
    
    if (input[4] == 'E') {
        result += 6;
    }
    
    return result;
}

// 带有多个分支的测试函数
void fuzz_me(char *input) {
    int cond = check_conditions(input);
    
    if (cond == 0) {
        printf("No conditions met.\n");
    } else if (cond == 6) {
        printf("Input is too short.\n");
    } else if (cond == 10) {
        printf("First character is 'A'.\n");
    } else if (cond == 13) {
        printf("First two characters are 'A' and 'B'.\n");
    } else if (cond == 22) {
        printf("Matched sequence: ABCD\n");
        // 模拟的“漏洞”
        char buffer[MAX_SIZE];
        strcpy(buffer, input);
        printf("Buffer content: %s\n", buffer);
    } else {
        printf("Other condition met: %d\n", cond);
    }
}

int main(int argc, char **argv) {
    if (argc != 2) {
        printf("Usage: %s <input>\n", argv[0]);
        return 1;
    }
    
    fuzz_me(argv[1]);
    return 0;
}
