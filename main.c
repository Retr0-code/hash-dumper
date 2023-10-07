#include <errno.h>
#include <stdio.h>

int main(int argc, char const *argv[])
{
    FILE* system_hive = open("hives/system.dump", "rb");
    if (system_hive == NULL)
    {
        printf("Unable to open system hive: %s\n", strerror(errno));
        return -1;
    }

    return 0;
}
