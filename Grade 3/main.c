#include "file_reader.h"

int main() {
    disk_open_from_file(NULL);
    disk_close(NULL);
    fat_open(NULL, 0);
    file_open(NULL, NULL);
    file_read(NULL, 0 ,0, NULL);
    file_seek(NULL, 0, 0);
    file_close(NULL);
    dir_open(NULL, NULL);
    dir_read(NULL, NULL);
    dir_close(NULL);
    return 0;
}
