#ifndef FILE_READER_H
#define FILE_READER_H
#define FAT_LFN_NAME_LEN 255
#define LFN_NAME_ENTRY_SIZE 13
#define LFN_NAME_PART_ONE_SIZE 5
#define LFN_NAME_PART_TWO_SIZE 6
#define LFN_NAME_PART_THREE_SIZE 2
#define FAT_LFN_LAST_ENTRY 0x40
#define FAT_NAME_LEN 8
#define FAT_EXTENSION_LEN 3
#define FAT_DIR_INFO_NAME_LEN 11
#define FAT_DIR_ENTRY_NAME_LEN 13
#define FAT_END_OF_SECTOR_MARKER 0xaa55
#define FAT_DIR_DELETED ((char) 0xe5)
#define FAT_BYTES_PER_SECTOR 512

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>

typedef uint32_t lba_t;

struct disk_t {
    FILE *f;
    lba_t total_sectors;
};

struct boot_sector_t {
    uint8_t jump_instruction[3];
    char oem_identifier[8];
    uint16_t bytes_per_sector;
    uint8_t sectors_per_cluster;
    uint16_t number_of_reserved_sectors;
    uint8_t number_of_fats;
    uint16_t root_dir_capacity;
    uint16_t small_number_of_sectors;
    uint8_t media_descriptor_type;
    uint16_t sectors_per_fat;
    uint16_t sectors_per_track;
    uint16_t number_of_heads;
    uint32_t number_of_hidden_sectors;
    uint32_t large_number_of_sectors;
    uint8_t drive_number;
    uint8_t current_head;
    uint8_t extended_boot_signature;
    uint32_t volume_serial_number;
    char volume_label[11];
    char system_type[8];
    uint8_t bootstrap_code[448];
    uint16_t end_of_sector_marker;
} __attribute__((packed));

struct volume_t {
    struct disk_t *pdisk;
    struct boot_sector_t boot_sector;
    uint8_t *first_fat;
    uint8_t *second_fat;
    uint8_t *root_dir;
    lba_t boot_sector_position;
    lba_t first_fat_position;
    lba_t second_fat_position;
    lba_t root_dir_position;
    lba_t second_cluster_position;
    lba_t root_dir_size;
};

enum fat_attributes_t {
    FAT_ATTRIBUTE_READ_ONLY = 0x0001,
    FAT_ATTRIBUTE_HIDDEN = 0x0002,
    FAT_ATTRIBUTE_SYSTEM = 0x0004,
    FAT_ATTRIBUTE_VOLUME_LABEL = 0x0008,
    FAT_ATTRIBUTE_LONG_FILE_NAME = 0x000f,
    FAT_ATTRIBUTE_DIRECTORY = 0x0010,
    FAT_ATTRIBUTE_ARCHIVED = 0x0020
} __attribute__((packed));

struct fat_time_t {
    uint16_t sec: 5;
    uint16_t min: 6;
    uint16_t hour: 5;
} __attribute__ ((packed));

struct fat_date_t {
    uint16_t day: 5;
    uint16_t month: 4;
    uint16_t year: 7;
} __attribute__ ((packed));

struct lfn_dir_info_t {
    uint8_t ordinal_number;
    uint16_t name_part_one[LFN_NAME_PART_ONE_SIZE];
    enum fat_attributes_t attributes;
    uint8_t reserved;
    uint8_t crc;
    uint16_t name_part_two[LFN_NAME_PART_TWO_SIZE];
    uint16_t cluster;
    uint16_t name_part_three[LFN_NAME_PART_THREE_SIZE];
} __attribute__ ((packed));

struct dir_info_t {
    char name[FAT_DIR_INFO_NAME_LEN];
    enum fat_attributes_t attributes;
    uint8_t reserved;
    uint8_t creation_time_ms;
    struct fat_time_t creation_time;
    struct fat_date_t creation_date;
    struct fat_date_t access_date;
    uint16_t first_cluster_high_bytes;
    struct fat_time_t modification_time;
    struct fat_date_t modification_date;
    uint16_t first_cluster_low_bytes;
    uint32_t size;
} __attribute__((packed));

struct dir_t {
    struct dir_info_t *info;
    uint32_t capacity;
    uint32_t position;
};

struct file_t {
    struct volume_t *pvolume;
    struct dir_info_t *info;
    struct clusters_chain_t *clusters_chain;
    uint32_t position;
};

struct clusters_chain_t {
    uint16_t *clusters;
    size_t size;
};

struct dir_entry_t {
    char name[FAT_DIR_ENTRY_NAME_LEN];
    char long_name[FAT_LFN_NAME_LEN];
    uint32_t size;
    uint8_t is_archived: 1;
    uint8_t is_readonly: 1;
    uint8_t is_system: 1;
    uint8_t is_hidden: 1;
    uint8_t is_directory: 1;
    uint8_t has_long_name: 1;
    struct fat_date_t creation_date;
    struct fat_time_t creation_time;
};

enum seek_type_t {
    SEEK_DIR,
    SEEK_FILE
};

int to_upper(char c);

int ignore_case_strcmp(const char *first, const char *second, size_t size);

void set_volume_statistics(struct volume_t *volume);

int boot_sector_validate(struct boot_sector_t *boot_sector);

struct disk_t *disk_open_from_file(const char *volume_file_name);

int disk_read(struct disk_t *pdisk, int32_t first_sector, void *buffer, int32_t sectors_to_read);

int disk_close(struct disk_t *pdisk);

struct volume_t *fat_open(struct disk_t *pdisk, uint32_t first_sector);

int fat_close(struct volume_t *pvolume);

struct file_t *file_open(struct volume_t *pvolume, const char *file_name);

size_t file_read(void *ptr, size_t size, size_t nmemb, struct file_t *stream);

int32_t file_seek(struct file_t *stream, int32_t offset, int whence);

int file_close(struct file_t *stream);

struct dir_t *dir_open(struct volume_t *pvolume, const char *dir_path);

int dir_read(struct dir_t *pdir, struct dir_entry_t *pentry);

int dir_close(struct dir_t *pdir);

size_t read_cluster(void *buffer, size_t bytes_per_cluster, struct file_t *stream);

uint16_t get_next_cluster(uint16_t current_cluster, void *buffer);

struct clusters_chain_t *get_chain_fat16(const void *buffer, size_t size, uint16_t first_cluster);

int convert_to_fat_dir_entry_name(char *fat_name, const char *file_name);

int convert_to_fat_dir_info_name(char *fat_name, const char *file_name);

void *find_dir_or_file_by_path(struct volume_t *pvolume, const char *path, enum seek_type_t seek_type);

#endif
