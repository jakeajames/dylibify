//
//  main.m
//  dylibify
//
//  Created by Jake James on 7/13/18.
//  Copyright © 2018 Jake James. All rights reserved.
//

#import <Foundation/Foundation.h>

#import <mach-o/loader.h>
#import <mach-o/swap.h>

#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#define SWAP32(p) __builtin_bswap32(p)

static void *load_bytes(FILE *obj_file, off_t offset, size_t size) {
    void *buf = calloc(1, size);
    fseek(obj_file, offset, SEEK_SET);
    fread(buf, size, 1, obj_file);
    return buf;
}

void write_bytes(FILE *obj_file, off_t offset, size_t size, void *bytes) {
    fseek(obj_file, offset, SEEK_SET);
    fwrite(bytes, size, 1, obj_file);
}

void patch_mach_header(FILE *obj_file, off_t offset, void *mh, BOOL is64bit) {
    if (is64bit) {
        printf("[*] Patching filetype & flags\n");
        printf("[-] FILETYPE was 0x%x\n", ((struct mach_header_64 *)mh)->filetype);
        printf("[-] FLAGS were: 0x%x\n", ((struct mach_header_64 *)mh)->flags);
        
        //----Change MH_EXECUTE to MH_DYLIB----//
        ((struct mach_header_64 *)mh)->filetype = MH_DYLIB;
        ((struct mach_header_64 *)mh)->flags |= MH_NO_REEXPORTED_DYLIBS;
        
        printf("[+] FILETYPE is 0x%x\n", ((struct mach_header_64 *)mh)->filetype);
        printf("[+] FLAGS are: 0x%x\n", ((struct mach_header_64 *)mh)->flags);
        
        write_bytes(obj_file, offset, sizeof(struct mach_header_64), mh);
    }
    else {
        printf("[*] Patching filetype & flags\n");
        printf("[-] FILETYPE was 0x%x\n", ((struct mach_header *)mh)->filetype);
        printf("[-] FLAGS were: 0x%x\n", ((struct mach_header *)mh)->flags);
        
        ((struct mach_header *)mh)->filetype = MH_DYLIB;
        ((struct mach_header *)mh)->flags |= MH_NO_REEXPORTED_DYLIBS;
        
        printf("[+] FILETYPE is 0x%x\n", ((struct mach_header *)mh)->filetype);
        printf("[+] FLAGS are: 0x%x\n", ((struct mach_header *)mh)->flags);
        
        write_bytes(obj_file, offset, sizeof(struct mach_header), mh);
    }
}

void patch_pagezero(FILE *obj_file, off_t offset, struct load_command *cmd, BOOL copied, void *seg, size_t sizeofseg, const char *target) {
    
    uint32_t size = cmd->cmdsize;
    
    printf("\t\t[*] Patching __PAGEZERO\n");
    printf("\t\t[*] Nullifying\n");
    
    //----Nullify it----//
    memset(seg, 0, sizeofseg);
    
    //----Allocate data for our new command + @executable_path/NAME_OF_TARGET.dylib----//
    //----So, if you plan to link with it, don't rename the file and put it on same location as binary----//
    //----Obviously, you can easily patch that yourself, if for some reason you want to----//
    struct dylib_command *dylib_cmd = (struct dylib_command*)malloc(sizeof(struct dylib_command) + [@(target) lastPathComponent].length + 18);
    
    dylib_cmd->cmd = LC_ID_DYLIB;
    dylib_cmd->cmdsize = size;
    //----The string will be located where our dylib command ends----//
    dylib_cmd->dylib.name.offset = sizeof(struct dylib_command);
    dylib_cmd->dylib.timestamp = 1;
    dylib_cmd->dylib.current_version = 0;
    dylib_cmd->dylib.compatibility_version = 0;
    
    //----If it's a FAT binary do not copy it twice----//
    if (!copied) {
        strcpy((char *)dylib_cmd + sizeof(struct dylib_command), ([[NSString stringWithFormat:@"@executable_path/%@", [@(target) lastPathComponent]] UTF8String]));
    }
    
    printf("\t\t[*] Doing the magic\n");
    
    write_bytes(obj_file, offset, sizeofseg, dylib_cmd);
    
    free(dylib_cmd);
}

void patch_dyldinfo(FILE *file, off_t offset, struct dyld_info_command *dyldinfo) {
    if (dyldinfo->rebase_off != 0) {
        
        //----Some maths takes place in here, we need to iterate over the opcodes----//
        //----Some of them are just 1 byte, some are 2 bytes, some are whole strings----//
        //----We only need the ones referencing to segments, which are 1 byte----//
        
        for (int i = 0; i < dyldinfo->rebase_size; i++) {
            uint8_t *bytes = load_bytes(file, offset + dyldinfo->rebase_off + i, sizeof(uint8_t));
            
            if ((*bytes & REBASE_OPCODE_MASK) == REBASE_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB) {
                printf("\t\t[-] REBASE_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB before = 0x%x\n", *bytes);
                *bytes -= 1; // "-1" -> one less segment = previous segment
                write_bytes(file, offset + dyldinfo->rebase_off + i, sizeof(uint8_t), bytes);
                bytes = load_bytes(file, offset + dyldinfo->rebase_off + i, sizeof(uint8_t));
                printf("\t\t[+] REBASE_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB now = 0x%x\n", *bytes);
                break;
            }
            free(bytes);
        }
    }
    if(dyldinfo->bind_off != 0) {
        for (int i = 0; i < dyldinfo->bind_size; i++) {
            uint8_t *bytes = load_bytes(file, offset + dyldinfo->bind_off + i, sizeof(uint8_t));
            
            switch (*bytes & BIND_OPCODE_MASK) {
                case BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB:
                    printf("\t\t[-] BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB before = 0x%x\n", *bytes);
                    if ((*bytes & 0xF) == 2) *bytes -= 1;
                    write_bytes(file, offset + dyldinfo->bind_off + i, sizeof(uint8_t), bytes);
                    bytes = load_bytes(file, offset + dyldinfo->bind_off + i, sizeof(uint8_t));
                    printf("\t\t[+] BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB now = 0x%x\n", *bytes);
                    while (*bytes != BIND_OPCODE_DO_BIND) {
                        i += 1;
                        bytes = load_bytes(file, offset + dyldinfo->bind_off + i, sizeof(uint8_t));
                    }
                    break;
                case BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM: // this means a string is coming next
                    while (*bytes != 0) { //all strings end with 0 (null byte) and don't have 0 in their body
                        i += 1;
                        bytes = load_bytes(file, offset + dyldinfo->bind_off + i, sizeof(uint8_t));
                    }
                    break;
                case BIND_OPCODE_ADD_ADDR_ULEB:
                    while (*bytes != BIND_OPCODE_DO_BIND) {
                        i += 1;
                        bytes = load_bytes(file, offset + dyldinfo->bind_off + i, sizeof(uint8_t));
                    }
                    break;
                default:
                    break;
            }
            free(bytes);
        }
    }
    if(dyldinfo->lazy_bind_off != 0) {
        for (int i = 0; i < dyldinfo->lazy_bind_size; i++) {
            uint8_t *bytes = load_bytes(file, offset + dyldinfo->lazy_bind_off + i, sizeof(uint8_t));
            
            switch (*bytes & BIND_OPCODE_MASK) {
                case BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB:
                    printf("\t\t[-] BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB before = 0x%x\n", *bytes);
                    if ((*bytes & 0xF) == 2) *bytes -= 1;
                    write_bytes(file, offset + dyldinfo->lazy_bind_off + i, sizeof(uint8_t), bytes);
                    bytes = load_bytes(file, offset + dyldinfo->lazy_bind_off + i, sizeof(uint8_t));
                    printf("\t\t[+] BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB now = 0x%x\n", *bytes);
                    while (*bytes != BIND_OPCODE_DO_BIND) {
                        i += 1;
                        bytes = load_bytes(file, offset + dyldinfo->lazy_bind_off + i, sizeof(uint8_t));
                    }
                    break;
                case BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM:
                    while (*bytes != 0) {
                        i += 1;
                        bytes = load_bytes(file, offset + dyldinfo->lazy_bind_off + i, sizeof(uint8_t));
                    }
                    break;
                case BIND_OPCODE_ADD_ADDR_ULEB:
                    while (*bytes != BIND_OPCODE_DO_BIND) {
                        i += 1;
                        bytes = load_bytes(file, offset + dyldinfo->lazy_bind_off + i, sizeof(uint8_t));
                    }
                    break;
                default:
                    break;
            }
            free(bytes);
        }
    }
    if(dyldinfo->weak_bind_off != 0) {
        for (int i = 0; i < dyldinfo->weak_bind_size; i++) {
            uint8_t *bytes = load_bytes(file, offset + dyldinfo->weak_bind_off + i, sizeof(uint8_t));
            
            switch (*bytes & BIND_OPCODE_MASK) {
                case BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB:
                    printf("\t\t[-] BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB before = 0x%x\n", *bytes);
                    if ((*bytes & 0xF) == 2) *bytes -= 1;
                    write_bytes(file, offset + dyldinfo->weak_bind_off + i, sizeof(uint8_t), bytes);
                    bytes = load_bytes(file, offset + dyldinfo->weak_bind_off + i, sizeof(uint8_t));
                    printf("\t\t[+] BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB now = 0x%x\n", *bytes);
                    while (*bytes != BIND_OPCODE_DO_BIND) {
                        i += 1;
                        bytes = load_bytes(file, offset + dyldinfo->weak_bind_off + i, sizeof(uint8_t));
                    }
                    break;
                case BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM:
                    while (*bytes != 0) {
                        i += 1;
                        bytes = load_bytes(file, offset + dyldinfo->weak_bind_off + i, sizeof(uint8_t));
                    }
                    break;
                case BIND_OPCODE_ADD_ADDR_ULEB:
                    while (*bytes != BIND_OPCODE_DO_BIND) {
                        i += 1;
                        bytes = load_bytes(file, offset + dyldinfo->weak_bind_off + i, sizeof(uint8_t));
                    }
                    break;
                default:
                    break;
            }
            free(bytes);
        }
    }
}

int dylibify(const char *macho, const char *saveto) {
    
    NSError *error;
    NSFileManager *fileManager = [NSFileManager defaultManager];
    
    //----Make sure we don't overwrite any file----//
    if ([fileManager fileExistsAtPath:@(saveto)]) {
        printf("[!] %s file exists!\n", saveto);
        return -1;
    }
    
    //----Create a copy of the file on the target destination----//
    [fileManager copyItemAtPath:@(macho) toPath:@(saveto) error:&error];
    
    //----Handle errors----//
    if (error) {
        printf("[!] %s\n", [[error localizedDescription] UTF8String]);
        return -1;
    }
    
    
    
    //----Open the copied file for updating, in binary mode----//
    FILE *file = fopen(saveto, "r+b");
    
    //----This variable will hold the binary location as we move on through reading it----//
    size_t offset = 0;
    BOOL copied = false;
    int ncmds = 0;
    struct load_command *cmd = NULL;
    uint32_t *magic = load_bytes(file, offset, sizeof(uint32_t)); //at offset 0 we have the magic number
    printf("[i] MAGIC = 0x%x\n", *magic);
    
    //----64bit magic number----//
    if (*magic == 0xFEEDFACF) {
        
        printf("[i] 64bit binary\n");
        
        struct mach_header_64 *mh64 = load_bytes(file, offset, sizeof(struct mach_header_64));
        
        //----Patch filetype and add MH_NO_REEXPORTED_DYLIB flag (required for linking with it)----//
        patch_mach_header(file, offset, mh64, true); //patch
        offset += sizeof(struct mach_header_64);
        ncmds = mh64->ncmds;
        free(mh64);
        
        printf("[i] %d LOAD COMMANDS\n", ncmds);
        
        for (int i = 0; i < ncmds; i++) {
            cmd = load_bytes(file, offset, sizeof(struct load_command));
            
            if (cmd->cmd == LC_SEGMENT_64) {
                struct segment_command_64 *seg64 = load_bytes(file, offset, sizeof(struct segment_command_64));
                
                printf("\t[i] LC_SEGMENT_64 (%s)\n", seg64->segname);
                
                //----Dylibs don't have the PAGEZERO segment, replace it with a LC_ID_DYLIB command----//
                if (!strcmp(seg64->segname, "__PAGEZERO")) {
                    patch_pagezero(file, offset, cmd, copied, seg64, sizeof(struct segment_command_64), saveto);
                }
                free(seg64);
            }
            else if (cmd->cmd == LC_DYLD_INFO_ONLY) {
                printf("[*] Found DYLD_INFO_ONLY!\n");
                struct dyld_info_command *dyldinfo = load_bytes(file, offset, sizeof(struct dyld_info_command));
                
                //----Since we removed one segment we have to to rework opcodes so DATA is not confused with LINKEDIT----//
                patch_dyldinfo(file, 0, dyldinfo);
                free(dyldinfo);
            }
            else {
                printf("[i] LOAD COMMAND %d = 0x%x\n", i, cmd->cmd);
            }
            offset += cmd->cmdsize;
            free(cmd);
        }
    }
    //----32bit magic number----//
    else if (*magic == 0xFEEDFACE) {
        
        printf("[i] 32bit binary\n");
        
        struct mach_header *mh = load_bytes(file, offset, sizeof(struct mach_header));
        patch_mach_header(file, offset, mh, false);
        offset += sizeof(struct mach_header);
        ncmds = mh->ncmds;
        free(mh);
        
        printf("[i] %d LOAD COMMANDS\n", ncmds);
        
        for (int i = 0; i < ncmds; i++) {
            cmd = load_bytes(file, offset, sizeof(struct load_command));
            if (cmd->cmd == LC_SEGMENT) {
                struct segment_command *seg = load_bytes(file, offset, sizeof(struct segment_command));
                
                printf("\t[i] LC_SEGMENT (%s)\n", seg->segname);
                
                if (!strcmp(seg->segname, "__PAGEZERO")) {
                    patch_pagezero(file, offset, cmd, copied, seg, sizeof(struct segment_command), saveto);
                }
                
                free(seg);
            }
            else if (cmd->cmd == LC_DYLD_INFO_ONLY) {
                printf("[*] Found DYLD_INFO_ONLY!\n");
                struct dyld_info_command *dyldinfo = load_bytes(file, offset, sizeof(struct dyld_info_command));
                patch_dyldinfo(file, 0, dyldinfo);
                free(dyldinfo);
            }
            else {
                printf("[i] LOAD COMMAND %d = 0x%x\n", i, cmd->cmd);
            }
            offset += cmd->cmdsize;
            free(cmd);
        }
    }
    //----More than one architecture----//
    else if (*magic == 0xBEBAFECA) {
        
        printf("[i] FAT binary\n");
        
        size_t arch_offset = sizeof(struct fat_header);
        struct fat_header *fat = load_bytes(file, offset, sizeof(struct fat_header));
        struct fat_arch *arch = load_bytes(file, arch_offset, sizeof(struct fat_arch));
        int n = SWAP32(fat->nfat_arch);
        
        printf("[i] %d ARCHS\n", n);
        
        while (n-- > 0) {
            offset = SWAP32(arch->offset);
            magic = load_bytes(file, offset, sizeof(uint32_t));
            
            if (*magic == 0xFEEDFACF) {
                printf("[i] Found 64bit architecture\n");
                
                struct mach_header_64 *mh64 = load_bytes(file, offset, sizeof(struct mach_header_64));
                patch_mach_header(file, offset, mh64, true);
                offset += sizeof(struct mach_header_64);
                ncmds = mh64->ncmds;
                free(mh64);
                
                printf("[i] %d LOAD COMMANDS\n", ncmds);
                
                for (int i = 0; i < ncmds; i++) {
                    cmd = load_bytes(file, offset, sizeof(struct load_command));
                    if (cmd->cmd == LC_SEGMENT_64) {
                        struct segment_command_64 *seg64 = load_bytes(file, offset, sizeof(struct segment_command_64));
                        
                        printf("\t[i] LC_SEGMENT_64 (%s)\n", seg64->segname);
                        
                        if (!strcmp(seg64->segname, "__PAGEZERO")) {
                            patch_pagezero(file, offset, cmd, copied, seg64, sizeof(struct segment_command_64), saveto);
                            copied = true;
                        }
                        free(seg64);
                    }
                    else if (cmd->cmd == LC_DYLD_INFO_ONLY) {
                        printf("[*] Found DYLD_INFO_ONLY!\n");
                        struct dyld_info_command *dyldinfo = load_bytes(file, offset, sizeof(struct dyld_info_command));
                        patch_dyldinfo(file, SWAP32(arch->offset), dyldinfo);
                        free(dyldinfo);
                    }
                    else {
                        printf("[i] LOAD COMMAND %d = 0x%x\n", i, cmd->cmd);
                    }
                    offset += cmd->cmdsize;
                    free(cmd);
                }
            }
            else if (*magic == 0xFEEDFACE) {
                printf("[i] Found 32bit architecture\n");
                
                struct mach_header *mh = load_bytes(file, offset, sizeof(struct mach_header));
                patch_mach_header(file, offset, mh, false);
                offset += sizeof(struct mach_header);
                ncmds = mh->ncmds;
                free(mh);
                
                printf("[i] %d LOAD COMMANDS\n", ncmds);
                
                for (int i = 0; i < ncmds; i++) {
                    cmd = load_bytes(file, offset, sizeof(struct load_command));
                    if (cmd->cmd == LC_SEGMENT) {
                        struct segment_command *seg = load_bytes(file, offset, sizeof(struct segment_command));
                        printf("\t[i] LC_SEGMENT (%s)\n", seg->segname);
                        if (!strcmp(seg->segname, "__PAGEZERO")) {
                            patch_pagezero(file, offset, cmd, copied, seg, sizeof(struct segment_command), saveto);
                            copied = true;
                        }
                        free(seg);
                    }
                    else if (cmd->cmd == LC_DYLD_INFO_ONLY) {
                        printf("[*] Found DYLD_INFO_ONLY!\n");
                        struct dyld_info_command *dyldinfo = load_bytes(file, offset, sizeof(struct dyld_info_command));
                        patch_dyldinfo(file, SWAP32(arch->offset), dyldinfo);
                        free(dyldinfo);
                    }
                    else {
                        printf("[i] LOAD COMMAND %d = 0x%x\n", i, cmd->cmd);
                    }
                    offset += cmd->cmdsize;
                    free(cmd);
                }
            }
            else {
                printf("[!] Unrecognized architecture with MAGIC = 0x%x\n", *magic);
                continue;
            }
            arch_offset += sizeof(struct fat_arch);
            arch = load_bytes(file, arch_offset, sizeof(struct fat_arch));
        }
        
        free(fat);
        free(arch);
    }
    else {
        printf("[!] Unrecognized file\n");
        goto err;
    }
    
err:
    fclose(file);
    return -1;
}

int main(int argc, const char * argv[]) {
     if (argc != 3) {
         printf("Usage:\n\t%s <in> <out>\nExample:\n\t%s /usr/bin/executable /usr/lib/dylibified.dylib\n", argv[0], argv[0]);
         return -1;
     }
    
    dylibify(argv[1], argv[2]);
    return 0;
}
