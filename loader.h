/***
 * 
 *  Interface for binary loader, this file will define
 *  the interface to manage binaries.
 *  Don't confuse this loader with OS loader, this will
 *  be a static loader to manage binaries.
 *
 */

#ifndef LOADER_H
#define LOADER_H

#include "incs.h"
#include "bfd.h"
#include "error.h"

namespace loader {

// classes to manage binaries

class Symbol;
class Section;
class Binary;
class Loader;

class Symbol     //符号  只关注函数符号
{
public:
    
    /* enum type for symbols */
    enum SymbolType
    {
        SYM_TYPE_UKN = 0,
        SYM_TYPE_FUNC = 1,   //唯一有效值
        SYM_TYPE_DATA = 2
    };

    // generic constructor
    Symbol();

    // setters
    void setSymbolType(SymbolType new_type);
    void setName(std::string new_name);
    void setAddr(std::uint64_t new_addr);
    // getters
    SymbolType getSymbolType();
    const char* getName();
    std::uint64_t getAddr();

private:
    SymbolType      type;
    std::string     name;   //符号名
    std::uint64_t   addr;   //符号描述的函数的起始地址
};


class Section     //节
{
public:

    /* What does that section is */
    enum SectionType    //区分代码段以及数据段
    {
        SEC_TYPE_NONE = 0,
        SEC_TYPE_CODE = 1,
        SEC_TYPE_DATA = 2
    };

    // generic constructor
    Section();

    // setters
    void setBinary(std::shared_ptr<Binary>& new_binary);     
    void setNewName(std::string new_name);          
    void setNewSectionType(SectionType new_type);
    void setNewVMA(std::uint64_t new_vma);
    void setNewSize(std::uint64_t new_size);
    void setNewBytes(std::uint64_t size);
    // getters
    Binary *getBinary();
    const char* getName();
    SectionType getSectionType();
    std::uint64_t getVMA();
    std::uint64_t getSize();
    std::uint8_t* getBytes();
    // functionalities
    bool contains (std::uint64_t addr);

private:
    std::shared_ptr<Binary> binary;   
    std::string             name;   //节名
    SectionType             type;   //类型
    std::uint64_t           vma;    // starting address of the section
    std::uint64_t           size;   // size in bytes（字节为单位）
    std::uint8_t*           bytes;  //节中的原始字节，从二进制文件中加载进来的吧。。。
};

class Binary     //表示整个二进制文件的抽象类
{
/*
*   Binary class represents a complete binary
*/
public:
    enum BinaryType
    {
        BIN_TYPE_AUTO   = 0,    //自动判断
        BIN_TYPE_ELF    = 1,    //ELF文件
        BIN_TYPE_PE     = 2     //PE文件
    };
    enum BinaryArch
    {
        ARCH_NONE   = 0,
        ARCH_X86    = 1     // X86 include x32 and x64
    };
    enum BinaryClass
    {
        X86_32      = 32,
        X86_64      = 64
    };

    Binary();

    Section* get_text_sections();    //自动查找并返回该节的内容

    // setters
    void setFileName(const char* filename);             
    void setType(BinaryType type);                      
    void setTypeStr(const char* type_str);              
    void setBinaryArch(BinaryArch arch);                
    void setBinaryArchStr(const char* arch_str);        
    void setBits(std::uint32_t bits);                   
    void setEntryPoint(std::uint64_t entry);            
    // getters
    const char*             getFileName();
    BinaryType              getType();
    const char*             getTypeStr();
    BinaryArch              getBinaryArch();
    const char*             getBinaryArchStr();
    std::uint32_t           getBits();
    std::uint64_t           getEntryPoint();
    std::vector<Section>&   getSections();      //存储节  
    std::vector<Symbol>&    getSymbols();       //存储符号


private:
    std::string             filename;           //文件名
    BinaryType              type;               //类型
    std::string             type_str;           //类型的字符串
    BinaryArch              arch;               //体系结构
    std::string             arch_str;           //体系结构的字符串
    std::uint32_t           bits;               //位宽
    std::uint64_t           entry;              //入口地址
    // to access sections and symbols through vectors
    std::vector<Section>    sections;                   //节
    std::vector<Symbol>     symbols;                    //符号
};


class Loader               //整个二进制的加载类，二进制文件文件加载进来后存入bin中
{
public:
    Loader(const char* file_name, Binary::BinaryType bin_type);

    void load_binary();     //使用要加载的二进制文件的名称指向一个二进制对象
    void unload_binary();   //得到先前加载的Binary对象指针，然后将其卸载
    
    Binary* getBinary();
private:
    bool                        bfd_inited;     //判断是否以及初始化
    std::string                 fname;          //设置需要加载的名称
    bfd*                        bfd_h;          // 二进制文件句柄
    std::shared_ptr<Binary>     bin;            //二进制文件加载到这个参数上，指向二进制文件的地址 
    Binary::BinaryType          type;           //二进制文件类型
    const bfd_arch_info_type*   bfd_info;       //二进制文件体系结构

    // private function
    void open_bfd();
    void load_binary_bfd();
    void load_symbols_bfd();
    void load_dynsym_bfd();
    void load_sections_bfd();
    void remove_symbol_by_name(const char* name);
};


}


#endif // LOADER_H
