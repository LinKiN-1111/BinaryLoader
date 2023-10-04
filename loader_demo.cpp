#include <stdio.h>
#include <stdint.h>
#include <string>
#include "loader.h"
using namespace loader;
int main(int argc, char * argv[])
{
    size_t i;
    Section * sec;
    Symbol * sym;
    std::string fname;
    const char *filename = (char *)malloc(100);

    if(argc < 2) {
        printf("Usage: %s <binary>\n", argv[0]);
        return 2;
    }

    fname.assign(argv[1]);
    filename = fname.c_str(); //设置文件名

    //创建loader实例
    Loader myloader(filename,Binary::BIN_TYPE_PE);

    //加载对应的二进制文件
    myloader.load_binary();

    //查看时候加载成功
    printf("loaded binary '%s' %s/%s (%u bits) entry@0x%016jx\n",
           myloader.getBinary()->getFileName(),
           myloader.getBinary()->getTypeStr(),
           myloader.getBinary()->getBinaryArchStr(),
           myloader.getBinary()->getBits(),
           myloader.getBinary()->getEntryPoint());

    //程序输出每个节的基址、大小、名称及类型
    for (i = 0; i < myloader.getBinary()->getSections().size(); ++i)
    {
        sec = &myloader.getBinary()->getSections()[i];
        printf(" 0x%016jx %-8ju %-20s %s\n",
               sec->getVMA(), sec->getSize(), sec->getName(),
               sec->getSectionType() == Section::SEC_TYPE_CODE ? "CODE" :"DATA");
    }

    //显示找到的所有符号
    if(myloader.getBinary()->getSymbols().size()>0)
    {
        for(i = 0; i < myloader.getBinary()->getSymbols().size(); i++)
        {
            sym = &myloader.getBinary()->getSymbols()[i];
            printf(" %-40s 0x%016jx %s\n",
                   sym->getName(), sym->getAddr(),
                   (sym->getSymbolType() & Symbol::SYM_TYPE_FUNC) ? "FUNC" :
                   "");
        }
    }

    myloader.unload_binary();
}