#include"bfd.h"
#include"loader.h"

namespace loader
{
   Symbol::Symbol() : type(SYM_TYPE_UKN), 
                    name(), 
                    addr(0) 
    {}

    void Symbol::setSymbolType(SymbolType new_type)
    {
        if (new_type != SYM_TYPE_UKN && 
            new_type != SYM_TYPE_FUNC &&
            new_type != SYM_TYPE_DATA)
        {
            throw exception_t::error("Error symbol type incorrect");
        }
        else
        {
            this->type = new_type;
        }
    }

    void Symbol::setName(std::string new_name)
    {
        this->name = new_name;
    }

    void Symbol::setAddr(std::uint64_t new_addr)
    {
        this->addr = new_addr;
    }

    Symbol::SymbolType Symbol::getSymbolType()
    {
        return this->type;
    }

    const char* Symbol::getName()
    {
        return this->name.c_str();
    }

    std::uint64_t Symbol::getAddr()
    {
        return this->addr;
    }

    /*
    *   Section functions
    */

    Section::Section() : type(SEC_TYPE_NONE),
                        vma(0),
                        size(0),
                        bytes(NULL)
    {
        binary = std::make_shared<Binary>();
    }

    void Section::setBinary(std::shared_ptr<Binary>& new_binary)
    {
        this->binary = new_binary;
    }

    void Section::setNewName(std::string new_name)
    {
        this->name = new_name;
    }

    void Section::setNewSectionType(SectionType new_type)
    {
        if (new_type != SEC_TYPE_NONE &&
            new_type != SEC_TYPE_CODE &&
            new_type != SEC_TYPE_DATA)
        {
            throw exception_t::error("Error section type incorrect");
        }
        else
        {
            this->type = new_type;
        }
    }

    void Section::setNewVMA(std::uint64_t new_vma)
    {
        this->vma = new_vma;
    }

    void Section::setNewSize(std::uint64_t new_size)
    {
        this->size = new_size;
    }

    void Section::setNewBytes(std::uint64_t size)
    {
        this->bytes = (std::uint8_t*) malloc (size);
    }

    Binary* Section::getBinary()
    {
        return this->binary.get();
    }

    const char* Section::getName()
    {
        return this->name.c_str();
    }

    Section::SectionType Section::getSectionType()
    {
        return this->type;
    }

    std::uint64_t Section::getVMA()
    {
        return this->vma;
    }

    std::uint64_t Section::getSize()
    {
        return this->size;
    }

    std::uint8_t* Section::getBytes()
    {
        return this->bytes;
    }

    bool Section::contains(std::uint64_t addr)
    {
        return (addr >= vma) && ((addr-vma) < size);
    }

    /*
    *   Binary functions
    */

    Binary::Binary() : type(BIN_TYPE_AUTO),
                      arch(ARCH_NONE),
                      bits(0),
                      entry(0)
    {}

    Section* Binary::get_text_sections()
    {
        for (auto &s : sections)
        {
            if (strcmp(s.getName(),".text") == 0)
                return &s;
        }
        return nullptr;
    }


    void Binary::setFileName(const char* filename)
    {
        this->filename = filename;
    }

    void Binary::setType(BinaryType type)
    {
        this->type = type;
    }

    void Binary::setTypeStr(const char* type_str)
    {
        this->type_str = std::string(type_str);
    }

    void Binary::setBinaryArch(BinaryArch arch)
    {
        this->arch = arch;
    }

    void Binary::setBinaryArchStr(const char* arch_str)
    {
        this->arch_str = std::string(arch_str);
    }

    void Binary::setBits(std::uint32_t bits)
    {
        this->bits = bits;
    }

    void Binary::setEntryPoint(std::uint64_t entry)
    {
        this->entry = entry;
    }

    const char* Binary::getFileName()
    {
        return this->filename.c_str();
    }

    Binary::BinaryType Binary::getType()
    {
        return this->type;
    }

    const char* Binary::getTypeStr()
    {
        return this->type_str.c_str();
    }

    Binary::BinaryArch Binary::getBinaryArch()
    {
        return this->arch;
    }

    const char* Binary::getBinaryArchStr()
    {
        return this->arch_str.c_str();
    }

    std::uint32_t Binary::getBits()
    {
        return this->bits;
    }

    std::uint64_t Binary::getEntryPoint()
    {
        return this->entry;
    }

    std::vector<Section>& Binary::getSections()
    {
        return this->sections;
    }

    std::vector<Symbol>& Binary::getSymbols()
    {
        return this->symbols;
    }

    /*
    *   Loader functions
    */
    Loader::Loader(const char* file_name, Binary::BinaryType bin_type) : bfd_inited(false),
                                      fname(file_name),
                                      bfd_h(nullptr),
                                      type(bin_type)
    {
        bin = std::make_shared<Binary>();
    }


    //这里开始对应一部分书上的代码，因为书上的代码应该版本太久了
    //所以代码实现有一点不一样，但感觉总体思路是差不多的。。。
    //
    /*
    *   public functions
    */
    void Loader::load_binary()
    {
        load_binary_bfd();  //在这个函数中，我们将实现功能，我们后面再解释该函数
    }

    //销毁Binary对象要比创建对象要容易
    //为了销毁Binary对象，加载器需要通过free来释放Binary动态分配的所有组建
    //幸运的是，Binary动态分配的组建不多，每个section中只有字节成员是malloc动态分配的
    void Loader::unload_binary()
    {
        
        size_t i;
        Section *sec;

        for (i = 0; i < bin->getSections().size(); i++)  //遍历所有section对象
        {
            sec = &bin->getSections()[i];
            if (sec->getBytes())
            {
                free(sec->getBytes());            //释放对应加载进来的内存
            }
        }
    }

    // 上述代码中展示了load_binary_bfd函数，该函数使用libbfd
    // 来处理与加载二进制文件有关的所有工作。继续讲解之前，需要先解
    // 决一个前提条件，即把需要解析和加载的二进制文件打开。打开二进
    // 制文件的代码在open_bfd函数中实现。

    Binary* Loader::getBinary()
    {
        return this->bin.get();
    }

    /*
    open_bfd函数使用libbfd通过文件名确定二进制文件的属性，并将其打开，然后返回该二进制文件的句柄
    在使用libbfd之前，我们需要将bfd_init初始化libbfd的内部状态，只需要初始化一次，所以使用bfd_inited来判定
    libbfd初始化完成后，通过调用bfd_openr函数以文件名打开二进制文件，
    bfd_openr的第2个参数允许你指定目标（二进制文件类型），但在这里我将其保留为NULL，以便libbfd自动确定二进
    制文件的类型。bfd_openr的返回值是一个指向bfd类型的文件句柄指针，这是libbfd的根数据结构，
    你可以将其传递给libbfd中的其他函数，以对二进制文件进行操作。如果打开发生错误，bfd_openr则返回NULL。
    */
    void Loader::open_bfd()
    {
        
        char error_message[1000];
    
        memset(error_message,0,1000);

        if(!bfd_inited){
            bfd_init();
            bfd_inited=true;   //bfd_inited来判定
        }
        //bfd_openr函数以文件名打开二进制文件,bfd_openr的第2个参数允许你指定目标（二进制文件类型）
        //但在这里我将其保留为NULL，以便libbfd自动确定二进制文件的类型。
        //bfd_openr的返回值是一个指向bfd类型的文件句柄指针，这是libbfd的根数据结构，
        //你可以将其传递给libbfd中的其他函数，以对二进制文件进行操作。如果打开发生错误，bfd_openr则返回NULL。
        bfd_h = bfd_openr(fname.c_str(),NULL);

        /*
        在发生错误的时候，一般可以通过调用bfd_get_error找到最新错误的类型，函数返回类型为bfd_error_type的对象，你可以将
        其与预定义的错误标识符（如bfd_error_no_memory或open_bfd）进行比较，以了解如何处理错误。
        通常，你可能只想通过错误消息触发退出。为了解决这个问题，bfd_errmsg函数可以将bfd_error_type转换为描述错误的字符
        串，你可以将其输出到屏幕。
        */
        
        if(!bfd_h)
        {
            snprintf(error_message,999,"failed to open binary '%s' (%s)",
            fname.c_str(),
            bfd_errmsg(bfd_get_error()));
            throw exception_t::error(error_message);
        }

       
        /*
        在获得二进制文件的句柄后，你应该用bfd_check_format函数检查二进制文件的格式。该函数会传入bfd句柄和bfd_format
        值，其中bfd_format可以设置成bfd_object、bfd_archive或者bfd_core。
        在这里加载器将其设置为bfd_object，用来验证打开的文件确实是一个对象。
        这里的“对象”在libbfd的术语中可以解释为可执行文件、可重定位对象，或者共享库。
        */

        if(!bfd_check_format(bfd_h,bfd_object))
        {
            snprintf(error_message, 999, "file '%s' does not look like an executable (%s)\n",
            fname.c_str(),
            bfd_errmsg(bfd_get_error()));

            throw exception_t::error(error_message);
        }


        /*
        确认正在处理的是bfd_object之后，加载器会手动将libbfd的错误状态设置为bfd_error_no_error。这是针对某些libbfd
        版本问题的解决方案，这些版本会在检测格式前设置bfd_error_wrong_format错误，并且即使格式检测没有问题，也
        会设置错误状态,所以我们在此将错误设置为没有错误。。
        */
        bfd_set_error(bfd_error_no_error);

        /*
        最后，加载器通过bfd_get_flavour函数检查二进制文件是否有已知的“flavour”。该函数返回一个bfd_flavour对象，该对象简
        单指向二进制文件类型（ELF、PE等）。有效的bfd_flavour值包括bfd_target_msdos_flavour、bfd_target_coff_flavour
        及bfd_target_elf_flavour。如果二进制格式未知，或者存在错误，则get_bfd_flavour返回bfd_error_invalid_target。
        在这种情况下，open_bfd就会bfd_target_unknown_flavour输出错误信息，并返回NULL。
        */
        if(bfd_get_flavour(bfd_h) == bfd_target_unknown_flavour)
        {
            snprintf(error_message, 999, "unrecognized format for binary '%s' (%s)",
            fname.c_str(),
            bfd_errmsg(bfd_get_error()));

            throw exception_t::error(error_message);
        }

        
    }

    void Loader::load_binary_bfd()
    {
        // initialize bfd object
        char error_message[1000];

        memset(error_message, 0, 1000);
        /*
        首先load_binary_bfd函数会使用open_bfd函数打开fname参数指定的二进制文件，并获得该二进制文件的bfd句柄。然后，
        load_binary_bfd设置bin的一些基本属性，先复制二进制文件的名称，再使用libbfd查找并复制入口点地址。
        句柄被保存在Loader类的bin_h参数
        */
        open_bfd();

        /*
        为了获取二进制文件的入口点地址，需要用到bfd_get_start_address，其返回bfd对象的start_address字
        段的值，起始地址是bfd_vma，实际上就是一个64位的无符号整数。
        接下来，加载器收集有关二进制类型的信息：是ELF格式、PE格式，还是其他不被支持的格式？你可以在libbfd维护的
        bfd_target结构中找到此信息，想要获取指向该数据结构的指针，只需要访问bfd句柄的xvec字段即可。换句话说，bfd_h->xvec为
        你提供了一个指向bfd_target结构的指针。除此以外，该结构提供了一个包含目标类型名称的字符串，加载器将字符串复制到Binary对象。
        接下来，使用switch语句检查bfd_h->xvec->flavour，并设置相应的Binary类型。
        这里加载器只支持ELF和PE格式，所以如果bfd_h->xvec->flavour指定了其他类型的二进制文件，就会发生错误。
        */
        bin->setFileName(fname.c_str());
        bin->setEntryPoint(static_cast<std::uint64_t>(bfd_get_start_address(bfd_h)));
        bin->setTypeStr(bfd_h->xvec->name);
        switch (bfd_h->xvec->flavour)
        {
        case bfd_target_elf_flavour:
            bin->setType(Binary::BIN_TYPE_ELF);
            break;
        case bfd_target_coff_flavour:
            bin->setType(Binary::BIN_TYPE_PE);
            break;
        case bfd_target_unknown_flavour:
        default:
            snprintf(error_message,999, "unsupported binary type (%s)\n", bfd_h->xvec->name);
            throw exception_t::error(error_message);
        }

        //这部分就是查找有关的二进制体系结构的信息。。。
        bfd_info = bfd_get_arch_info(bfd_h);
        bin->setBinaryArchStr(bfd_info->printable_name);

                switch (bfd_info->mach)
        {
        case bfd_mach_i386_i386:
            bin->setBinaryArch(Binary::ARCH_X86);
            bin->setBits(Binary::X86_32);
            break;
        case bfd_mach_x86_64:
            bin->setBinaryArch(Binary::ARCH_X86);
            bin->setBits(Binary::X86_64);
            break;
        default:
            snprintf(error_message, 999, "unsupported architecture (%s)\n", bfd_info->printable_name);
            throw exception_t::error(error_message);
        }

        /*
        加载器分别使用两个函数load_symbols和load_dynsym_bfd来加载符号，加载器
        中还实现了load_sections_bfd，这是用来加载二进制节的特定函数，等下会将其实现。。。
        */
        /* Symbol handling is best-effort only (they may not even be present) */
        load_symbols_bfd();
        load_dynsym_bfd();

        load_sections_bfd();
        
        /*
        加载完符号和节后，你已经将所有感兴趣的信息复制到自己的Binary对象中，这意味着你已经完成了libbfd的使用操作。因为不
        需要bfd句柄，所以加载器会用bfd_close将其关闭。当然，如果在加载二进制文件之前就发生错误，bfd_close也会关闭句柄。
        */

        if (bfd_h)
            bfd_close(bfd_h);
    }
    
    /**
    在libbfd中，符号由asymbol（结构bfd_symbol的缩写）结构表示。反过来，符号表就是asymbol**，表示指向符号的指针数
    组，因此，load_symbols_bfd的工作是填充处声明的asymbol指针数组， 然后将需要的信息复制到Binary对象中。
    */

    void Loader::load_symbols_bfd()
    {
        //该处我们重点注意的就是bfd_h句柄以及用于存储符号信息的Binary对象...
        long n,nsyms,i;
        asymbol **bfd_symtab;    //符号表
        Symbol *sym;             //具体符号
        char error_message[1000];
        memset(error_message, 0, 1000);
        std::vector<std::string> weak_names; //
        bfd_symtab = nullptr;
        n = bfd_get_symtab_upper_bound(bfd_h);  //获取符号表的大小 
        if(n<0)
        {
            snprintf(error_message, 999, "failed to read symtab (%s)",
            bfd_errmsg(bfd_get_error()));
            throw exception_t::error(error_message);
        }
        else if(n)
        {
            bfd_symtab = (asymbol**) malloc (n);   //根据符号表的大小赋值
            if (!bfd_symtab)
            {
                throw exception_t::error("Error allocating memory for symbols");
            }
            //请求libbfd填充符号表，可以使用bfd_canonicalize_symtab函数...
            //该函数将bfd句柄和要填充的符号表（asymbol**）作为参数。根据要求，libbfd会适当地填充符号表，并返回表中的符号数。
            nsyms = bfd_canonicalize_symtab(bfd_h, bfd_symtab);
            if (nsyms < 0)
            {
                snprintf(error_message, 999, "failed to read symtab (%s)",
                    bfd_errmsg(bfd_get_error()));
                throw exception_t::error(error_message);
            }
            //遍历所有符号
            for (i = 0; i < nsyms; i++)
            {
                if (std::find(weak_names.begin(), weak_names.end(), std::string(bfd_symtab[i]->name)) != weak_names.end())
                {
                    remove_symbol_by_name(bfd_symtab[i]->name);
                    weak_names.erase(
                        std::remove(weak_names.begin(), weak_names.end(), std::string(bfd_symtab[i]->name)), 
                        weak_names.end());
                }
                /*
                对二进制加载器来说，我们只对函数符号感兴趣，所以对于每个符号，要检查其是否设置了BSF_FUNCTION标志，是否是
                一个函数符号..书上其实是只对function进行了操作,但是这里其实是把所有都加载进来了..
                */
                if (bfd_symtab[i]->flags & BSF_WEAK)
                {
                    weak_names.push_back(std::string(bfd_symtab[i]->name));
                }

                if (bfd_symtab[i]->flags & BSF_FUNCTION)
                {
                    /*
                    Symbol是加载器用于存储符号的类。你需要将新创建的符号标记为函数符号，复制符号名称，
                    然后设置符号的地址。为了得到函数符号的起始地址，这里需要用到libbfd提供的bfd_asymbol_value函数
                    */
                    bin->getSymbols().push_back(Symbol());
                    sym = &bin->getSymbols().back();
                    sym->setSymbolType(Symbol::SYM_TYPE_FUNC);
                    sym->setName(std::string(bfd_symtab[i]->name));
                    sym->setAddr(static_cast<std::uint64_t>(bfd_asymbol_value(bfd_symtab[i])));
                }
                else if (((bfd_symtab[i]->flags & BSF_LOCAL) ||
                          (bfd_symtab[i]->flags & BSF_GLOBAL)) &&
                          bfd_symtab[i]->flags & BSF_OBJECT)
                {
                    bin->getSymbols().push_back(Symbol());
                    sym = &bin->getSymbols().back();
                    sym->setSymbolType(Symbol::SYM_TYPE_DATA);
                    sym->setName(std::string(bfd_symtab[i]->name));
                    sym->setAddr(static_cast<std::uint64_t>(bfd_asymbol_value(bfd_symtab[i])));
                }
            }

        }
        /*
        所有有用的符号都已经复制到Symbol对象中，加载器也不需要libbfd的解析了。所以，当load_symbols_bfd执行完以
        后，它会释放所有用于存储libbfd符号的空间，然后返回，符号加载过程结束
        */
        if (bfd_symtab)
            free(bfd_symtab);
    }

    //动态符号表的加载其实和静态表的加载步骤一样...只有个别的不同
    /*与前面显示的load_symbols_bfd函数唯一不同的是：首先，需要找到为符号指针保留的字节数，这里调用的是
    bfd_get_dynamic_symtab_upper_bound，而不是bfd_get_symtab_upper_bound；另外，填充符号表这里用的是
    bfd_ canonicalize_dynamic_symtab❸，而不是bfd_canonicalize_symtab。除此之外，剩余部分和从静态符号
    表中加载符号相同。
    */
     void Loader::load_dynsym_bfd()
    {
        long n, nsyms, i;
        asymbol** bfd_dynsym;
        Symbol *sym;
        std::vector<std::string> weak_names;
        char error_message[1000];

        memset(error_message, 0, 1000);
        bfd_dynsym = nullptr;

        n = bfd_get_dynamic_symtab_upper_bound(bfd_h);
        if (n < 0)
        {
            snprintf(error_message, 999, "failed to read dynamic symtab (%s)",
                bfd_errmsg(bfd_get_error()));
            throw exception_t::error(error_message);
        }
        else if (n)
        {
            bfd_dynsym = (asymbol**) malloc (n);
            if (!bfd_dynsym)
                throw exception_t::error("Not possible to allocate memory for dynamic symbols");

            nsyms = bfd_canonicalize_dynamic_symtab(bfd_h, bfd_dynsym);
            if (nsyms < 0)
            {
                snprintf(error_message, 999, "failed to read dynamic symtab (%s)",
                    bfd_errmsg(bfd_get_error()));
                throw exception_t::error(error_message);
            }

            for (i = 0; i < nsyms; i++)
            {
                if (std::find(weak_names.begin(), weak_names.end(), std::string(bfd_dynsym[i]->name)) != weak_names.end())
                {
                    remove_symbol_by_name(bfd_dynsym[i]->name);
                    weak_names.erase(
                        std::remove(weak_names.begin(), weak_names.end(), std::string(bfd_dynsym[i]->name)), 
                        weak_names.end());
                }

                if (bfd_dynsym[i]->flags & BSF_WEAK)
                {
                    weak_names.push_back(std::string(bfd_dynsym[i]->name));
                }

                if (bfd_dynsym[i]->flags & BSF_FUNCTION)
                {
                    bin->getSymbols().push_back(Symbol());
                    sym = &bin->getSymbols().back();
                    sym->setSymbolType(Symbol::SYM_TYPE_FUNC);
                    sym->setName(std::string(bfd_dynsym[i]->name));
                    sym->setAddr(static_cast<std::uint64_t>(bfd_asymbol_value(bfd_dynsym[i])));
                }else if (((bfd_dynsym[i]->flags & BSF_LOCAL) ||
                          (bfd_dynsym[i]->flags & BSF_GLOBAL)) &&
                          bfd_dynsym[i]->flags & BSF_OBJECT)
                {
                    bin->getSymbols().push_back(Symbol());
                    sym = &bin->getSymbols().back();
                    sym->setSymbolType(Symbol::SYM_TYPE_DATA);
                    sym->setName(std::string(bfd_dynsym[i]->name));
                    sym->setAddr(static_cast<std::uint64_t>(bfd_asymbol_value(bfd_dynsym[i])));
                }
            }
        }

        if (bfd_dynsym)
            free (bfd_dynsym);
    }
    
    void Loader::load_sections_bfd()
    {
        int bfd_flags;
        std::uint64_t vma,size;
        const char *secname;    //节名
        asection* bfd_sec;  //通过asection链表表示所有的节,也通过该值来遍历该链表
        Section *sec;       //单个节的指针
        Section::SectionType sectype;
        char error_message[1000];

        memset(error_message, 0, 1000);
        /*
         为了遍历所有的节，先从第一个节开始，由libbfd的节的链表
         头指向bfd_h->sections，然后接下来的每个asection对象都
         包含一个next指针，当next指针为NULL时，说明遍历到链表的结
         尾。
         */
        for (bfd_sec = bfd_h->sections; bfd_sec; bfd_sec = bfd_sec->next)
        {
            /*
             对每个节来说，加载器应该先检查能否加载该节，因为加载器只
             加载代码和数据段，所以应该先获取节的标志，以检查节的类型。为
             了得到标志位，我们用到bfd_get_section_flags，然后，检查
             是否设置SEC_CODE、SEC_DATA标志。如果没有，那么跳过该节，
             继续检查下一个节；如果设置了其中任意一个标志，那么加载器会为
             对应的Section对象设置节类型，并加载该节。
             */
            bfd_flags = bfd_section_flags(bfd_sec);

            sectype = Section::SEC_TYPE_NONE;

            if (bfd_flags & SEC_CODE)
                sectype = Section::SEC_TYPE_CODE;
            else if (bfd_flags & SEC_DATA)
                sectype = Section::SEC_TYPE_DATA;
            else
                continue;

//            除了节类型，加载器还会复制每个代码节、数据节的虚拟地址、
//            大小（以字节为单位）、名称及原始字节数。我们使用
//            bfd_section_vma查找libbfd节的虚拟基址，同样地，使用
//            bfd_section_size和bfd_section_name分别得到节的大小
//            和名称。另外，节可能没有名称，在这种情况下
//            bfd_section_name就会返回NULL。
            vma     = bfd_section_vma(bfd_sec);
            size    = bfd_section_size(bfd_sec);
            secname = bfd_section_name(bfd_sec);
            if (!secname)
                secname = "<unnamed>";

            bin->getSections().push_back(Section());

            sec = &bin->getSections().back();

            sec->setBinary(bin);
            sec->setNewName(std::string(secname));
            sec->setNewSectionType(sectype);
            sec->setNewVMA(vma);
            sec->setNewSize(size);
            sec->setNewBytes(size);
            if (sec->getBytes() == nullptr)
            {
                throw exception_t::error("Error allocating bytes for section data");
            }

            if (!bfd_get_section_contents(bfd_h, bfd_sec, sec->getBytes(), 0, size))
            {
                snprintf(error_message, 999, "failed to read section '%s' (%s)",
                    secname, bfd_errmsg(bfd_get_error()));
                throw exception_t::error(error_message);
            }
        }
    }

    void Loader::remove_symbol_by_name(const char* name)
    {
        size_t i;

        for (i = 0; i < bin->getSymbols().size(); i++)
        {
            if (strcmp(bin->getSymbols()[i].getName(), name) == 0)
            {
                bin->getSymbols().erase(bin->getSymbols().begin() + i);
                break;
            }
        }
    }
} // namespace loader

