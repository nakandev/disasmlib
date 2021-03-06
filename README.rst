=========
disasmlib
=========

Simple ELF & Disassembly code analyzer

Features
========

* Read a few ELF headers

  * ELF header
  * Section headers
  * Symbol table headers

* Estimate section/function list even if only disassembly is given

* Build disassembly Control Flow Graph

Requirements
------------

* python>=2.7

Installation
------------

::

  $ pip install git+https://github.com/nakandev/disasmlib

or

::

  $ git clone git@github.com:nakandev/disasmlib.git <your_package_dir>
  $ export PYTHONPATH=<your_package_dir>:$PYTHONPATH

  

Usage
-----

::

  import disasmlib
  
  elf = disasmlib.ElfFile('test1-riscv.elf')
  elf.set_machine(disasmlib.RISCVMachine())
  elf.set_toolchain('/your/riscv-gnu-toolchain/bin')
  elf.read()
  
  for section in elf.disasm.sections:
      print(section.name)
      for block in section.blocks:
          print(hex(block.addr), block.label)
          for op in block.operators:
              print(hex(op.addr), op.op)

See examples for more information.
