/* ###
 * IP: BinCraft
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
*/
use super::{Patches, new_patches, super::cfs::control_flow_structure};

#[cxx::bridge]
pub(crate) mod ffi {
    
    extern "Rust" {
        type Patches;
        unsafe fn new_patches(arch: *mut Architecture) -> Box<Patches>;
        fn add_patch(self: &mut Patches, space: &CxxString, offset: usize, size: i32, payload: &CxxString);
        unsafe fn resolve_patch(self: &Patches, addr: &Address, emit: *mut PcodeEmit) -> i32;

        fn control_flow_structure(graph: Pin<&mut BlockGraph>, fd: Pin<&mut Funcdata>) -> bool;
    }

    unsafe extern "C++" {
        include!("fspec.hh");
        include!("varnode.hh");
        include!("pcoderaw.hh");
        include!("architecture.hh");
        include!("space.hh");
        include!("address.hh");
        include!("translate.hh");
        include!("libdecomp.hh");
        include!("interface.hh");
        include!("consolemain.hh");
        include!("ifacedecomp.hh");
        include!("ruststream.hh");
        include!("ghidra_process.hh");
        include!("block.hh");


        fn ghidra_process_main();

        type AddrSpace;
        fn getName(self: &AddrSpace) -> &CxxString;

        type PcodeOp;

        type Datatype;
        type Varnode;

        type Funcdata;
        unsafe fn getArch(self: &Funcdata) -> *mut Architecture;
        unsafe fn newOp(self: Pin<&mut Funcdata>, inputs: i32, addr: &Address) -> *mut PcodeOp;
        unsafe fn opInsertBegin(self: Pin<&mut Funcdata>, op: *mut PcodeOp, block: *mut BlockBasic);
        unsafe fn opInsertAfter(self: Pin<&mut Funcdata>, op: *mut PcodeOp, prev: *mut PcodeOp);
        unsafe fn opInsertInput(self: Pin<&mut Funcdata>, op: *mut PcodeOp, varnode: *mut Varnode, slot: i32);
        unsafe fn opSetOutput(self: Pin<&mut Funcdata>, op: *mut PcodeOp, varnode: *mut Varnode);
        unsafe fn newVarnodeOut(
            self: Pin<&mut Funcdata>,
            size: i32,
            addr: &Address,
            op: *mut PcodeOp) -> *mut Varnode;
        unsafe fn newUniqueOut(
            self: Pin<&mut Funcdata>,
            size: i32,
            op: *mut PcodeOp
        ) -> *mut Varnode;
        unsafe fn newUnique(self: Pin<&mut Funcdata>, size: i32, datatype: *mut Datatype) -> *mut Varnode;
        unsafe fn newConstant(self: Pin<&mut Funcdata>, size: i32, val: usize) -> *mut Varnode;

        type Address;
        unsafe fn new_address(space: *mut AddrSpace, off: usize) -> UniquePtr<Address>;
        fn isInvalid(self: &Address) -> bool;
        fn getSpace(self: &Address) -> *mut AddrSpace;
        fn getOffset(self: &Address) -> usize;

        type VarnodeData;
        unsafe fn new_varnode_data(
            space: *mut AddrSpace,
            offset: usize,
            size: u32,
        ) -> UniquePtr<VarnodeData>;

        type Architecture;
        fn getAddrSpaceManager(self: &Architecture) -> &AddrSpaceManager;

        type AddrSpaceManager;
        fn getSpaceByName(self: &AddrSpaceManager, name: &CxxString) -> *mut AddrSpace;

        type OpCode = pcodecraft::OpCode;
        fn get_opcode(s: &CxxString) -> OpCode;

        type PcodeEmit;
        unsafe fn dump_rust(
            emit: *mut PcodeEmit,
            addr: &Address,
            opcode: OpCode,
            out_var: UniquePtr<VarnodeData>,
            input_vars: &[UniquePtr<VarnodeData>],
            size: i32,
        );

        type StreamReader;
        fn read(self: Pin<&mut StreamReader>, buf: &mut [u8]) -> usize;


        type FlowBlock;
        fn getOut(self: &FlowBlock, idx: i32) -> *const FlowBlock;
        fn sizeOut(self: &FlowBlock) -> i32;
        fn getStartAddress(self: &FlowBlock) -> UniquePtr<Address>;
        fn getStopAddress(self: &FlowBlock) -> UniquePtr<Address>;

        type BlockBasic;
        fn asFlowBlock(self: &BlockBasic) -> *mut FlowBlock;
        type BlockCopy;
        type BlockGoto;
        type BlockMultiGoto;
        type BlockList;
        type BlockCondition;
        type BlockIf;
        type BlockWhileDo;
        type BlockDoWhile;
        type BlockInfLoop;
        type BlockSwitch;

        type BlockGraph;
        fn getSize(self: &BlockGraph) -> i32;
        fn getBlock(self: &BlockGraph, idx: i32) -> *mut FlowBlock;
        fn getStartBlock(self: &BlockGraph) -> *mut FlowBlock;
        unsafe fn newBlockBasic(self: Pin<&mut BlockGraph>, fd: Pin<&mut Funcdata>) -> *mut BlockBasic;
        unsafe fn newBlockCopy(self: Pin<&mut BlockGraph>, block: *mut FlowBlock) -> *mut BlockCopy;
        unsafe fn newBlockGoto(self: Pin<&mut BlockGraph>, block: *mut FlowBlock) -> *mut BlockGoto;
        unsafe fn newBlockMultiGoto(
            self: Pin<&mut BlockGraph>,
            block: *mut FlowBlock,
            out_edge: i32) -> *mut BlockMultiGoto;
        unsafe fn newBlockList(
            self: Pin<&mut BlockGraph>,
            nodes: &mut[*mut FlowBlock]) -> *mut BlockList;
        unsafe fn newBlockCondition(
            self: Pin<&mut BlockGraph>,
            b1: *mut FlowBlock, b2: *mut FlowBlock) -> *mut BlockCondition;
        unsafe fn newBlockIfGoto(
            self: Pin<&mut BlockGraph>,
            cond: *mut FlowBlock) -> *mut BlockIf;
        unsafe fn newBlockIf(
            self: Pin<&mut BlockGraph>,
            cond: *mut FlowBlock, true_case: *mut FlowBlock) -> *mut BlockIf;
        unsafe fn newBlockIfElse(
            self: Pin<&mut BlockGraph>,
            cond: *mut FlowBlock,
            true_case: *mut FlowBlock,
            false_case: *mut FlowBlock
        ) -> *mut BlockIf;
        unsafe fn newBlockWhileDo(
            self: Pin<&mut BlockGraph>,
            cond: *mut FlowBlock, body: *mut FlowBlock) -> *mut BlockWhileDo;
        unsafe fn newBlockDoWhile(
            self: Pin<&mut BlockGraph>,
            cond: *mut FlowBlock) -> *mut BlockDoWhile;
        unsafe fn newBlockInfLoop(
            self: Pin<&mut BlockGraph>,
            body: *mut FlowBlock) -> *mut BlockInfLoop;
        unsafe fn newBlockSwitch(
            self: Pin<&mut BlockGraph>,
            cases: &mut [*mut FlowBlock], has_exit: bool) -> *mut BlockSwitch;
    }
}
pub use ffi::*;