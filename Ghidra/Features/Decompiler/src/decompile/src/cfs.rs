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

//! Control Flow Structuring implementation based on reccon
use crate::bridge::ffi::*;
use cxx::UniquePtr;
use reccon::{
    ast::{BoolExpr, Expr, Statement},
    graph::{ControlFlowEdge, ControlFlowGraph, NodeIndex},
    reconstruct, RecResult,
};
use std::pin::Pin;
use std::{collections::HashMap, ptr::null_mut};

fn cfg_from_graph(graph: &Pin<&mut BlockGraph>) -> (ControlFlowGraph<*mut FlowBlock>, NodeIndex) {
    let mut cfg = ControlFlowGraph::new();
    let mut node_map = HashMap::new();

    for i in 0..graph.getSize() {
        let block = graph.getBlock(i);
        let idx = cfg.add_node(block);
        node_map.insert(block as usize, idx);
    }

    for i in 0..graph.getSize() {
        let block = graph.getBlock(i);
        let block_idx = node_map.get(&(block as usize)).unwrap();
        let block = unsafe { block.as_ref().unwrap() };
        for out_i in 0..block.sizeOut() {
            let out_idx = node_map.get(&(block.getOut(out_i) as usize)).unwrap();
            let branch_type = if out_i == 0 {
                ControlFlowEdge::Branch(true)
            } else if out_i == 1 {
                ControlFlowEdge::Branch(false)
            } else {
                ControlFlowEdge::NotBranch
            };
            cfg.add_edge(*block_idx, *out_idx, branch_type);
        }
    }

    let entry = node_map.get(&(graph.getStartBlock() as usize)).unwrap();

    (cfg, *entry)
}

/// Return value for recursively import
enum ImportResult {
    /// we'd like to combine continuous compound statements into one,
    /// instead of have multiple BlockLists
    Compound(Vec<*mut FlowBlock>),

    /// Just internal block
    Block(*mut FlowBlock),

    /// assignment needs to be delayed until its address resolved
    Assign(Vec<Box<Statement>>),
}

impl ImportResult {
    fn is_assign(&self) -> bool {
        match self {
            &Self::Assign(_) => true,
            _ => false,
        }
    }

    fn resolved_addr(&self, start: bool) -> Option<UniquePtr<Address>> {
        match self {
            Self::Assign(_) => None,
            Self::Block(block) => {
                if start {
                    unsafe { Some(block.as_ref().unwrap().getStartAddress()) }
                } else {
                    unsafe { Some(block.as_ref().unwrap().getStopAddress()) }
                }
            }
            Self::Compound(blocks) => {
                if start {
                    unsafe { Some(blocks[0].as_ref().unwrap().getStartAddress()) }
                } else {
                    unsafe { Some(blocks[blocks.len() - 1].as_ref().unwrap().getStopAddress()) }
                }
            }
        }
    }
}

struct ImportStatus<'a> {
    /// if we are entering looping area, this should be the node index
    /// of the looping node. When we are breaking or continueing, we
    /// can use this to know where we are going out
    looping_node: Option<NodeIndex>,

    cfg: &'a ControlFlowGraph<*mut FlowBlock>,
    /// The str -> varnode table
    varnode_map: &'a HashMap<&'a str, *mut Varnode>,
    /// the ghidra side graph
    graph: Pin<&'a mut BlockGraph>,
    func_data: Pin<&'a mut Funcdata>,
}
unsafe fn gen_bool_expr(
    fd: Pin<&mut Funcdata>,
    tab: &HashMap<&str, *mut Varnode>,
    block: *mut BlockBasic,
    bool_expr: BoolExpr,
) -> *mut Varnode {
    todo!()
}

unsafe fn gen_expr(
    fd: Pin<&mut Funcdata>,
    tab: &HashMap<&str, *mut Varnode>,
    block: *mut BlockBasic,
    expr: Box<Expr>,
) -> *mut Varnode {
    match *expr {
        Expr::Int(val) => fd.newConstant(8, val as usize),
        Expr::Bool(bool_expr) => gen_bool_expr(fd, tab, block, bool_expr),
    }
}

/// match the statement, returns corresponding block
///
/// This is where we perform one step of matching on a stmt.
/// Recursively, this function matches on the statement.
/// Once a construct is found, this function will setup
/// the block and return it.
///
/// Example:
///
/// ```text
/// if (a == true && b == false && Original(2)) {
///   Original(1);
///   Original(3);
/// }
/// ```
///
/// In an ast, this would be written like this:
///
/// ```yaml
/// - IfThen
///   - And
///     - Eq
///       var: a
///       value
///         - True
///     - And
///       - Eq
///         var: b
///         value
///           - False
///       - Original
///         index: 2
///   - Compound
///     - Original
///       index: 1
///     - Original
///       index: 3
/// ```
///
/// In this case, we first try to find the original block, and
/// find its corresponding FlowBlock. That is, all that belongs
/// to original.
///
/// Three such blocks are found. Then, we check what is the
/// parent of such block. For example, one of them is And
/// statement, the other one is compound.
///
/// So, we setup the `compound` block and the `and` block. For
/// compound block, we setup the BlockList, and for And block,
/// we setup BlockCondition. We can refer to `blockaction.cc`
/// to check how this can be done by following `RuleXXX`.
fn import_recursively(cur_stmt: &Statement, import_status: &mut ImportStatus) -> ImportResult {
    use reccon::ast::Statement::*;

    let cfg = import_status.cfg;

    fn construct_assign_block(
        assigns: Vec<Box<Statement>>,
        address: UniquePtr<Address>,
        status: &mut ImportStatus,
    ) -> ImportResult {
        let new_block = unsafe {
            status
                .graph
                .as_mut()
                .newBlockBasic(status.func_data.as_mut())
        };
        for assign in assigns.into_iter() {
            if let Statement::Assign { var, value } = *assign {
                let varnode = status.varnode_map.get(var.as_str()).unwrap();
                todo!("implement assignment -> block");
            }
        }

        unsafe { ImportResult::Block(new_block.as_ref().unwrap().asFlowBlock()) }
    };

    let extend = |res, blocks: &mut Vec<*mut FlowBlock>| match res {
        ImportResult::Block(block) => blocks.push(block),
        ImportResult::Compound(inner_blocks) => blocks.extend(inner_blocks),
        _ => unreachable!(),
    };

    match cur_stmt {
        Original { node_idx } => ImportResult::Block(*cfg.node_weight(*node_idx).unwrap()),
        Compound { first, next } => {
            let first_import = import_recursively(&*first, import_status);
            let second_import = import_recursively(&*next, import_status);

            if !first_import.is_assign() && !second_import.is_assign() {
                // no delayed assign, great!

                let mut blocks = vec![];
                extend(first_import, &mut blocks);
                extend(second_import, &mut blocks);

                ImportResult::Compound(blocks)
            } else if first_import.is_assign() && second_import.is_assign() {
                // both are assigns. Merge them.
                if let ImportResult::Assign(mut assigns) = first_import {
                    if let ImportResult::Assign(sec_assigns) = second_import {
                        assigns.extend(sec_assigns);
                        ImportResult::Assign(assigns)
                    } else {
                        unreachable!()
                    }
                } else {
                    unreachable!()
                }
            } else if let ImportResult::Assign(assigns) = first_import {
                let resolved_addr = second_import.resolved_addr(true).unwrap();
                let block = construct_assign_block(assigns, resolved_addr, import_status);

                let mut blocks = vec![];
                extend(block, &mut blocks);
                extend(second_import, &mut blocks);

                ImportResult::Compound(blocks)
                // one of them are assigns, resolve the address
            } else if let ImportResult::Assign(assigns) = second_import {
                let resolved_addr = first_import.resolved_addr(false).unwrap();
                let block = construct_assign_block(assigns, resolved_addr, import_status);

                let mut blocks = vec![];
                extend(block, &mut blocks);
                extend(first_import, &mut blocks);

                ImportResult::Compound(blocks)
            } else {
                unreachable!()
            }
        }
        Assign { .. } => {
            // assign is delayed until address are resolved.
            // That is, only if we find a proper address for assignment statement, we
            // then actually generate the assign block ourselves.

            ImportResult::Assign(vec![Box::new(cur_stmt.clone())])
        }
        _ => todo!(),
    }
}

fn import_restruct_res(
    res: RecResult,
    cfg: ControlFlowGraph<*mut FlowBlock>,
    mut graph: Pin<&mut BlockGraph>,
    mut fd: Pin<&mut Funcdata>,
) {
    let mut varnode_map = HashMap::new();
    let new_vars = &res.new_vars;

    for v in new_vars.iter() {
        unsafe {
            varnode_map.insert(v.as_str(), fd.as_mut().newUnique(1, null_mut()));
        }
    }

    let mut status = ImportStatus {
        looping_node: None,
        cfg: &cfg,
        varnode_map: &varnode_map,
        graph,
        func_data: fd,
    };

    import_recursively(&res.stmt, &mut status);
}

pub fn control_flow_structure(graph: Pin<&mut BlockGraph>, fd: Pin<&mut Funcdata>) -> bool {
    let (cfg, entry) = cfg_from_graph(&graph);
    let res = match reconstruct(&cfg, entry) {
        Some(res) => res,
        None => return false,
    };
    import_restruct_res(res, cfg, graph, fd);

    true
}
