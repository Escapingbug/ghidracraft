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
use cxx::let_cxx_string;
use pcodecraft::OpCode;
use reccon::{
    ast::{BoolExpr, Expr, Statement},
    graph::{ControlFlowEdge, ControlFlowGraph, NodeIndex},
    reconstruct, RecResult,
};
use core::slice::SlicePattern;
use std::{collections::{HashSet}, pin::Pin};
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

struct GraphTranslator<'a> {
    cfg: &'a ControlFlowGraph<*mut FlowBlock>,
    fd: Pin<&'a mut Funcdata>,
    graph: Pin<&'a mut BlockGraph>,
    vars: HashMap<String, *mut Varnode>,
    temp_space: *mut AddrSpace,
}

impl<'a> GraphTranslator<'a> {
    fn new(
        cfg: &'a ControlFlowGraph<*mut FlowBlock>,
        mut fd: Pin<&'a mut Funcdata>,
        graph: Pin<&'a mut BlockGraph>
    ) -> Self {
        let arch = unsafe {
            fd.as_mut().getArch()
        };
        let addr_manager = unsafe {
            (*arch).getAddrSpaceManager()
        };
        let_cxx_string!(space_name = "ram");
        let temp_space = addr_manager.getSpaceByName(&space_name);
        Self {
            cfg, graph, fd,
            temp_space,
            vars: HashMap::new()
        }
    }

    fn translate_boolexpr(&mut self, expr: Box<BoolExpr>, target_varnode: *mut Varnode) -> *mut BlockBasic {
        todo!()
    }

    fn translate_expr(&mut self, expr: Box<Expr>, target_varnode: *mut Varnode) -> *mut BlockBasic {
        todo!()
    }

    fn translate_stmt(&mut self, stmt: Box<Statement>) -> *mut FlowBlock {
        match *stmt {
            Statement::Compound { first, next } => {
                let first = self.translate_stmt(first);
                let second = self.translate_stmt(next);
                unsafe {
                    self.graph.as_mut().newBlockList(&mut [first, second]) as *mut FlowBlock
                }
            },
            Statement::Original { node_idx } => {
                *self.cfg.node_weight(node_idx).unwrap()
            },
            Statement::Assign { var, value } => {
                let var_ref = *self.vars.get(&var).unwrap();
                let value_block = self.translate_expr(value, var_ref);
                value_block as *mut FlowBlock
            },
            Statement::IfThen { cond, body_then } => {
                let cond_block = self.translate_boolexpr(cond, target_varnode) as *mut FlowBlock;
                let body = self.translate_stmt(body_then);

                unsafe {
                    self.graph.as_mut().newBlockIf(cond_block, body) as *mut FlowBlock
                }
            },
            Statement::IfThenElse { cond, body_then, body_else } => {
                todo!()
                //let cond_block = self.translate_boolexpr(cond, target_varnode) as 8mut F
            }
            _ => {todo!()}
        }
    }

    fn translate(&mut self, res: RecResult) {
        self.translate_stmt(Box::new(res.stmt));
    }
}

pub fn control_flow_structure(graph: Pin<&mut BlockGraph>, fd: Pin<&mut Funcdata>) -> bool {
    let (cfg, entry) = cfg_from_graph(&graph);
    let res = match reconstruct(&cfg, entry) {
        Some(res) => res,
        None => return false,
    };

    println!("reccon result: {}", res.stmt.to_string());
    let mut translator = GraphTranslator::new(&cfg, fd, graph);
    translator.translate(res);

    true
}
