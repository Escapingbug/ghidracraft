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
use reccon::{RecResult, ast::Statement, graph::{ControlFlowEdge, ControlFlowGraph, NodeIndex}, reconstruct};
use std::{collections::HashMap, ptr::null_mut};
use std::pin::Pin;
use crate::bridge::ffi::*;

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
        let block = unsafe {
            block.as_ref().unwrap()
        };
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

fn import_recursively(
    cur_stmt: &Statement,
    varnode_map: &HashMap<&str, *mut Varnode>,
    mut graph: Pin<&mut BlockGraph>,
    mut fd: Pin<&mut Funcdata>) {
    todo!()
} 

fn import_restruct_res(res: RecResult, mut graph: Pin<&mut BlockGraph>, mut fd: Pin<&mut Funcdata>) {
    let mut varnode_map = HashMap::new();
    let new_vars = &res.new_vars;

    for v in new_vars.iter() {
        unsafe {
            varnode_map.insert(v.as_str(), fd.as_mut().newUnique(1, null_mut()));
        }
    }

    import_recursively(&res.stmt, &varnode_map, graph, fd);
}

pub fn control_flow_structure(graph: Pin<&mut BlockGraph>, fd: Pin<&mut Funcdata>) -> bool {
    let (cfg, entry) = cfg_from_graph(&graph);
    let res = match reconstruct(&cfg, entry) {
        Some(res) => res,
        None => return false
    };
    import_restruct_res(res, graph, fd);

    true
}