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
package ghidra.pcode.pcodetruffle;

import java.io.IOException;

import com.oracle.truffle.api.Truffle;
import com.oracle.truffle.api.TruffleContext;
import com.oracle.truffle.api.TruffleLanguage;
import com.oracle.truffle.api.TruffleRuntime;
import com.oracle.truffle.api.interop.TruffleObject;

import org.graalvm.polyglot.Context;
import org.graalvm.polyglot.Engine;
import org.graalvm.polyglot.Instrument;
import org.graalvm.polyglot.Source;

import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.pcode.emulate.AbstractEmulate;
import ghidra.pcode.emulate.BreakTable;
import ghidra.pcode.memstate.MemoryState;
import ghidra.program.model.address.Address;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class GraalEmulate extends AbstractEmulate {

    private TruffleRuntime runtime;
    private PcodeOpContext context;
    private Engine engine;
    private Context graalContext;

    public GraalEmulate(SleighLanguage language, MemoryState memState, BreakTable breakTable) {
        super(language, memState, breakTable);
        graalContext = Context.newBuilder(PcodeOpLanguage.ID).build();
        /*
        // instrument not yet used
        Instrument instrument = engine.getInstruments().get(GraalBreakTableInstrument.ID);
        GraalBreakTable graalBreakTable = instrument.lookup(GraalBreakTable.class);
        graalBreakTable.setBreakTable(breakTable);
        graalBreakTable.setEmulate(this);
        */
        /*
        graalContext.initialize(PcodeOpLanguage.ID);
        graalContext.enter();
        */
        this.engine = graalContext.getEngine();
        this.context = new PcodeOpContext(this);
        //this.context.setEmulate(this);
        this.runtime = Truffle.getRuntime();
    }

    public GraalEmulate(PcodeOpContext context, BreakTable breakTable) {
        super(context.getSleighLanguage(), context.getMemoryState(), breakTable);
        this.context = context;
        this.runtime = Truffle.getRuntime();
    }

    public PcodeOpContext getContext() {
        return context;
    }

    public Address parseAddress(String addrString) {
        return this.getAddrFactory().getAddress(addrString);
    }

    @Override
    public void setExecuteAddress(Address address) {
        this.context.setCurrentAddress(address);
    }

    @Override
    public Address getExecuteAddress() {
        return this.context.getCurrentAddress();
    }

    public PcodeOp[] emitPcode(Address addr) {
        return super.emitPcode(addr);
    }

    public void continueExecution(TaskMonitor monitor) throws CancelledException {
        this.context.continueExecution();
    }
}
