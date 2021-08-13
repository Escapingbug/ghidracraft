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

import com.oracle.truffle.api.CallTarget;
import com.oracle.truffle.api.Truffle;
import com.oracle.truffle.api.TruffleRuntime;

import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.pcode.emulate.AbstractEmulate;
import ghidra.pcode.emulate.BreakTable;
import ghidra.pcode.memstate.MemoryState;
import ghidra.program.model.address.Address;

public class GraalEmulate extends AbstractEmulate {

    private TruffleRuntime runtime;
    private PcodeOpContext context;

    public GraalEmulate(SleighLanguage language, MemoryState memState, BreakTable breakTable) {
        super(language, memState, breakTable);
        this.context = new PcodeOpContext(language, memState, null);
        this.runtime = Truffle.getRuntime();
    }

    public GraalEmulate(PcodeOpContext context, BreakTable breakTable) {
        super(context.getSleighLanguage(), context.getMemoryState(), breakTable);
        this.context = context;
        this.runtime = Truffle.getRuntime();
    }

    @Override
    public void setExecuteAddress(Address address) {
        this.context.setCurrentAddress(address);
    }

    @Override
    public Address getExecuteAddress() {
        return this.context.getCurrentAddress();
    }

    public void run() {
        CallTarget target = runtime.createCallTarget(new PcodeOpRootNode(null, getLanguage(), context));
        target.call();
    }

    public void run(Address entry) {
        setExecuteAddress(entry);
        run();
    }
}
