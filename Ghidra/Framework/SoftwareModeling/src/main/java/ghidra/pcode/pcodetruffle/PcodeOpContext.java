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

import java.util.HashMap;

import com.oracle.truffle.api.TruffleLanguage;

import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.pcode.emulate.EmulateInstructionStateModifier;
import ghidra.pcode.memstate.MemoryState;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;

public class PcodeOpContext {
    private final TruffleLanguage.Env env;
    private final PcodeOpLanguage language;
    private final AddressFactory addrFactory;
    private final MemoryState memoryState;
    private final SleighLanguage sleighLang;
    private final EmulateInstructionStateModifier instructionStateModifier;

    private HashMap<Address, PcodeOpBlockNode> blockCache = new HashMap<Address, PcodeOpBlockNode>();
    private Address currentAddress;
    private boolean halt = false;

    public PcodeOpContext(
        final SleighLanguage sleighLang,
        final MemoryState memoryState,
        Address curAddress,
        final EmulateInstructionStateModifier instructionStateModifier) {
        this(null, null, sleighLang, memoryState, instructionStateModifier);
        this.currentAddress = curAddress;
    }

    public PcodeOpContext(
        final PcodeOpLanguage language,
        final TruffleLanguage.Env env,
        final SleighLanguage sleighLang,
        final MemoryState memoryState,
        final EmulateInstructionStateModifier instructionStateModifier
    ) {
        this.sleighLang = sleighLang;
        this.env = env;
        this.language = language;
        this.addrFactory = sleighLang.getAddressFactory();
        this.memoryState = memoryState;
        this.instructionStateModifier = instructionStateModifier;
    }

    protected SleighLanguage getSleighLanguage() {
        return this.sleighLang;
    }

    public EmulateInstructionStateModifier getInstructionStateModifier() {
        return this.instructionStateModifier;
    }

    public HashMap<Address, PcodeOpBlockNode> getBlockCache() {
        return this.blockCache;
    }

    public TruffleLanguage.Env getEnv() {
        return this.env;
    }

    public PcodeOpLanguage getLanguage() {
        return this.language;
    }

    public AddressFactory getAddressFactory() {
        return this.addrFactory;
    }

    public MemoryState getMemoryState() {
        return this.memoryState;
    }

    public Address getCurrentAddress() {
        return this.currentAddress;
    }

    public void setCurrentAddress(Address curAddress) {
        this.currentAddress = curAddress;
    }

    public boolean getHalt() {
        return halt;
    }

    public void setHalt(boolean halt) {
        this.halt = halt;
    }
}
