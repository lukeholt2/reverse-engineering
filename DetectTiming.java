import ghidra.app.script.GhidraScript;
import ghidra.program.model.pcode.*;
import ghidra.app.decompiler.*;
import ghidra.program.model.listing.*;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Scanner;
import java.io.File;
import java.io.FileNotFoundException;
import java.util.Iterator;
import java.util.Set;

public class DetectTiming extends BaseScript {

    private final int THRESHOLD = 500;

    private int loop_iterations = 0;

    @Override
    protected void run() throws Exception {

        super.run();

        DecompInterface ifc = new DecompInterface();

        ifc.toggleSyntaxTree(true);
        ifc.toggleCCode(true);

        ifc.openProgram(currentProgram);

        for (Function func : currentProgram.getFunctionManager().getFunctions(true)) {
          
            DecompileResults res = ifc.decompileFunction(func, 0, this.monitor);

            ClangTokenGroup tokenGroup = res.getCCodeMarkup();

            for (ClangNode node : tokenGroup) {
                if (node instanceof ClangTokenGroup) {
                    IterateTokenGroup((ClangTokenGroup) node);
                    if (this.loop_iterations >= this.THRESHOLD && CallsSleep(func)) {
                        println(String.format("Possible Timing Attack: %s: %s", func.getName(), func.getEntryPoint()));
                        return;
                    }
                }
            }
        }
    }

    private boolean CallsSleep(Function func) {
        Set<Function> calledFunctions = func.getCalledFunctions(this.monitor);
        for (Function calledFunc : calledFunctions) {
            if (calledFunc.getName().toLowerCase().contains("sleep")) {
                return true;
            }
        }
        return false;
    }

    private void IterateTokenGroup(ClangTokenGroup tokenGroup) {
        for (ClangNode childNode : tokenGroup) {
            if (isLoop(childNode)) {
                this.loop_iterations = DetermineIterations((ClangStatement) childNode);
            }
            if (childNode instanceof ClangTokenGroup) {
                IterateTokenGroup((ClangTokenGroup) childNode);
            }
        }
    }

    private boolean isLoop(ClangNode node) {
        return (node instanceof ClangStatement)
                ? ((ClangStatement) node).getPcodeOp().getOpcode() == 5
                : false;

    }

    private int DetermineIterations(ClangStatement node) {
        Iterator<ClangNode> iterator = node.iterator();
        ClangNode childNode = iterator.next();
        do {
            childNode = iterator.next();
        } while (iterator.hasNext() && !(childNode instanceof ClangVariableToken));

        String plainText = ((ClangVariableToken) childNode).getText();
        return plainText.contains("0x")
                ? Integer.parseInt(plainText.substring(2).toUpperCase(), 16)
                : Integer.parseInt(plainText);
    }
}
