/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package com.trustiv.cyberchallenge;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.ListIterator;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.tree.*;
import static org.objectweb.asm.tree.AbstractInsnNode.*;
import static org.objectweb.asm.Opcodes.*;
import org.objectweb.asm.tree.TypeInsnNode;


/**
 *
 * @author james
 */
public class SQLInject {

    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) throws IOException {
        ClassNode node = new ClassNode();
        String filename;
        if (args.length == 0) {
            filename = "/home/james/Garage/cyber-challenge/VulnerableApp.class";
        } else filename = args[0];
        try (FileInputStream instream = new FileInputStream(filename); FileOutputStream outstream = new FileOutputStream(filename + ".new")) {
            ClassReader reader = new ClassReader(instream);
            reader.accept(node, 0);
            fixClass(node);
            ClassWriter writer = new ClassWriter(0);
            node.accept(writer);
            outstream.write(writer.toByteArray());
        }
    }
    
    public static void fixClass(ClassNode clazz) {
        for (Object method: clazz.methods) {
            fixMethod((MethodNode) method);
        }
    }
    
    public static void fixMethod(MethodNode method) {
        method.maxStack += 5;
        List<Integer> calls = findExecuteCalls(method);
        /*
         * Process calls in reverse order, so that inserting instructions can't
         * affect earlier instructions
         */
        Collections.reverse(calls);
        for (int callLoc : calls) {
            System.out.println("Seeing if " + method.name + " is injectable");
            if (isInjectable(method, callLoc)) {
                System.out.println("It's injectable - trying to fix");
                try{
                    tryToFix(method, callLoc);
                } catch(CantFixException e) {
                    e.printStackTrace();
                    System.out.println("Could not fix method " + method.name);
                }
            }
        }
    }
    
    private static boolean isInjectable(MethodNode method, int insnLoc) {
        AbstractInsnNode prev = method.instructions.get(insnLoc - 1);
        int prevOpcode = prev.getOpcode();
        return (prev.getOpcode() != LDC);
    }
    
    private static void tryToFix(MethodNode method, int insnLoc) throws CantFixException {
        MethodInsnNode executeOp = (MethodInsnNode) method.instructions.get(insnLoc);
        if (!(executeOp.owner.equals("java/sql/Statement")
                && executeOp.name.startsWith("execute") 
                && executeOp.desc.startsWith("(Ljava/lang/String;)"))) {
            throw new CantFixException();
        }
        AbstractInsnNode prevOp = method.instructions.get(insnLoc - 1);
        if (prevOp.getType() != METHOD_INSN) throw new CantFixException();
        MethodInsnNode prevNode = (MethodInsnNode) prevOp;
        if (!prevNode.owner.equals("java/lang/StringBuilder") || !prevNode.name.equals("toString")) {
            throw new CantFixException();
        }
        
        int stringBuilderStart = findStartOfStringBuilder(method, insnLoc);
        int createStmtLoc = ensureNewlyCreatedStatement(method, stringBuilderStart);
        
        // Iterate through instructions, starting at StringBuilder construction and finishing at execution
        StringBuilder query = new StringBuilder();
        int paramNum = 1;
        ListIterator<AbstractInsnNode> iterator = method.instructions.iterator(stringBuilderStart);
        //Remove StringBuilder initialisation
        iterator.next();
        iterator.remove();
        iterator.next();
        iterator.remove();
        iterator.next();
        iterator.remove();
        //push first paramNum to the stack
        iterator.add(new LdcInsnNode(paramNum));
        paramNum += 1;
        Object lastConst = null;
        while (true) {
            AbstractInsnNode insn = iterator.next();
            if (insn.getOpcode() == INVOKEVIRTUAL) {
                MethodInsnNode node = (MethodInsnNode) insn;
                if (node.owner.equals("java/lang/StringBuilder")) {
                    if (lastConst != null) {
                        if (node.name.equals("append")
                                && node.desc.startsWith("(Ljava/lang/String;")) {
                            String fragment = (String) lastConst;
                            if (fragment.startsWith("'")) fragment = fragment.substring(1);
                            if (fragment.endsWith("'")) fragment = fragment.substring(0, fragment.length() - 2);
                            query.append(fragment);
                            //remove redundant LDC and invokevirtual
                            iterator.previous();
                            iterator.remove();
                            iterator.next();
                            iterator.remove();
                        }
                    } else {
                        if (node.name.equals("append")) {
                            if (node.desc.startsWith("(Ljava/lang/String;)")) {
                                node.setOpcode(INVOKEINTERFACE);
                                node.owner = "java/sql/PreparedStatement";
                                node.name = "setString";
                                node.desc = "(ILjava/lang/String;)V";
                            } else if (node.desc.startsWith("(D)")) {
                                node.setOpcode(INVOKEINTERFACE);
                                node.owner = "java/sql/PreparedStatement";
                                node.name = "setDouble";
                                node.desc = "(ID)V";
                            } else if (node.desc.startsWith("(F)")) {
                                node.setOpcode(INVOKEINTERFACE);
                                node.owner = "java/sql/PreparedStatement";
                                node.name = "setFloat";
                                node.desc = "(IF)V";
                            } else if (node.desc.startsWith("(J)")) {
                                node.setOpcode(INVOKEINTERFACE);
                                node.owner = "java/sql/PreparedStatement";
                                node.name = "setLong";
                                node.desc = "(IJ)V";
                            } else if (node.desc.startsWith("(I)")) {
                                node.setOpcode(INVOKEINTERFACE);
                                node.owner = "java/sql/PreparedStatement";
                                node.name = "setInt";
                                node.desc = "(II)V";
                            } else if (node.desc.startsWith("(Z)")) {
                                node.setOpcode(INVOKEINTERFACE);
                                node.owner = "java/sql/PreparedStatement";
                                node.name = "setBoolean";
                                node.desc = "(IZ)V";
                            } else if (node.desc.startsWith("(L")) {
                                node.setOpcode(INVOKEINTERFACE);
                                node.owner = "java/sql/PreparedStatement";
                                node.name = "setObject";
                                node.desc = "(ILjava/lang/Object;)V";
                            }
                            //FIXME Char and substring not handled
                            iterator.add(new InsnNode(DUP));
                            iterator.add(new LdcInsnNode(paramNum));
                            paramNum += 1;
                            query.append("?");
                        } else if (node.name.equals("toString")) {
                            iterator.remove();
                            iterator.add(new InsnNode(POP));
                        } else throw new RuntimeException("Unexpected StringBuilder operation");
                    }
                }
            } else if (insn.getOpcode() == INVOKEINTERFACE) {
                MethodInsnNode node = (MethodInsnNode) insn;
                if (node.owner.equals("java/sql/Statement")
                        && node.name.startsWith("execute")) {
                    if (node.name.equals("execute")) {
                        node.desc = "()Z";
                    } else if (node.name.equals("executeUpdate")) {
                        node.desc = "()I";
                    } else if (node.name.equals("executeQuery")) {
                        node.desc = "()Ljava/sql/ResultSet;";
                    }
                    node.owner = "java/sql/PreparedStatement";
                    break;
                }
            }
            if (insn.getOpcode() == LDC) {
                LdcInsnNode node = (LdcInsnNode) insn;
                lastConst = node.cst;
            } else {
                lastConst = null;
            }
            
        }
        //Finally, replace the createStatement with a prepareStatement
        MethodInsnNode createStmt = (MethodInsnNode) method.instructions.get(createStmtLoc);
        createStmt.name = "prepareStatement";
        method.instructions.insertBefore(createStmt, new LdcInsnNode(query.toString()));
    }
    
    private static int findStartOfStringBuilder(MethodNode method, int insnLoc) throws CantFixException {
        ListIterator<AbstractInsnNode> iterator = method.instructions.iterator(insnLoc);
        while (iterator.hasPrevious()) {
            int index = iterator.previousIndex();
            AbstractInsnNode node = iterator.previous();
            if (node.getOpcode() == NEW) {
                TypeInsnNode newNode = (TypeInsnNode) node;
                if (newNode.desc.equals("java/lang/StringBuilder")) {
                    return index;
                }
            }
        }
        throw new CantFixException("No StringBuilder constructor found");
    }
    
    private static int ensureNewlyCreatedStatement(MethodNode method, int insnLoc) throws CantFixException {
        ListIterator<AbstractInsnNode> iterator = method.instructions.iterator(insnLoc);
        while (iterator.hasPrevious()) {
            int index = iterator.previousIndex();
            AbstractInsnNode node = iterator.previous();
            if (node.getOpcode() == INVOKEINTERFACE) {
                MethodInsnNode prevNode = (MethodInsnNode) node;
                if (prevNode.owner.equals("java/sql/Connection")
                        && prevNode.name.equals("createStatement")) {
                    return index;
                } else {
                    throw new CantFixException();
                }
            }
            if ((node.getOpcode() != ALOAD) && (node.getOpcode() != ASTORE) && (node.getOpcode() != F_NEW)) {
                throw new CantFixException();
            }
        }
        throw new CantFixException();
    }
    
    private static List<Integer> findExecuteCalls(MethodNode method) {
        List<Integer> calls = new ArrayList<Integer>();
        ListIterator<AbstractInsnNode> instructions = method.instructions.iterator();
        while (instructions.hasNext()) {
            int index = instructions.nextIndex();
            AbstractInsnNode node = instructions.next();
            //System.out.println("Examining instruction " + node);
            if (node.getOpcode() == INVOKEINTERFACE) {
                MethodInsnNode mNode = (MethodInsnNode) node;
                if (mNode.owner.equals("java/sql/Statement")
                        && mNode.name.startsWith("execute")) {
                    calls.add(index);
                }
            }
        }
        return calls;
    }
}
