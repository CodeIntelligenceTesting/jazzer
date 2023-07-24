package com.code_intelligence.jazzer.runtime;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;

public class ClojureLangIFnProxy implements java.lang.reflect.InvocationHandler {

    private final Object obj;
    private final int hookId;

    public static Object newInstance(Object obj, int hookId) throws ClassNotFoundException {
        HashSet<Class<?>> interfaces = new HashSet<>();
        ClassLoader classloader = obj.getClass().getClassLoader();
        Class<?> currentClass = obj.getClass();
        while (currentClass != null) {
            interfaces.addAll(Arrays.asList(currentClass.getInterfaces()));
            currentClass = currentClass.getSuperclass();
        }

        return java.lang.reflect.Proxy.newProxyInstance(
                classloader,
                interfaces.toArray(new Class[0]),
                new ClojureLangIFnProxy(obj, hookId));
    }

    private ClojureLangIFnProxy(Object obj, int hookId) {
        this.obj = obj;
        this.hookId = hookId;
    }

    public Object invoke(Object proxy, Method m, Object[] args)
            throws Throwable {
        Object result;
        try {
            TraceDataFlowNativeCallbacks.traceStrstr((String)args[0], (String)args[1], hookId);
            result = m.invoke(obj, args);
        } catch (InvocationTargetException e) {
            throw e.getTargetException();
        } catch (Exception e) {
            throw new RuntimeException("Unexpected invocation exception in function wrapper: " +
                    e.getMessage());
        }
        return result;
    }
}
