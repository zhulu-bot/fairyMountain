package com.provenance.fairymountain.utils;

public class myLog {
    //写一个log的工具类，我知道有日志框架但是还没学，为了方便，我自己搞一个
    //低端，想要什么参数，就全部传进来
    //高端，基于注解解析器的日志系统，使用aop来切入程序，让程序知道在哪里输出，可能当前主流的框架就是这么写的
    public static void printLog(String className,String methordName,String msg){
        System.out.println("在"+className+"的"+methordName+"的方法里"+msg);
    }

}
