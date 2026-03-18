.class public final Lio/opentelemetry/exporter/sender/okhttp/internal/OkHttpUtil;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field private static propagateContextForTestingInDispatcher:Z = false


# direct methods
.method private constructor <init>()V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static synthetic a(Ljava/lang/Runnable;)Ljava/lang/Thread;
    .locals 0

    .line 1
    invoke-static {p0}, Lio/opentelemetry/exporter/sender/okhttp/internal/OkHttpUtil;->lambda$createThreadFactory$0(Ljava/lang/Runnable;)Ljava/lang/Thread;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method private static createThreadFactory(Ljava/lang/String;)Lio/opentelemetry/sdk/internal/DaemonThreadFactory;
    .locals 2

    .line 1
    sget-boolean v0, Lio/opentelemetry/exporter/sender/okhttp/internal/OkHttpUtil;->propagateContextForTestingInDispatcher:Z

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    new-instance v0, Lio/opentelemetry/sdk/internal/DaemonThreadFactory;

    .line 6
    .line 7
    new-instance v1, Lio/opentelemetry/exporter/sender/okhttp/internal/d;

    .line 8
    .line 9
    invoke-direct {v1}, Ljava/lang/Object;-><init>()V

    .line 10
    .line 11
    .line 12
    invoke-direct {v0, p0, v1}, Lio/opentelemetry/sdk/internal/DaemonThreadFactory;-><init>(Ljava/lang/String;Ljava/util/concurrent/ThreadFactory;)V

    .line 13
    .line 14
    .line 15
    return-object v0

    .line 16
    :cond_0
    new-instance v0, Lio/opentelemetry/sdk/internal/DaemonThreadFactory;

    .line 17
    .line 18
    invoke-direct {v0, p0}, Lio/opentelemetry/sdk/internal/DaemonThreadFactory;-><init>(Ljava/lang/String;)V

    .line 19
    .line 20
    .line 21
    return-object v0
.end method

.method private static synthetic lambda$createThreadFactory$0(Ljava/lang/Runnable;)Ljava/lang/Thread;
    .locals 2

    .line 1
    invoke-static {}, Ljava/util/concurrent/Executors;->defaultThreadFactory()Ljava/util/concurrent/ThreadFactory;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    invoke-static {}, Lio/opentelemetry/context/Context;->current()Lio/opentelemetry/context/Context;

    .line 6
    .line 7
    .line 8
    move-result-object v1

    .line 9
    invoke-interface {v1, p0}, Lio/opentelemetry/context/Context;->wrap(Ljava/lang/Runnable;)Ljava/lang/Runnable;

    .line 10
    .line 11
    .line 12
    move-result-object p0

    .line 13
    invoke-interface {v0, p0}, Ljava/util/concurrent/ThreadFactory;->newThread(Ljava/lang/Runnable;)Ljava/lang/Thread;

    .line 14
    .line 15
    .line 16
    move-result-object p0

    .line 17
    return-object p0
.end method

.method public static newDispatcher()Ld01/t;
    .locals 9

    .line 1
    new-instance v0, Ld01/t;

    .line 2
    .line 3
    new-instance v1, Ljava/util/concurrent/ThreadPoolExecutor;

    .line 4
    .line 5
    sget-object v6, Ljava/util/concurrent/TimeUnit;->SECONDS:Ljava/util/concurrent/TimeUnit;

    .line 6
    .line 7
    new-instance v7, Ljava/util/concurrent/SynchronousQueue;

    .line 8
    .line 9
    invoke-direct {v7}, Ljava/util/concurrent/SynchronousQueue;-><init>()V

    .line 10
    .line 11
    .line 12
    const-string v2, "okhttp-dispatch"

    .line 13
    .line 14
    invoke-static {v2}, Lio/opentelemetry/exporter/sender/okhttp/internal/OkHttpUtil;->createThreadFactory(Ljava/lang/String;)Lio/opentelemetry/sdk/internal/DaemonThreadFactory;

    .line 15
    .line 16
    .line 17
    move-result-object v8

    .line 18
    const/4 v2, 0x0

    .line 19
    const v3, 0x7fffffff

    .line 20
    .line 21
    .line 22
    const-wide/16 v4, 0x3c

    .line 23
    .line 24
    invoke-direct/range {v1 .. v8}, Ljava/util/concurrent/ThreadPoolExecutor;-><init>(IIJLjava/util/concurrent/TimeUnit;Ljava/util/concurrent/BlockingQueue;Ljava/util/concurrent/ThreadFactory;)V

    .line 25
    .line 26
    .line 27
    invoke-direct {v0, v1}, Ld01/t;-><init>(Ljava/util/concurrent/ExecutorService;)V

    .line 28
    .line 29
    .line 30
    return-object v0
.end method

.method public static setPropagateContextForTestingInDispatcher(Z)V
    .locals 0

    .line 1
    sput-boolean p0, Lio/opentelemetry/exporter/sender/okhttp/internal/OkHttpUtil;->propagateContextForTestingInDispatcher:Z

    .line 2
    .line 3
    return-void
.end method
