.class public final Lio/opentelemetry/instrumentation/api/internal/cache/weaklockfree/WeakConcurrentMapCleaner;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field private static thread:Ljava/lang/Thread;
    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation
.end field


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

.method public static declared-synchronized start()V
    .locals 4

    .line 1
    const-class v0, Lio/opentelemetry/instrumentation/api/internal/cache/weaklockfree/WeakConcurrentMapCleaner;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    :try_start_0
    sget-object v1, Lio/opentelemetry/instrumentation/api/internal/cache/weaklockfree/WeakConcurrentMapCleaner;->thread:Ljava/lang/Thread;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 5
    .line 6
    if-eqz v1, :cond_0

    .line 7
    .line 8
    monitor-exit v0

    .line 9
    return-void

    .line 10
    :cond_0
    :try_start_1
    new-instance v1, Ljava/lang/Thread;

    .line 11
    .line 12
    new-instance v2, Lio/opentelemetry/instrumentation/api/internal/cache/weaklockfree/b;

    .line 13
    .line 14
    invoke-direct {v2}, Ljava/lang/Object;-><init>()V

    .line 15
    .line 16
    .line 17
    const-string v3, "weak-ref-cleaner"

    .line 18
    .line 19
    invoke-direct {v1, v2, v3}, Ljava/lang/Thread;-><init>(Ljava/lang/Runnable;Ljava/lang/String;)V

    .line 20
    .line 21
    .line 22
    sput-object v1, Lio/opentelemetry/instrumentation/api/internal/cache/weaklockfree/WeakConcurrentMapCleaner;->thread:Ljava/lang/Thread;

    .line 23
    .line 24
    const/4 v2, 0x1

    .line 25
    invoke-virtual {v1, v2}, Ljava/lang/Thread;->setDaemon(Z)V

    .line 26
    .line 27
    .line 28
    sget-object v1, Lio/opentelemetry/instrumentation/api/internal/cache/weaklockfree/WeakConcurrentMapCleaner;->thread:Ljava/lang/Thread;

    .line 29
    .line 30
    const/4 v2, 0x0

    .line 31
    invoke-virtual {v1, v2}, Ljava/lang/Thread;->setContextClassLoader(Ljava/lang/ClassLoader;)V

    .line 32
    .line 33
    .line 34
    sget-object v1, Lio/opentelemetry/instrumentation/api/internal/cache/weaklockfree/WeakConcurrentMapCleaner;->thread:Ljava/lang/Thread;

    .line 35
    .line 36
    invoke-virtual {v1}, Ljava/lang/Thread;->start()V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 37
    .line 38
    .line 39
    monitor-exit v0

    .line 40
    return-void

    .line 41
    :catchall_0
    move-exception v1

    .line 42
    :try_start_2
    monitor-exit v0
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 43
    throw v1
.end method

.method public static declared-synchronized stop()V
    .locals 2

    .line 1
    const-class v0, Lio/opentelemetry/instrumentation/api/internal/cache/weaklockfree/WeakConcurrentMapCleaner;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    :try_start_0
    sget-object v1, Lio/opentelemetry/instrumentation/api/internal/cache/weaklockfree/WeakConcurrentMapCleaner;->thread:Ljava/lang/Thread;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 5
    .line 6
    if-nez v1, :cond_0

    .line 7
    .line 8
    monitor-exit v0

    .line 9
    return-void

    .line 10
    :cond_0
    :try_start_1
    invoke-virtual {v1}, Ljava/lang/Thread;->interrupt()V

    .line 11
    .line 12
    .line 13
    const/4 v1, 0x0

    .line 14
    sput-object v1, Lio/opentelemetry/instrumentation/api/internal/cache/weaklockfree/WeakConcurrentMapCleaner;->thread:Ljava/lang/Thread;
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 15
    .line 16
    monitor-exit v0

    .line 17
    return-void

    .line 18
    :catchall_0
    move-exception v1

    .line 19
    :try_start_2
    monitor-exit v0
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 20
    throw v1
.end method
