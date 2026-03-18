.class Lio/opentelemetry/context/StrictContextStorage$PendingScopes;
.super Lio/opentelemetry/context/internal/shaded/WeakConcurrentMap;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lio/opentelemetry/context/StrictContextStorage;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x9
    name = "PendingScopes"
.end annotation

.annotation system Ldalvik/annotation/Signature;
    value = {
        "Lio/opentelemetry/context/internal/shaded/WeakConcurrentMap<",
        "Lio/opentelemetry/context/Scope;",
        "Lio/opentelemetry/context/StrictContextStorage$CallerStackTrace;",
        ">;"
    }
.end annotation


# instance fields
.field private final map:Ljava/util/concurrent/ConcurrentHashMap;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/concurrent/ConcurrentHashMap<",
            "Lio/opentelemetry/context/internal/shaded/AbstractWeakConcurrentMap$WeakKey<",
            "Lio/opentelemetry/context/Scope;",
            ">;",
            "Lio/opentelemetry/context/StrictContextStorage$CallerStackTrace;",
            ">;"
        }
    .end annotation
.end field


# direct methods
.method public constructor <init>(Ljava/util/concurrent/ConcurrentHashMap;)V
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/concurrent/ConcurrentHashMap<",
            "Lio/opentelemetry/context/internal/shaded/AbstractWeakConcurrentMap$WeakKey<",
            "Lio/opentelemetry/context/Scope;",
            ">;",
            "Lio/opentelemetry/context/StrictContextStorage$CallerStackTrace;",
            ">;)V"
        }
    .end annotation

    .line 1
    const/4 v0, 0x0

    .line 2
    invoke-direct {p0, v0, v0, p1}, Lio/opentelemetry/context/internal/shaded/WeakConcurrentMap;-><init>(ZZLjava/util/concurrent/ConcurrentMap;)V

    .line 3
    .line 4
    .line 5
    iput-object p1, p0, Lio/opentelemetry/context/StrictContextStorage$PendingScopes;->map:Ljava/util/concurrent/ConcurrentHashMap;

    .line 6
    .line 7
    new-instance p1, Ljava/lang/Thread;

    .line 8
    .line 9
    invoke-direct {p1, p0}, Ljava/lang/Thread;-><init>(Ljava/lang/Runnable;)V

    .line 10
    .line 11
    .line 12
    const-string p0, "weak-ref-cleaner-strictcontextstorage"

    .line 13
    .line 14
    invoke-virtual {p1, p0}, Ljava/lang/Thread;->setName(Ljava/lang/String;)V

    .line 15
    .line 16
    .line 17
    const/4 p0, 0x1

    .line 18
    invoke-virtual {p1, p0}, Ljava/lang/Thread;->setPriority(I)V

    .line 19
    .line 20
    .line 21
    invoke-virtual {p1, p0}, Ljava/lang/Thread;->setDaemon(Z)V

    .line 22
    .line 23
    .line 24
    const/4 p0, 0x0

    .line 25
    invoke-virtual {p1, p0}, Ljava/lang/Thread;->setContextClassLoader(Ljava/lang/ClassLoader;)V

    .line 26
    .line 27
    .line 28
    invoke-virtual {p1}, Ljava/lang/Thread;->start()V

    .line 29
    .line 30
    .line 31
    return-void
.end method

.method public static synthetic c(Lio/opentelemetry/context/StrictContextStorage$CallerStackTrace;)Z
    .locals 0

    .line 1
    invoke-static {p0}, Lio/opentelemetry/context/StrictContextStorage$PendingScopes;->lambda$drainPendingCallers$0(Lio/opentelemetry/context/StrictContextStorage$CallerStackTrace;)Z

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    return p0
.end method

.method public static create()Lio/opentelemetry/context/StrictContextStorage$PendingScopes;
    .locals 2

    .line 1
    new-instance v0, Lio/opentelemetry/context/StrictContextStorage$PendingScopes;

    .line 2
    .line 3
    new-instance v1, Ljava/util/concurrent/ConcurrentHashMap;

    .line 4
    .line 5
    invoke-direct {v1}, Ljava/util/concurrent/ConcurrentHashMap;-><init>()V

    .line 6
    .line 7
    .line 8
    invoke-direct {v0, v1}, Lio/opentelemetry/context/StrictContextStorage$PendingScopes;-><init>(Ljava/util/concurrent/ConcurrentHashMap;)V

    .line 9
    .line 10
    .line 11
    return-object v0
.end method

.method private static synthetic lambda$drainPendingCallers$0(Lio/opentelemetry/context/StrictContextStorage$CallerStackTrace;)Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Lio/opentelemetry/context/StrictContextStorage$CallerStackTrace;->closed:Z

    .line 2
    .line 3
    xor-int/lit8 p0, p0, 0x1

    .line 4
    .line 5
    return p0
.end method


# virtual methods
.method public drainPendingCallers()Ljava/util/List;
    .locals 2
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/List<",
            "Lio/opentelemetry/context/StrictContextStorage$CallerStackTrace;",
            ">;"
        }
    .end annotation

    .line 1
    iget-object v0, p0, Lio/opentelemetry/context/StrictContextStorage$PendingScopes;->map:Ljava/util/concurrent/ConcurrentHashMap;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/util/concurrent/ConcurrentHashMap;->values()Ljava/util/Collection;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    invoke-interface {v0}, Ljava/util/Collection;->stream()Ljava/util/stream/Stream;

    .line 8
    .line 9
    .line 10
    move-result-object v0

    .line 11
    new-instance v1, Lio/opentelemetry/context/e;

    .line 12
    .line 13
    invoke-direct {v1}, Ljava/lang/Object;-><init>()V

    .line 14
    .line 15
    .line 16
    invoke-interface {v0, v1}, Ljava/util/stream/Stream;->filter(Ljava/util/function/Predicate;)Ljava/util/stream/Stream;

    .line 17
    .line 18
    .line 19
    move-result-object v0

    .line 20
    invoke-static {}, Ljava/util/stream/Collectors;->toList()Ljava/util/stream/Collector;

    .line 21
    .line 22
    .line 23
    move-result-object v1

    .line 24
    invoke-interface {v0, v1}, Ljava/util/stream/Stream;->collect(Ljava/util/stream/Collector;)Ljava/lang/Object;

    .line 25
    .line 26
    .line 27
    move-result-object v0

    .line 28
    check-cast v0, Ljava/util/List;

    .line 29
    .line 30
    iget-object p0, p0, Lio/opentelemetry/context/StrictContextStorage$PendingScopes;->map:Ljava/util/concurrent/ConcurrentHashMap;

    .line 31
    .line 32
    invoke-virtual {p0}, Ljava/util/concurrent/ConcurrentHashMap;->clear()V

    .line 33
    .line 34
    .line 35
    return-object v0
.end method

.method public run()V
    .locals 4

    .line 1
    :cond_0
    :goto_0
    :try_start_0
    invoke-static {}, Ljava/lang/Thread;->interrupted()Z

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    if-nez v0, :cond_2

    .line 6
    .line 7
    invoke-virtual {p0}, Ljava/lang/ref/ReferenceQueue;->remove()Ljava/lang/ref/Reference;

    .line 8
    .line 9
    .line 10
    move-result-object v0

    .line 11
    if-eqz v0, :cond_1

    .line 12
    .line 13
    iget-object v1, p0, Lio/opentelemetry/context/StrictContextStorage$PendingScopes;->map:Ljava/util/concurrent/ConcurrentHashMap;

    .line 14
    .line 15
    invoke-virtual {v1, v0}, Ljava/util/concurrent/ConcurrentHashMap;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    .line 16
    .line 17
    .line 18
    move-result-object v0

    .line 19
    check-cast v0, Lio/opentelemetry/context/StrictContextStorage$CallerStackTrace;

    .line 20
    .line 21
    goto :goto_1

    .line 22
    :cond_1
    const/4 v0, 0x0

    .line 23
    :goto_1
    if-eqz v0, :cond_0

    .line 24
    .line 25
    iget-boolean v1, v0, Lio/opentelemetry/context/StrictContextStorage$CallerStackTrace;->closed:Z

    .line 26
    .line 27
    if-nez v1, :cond_0

    .line 28
    .line 29
    invoke-static {}, Lio/opentelemetry/context/StrictContextStorage;->access$100()Ljava/util/logging/Logger;

    .line 30
    .line 31
    .line 32
    move-result-object v1

    .line 33
    sget-object v2, Ljava/util/logging/Level;->SEVERE:Ljava/util/logging/Level;

    .line 34
    .line 35
    const-string v3, "Scope garbage collected before being closed."

    .line 36
    .line 37
    invoke-static {v0}, Lio/opentelemetry/context/StrictContextStorage;->callerError(Lio/opentelemetry/context/StrictContextStorage$CallerStackTrace;)Ljava/lang/AssertionError;

    .line 38
    .line 39
    .line 40
    move-result-object v0

    .line 41
    invoke-virtual {v1, v2, v3, v0}, Ljava/util/logging/Logger;->log(Ljava/util/logging/Level;Ljava/lang/String;Ljava/lang/Throwable;)V
    :try_end_0
    .catch Ljava/lang/InterruptedException; {:try_start_0 .. :try_end_0} :catch_0

    .line 42
    .line 43
    .line 44
    goto :goto_0

    .line 45
    :catch_0
    :cond_2
    return-void
.end method
