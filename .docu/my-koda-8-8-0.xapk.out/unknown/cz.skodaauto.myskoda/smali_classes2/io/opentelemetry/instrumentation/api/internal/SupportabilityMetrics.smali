.class public final Lio/opentelemetry/instrumentation/api/internal/SupportabilityMetrics;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lio/opentelemetry/instrumentation/api/internal/SupportabilityMetrics$KindCounters;,
        Lio/opentelemetry/instrumentation/api/internal/SupportabilityMetrics$CounterNames;
    }
.end annotation


# static fields
.field private static final INSTANCE:Lio/opentelemetry/instrumentation/api/internal/SupportabilityMetrics;

.field private static final logger:Ljava/util/logging/Logger;


# instance fields
.field private final agentDebugEnabled:Z

.field private final counters:Ljava/util/concurrent/ConcurrentMap;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/concurrent/ConcurrentMap<",
            "Ljava/lang/String;",
            "Ljava/util/concurrent/atomic/AtomicLong;",
            ">;"
        }
    .end annotation
.end field

.field private final reporter:Ljava/util/function/Consumer;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/function/Consumer<",
            "Ljava/lang/String;",
            ">;"
        }
    .end annotation
.end field

.field private final suppressionCounters:Ljava/util/concurrent/ConcurrentMap;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/concurrent/ConcurrentMap<",
            "Ljava/lang/String;",
            "Lio/opentelemetry/instrumentation/api/internal/SupportabilityMetrics$KindCounters;",
            ">;"
        }
    .end annotation
.end field


# direct methods
.method static constructor <clinit>()V
    .locals 4

    .line 1
    const-class v0, Lio/opentelemetry/instrumentation/api/internal/SupportabilityMetrics;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/Class;->getName()Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    invoke-static {v0}, Ljava/util/logging/Logger;->getLogger(Ljava/lang/String;)Ljava/util/logging/Logger;

    .line 8
    .line 9
    .line 10
    move-result-object v0

    .line 11
    sput-object v0, Lio/opentelemetry/instrumentation/api/internal/SupportabilityMetrics;->logger:Ljava/util/logging/Logger;

    .line 12
    .line 13
    new-instance v1, Lio/opentelemetry/instrumentation/api/internal/SupportabilityMetrics;

    .line 14
    .line 15
    const-string v2, "otel.javaagent.debug"

    .line 16
    .line 17
    const/4 v3, 0x0

    .line 18
    invoke-static {v2, v3}, Lio/opentelemetry/instrumentation/api/internal/ConfigPropertiesUtil;->getBoolean(Ljava/lang/String;Z)Z

    .line 19
    .line 20
    .line 21
    move-result v2

    .line 22
    invoke-static {v0}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;)Ljava/lang/Object;

    .line 23
    .line 24
    .line 25
    new-instance v3, Lio/opentelemetry/instrumentation/api/internal/g;

    .line 26
    .line 27
    invoke-direct {v3, v0}, Lio/opentelemetry/instrumentation/api/internal/g;-><init>(Ljava/util/logging/Logger;)V

    .line 28
    .line 29
    .line 30
    invoke-direct {v1, v2, v3}, Lio/opentelemetry/instrumentation/api/internal/SupportabilityMetrics;-><init>(ZLjava/util/function/Consumer;)V

    .line 31
    .line 32
    .line 33
    invoke-direct {v1}, Lio/opentelemetry/instrumentation/api/internal/SupportabilityMetrics;->start()Lio/opentelemetry/instrumentation/api/internal/SupportabilityMetrics;

    .line 34
    .line 35
    .line 36
    move-result-object v0

    .line 37
    sput-object v0, Lio/opentelemetry/instrumentation/api/internal/SupportabilityMetrics;->INSTANCE:Lio/opentelemetry/instrumentation/api/internal/SupportabilityMetrics;

    .line 38
    .line 39
    return-void
.end method

.method public constructor <init>(ZLjava/util/function/Consumer;)V
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(Z",
            "Ljava/util/function/Consumer<",
            "Ljava/lang/String;",
            ">;)V"
        }
    .end annotation

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    new-instance v0, Ljava/util/concurrent/ConcurrentHashMap;

    .line 5
    .line 6
    invoke-direct {v0}, Ljava/util/concurrent/ConcurrentHashMap;-><init>()V

    .line 7
    .line 8
    .line 9
    iput-object v0, p0, Lio/opentelemetry/instrumentation/api/internal/SupportabilityMetrics;->suppressionCounters:Ljava/util/concurrent/ConcurrentMap;

    .line 10
    .line 11
    new-instance v0, Ljava/util/concurrent/ConcurrentHashMap;

    .line 12
    .line 13
    invoke-direct {v0}, Ljava/util/concurrent/ConcurrentHashMap;-><init>()V

    .line 14
    .line 15
    .line 16
    iput-object v0, p0, Lio/opentelemetry/instrumentation/api/internal/SupportabilityMetrics;->counters:Ljava/util/concurrent/ConcurrentMap;

    .line 17
    .line 18
    iput-boolean p1, p0, Lio/opentelemetry/instrumentation/api/internal/SupportabilityMetrics;->agentDebugEnabled:Z

    .line 19
    .line 20
    iput-object p2, p0, Lio/opentelemetry/instrumentation/api/internal/SupportabilityMetrics;->reporter:Ljava/util/function/Consumer;

    .line 21
    .line 22
    return-void
.end method

.method public static synthetic a(Ljava/lang/String;)Ljava/util/concurrent/atomic/AtomicLong;
    .locals 0

    .line 1
    invoke-static {p0}, Lio/opentelemetry/instrumentation/api/internal/SupportabilityMetrics;->lambda$incrementCounter$1(Ljava/lang/String;)Ljava/util/concurrent/atomic/AtomicLong;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic b(Ljava/lang/Runnable;)Ljava/lang/Thread;
    .locals 0

    .line 1
    invoke-static {p0}, Lio/opentelemetry/instrumentation/api/internal/SupportabilityMetrics;->lambda$start$4(Ljava/lang/Runnable;)Ljava/lang/Thread;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic c(Lio/opentelemetry/instrumentation/api/internal/SupportabilityMetrics;Ljava/lang/String;Lio/opentelemetry/instrumentation/api/internal/SupportabilityMetrics$KindCounters;)V
    .locals 0

    .line 1
    invoke-direct {p0, p1, p2}, Lio/opentelemetry/instrumentation/api/internal/SupportabilityMetrics;->lambda$report$2(Ljava/lang/String;Lio/opentelemetry/instrumentation/api/internal/SupportabilityMetrics$KindCounters;)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static synthetic d(Ljava/lang/Runnable;)Ljava/lang/Thread;
    .locals 0

    .line 1
    invoke-static {p0}, Lio/opentelemetry/instrumentation/api/internal/SupportabilityMetrics;->lambda$start$5(Ljava/lang/Runnable;)Ljava/lang/Thread;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method private static doPrivileged(Ljava/security/PrivilegedAction;)Ljava/lang/Object;
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "<T:",
            "Ljava/lang/Object;",
            ">(",
            "Ljava/security/PrivilegedAction<",
            "TT;>;)TT;"
        }
    .end annotation

    .line 1
    invoke-static {}, Ljava/lang/System;->getSecurityManager()Ljava/lang/SecurityManager;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    if-nez v0, :cond_0

    .line 6
    .line 7
    invoke-interface {p0}, Ljava/security/PrivilegedAction;->run()Ljava/lang/Object;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    return-object p0

    .line 12
    :cond_0
    invoke-static {p0}, Ljava/security/AccessController;->doPrivileged(Ljava/security/PrivilegedAction;)Ljava/lang/Object;

    .line 13
    .line 14
    .line 15
    move-result-object p0

    .line 16
    return-object p0
.end method

.method public static synthetic e(Lio/opentelemetry/instrumentation/api/internal/SupportabilityMetrics;Ljava/lang/String;Ljava/util/concurrent/atomic/AtomicLong;)V
    .locals 0

    .line 1
    invoke-direct {p0, p1, p2}, Lio/opentelemetry/instrumentation/api/internal/SupportabilityMetrics;->lambda$report$3(Ljava/lang/String;Ljava/util/concurrent/atomic/AtomicLong;)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static synthetic f(Ljava/lang/String;)Lio/opentelemetry/instrumentation/api/internal/SupportabilityMetrics$KindCounters;
    .locals 0

    .line 1
    invoke-static {p0}, Lio/opentelemetry/instrumentation/api/internal/SupportabilityMetrics;->lambda$recordSuppressedSpan$0(Ljava/lang/String;)Lio/opentelemetry/instrumentation/api/internal/SupportabilityMetrics$KindCounters;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static instance()Lio/opentelemetry/instrumentation/api/internal/SupportabilityMetrics;
    .locals 1

    .line 1
    sget-object v0, Lio/opentelemetry/instrumentation/api/internal/SupportabilityMetrics;->INSTANCE:Lio/opentelemetry/instrumentation/api/internal/SupportabilityMetrics;

    .line 2
    .line 3
    return-object v0
.end method

.method private static synthetic lambda$incrementCounter$1(Ljava/lang/String;)Ljava/util/concurrent/atomic/AtomicLong;
    .locals 0

    .line 1
    new-instance p0, Ljava/util/concurrent/atomic/AtomicLong;

    .line 2
    .line 3
    invoke-direct {p0}, Ljava/util/concurrent/atomic/AtomicLong;-><init>()V

    .line 4
    .line 5
    .line 6
    return-object p0
.end method

.method private static synthetic lambda$recordSuppressedSpan$0(Ljava/lang/String;)Lio/opentelemetry/instrumentation/api/internal/SupportabilityMetrics$KindCounters;
    .locals 1

    .line 1
    new-instance p0, Lio/opentelemetry/instrumentation/api/internal/SupportabilityMetrics$KindCounters;

    .line 2
    .line 3
    const/4 v0, 0x0

    .line 4
    invoke-direct {p0, v0}, Lio/opentelemetry/instrumentation/api/internal/SupportabilityMetrics$KindCounters;-><init>(Lio/opentelemetry/instrumentation/api/internal/SupportabilityMetrics$1;)V

    .line 5
    .line 6
    .line 7
    return-object p0
.end method

.method private synthetic lambda$report$2(Ljava/lang/String;Lio/opentelemetry/instrumentation/api/internal/SupportabilityMetrics$KindCounters;)V
    .locals 9

    .line 1
    invoke-static {}, Lio/opentelemetry/api/trace/SpanKind;->values()[Lio/opentelemetry/api/trace/SpanKind;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    array-length v1, v0

    .line 6
    const/4 v2, 0x0

    .line 7
    :goto_0
    if-ge v2, v1, :cond_1

    .line 8
    .line 9
    aget-object v3, v0, v2

    .line 10
    .line 11
    invoke-virtual {p2, v3}, Lio/opentelemetry/instrumentation/api/internal/SupportabilityMetrics$KindCounters;->getAndReset(Lio/opentelemetry/api/trace/SpanKind;)J

    .line 12
    .line 13
    .line 14
    move-result-wide v4

    .line 15
    const-wide/16 v6, 0x0

    .line 16
    .line 17
    cmp-long v6, v4, v6

    .line 18
    .line 19
    if-lez v6, :cond_0

    .line 20
    .line 21
    iget-object v6, p0, Lio/opentelemetry/instrumentation/api/internal/SupportabilityMetrics;->reporter:Ljava/util/function/Consumer;

    .line 22
    .line 23
    new-instance v7, Ljava/lang/StringBuilder;

    .line 24
    .line 25
    const-string v8, "Suppressed Spans by \'"

    .line 26
    .line 27
    invoke-direct {v7, v8}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 28
    .line 29
    .line 30
    invoke-virtual {v7, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 31
    .line 32
    .line 33
    const-string v8, "\' ("

    .line 34
    .line 35
    invoke-virtual {v7, v8}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 36
    .line 37
    .line 38
    invoke-virtual {v7, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 39
    .line 40
    .line 41
    const-string v3, ") : "

    .line 42
    .line 43
    invoke-virtual {v7, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 44
    .line 45
    .line 46
    invoke-virtual {v7, v4, v5}, Ljava/lang/StringBuilder;->append(J)Ljava/lang/StringBuilder;

    .line 47
    .line 48
    .line 49
    invoke-virtual {v7}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 50
    .line 51
    .line 52
    move-result-object v3

    .line 53
    invoke-interface {v6, v3}, Ljava/util/function/Consumer;->accept(Ljava/lang/Object;)V

    .line 54
    .line 55
    .line 56
    :cond_0
    add-int/lit8 v2, v2, 0x1

    .line 57
    .line 58
    goto :goto_0

    .line 59
    :cond_1
    return-void
.end method

.method private synthetic lambda$report$3(Ljava/lang/String;Ljava/util/concurrent/atomic/AtomicLong;)V
    .locals 4

    .line 1
    const-wide/16 v0, 0x0

    .line 2
    .line 3
    invoke-virtual {p2, v0, v1}, Ljava/util/concurrent/atomic/AtomicLong;->getAndSet(J)J

    .line 4
    .line 5
    .line 6
    move-result-wide v2

    .line 7
    cmp-long p2, v2, v0

    .line 8
    .line 9
    if-lez p2, :cond_0

    .line 10
    .line 11
    iget-object p0, p0, Lio/opentelemetry/instrumentation/api/internal/SupportabilityMetrics;->reporter:Ljava/util/function/Consumer;

    .line 12
    .line 13
    new-instance p2, Ljava/lang/StringBuilder;

    .line 14
    .line 15
    const-string v0, "Counter \'"

    .line 16
    .line 17
    invoke-direct {p2, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 18
    .line 19
    .line 20
    invoke-virtual {p2, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 21
    .line 22
    .line 23
    const-string p1, "\' : "

    .line 24
    .line 25
    invoke-virtual {p2, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 26
    .line 27
    .line 28
    invoke-virtual {p2, v2, v3}, Ljava/lang/StringBuilder;->append(J)Ljava/lang/StringBuilder;

    .line 29
    .line 30
    .line 31
    invoke-virtual {p2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 32
    .line 33
    .line 34
    move-result-object p1

    .line 35
    invoke-interface {p0, p1}, Ljava/util/function/Consumer;->accept(Ljava/lang/Object;)V

    .line 36
    .line 37
    .line 38
    :cond_0
    return-void
.end method

.method private static synthetic lambda$start$4(Ljava/lang/Runnable;)Ljava/lang/Thread;
    .locals 2

    .line 1
    new-instance v0, Ljava/lang/Thread;

    .line 2
    .line 3
    const-string v1, "supportability_metrics_reporter"

    .line 4
    .line 5
    invoke-direct {v0, p0, v1}, Ljava/lang/Thread;-><init>(Ljava/lang/Runnable;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    const/4 p0, 0x1

    .line 9
    invoke-virtual {v0, p0}, Ljava/lang/Thread;->setDaemon(Z)V

    .line 10
    .line 11
    .line 12
    const/4 p0, 0x0

    .line 13
    invoke-virtual {v0, p0}, Ljava/lang/Thread;->setContextClassLoader(Ljava/lang/ClassLoader;)V

    .line 14
    .line 15
    .line 16
    return-object v0
.end method

.method private static synthetic lambda$start$5(Ljava/lang/Runnable;)Ljava/lang/Thread;
    .locals 1

    .line 1
    new-instance v0, Lio/opentelemetry/instrumentation/api/internal/h;

    .line 2
    .line 3
    invoke-direct {v0, p0}, Lio/opentelemetry/instrumentation/api/internal/h;-><init>(Ljava/lang/Runnable;)V

    .line 4
    .line 5
    .line 6
    invoke-static {v0}, Lio/opentelemetry/instrumentation/api/internal/SupportabilityMetrics;->doPrivileged(Ljava/security/PrivilegedAction;)Ljava/lang/Object;

    .line 7
    .line 8
    .line 9
    move-result-object p0

    .line 10
    check-cast p0, Ljava/lang/Thread;

    .line 11
    .line 12
    return-object p0
.end method

.method private start()Lio/opentelemetry/instrumentation/api/internal/SupportabilityMetrics;
    .locals 9

    .line 1
    iget-boolean v0, p0, Lio/opentelemetry/instrumentation/api/internal/SupportabilityMetrics;->agentDebugEnabled:Z

    .line 2
    .line 3
    if-eqz v0, :cond_1

    .line 4
    .line 5
    new-instance v0, Lio/opentelemetry/instrumentation/api/internal/d;

    .line 6
    .line 7
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 8
    .line 9
    .line 10
    const/4 v1, 0x1

    .line 11
    invoke-static {v1, v0}, Ljava/util/concurrent/Executors;->newScheduledThreadPool(ILjava/util/concurrent/ThreadFactory;)Ljava/util/concurrent/ScheduledExecutorService;

    .line 12
    .line 13
    .line 14
    move-result-object v2

    .line 15
    new-instance v3, Lio/opentelemetry/instrumentation/api/internal/e;

    .line 16
    .line 17
    invoke-direct {v3, p0}, Lio/opentelemetry/instrumentation/api/internal/e;-><init>(Lio/opentelemetry/instrumentation/api/internal/SupportabilityMetrics;)V

    .line 18
    .line 19
    .line 20
    const-wide/16 v6, 0x5

    .line 21
    .line 22
    sget-object v8, Ljava/util/concurrent/TimeUnit;->SECONDS:Ljava/util/concurrent/TimeUnit;

    .line 23
    .line 24
    const-wide/16 v4, 0x5

    .line 25
    .line 26
    invoke-interface/range {v2 .. v8}, Ljava/util/concurrent/ScheduledExecutorService;->scheduleAtFixedRate(Ljava/lang/Runnable;JJLjava/util/concurrent/TimeUnit;)Ljava/util/concurrent/ScheduledFuture;

    .line 27
    .line 28
    .line 29
    invoke-interface {v2}, Ljava/util/concurrent/ExecutorService;->isTerminated()Z

    .line 30
    .line 31
    .line 32
    move-result v0

    .line 33
    if-nez v0, :cond_0

    .line 34
    .line 35
    goto :goto_0

    .line 36
    :cond_0
    new-instance p0, Ljava/lang/AssertionError;

    .line 37
    .line 38
    invoke-direct {p0}, Ljava/lang/AssertionError;-><init>()V

    .line 39
    .line 40
    .line 41
    throw p0

    .line 42
    :cond_1
    :goto_0
    return-object p0
.end method


# virtual methods
.method public incrementCounter(Ljava/lang/String;)V
    .locals 2

    .line 1
    iget-boolean v0, p0, Lio/opentelemetry/instrumentation/api/internal/SupportabilityMetrics;->agentDebugEnabled:Z

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    return-void

    .line 6
    :cond_0
    iget-object p0, p0, Lio/opentelemetry/instrumentation/api/internal/SupportabilityMetrics;->counters:Ljava/util/concurrent/ConcurrentMap;

    .line 7
    .line 8
    new-instance v0, Lio/opentelemetry/instrumentation/api/internal/c;

    .line 9
    .line 10
    const/4 v1, 0x6

    .line 11
    invoke-direct {v0, v1}, Lio/opentelemetry/instrumentation/api/internal/c;-><init>(I)V

    .line 12
    .line 13
    .line 14
    invoke-interface {p0, p1, v0}, Ljava/util/concurrent/ConcurrentMap;->computeIfAbsent(Ljava/lang/Object;Ljava/util/function/Function;)Ljava/lang/Object;

    .line 15
    .line 16
    .line 17
    move-result-object p0

    .line 18
    check-cast p0, Ljava/util/concurrent/atomic/AtomicLong;

    .line 19
    .line 20
    invoke-virtual {p0}, Ljava/util/concurrent/atomic/AtomicLong;->incrementAndGet()J

    .line 21
    .line 22
    .line 23
    return-void
.end method

.method public recordSuppressedSpan(Lio/opentelemetry/api/trace/SpanKind;Ljava/lang/String;)V
    .locals 2

    .line 1
    iget-boolean v0, p0, Lio/opentelemetry/instrumentation/api/internal/SupportabilityMetrics;->agentDebugEnabled:Z

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    return-void

    .line 6
    :cond_0
    iget-object p0, p0, Lio/opentelemetry/instrumentation/api/internal/SupportabilityMetrics;->suppressionCounters:Ljava/util/concurrent/ConcurrentMap;

    .line 7
    .line 8
    new-instance v0, Lio/opentelemetry/instrumentation/api/internal/c;

    .line 9
    .line 10
    const/4 v1, 0x7

    .line 11
    invoke-direct {v0, v1}, Lio/opentelemetry/instrumentation/api/internal/c;-><init>(I)V

    .line 12
    .line 13
    .line 14
    invoke-interface {p0, p2, v0}, Ljava/util/concurrent/ConcurrentMap;->computeIfAbsent(Ljava/lang/Object;Ljava/util/function/Function;)Ljava/lang/Object;

    .line 15
    .line 16
    .line 17
    move-result-object p0

    .line 18
    check-cast p0, Lio/opentelemetry/instrumentation/api/internal/SupportabilityMetrics$KindCounters;

    .line 19
    .line 20
    invoke-virtual {p0, p1}, Lio/opentelemetry/instrumentation/api/internal/SupportabilityMetrics$KindCounters;->increment(Lio/opentelemetry/api/trace/SpanKind;)V

    .line 21
    .line 22
    .line 23
    return-void
.end method

.method public report()V
    .locals 3

    .line 1
    iget-object v0, p0, Lio/opentelemetry/instrumentation/api/internal/SupportabilityMetrics;->suppressionCounters:Ljava/util/concurrent/ConcurrentMap;

    .line 2
    .line 3
    new-instance v1, Lio/opentelemetry/instrumentation/api/internal/f;

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    invoke-direct {v1, p0, v2}, Lio/opentelemetry/instrumentation/api/internal/f;-><init>(Ljava/lang/Object;I)V

    .line 7
    .line 8
    .line 9
    invoke-interface {v0, v1}, Ljava/util/concurrent/ConcurrentMap;->forEach(Ljava/util/function/BiConsumer;)V

    .line 10
    .line 11
    .line 12
    iget-object v0, p0, Lio/opentelemetry/instrumentation/api/internal/SupportabilityMetrics;->counters:Ljava/util/concurrent/ConcurrentMap;

    .line 13
    .line 14
    new-instance v1, Lio/opentelemetry/instrumentation/api/internal/f;

    .line 15
    .line 16
    const/4 v2, 0x1

    .line 17
    invoke-direct {v1, p0, v2}, Lio/opentelemetry/instrumentation/api/internal/f;-><init>(Ljava/lang/Object;I)V

    .line 18
    .line 19
    .line 20
    invoke-interface {v0, v1}, Ljava/util/concurrent/ConcurrentMap;->forEach(Ljava/util/function/BiConsumer;)V

    .line 21
    .line 22
    .line 23
    return-void
.end method
