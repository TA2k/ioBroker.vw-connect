.class public final Lio/opentelemetry/instrumentation/api/internal/ContextPropagationDebug;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lio/opentelemetry/instrumentation/api/internal/ContextPropagationDebug$Propagation;
    }
.end annotation


# static fields
.field private static final FAIL_ON_CONTEXT_LEAK:Z

.field private static final THREAD_PROPAGATION_DEBUGGER:Z

.field private static final THREAD_PROPAGATION_LOCATIONS:Lio/opentelemetry/context/ContextKey;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lio/opentelemetry/context/ContextKey<",
            "Lio/opentelemetry/instrumentation/api/internal/ContextPropagationDebug;",
            ">;"
        }
    .end annotation
.end field

.field private static final logger:Ljava/util/logging/Logger;


# instance fields
.field private final locations:Ljava/util/List;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/List<",
            "Lio/opentelemetry/instrumentation/api/internal/ContextPropagationDebug$Propagation;",
            ">;"
        }
    .end annotation
.end field

.field private final sourceContext:Lio/opentelemetry/context/Context;

.field private wrappedContext:Lio/opentelemetry/context/Context;
    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation
.end field


# direct methods
.method static constructor <clinit>()V
    .locals 3

    .line 1
    const-class v0, Lio/opentelemetry/instrumentation/api/internal/ContextPropagationDebug;

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
    sput-object v0, Lio/opentelemetry/instrumentation/api/internal/ContextPropagationDebug;->logger:Ljava/util/logging/Logger;

    .line 12
    .line 13
    const-string v0, "thread-propagation-locations"

    .line 14
    .line 15
    invoke-static {v0}, Lio/opentelemetry/context/ContextKey;->named(Ljava/lang/String;)Lio/opentelemetry/context/ContextKey;

    .line 16
    .line 17
    .line 18
    move-result-object v0

    .line 19
    sput-object v0, Lio/opentelemetry/instrumentation/api/internal/ContextPropagationDebug;->THREAD_PROPAGATION_LOCATIONS:Lio/opentelemetry/context/ContextKey;

    .line 20
    .line 21
    const-string v0, "otel.javaagent.debug"

    .line 22
    .line 23
    const/4 v1, 0x0

    .line 24
    invoke-static {v0, v1}, Lio/opentelemetry/instrumentation/api/internal/ConfigPropertiesUtil;->getBoolean(Ljava/lang/String;Z)Z

    .line 25
    .line 26
    .line 27
    move-result v0

    .line 28
    const-string v2, "otel.javaagent.experimental.thread-propagation-debugger.enabled"

    .line 29
    .line 30
    invoke-static {v2, v0}, Lio/opentelemetry/instrumentation/api/internal/ConfigPropertiesUtil;->getBoolean(Ljava/lang/String;Z)Z

    .line 31
    .line 32
    .line 33
    move-result v0

    .line 34
    sput-boolean v0, Lio/opentelemetry/instrumentation/api/internal/ContextPropagationDebug;->THREAD_PROPAGATION_DEBUGGER:Z

    .line 35
    .line 36
    const-string v0, "otel.javaagent.testing.fail-on-context-leak"

    .line 37
    .line 38
    invoke-static {v0, v1}, Lio/opentelemetry/instrumentation/api/internal/ConfigPropertiesUtil;->getBoolean(Ljava/lang/String;Z)Z

    .line 39
    .line 40
    .line 41
    move-result v0

    .line 42
    sput-boolean v0, Lio/opentelemetry/instrumentation/api/internal/ContextPropagationDebug;->FAIL_ON_CONTEXT_LEAK:Z

    .line 43
    .line 44
    return-void
.end method

.method private constructor <init>(Lio/opentelemetry/context/Context;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lio/opentelemetry/instrumentation/api/internal/ContextPropagationDebug;->sourceContext:Lio/opentelemetry/context/Context;

    .line 5
    .line 6
    new-instance p1, Ljava/util/concurrent/CopyOnWriteArrayList;

    .line 7
    .line 8
    invoke-direct {p1}, Ljava/util/concurrent/CopyOnWriteArrayList;-><init>()V

    .line 9
    .line 10
    .line 11
    iput-object p1, p0, Lio/opentelemetry/instrumentation/api/internal/ContextPropagationDebug;->locations:Ljava/util/List;

    .line 12
    .line 13
    return-void
.end method

.method public static addDebugInfo(Lio/opentelemetry/context/Context;Ljava/lang/Object;)Lio/opentelemetry/context/Context;
    .locals 1

    .line 1
    invoke-static {}, Lio/opentelemetry/instrumentation/api/internal/ContextPropagationDebug;->isThreadPropagationDebuggerEnabled()Z

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    if-eqz v0, :cond_0

    .line 6
    .line 7
    new-instance v0, Ljava/lang/Exception;

    .line 8
    .line 9
    invoke-direct {v0}, Ljava/lang/Exception;-><init>()V

    .line 10
    .line 11
    .line 12
    invoke-virtual {v0}, Ljava/lang/Throwable;->getStackTrace()[Ljava/lang/StackTraceElement;

    .line 13
    .line 14
    .line 15
    move-result-object v0

    .line 16
    invoke-static {p0, v0, p1}, Lio/opentelemetry/instrumentation/api/internal/ContextPropagationDebug;->appendLocations(Lio/opentelemetry/context/Context;[Ljava/lang/StackTraceElement;Ljava/lang/Object;)Lio/opentelemetry/context/Context;

    .line 17
    .line 18
    .line 19
    move-result-object p0

    .line 20
    :cond_0
    return-object p0
.end method

.method public static appendLocations(Lio/opentelemetry/context/Context;[Ljava/lang/StackTraceElement;Ljava/lang/Object;)Lio/opentelemetry/context/Context;
    .locals 2

    .line 1
    invoke-static {p0}, Lio/opentelemetry/instrumentation/api/internal/ContextPropagationDebug;->getPropagations(Lio/opentelemetry/context/Context;)Lio/opentelemetry/instrumentation/api/internal/ContextPropagationDebug;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    if-nez v0, :cond_0

    .line 6
    .line 7
    new-instance v0, Lio/opentelemetry/instrumentation/api/internal/ContextPropagationDebug;

    .line 8
    .line 9
    invoke-direct {v0, p0}, Lio/opentelemetry/instrumentation/api/internal/ContextPropagationDebug;-><init>(Lio/opentelemetry/context/Context;)V

    .line 10
    .line 11
    .line 12
    sget-object v1, Lio/opentelemetry/instrumentation/api/internal/ContextPropagationDebug;->THREAD_PROPAGATION_LOCATIONS:Lio/opentelemetry/context/ContextKey;

    .line 13
    .line 14
    invoke-interface {p0, v1, v0}, Lio/opentelemetry/context/Context;->with(Lio/opentelemetry/context/ContextKey;Ljava/lang/Object;)Lio/opentelemetry/context/Context;

    .line 15
    .line 16
    .line 17
    move-result-object p0

    .line 18
    iput-object p0, v0, Lio/opentelemetry/instrumentation/api/internal/ContextPropagationDebug;->wrappedContext:Lio/opentelemetry/context/Context;

    .line 19
    .line 20
    :cond_0
    iget-object v0, v0, Lio/opentelemetry/instrumentation/api/internal/ContextPropagationDebug;->locations:Ljava/util/List;

    .line 21
    .line 22
    new-instance v1, Lio/opentelemetry/instrumentation/api/internal/ContextPropagationDebug$Propagation;

    .line 23
    .line 24
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 25
    .line 26
    .line 27
    move-result-object p2

    .line 28
    invoke-virtual {p2}, Ljava/lang/Class;->getName()Ljava/lang/String;

    .line 29
    .line 30
    .line 31
    move-result-object p2

    .line 32
    invoke-direct {v1, p2, p1}, Lio/opentelemetry/instrumentation/api/internal/ContextPropagationDebug$Propagation;-><init>(Ljava/lang/String;[Ljava/lang/StackTraceElement;)V

    .line 33
    .line 34
    .line 35
    const/4 p1, 0x0

    .line 36
    invoke-interface {v0, p1, v1}, Ljava/util/List;->add(ILjava/lang/Object;)V

    .line 37
    .line 38
    .line 39
    return-object p0
.end method

.method public static debugContextLeakIfEnabled()V
    .locals 5

    .line 1
    invoke-static {}, Lio/opentelemetry/instrumentation/api/internal/ContextPropagationDebug;->isThreadPropagationDebuggerEnabled()Z

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    if-nez v0, :cond_0

    .line 6
    .line 7
    goto :goto_0

    .line 8
    :cond_0
    invoke-static {}, Lio/opentelemetry/context/Context;->current()Lio/opentelemetry/context/Context;

    .line 9
    .line 10
    .line 11
    move-result-object v0

    .line 12
    invoke-static {}, Lio/opentelemetry/context/Context;->root()Lio/opentelemetry/context/Context;

    .line 13
    .line 14
    .line 15
    move-result-object v1

    .line 16
    if-eq v0, v1, :cond_3

    .line 17
    .line 18
    sget-object v1, Lio/opentelemetry/instrumentation/api/internal/ContextPropagationDebug;->logger:Ljava/util/logging/Logger;

    .line 19
    .line 20
    const-string v2, "Unexpected non-root current context found when extracting remote context!"

    .line 21
    .line 22
    invoke-virtual {v1, v2}, Ljava/util/logging/Logger;->warning(Ljava/lang/String;)V

    .line 23
    .line 24
    .line 25
    invoke-static {v0}, Lio/opentelemetry/api/trace/Span;->fromContextOrNull(Lio/opentelemetry/context/Context;)Lio/opentelemetry/api/trace/Span;

    .line 26
    .line 27
    .line 28
    move-result-object v2

    .line 29
    if-eqz v2, :cond_1

    .line 30
    .line 31
    sget-object v3, Ljava/util/logging/Level;->WARNING:Ljava/util/logging/Level;

    .line 32
    .line 33
    const-string v4, "It contains this span: {0}"

    .line 34
    .line 35
    invoke-virtual {v1, v3, v4, v2}, Ljava/util/logging/Logger;->log(Ljava/util/logging/Level;Ljava/lang/String;Ljava/lang/Object;)V

    .line 36
    .line 37
    .line 38
    :cond_1
    invoke-static {v0}, Lio/opentelemetry/instrumentation/api/internal/ContextPropagationDebug;->debugContextPropagation(Lio/opentelemetry/context/Context;)V

    .line 39
    .line 40
    .line 41
    sget-boolean v0, Lio/opentelemetry/instrumentation/api/internal/ContextPropagationDebug;->FAIL_ON_CONTEXT_LEAK:Z

    .line 42
    .line 43
    if-nez v0, :cond_2

    .line 44
    .line 45
    goto :goto_0

    .line 46
    :cond_2
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 47
    .line 48
    const-string v1, "Context leak detected"

    .line 49
    .line 50
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 51
    .line 52
    .line 53
    throw v0

    .line 54
    :cond_3
    :goto_0
    return-void
.end method

.method private static debugContextPropagation(Lio/opentelemetry/context/Context;)V
    .locals 6

    .line 1
    invoke-static {p0}, Lio/opentelemetry/instrumentation/api/internal/ContextPropagationDebug;->getPropagations(Lio/opentelemetry/context/Context;)Lio/opentelemetry/instrumentation/api/internal/ContextPropagationDebug;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    if-eqz p0, :cond_3

    .line 6
    .line 7
    iget-object p0, p0, Lio/opentelemetry/instrumentation/api/internal/ContextPropagationDebug;->locations:Ljava/util/List;

    .line 8
    .line 9
    new-instance v0, Ljava/lang/StringBuilder;

    .line 10
    .line 11
    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    .line 12
    .line 13
    .line 14
    invoke-interface {p0}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 15
    .line 16
    .line 17
    move-result-object p0

    .line 18
    :cond_0
    :goto_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 19
    .line 20
    .line 21
    move-result v1

    .line 22
    if-eqz v1, :cond_2

    .line 23
    .line 24
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 25
    .line 26
    .line 27
    move-result-object v1

    .line 28
    check-cast v1, Lio/opentelemetry/instrumentation/api/internal/ContextPropagationDebug$Propagation;

    .line 29
    .line 30
    const-string v2, "\ncarrier of type: "

    .line 31
    .line 32
    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 33
    .line 34
    .line 35
    iget-object v2, v1, Lio/opentelemetry/instrumentation/api/internal/ContextPropagationDebug$Propagation;->carrierClassName:Ljava/lang/String;

    .line 36
    .line 37
    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 38
    .line 39
    .line 40
    iget-object v1, v1, Lio/opentelemetry/instrumentation/api/internal/ContextPropagationDebug$Propagation;->location:[Ljava/lang/StackTraceElement;

    .line 41
    .line 42
    array-length v2, v1

    .line 43
    const/4 v3, 0x0

    .line 44
    :goto_1
    if-ge v3, v2, :cond_1

    .line 45
    .line 46
    aget-object v4, v1, v3

    .line 47
    .line 48
    const-string v5, "\n    "

    .line 49
    .line 50
    invoke-virtual {v0, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 51
    .line 52
    .line 53
    invoke-virtual {v0, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 54
    .line 55
    .line 56
    add-int/lit8 v3, v3, 0x1

    .line 57
    .line 58
    goto :goto_1

    .line 59
    :cond_1
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 60
    .line 61
    .line 62
    move-result v1

    .line 63
    if-eqz v1, :cond_0

    .line 64
    .line 65
    const-string v1, "\nwhich was propagated from:"

    .line 66
    .line 67
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 68
    .line 69
    .line 70
    goto :goto_0

    .line 71
    :cond_2
    sget-object p0, Lio/opentelemetry/instrumentation/api/internal/ContextPropagationDebug;->logger:Ljava/util/logging/Logger;

    .line 72
    .line 73
    sget-object v1, Ljava/util/logging/Level;->WARNING:Ljava/util/logging/Level;

    .line 74
    .line 75
    const-string v2, "a context leak was detected. it was propagated from: {0}"

    .line 76
    .line 77
    invoke-virtual {p0, v1, v2, v0}, Ljava/util/logging/Logger;->log(Ljava/util/logging/Level;Ljava/lang/String;Ljava/lang/Object;)V

    .line 78
    .line 79
    .line 80
    :cond_3
    return-void
.end method

.method private static getPropagations(Lio/opentelemetry/context/Context;)Lio/opentelemetry/instrumentation/api/internal/ContextPropagationDebug;
    .locals 1
    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation

    .line 1
    sget-object v0, Lio/opentelemetry/instrumentation/api/internal/ContextPropagationDebug;->THREAD_PROPAGATION_LOCATIONS:Lio/opentelemetry/context/ContextKey;

    .line 2
    .line 3
    invoke-interface {p0, v0}, Lio/opentelemetry/context/Context;->get(Lio/opentelemetry/context/ContextKey;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Lio/opentelemetry/instrumentation/api/internal/ContextPropagationDebug;

    .line 8
    .line 9
    return-object p0
.end method

.method public static isThreadPropagationDebuggerEnabled()Z
    .locals 1

    .line 1
    sget-boolean v0, Lio/opentelemetry/instrumentation/api/internal/ContextPropagationDebug;->THREAD_PROPAGATION_DEBUGGER:Z

    .line 2
    .line 3
    return v0
.end method

.method public static unwrap(Lio/opentelemetry/context/Context;)Lio/opentelemetry/context/Context;
    .locals 2

    .line 1
    if-eqz p0, :cond_2

    .line 2
    .line 3
    invoke-static {}, Lio/opentelemetry/instrumentation/api/internal/ContextPropagationDebug;->isThreadPropagationDebuggerEnabled()Z

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    if-nez v0, :cond_0

    .line 8
    .line 9
    goto :goto_0

    .line 10
    :cond_0
    invoke-static {p0}, Lio/opentelemetry/instrumentation/api/internal/ContextPropagationDebug;->getPropagations(Lio/opentelemetry/context/Context;)Lio/opentelemetry/instrumentation/api/internal/ContextPropagationDebug;

    .line 11
    .line 12
    .line 13
    move-result-object v0

    .line 14
    if-nez v0, :cond_1

    .line 15
    .line 16
    goto :goto_0

    .line 17
    :cond_1
    iget-object v1, v0, Lio/opentelemetry/instrumentation/api/internal/ContextPropagationDebug;->wrappedContext:Lio/opentelemetry/context/Context;

    .line 18
    .line 19
    if-ne v1, p0, :cond_2

    .line 20
    .line 21
    iget-object p0, v0, Lio/opentelemetry/instrumentation/api/internal/ContextPropagationDebug;->sourceContext:Lio/opentelemetry/context/Context;

    .line 22
    .line 23
    :cond_2
    :goto_0
    return-object p0
.end method
