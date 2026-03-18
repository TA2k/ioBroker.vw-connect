.class final Lio/opentelemetry/context/StrictContextStorage;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lio/opentelemetry/context/ContextStorage;
.implements Ljava/lang/AutoCloseable;


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lio/opentelemetry/context/StrictContextStorage$PendingScopes;,
        Lio/opentelemetry/context/StrictContextStorage$CallerStackTrace;,
        Lio/opentelemetry/context/StrictContextStorage$StrictScope;
    }
.end annotation


# static fields
.field private static final logger:Ljava/util/logging/Logger;


# instance fields
.field private final delegate:Lio/opentelemetry/context/ContextStorage;

.field private final pendingScopes:Lio/opentelemetry/context/StrictContextStorage$PendingScopes;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    const-class v0, Lio/opentelemetry/context/StrictContextStorage;

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
    sput-object v0, Lio/opentelemetry/context/StrictContextStorage;->logger:Ljava/util/logging/Logger;

    .line 12
    .line 13
    return-void
.end method

.method private constructor <init>(Lio/opentelemetry/context/ContextStorage;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lio/opentelemetry/context/StrictContextStorage;->delegate:Lio/opentelemetry/context/ContextStorage;

    .line 5
    .line 6
    invoke-static {}, Lio/opentelemetry/context/StrictContextStorage$PendingScopes;->create()Lio/opentelemetry/context/StrictContextStorage$PendingScopes;

    .line 7
    .line 8
    .line 9
    move-result-object p1

    .line 10
    iput-object p1, p0, Lio/opentelemetry/context/StrictContextStorage;->pendingScopes:Lio/opentelemetry/context/StrictContextStorage$PendingScopes;

    .line 11
    .line 12
    return-void
.end method

.method public static synthetic access$000(Lio/opentelemetry/context/StrictContextStorage;)Lio/opentelemetry/context/StrictContextStorage$PendingScopes;
    .locals 0

    .line 1
    iget-object p0, p0, Lio/opentelemetry/context/StrictContextStorage;->pendingScopes:Lio/opentelemetry/context/StrictContextStorage$PendingScopes;

    .line 2
    .line 3
    return-object p0
.end method

.method public static synthetic access$100()Ljava/util/logging/Logger;
    .locals 1

    .line 1
    sget-object v0, Lio/opentelemetry/context/StrictContextStorage;->logger:Ljava/util/logging/Logger;

    .line 2
    .line 3
    return-object v0
.end method

.method public static callerError(Lio/opentelemetry/context/StrictContextStorage$CallerStackTrace;)Ljava/lang/AssertionError;
    .locals 3

    .line 1
    new-instance v0, Ljava/lang/AssertionError;

    .line 2
    .line 3
    new-instance v1, Ljava/lang/StringBuilder;

    .line 4
    .line 5
    const-string v2, "Thread ["

    .line 6
    .line 7
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 8
    .line 9
    .line 10
    iget-object v2, p0, Lio/opentelemetry/context/StrictContextStorage$CallerStackTrace;->threadName:Ljava/lang/String;

    .line 11
    .line 12
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 13
    .line 14
    .line 15
    const-string v2, "] opened a scope of "

    .line 16
    .line 17
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 18
    .line 19
    .line 20
    iget-object v2, p0, Lio/opentelemetry/context/StrictContextStorage$CallerStackTrace;->context:Lio/opentelemetry/context/Context;

    .line 21
    .line 22
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 23
    .line 24
    .line 25
    const-string v2, " here:"

    .line 26
    .line 27
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 28
    .line 29
    .line 30
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 31
    .line 32
    .line 33
    move-result-object v1

    .line 34
    invoke-direct {v0, v1}, Ljava/lang/AssertionError;-><init>(Ljava/lang/Object;)V

    .line 35
    .line 36
    .line 37
    invoke-virtual {p0}, Ljava/lang/Throwable;->getStackTrace()[Ljava/lang/StackTraceElement;

    .line 38
    .line 39
    .line 40
    move-result-object p0

    .line 41
    invoke-virtual {v0, p0}, Ljava/lang/Throwable;->setStackTrace([Ljava/lang/StackTraceElement;)V

    .line 42
    .line 43
    .line 44
    return-object v0
.end method

.method public static create(Lio/opentelemetry/context/ContextStorage;)Lio/opentelemetry/context/StrictContextStorage;
    .locals 1

    .line 1
    new-instance v0, Lio/opentelemetry/context/StrictContextStorage;

    .line 2
    .line 3
    invoke-direct {v0, p0}, Lio/opentelemetry/context/StrictContextStorage;-><init>(Lio/opentelemetry/context/ContextStorage;)V

    .line 4
    .line 5
    .line 6
    return-object v0
.end method


# virtual methods
.method public attach(Lio/opentelemetry/context/Context;)Lio/opentelemetry/context/Scope;
    .locals 6

    .line 1
    iget-object v0, p0, Lio/opentelemetry/context/StrictContextStorage;->delegate:Lio/opentelemetry/context/ContextStorage;

    .line 2
    .line 3
    invoke-interface {v0, p1}, Lio/opentelemetry/context/ContextStorage;->attach(Lio/opentelemetry/context/Context;)Lio/opentelemetry/context/Scope;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    new-instance v1, Lio/opentelemetry/context/StrictContextStorage$CallerStackTrace;

    .line 8
    .line 9
    invoke-direct {v1, p1}, Lio/opentelemetry/context/StrictContextStorage$CallerStackTrace;-><init>(Lio/opentelemetry/context/Context;)V

    .line 10
    .line 11
    .line 12
    invoke-virtual {v1}, Ljava/lang/Throwable;->getStackTrace()[Ljava/lang/StackTraceElement;

    .line 13
    .line 14
    .line 15
    move-result-object p1

    .line 16
    const/4 v2, 0x0

    .line 17
    :goto_0
    array-length v3, p1

    .line 18
    if-ge v2, v3, :cond_2

    .line 19
    .line 20
    aget-object v3, p1, v2

    .line 21
    .line 22
    invoke-virtual {v3}, Ljava/lang/StackTraceElement;->getClassName()Ljava/lang/String;

    .line 23
    .line 24
    .line 25
    move-result-object v4

    .line 26
    const-class v5, Lio/opentelemetry/context/Context;

    .line 27
    .line 28
    invoke-virtual {v5}, Ljava/lang/Class;->getName()Ljava/lang/String;

    .line 29
    .line 30
    .line 31
    move-result-object v5

    .line 32
    invoke-virtual {v4, v5}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 33
    .line 34
    .line 35
    move-result v4

    .line 36
    if-eqz v4, :cond_1

    .line 37
    .line 38
    invoke-virtual {v3}, Ljava/lang/StackTraceElement;->getMethodName()Ljava/lang/String;

    .line 39
    .line 40
    .line 41
    move-result-object v3

    .line 42
    const-string v4, "makeCurrent"

    .line 43
    .line 44
    invoke-virtual {v3, v4}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 45
    .line 46
    .line 47
    move-result v3

    .line 48
    if-eqz v3, :cond_1

    .line 49
    .line 50
    add-int/lit8 v3, v2, 0x2

    .line 51
    .line 52
    array-length v4, p1

    .line 53
    if-ge v3, v4, :cond_1

    .line 54
    .line 55
    aget-object v3, p1, v3

    .line 56
    .line 57
    invoke-virtual {v3}, Ljava/lang/StackTraceElement;->getClassName()Ljava/lang/String;

    .line 58
    .line 59
    .line 60
    move-result-object v4

    .line 61
    const-string v5, "kotlin.coroutines.jvm.internal.BaseContinuationImpl"

    .line 62
    .line 63
    invoke-virtual {v4, v5}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 64
    .line 65
    .line 66
    move-result v4

    .line 67
    if-eqz v4, :cond_1

    .line 68
    .line 69
    invoke-virtual {v3}, Ljava/lang/StackTraceElement;->getMethodName()Ljava/lang/String;

    .line 70
    .line 71
    .line 72
    move-result-object v3

    .line 73
    const-string v4, "resumeWith"

    .line 74
    .line 75
    invoke-virtual {v3, v4}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 76
    .line 77
    .line 78
    move-result v3

    .line 79
    if-nez v3, :cond_0

    .line 80
    .line 81
    goto :goto_1

    .line 82
    :cond_0
    new-instance p0, Ljava/lang/AssertionError;

    .line 83
    .line 84
    const-string p1, "Attempting to call Context.makeCurrent from inside a Kotlin coroutine. This is not allowed. Use Context.asContextElement provided by opentelemetry-extension-kotlin instead of makeCurrent."

    .line 85
    .line 86
    invoke-direct {p0, p1}, Ljava/lang/AssertionError;-><init>(Ljava/lang/Object;)V

    .line 87
    .line 88
    .line 89
    throw p0

    .line 90
    :cond_1
    :goto_1
    add-int/lit8 v2, v2, 0x1

    .line 91
    .line 92
    goto :goto_0

    .line 93
    :cond_2
    const/4 v2, 0x1

    .line 94
    :goto_2
    array-length v3, p1

    .line 95
    if-ge v2, v3, :cond_4

    .line 96
    .line 97
    aget-object v3, p1, v2

    .line 98
    .line 99
    invoke-virtual {v3}, Ljava/lang/StackTraceElement;->getClassName()Ljava/lang/String;

    .line 100
    .line 101
    .line 102
    move-result-object v3

    .line 103
    const-string v4, "io.opentelemetry.api."

    .line 104
    .line 105
    invoke-virtual {v3, v4}, Ljava/lang/String;->startsWith(Ljava/lang/String;)Z

    .line 106
    .line 107
    .line 108
    move-result v4

    .line 109
    if-nez v4, :cond_3

    .line 110
    .line 111
    const-string v4, "io.opentelemetry.sdk.testing.context.SettableContextStorageProvider"

    .line 112
    .line 113
    invoke-virtual {v3, v4}, Ljava/lang/String;->startsWith(Ljava/lang/String;)Z

    .line 114
    .line 115
    .line 116
    move-result v4

    .line 117
    if-nez v4, :cond_3

    .line 118
    .line 119
    const-string v4, "io.opentelemetry.context."

    .line 120
    .line 121
    invoke-virtual {v3, v4}, Ljava/lang/String;->startsWith(Ljava/lang/String;)Z

    .line 122
    .line 123
    .line 124
    move-result v3

    .line 125
    if-eqz v3, :cond_4

    .line 126
    .line 127
    :cond_3
    add-int/lit8 v2, v2, 0x1

    .line 128
    .line 129
    goto :goto_2

    .line 130
    :cond_4
    array-length v3, p1

    .line 131
    invoke-static {p1, v2, v3}, Ljava/util/Arrays;->copyOfRange([Ljava/lang/Object;II)[Ljava/lang/Object;

    .line 132
    .line 133
    .line 134
    move-result-object p1

    .line 135
    check-cast p1, [Ljava/lang/StackTraceElement;

    .line 136
    .line 137
    invoke-virtual {v1, p1}, Ljava/lang/Throwable;->setStackTrace([Ljava/lang/StackTraceElement;)V

    .line 138
    .line 139
    .line 140
    new-instance p1, Lio/opentelemetry/context/StrictContextStorage$StrictScope;

    .line 141
    .line 142
    invoke-direct {p1, p0, v0, v1}, Lio/opentelemetry/context/StrictContextStorage$StrictScope;-><init>(Lio/opentelemetry/context/StrictContextStorage;Lio/opentelemetry/context/Scope;Lio/opentelemetry/context/StrictContextStorage$CallerStackTrace;)V

    .line 143
    .line 144
    .line 145
    return-object p1
.end method

.method public close()V
    .locals 5

    .line 1
    iget-object v0, p0, Lio/opentelemetry/context/StrictContextStorage;->pendingScopes:Lio/opentelemetry/context/StrictContextStorage$PendingScopes;

    .line 2
    .line 3
    invoke-virtual {v0}, Lio/opentelemetry/context/internal/shaded/WeakConcurrentMap;->expungeStaleEntries()V

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lio/opentelemetry/context/StrictContextStorage;->pendingScopes:Lio/opentelemetry/context/StrictContextStorage$PendingScopes;

    .line 7
    .line 8
    invoke-virtual {p0}, Lio/opentelemetry/context/StrictContextStorage$PendingScopes;->drainPendingCallers()Ljava/util/List;

    .line 9
    .line 10
    .line 11
    move-result-object p0

    .line 12
    invoke-interface {p0}, Ljava/util/List;->isEmpty()Z

    .line 13
    .line 14
    .line 15
    move-result v0

    .line 16
    if-nez v0, :cond_1

    .line 17
    .line 18
    invoke-interface {p0}, Ljava/util/List;->size()I

    .line 19
    .line 20
    .line 21
    move-result v0

    .line 22
    const/4 v1, 0x1

    .line 23
    if-le v0, v1, :cond_0

    .line 24
    .line 25
    sget-object v0, Lio/opentelemetry/context/StrictContextStorage;->logger:Ljava/util/logging/Logger;

    .line 26
    .line 27
    sget-object v1, Ljava/util/logging/Level;->SEVERE:Ljava/util/logging/Level;

    .line 28
    .line 29
    const-string v2, "Multiple scopes leaked - first will be thrown as an error."

    .line 30
    .line 31
    invoke-virtual {v0, v1, v2}, Ljava/util/logging/Logger;->log(Ljava/util/logging/Level;Ljava/lang/String;)V

    .line 32
    .line 33
    .line 34
    invoke-interface {p0}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 35
    .line 36
    .line 37
    move-result-object v0

    .line 38
    :goto_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 39
    .line 40
    .line 41
    move-result v1

    .line 42
    if-eqz v1, :cond_0

    .line 43
    .line 44
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 45
    .line 46
    .line 47
    move-result-object v1

    .line 48
    check-cast v1, Lio/opentelemetry/context/StrictContextStorage$CallerStackTrace;

    .line 49
    .line 50
    sget-object v2, Lio/opentelemetry/context/StrictContextStorage;->logger:Ljava/util/logging/Logger;

    .line 51
    .line 52
    sget-object v3, Ljava/util/logging/Level;->SEVERE:Ljava/util/logging/Level;

    .line 53
    .line 54
    const-string v4, "Scope leaked"

    .line 55
    .line 56
    invoke-static {v1}, Lio/opentelemetry/context/StrictContextStorage;->callerError(Lio/opentelemetry/context/StrictContextStorage$CallerStackTrace;)Ljava/lang/AssertionError;

    .line 57
    .line 58
    .line 59
    move-result-object v1

    .line 60
    invoke-virtual {v2, v3, v4, v1}, Ljava/util/logging/Logger;->log(Ljava/util/logging/Level;Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 61
    .line 62
    .line 63
    goto :goto_0

    .line 64
    :cond_0
    const/4 v0, 0x0

    .line 65
    invoke-interface {p0, v0}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 66
    .line 67
    .line 68
    move-result-object p0

    .line 69
    check-cast p0, Lio/opentelemetry/context/StrictContextStorage$CallerStackTrace;

    .line 70
    .line 71
    invoke-static {p0}, Lio/opentelemetry/context/StrictContextStorage;->callerError(Lio/opentelemetry/context/StrictContextStorage$CallerStackTrace;)Ljava/lang/AssertionError;

    .line 72
    .line 73
    .line 74
    move-result-object p0

    .line 75
    throw p0

    .line 76
    :cond_1
    return-void
.end method

.method public current()Lio/opentelemetry/context/Context;
    .locals 0
    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation

    .line 1
    iget-object p0, p0, Lio/opentelemetry/context/StrictContextStorage;->delegate:Lio/opentelemetry/context/ContextStorage;

    .line 2
    .line 3
    invoke-interface {p0}, Lio/opentelemetry/context/ContextStorage;->current()Lio/opentelemetry/context/Context;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method
