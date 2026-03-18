.class final Lio/opentelemetry/context/StrictContextStorage$StrictScope;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lio/opentelemetry/context/Scope;


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lio/opentelemetry/context/StrictContextStorage;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x11
    name = "StrictScope"
.end annotation


# instance fields
.field final caller:Lio/opentelemetry/context/StrictContextStorage$CallerStackTrace;

.field final delegate:Lio/opentelemetry/context/Scope;

.field final synthetic this$0:Lio/opentelemetry/context/StrictContextStorage;


# direct methods
.method public constructor <init>(Lio/opentelemetry/context/StrictContextStorage;Lio/opentelemetry/context/Scope;Lio/opentelemetry/context/StrictContextStorage$CallerStackTrace;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lio/opentelemetry/context/StrictContextStorage$StrictScope;->this$0:Lio/opentelemetry/context/StrictContextStorage;

    .line 2
    .line 3
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    iput-object p2, p0, Lio/opentelemetry/context/StrictContextStorage$StrictScope;->delegate:Lio/opentelemetry/context/Scope;

    .line 7
    .line 8
    iput-object p3, p0, Lio/opentelemetry/context/StrictContextStorage$StrictScope;->caller:Lio/opentelemetry/context/StrictContextStorage$CallerStackTrace;

    .line 9
    .line 10
    invoke-static {p1}, Lio/opentelemetry/context/StrictContextStorage;->access$000(Lio/opentelemetry/context/StrictContextStorage;)Lio/opentelemetry/context/StrictContextStorage$PendingScopes;

    .line 11
    .line 12
    .line 13
    move-result-object p1

    .line 14
    invoke-virtual {p1, p0, p3}, Lio/opentelemetry/context/internal/shaded/WeakConcurrentMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 15
    .line 16
    .line 17
    return-void
.end method


# virtual methods
.method public close()V
    .locals 6

    .line 1
    iget-object v0, p0, Lio/opentelemetry/context/StrictContextStorage$StrictScope;->caller:Lio/opentelemetry/context/StrictContextStorage$CallerStackTrace;

    .line 2
    .line 3
    const/4 v1, 0x1

    .line 4
    iput-boolean v1, v0, Lio/opentelemetry/context/StrictContextStorage$CallerStackTrace;->closed:Z

    .line 5
    .line 6
    iget-object v0, p0, Lio/opentelemetry/context/StrictContextStorage$StrictScope;->this$0:Lio/opentelemetry/context/StrictContextStorage;

    .line 7
    .line 8
    invoke-static {v0}, Lio/opentelemetry/context/StrictContextStorage;->access$000(Lio/opentelemetry/context/StrictContextStorage;)Lio/opentelemetry/context/StrictContextStorage$PendingScopes;

    .line 9
    .line 10
    .line 11
    move-result-object v0

    .line 12
    invoke-virtual {v0, p0}, Lio/opentelemetry/context/internal/shaded/WeakConcurrentMap;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    .line 13
    .line 14
    .line 15
    new-instance v0, Ljava/lang/Throwable;

    .line 16
    .line 17
    invoke-direct {v0}, Ljava/lang/Throwable;-><init>()V

    .line 18
    .line 19
    .line 20
    invoke-virtual {v0}, Ljava/lang/Throwable;->getStackTrace()[Ljava/lang/StackTraceElement;

    .line 21
    .line 22
    .line 23
    move-result-object v0

    .line 24
    const/4 v1, 0x0

    .line 25
    :goto_0
    array-length v2, v0

    .line 26
    if-ge v1, v2, :cond_4

    .line 27
    .line 28
    aget-object v2, v0, v1

    .line 29
    .line 30
    invoke-virtual {v2}, Ljava/lang/StackTraceElement;->getClassName()Ljava/lang/String;

    .line 31
    .line 32
    .line 33
    move-result-object v3

    .line 34
    const-class v4, Lio/opentelemetry/context/StrictContextStorage$StrictScope;

    .line 35
    .line 36
    invoke-virtual {v4}, Ljava/lang/Class;->getName()Ljava/lang/String;

    .line 37
    .line 38
    .line 39
    move-result-object v4

    .line 40
    invoke-virtual {v3, v4}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 41
    .line 42
    .line 43
    move-result v3

    .line 44
    if-eqz v3, :cond_3

    .line 45
    .line 46
    invoke-virtual {v2}, Ljava/lang/StackTraceElement;->getMethodName()Ljava/lang/String;

    .line 47
    .line 48
    .line 49
    move-result-object v2

    .line 50
    const-string v3, "close"

    .line 51
    .line 52
    invoke-virtual {v2, v3}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 53
    .line 54
    .line 55
    move-result v2

    .line 56
    if-eqz v2, :cond_3

    .line 57
    .line 58
    add-int/lit8 v2, v1, 0x2

    .line 59
    .line 60
    add-int/lit8 v3, v1, 0x1

    .line 61
    .line 62
    array-length v4, v0

    .line 63
    if-ge v3, v4, :cond_0

    .line 64
    .line 65
    aget-object v3, v0, v3

    .line 66
    .line 67
    invoke-virtual {v3}, Ljava/lang/StackTraceElement;->getClassName()Ljava/lang/String;

    .line 68
    .line 69
    .line 70
    move-result-object v4

    .line 71
    const-string v5, "kotlin.jdk7.AutoCloseableKt"

    .line 72
    .line 73
    invoke-virtual {v4, v5}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 74
    .line 75
    .line 76
    move-result v4

    .line 77
    if-eqz v4, :cond_0

    .line 78
    .line 79
    invoke-virtual {v3}, Ljava/lang/StackTraceElement;->getMethodName()Ljava/lang/String;

    .line 80
    .line 81
    .line 82
    move-result-object v3

    .line 83
    const-string v4, "closeFinally"

    .line 84
    .line 85
    invoke-virtual {v3, v4}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 86
    .line 87
    .line 88
    move-result v3

    .line 89
    if-eqz v3, :cond_0

    .line 90
    .line 91
    array-length v3, v0

    .line 92
    if-ge v2, v3, :cond_0

    .line 93
    .line 94
    add-int/lit8 v2, v1, 0x3

    .line 95
    .line 96
    :cond_0
    aget-object v3, v0, v2

    .line 97
    .line 98
    invoke-virtual {v3}, Ljava/lang/StackTraceElement;->getMethodName()Ljava/lang/String;

    .line 99
    .line 100
    .line 101
    move-result-object v3

    .line 102
    const-string v4, "invokeSuspend"

    .line 103
    .line 104
    invoke-virtual {v3, v4}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 105
    .line 106
    .line 107
    move-result v3

    .line 108
    if-eqz v3, :cond_1

    .line 109
    .line 110
    add-int/lit8 v2, v2, 0x1

    .line 111
    .line 112
    :cond_1
    array-length v3, v0

    .line 113
    if-ge v2, v3, :cond_3

    .line 114
    .line 115
    aget-object v2, v0, v2

    .line 116
    .line 117
    invoke-virtual {v2}, Ljava/lang/StackTraceElement;->getClassName()Ljava/lang/String;

    .line 118
    .line 119
    .line 120
    move-result-object v3

    .line 121
    const-string v4, "kotlin.coroutines.jvm.internal.BaseContinuationImpl"

    .line 122
    .line 123
    invoke-virtual {v3, v4}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 124
    .line 125
    .line 126
    move-result v3

    .line 127
    if-eqz v3, :cond_3

    .line 128
    .line 129
    invoke-virtual {v2}, Ljava/lang/StackTraceElement;->getMethodName()Ljava/lang/String;

    .line 130
    .line 131
    .line 132
    move-result-object v2

    .line 133
    const-string v3, "resumeWith"

    .line 134
    .line 135
    invoke-virtual {v2, v3}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 136
    .line 137
    .line 138
    move-result v2

    .line 139
    if-nez v2, :cond_2

    .line 140
    .line 141
    goto :goto_1

    .line 142
    :cond_2
    new-instance p0, Ljava/lang/AssertionError;

    .line 143
    .line 144
    const-string v0, "Attempting to close a Scope created by Context.makeCurrent from inside a Kotlin coroutine. This is not allowed. Use Context.asContextElement provided by opentelemetry-extension-kotlin instead of makeCurrent."

    .line 145
    .line 146
    invoke-direct {p0, v0}, Ljava/lang/AssertionError;-><init>(Ljava/lang/Object;)V

    .line 147
    .line 148
    .line 149
    throw p0

    .line 150
    :cond_3
    :goto_1
    add-int/lit8 v1, v1, 0x1

    .line 151
    .line 152
    goto :goto_0

    .line 153
    :cond_4
    invoke-static {}, Ljava/lang/Thread;->currentThread()Ljava/lang/Thread;

    .line 154
    .line 155
    .line 156
    move-result-object v0

    .line 157
    invoke-virtual {v0}, Ljava/lang/Thread;->getId()J

    .line 158
    .line 159
    .line 160
    move-result-wide v0

    .line 161
    iget-object v2, p0, Lio/opentelemetry/context/StrictContextStorage$StrictScope;->caller:Lio/opentelemetry/context/StrictContextStorage$CallerStackTrace;

    .line 162
    .line 163
    iget-wide v2, v2, Lio/opentelemetry/context/StrictContextStorage$CallerStackTrace;->threadId:J

    .line 164
    .line 165
    cmp-long v0, v0, v2

    .line 166
    .line 167
    if-nez v0, :cond_5

    .line 168
    .line 169
    iget-object p0, p0, Lio/opentelemetry/context/StrictContextStorage$StrictScope;->delegate:Lio/opentelemetry/context/Scope;

    .line 170
    .line 171
    invoke-interface {p0}, Lio/opentelemetry/context/Scope;->close()V

    .line 172
    .line 173
    .line 174
    return-void

    .line 175
    :cond_5
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 176
    .line 177
    iget-object v1, p0, Lio/opentelemetry/context/StrictContextStorage$StrictScope;->caller:Lio/opentelemetry/context/StrictContextStorage$CallerStackTrace;

    .line 178
    .line 179
    iget-object v1, v1, Lio/opentelemetry/context/StrictContextStorage$CallerStackTrace;->threadName:Ljava/lang/String;

    .line 180
    .line 181
    invoke-static {}, Ljava/lang/Thread;->currentThread()Ljava/lang/Thread;

    .line 182
    .line 183
    .line 184
    move-result-object v2

    .line 185
    invoke-virtual {v2}, Ljava/lang/Thread;->getName()Ljava/lang/String;

    .line 186
    .line 187
    .line 188
    move-result-object v2

    .line 189
    const-string v3, "] opened scope, but thread ["

    .line 190
    .line 191
    const-string v4, "] closed it"

    .line 192
    .line 193
    const-string v5, "Thread ["

    .line 194
    .line 195
    invoke-static {v5, v1, v3, v2, v4}, Lu/w;->g(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 196
    .line 197
    .line 198
    move-result-object v1

    .line 199
    iget-object p0, p0, Lio/opentelemetry/context/StrictContextStorage$StrictScope;->caller:Lio/opentelemetry/context/StrictContextStorage$CallerStackTrace;

    .line 200
    .line 201
    invoke-direct {v0, v1, p0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 202
    .line 203
    .line 204
    throw v0
.end method

.method public toString()Ljava/lang/String;
    .locals 1

    .line 1
    iget-object v0, p0, Lio/opentelemetry/context/StrictContextStorage$StrictScope;->caller:Lio/opentelemetry/context/StrictContextStorage$CallerStackTrace;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/Throwable;->getMessage()Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    if-eqz v0, :cond_0

    .line 8
    .line 9
    return-object v0

    .line 10
    :cond_0
    invoke-super {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    return-object p0
.end method
