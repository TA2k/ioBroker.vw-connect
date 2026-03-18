.class public final Lw51/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Lw51/b;

.field public static final b:Ljava/util/concurrent/CopyOnWriteArraySet;

.field public static final c:Lw51/d;

.field public static final d:Z


# direct methods
.method static constructor <clinit>()V
    .locals 9

    .line 1
    new-instance v0, Lw51/b;

    .line 2
    .line 3
    const-string v1, "Main"

    .line 4
    .line 5
    invoke-direct {v0, v1}, Lw51/b;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    sput-object v0, Lw51/c;->a:Lw51/b;

    .line 9
    .line 10
    new-instance v0, Ljava/util/concurrent/CopyOnWriteArraySet;

    .line 11
    .line 12
    invoke-direct {v0}, Ljava/util/concurrent/CopyOnWriteArraySet;-><init>()V

    .line 13
    .line 14
    .line 15
    sput-object v0, Lw51/c;->b:Ljava/util/concurrent/CopyOnWriteArraySet;

    .line 16
    .line 17
    new-instance v1, Lw51/d;

    .line 18
    .line 19
    sget-object v6, Ljava/util/concurrent/TimeUnit;->MILLISECONDS:Ljava/util/concurrent/TimeUnit;

    .line 20
    .line 21
    new-instance v7, Ljava/util/concurrent/LinkedBlockingQueue;

    .line 22
    .line 23
    invoke-direct {v7}, Ljava/util/concurrent/LinkedBlockingQueue;-><init>()V

    .line 24
    .line 25
    .line 26
    new-instance v8, Lw51/g;

    .line 27
    .line 28
    const-string v0, "L"

    .line 29
    .line 30
    invoke-direct {v8, v0}, Lw51/g;-><init>(Ljava/lang/String;)V

    .line 31
    .line 32
    .line 33
    const/4 v2, 0x1

    .line 34
    const/4 v3, 0x1

    .line 35
    const-wide/16 v4, 0x0

    .line 36
    .line 37
    invoke-direct/range {v1 .. v8}, Ljava/util/concurrent/ThreadPoolExecutor;-><init>(IIJLjava/util/concurrent/TimeUnit;Ljava/util/concurrent/BlockingQueue;Ljava/util/concurrent/ThreadFactory;)V

    .line 38
    .line 39
    .line 40
    sput-object v1, Lw51/c;->c:Lw51/d;

    .line 41
    .line 42
    const/4 v0, 0x1

    .line 43
    sput-boolean v0, Lw51/c;->d:Z

    .line 44
    .line 45
    return-void
.end method

.method public static final a(Lw51/b;Ljava/lang/Exception;Lay0/a;)V
    .locals 2

    .line 1
    const-string v0, "moduleName"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    sget-object v0, Lw51/e;->f:Lw51/e;

    .line 7
    .line 8
    const-class v1, Lw51/c;

    .line 9
    .line 10
    invoke-virtual {v1}, Ljava/lang/Class;->getName()Ljava/lang/String;

    .line 11
    .line 12
    .line 13
    move-result-object v1

    .line 14
    invoke-static {v1, v0}, Lw51/c;->c(Ljava/lang/String;Lw51/e;)Lw51/a;

    .line 15
    .line 16
    .line 17
    move-result-object v0

    .line 18
    const/16 v1, 0x8

    .line 19
    .line 20
    invoke-static {p0, v0, p1, p2, v1}, Lw51/c;->b(Lw51/b;Lw51/a;Ljava/lang/Exception;Lay0/a;I)V

    .line 21
    .line 22
    .line 23
    return-void
.end method

.method public static b(Lw51/b;Lw51/a;Ljava/lang/Exception;Lay0/a;I)V
    .locals 8

    .line 1
    and-int/lit8 p4, p4, 0x1

    .line 2
    .line 3
    if-eqz p4, :cond_0

    .line 4
    .line 5
    sget-object p0, Lw51/c;->a:Lw51/b;

    .line 6
    .line 7
    :cond_0
    move-object v1, p0

    .line 8
    const-string p0, "moduleName"

    .line 9
    .line 10
    invoke-static {v1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 11
    .line 12
    .line 13
    sget-object v2, Lw51/e;->f:Lw51/e;

    .line 14
    .line 15
    invoke-static {}, Lw51/c;->d()Z

    .line 16
    .line 17
    .line 18
    move-result p0

    .line 19
    if-eqz p0, :cond_1

    .line 20
    .line 21
    new-instance v0, Lw51/f;

    .line 22
    .line 23
    iget-object v4, p1, Lw51/a;->a:Ljava/lang/String;

    .line 24
    .line 25
    iget v5, p1, Lw51/a;->b:I

    .line 26
    .line 27
    iget-object v6, p1, Lw51/a;->c:Ljava/lang/String;

    .line 28
    .line 29
    move-object v7, p2

    .line 30
    move-object v3, p3

    .line 31
    invoke-direct/range {v0 .. v7}, Lw51/f;-><init>(Lw51/b;Lw51/e;Lay0/a;Ljava/lang/String;ILjava/lang/String;Ljava/lang/Throwable;)V

    .line 32
    .line 33
    .line 34
    invoke-static {}, Lw51/c;->d()Z

    .line 35
    .line 36
    .line 37
    move-result p0

    .line 38
    if-eqz p0, :cond_1

    .line 39
    .line 40
    new-instance p0, Lvp/g4;

    .line 41
    .line 42
    const/4 p1, 0x3

    .line 43
    invoke-direct {p0, v0, p1}, Lvp/g4;-><init>(Ljava/lang/Object;I)V

    .line 44
    .line 45
    .line 46
    sget-object p1, Lw51/c;->c:Lw51/d;

    .line 47
    .line 48
    invoke-virtual {p1, p0}, Ljava/util/concurrent/AbstractExecutorService;->submit(Ljava/lang/Runnable;)Ljava/util/concurrent/Future;

    .line 49
    .line 50
    .line 51
    :cond_1
    return-void
.end method

.method public static c(Ljava/lang/String;Lw51/e;)Lw51/a;
    .locals 6

    .line 1
    invoke-static {}, Lw51/c;->d()Z

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    if-eqz v0, :cond_4

    .line 6
    .line 7
    new-instance p1, Ljava/lang/Throwable;

    .line 8
    .line 9
    invoke-direct {p1}, Ljava/lang/Throwable;-><init>()V

    .line 10
    .line 11
    .line 12
    invoke-virtual {p1}, Ljava/lang/Throwable;->getStackTrace()[Ljava/lang/StackTraceElement;

    .line 13
    .line 14
    .line 15
    move-result-object p1

    .line 16
    const-string v0, "getStackTrace(...)"

    .line 17
    .line 18
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 19
    .line 20
    .line 21
    array-length v0, p1

    .line 22
    const/4 v1, 0x0

    .line 23
    move v2, v1

    .line 24
    :goto_0
    if-ge v2, v0, :cond_1

    .line 25
    .line 26
    aget-object v3, p1, v2

    .line 27
    .line 28
    invoke-virtual {v3}, Ljava/lang/StackTraceElement;->getClassName()Ljava/lang/String;

    .line 29
    .line 30
    .line 31
    move-result-object v4

    .line 32
    invoke-static {v4, p0}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 33
    .line 34
    .line 35
    move-result v4

    .line 36
    if-nez v4, :cond_0

    .line 37
    .line 38
    invoke-virtual {v3}, Ljava/lang/StackTraceElement;->getClassName()Ljava/lang/String;

    .line 39
    .line 40
    .line 41
    move-result-object v4

    .line 42
    const-class v5, Lw51/c;

    .line 43
    .line 44
    invoke-virtual {v5}, Ljava/lang/Class;->getName()Ljava/lang/String;

    .line 45
    .line 46
    .line 47
    move-result-object v5

    .line 48
    invoke-static {v4, v5}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 49
    .line 50
    .line 51
    move-result v4

    .line 52
    if-nez v4, :cond_0

    .line 53
    .line 54
    goto :goto_1

    .line 55
    :cond_0
    add-int/lit8 v2, v2, 0x1

    .line 56
    .line 57
    goto :goto_0

    .line 58
    :cond_1
    const/4 v3, 0x0

    .line 59
    :goto_1
    if-eqz v3, :cond_3

    .line 60
    .line 61
    invoke-virtual {v3}, Ljava/lang/StackTraceElement;->getClassName()Ljava/lang/String;

    .line 62
    .line 63
    .line 64
    move-result-object p0

    .line 65
    const-string p1, "getClassName(...)"

    .line 66
    .line 67
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 68
    .line 69
    .line 70
    const-string p1, "."

    .line 71
    .line 72
    filled-new-array {p1}, [Ljava/lang/String;

    .line 73
    .line 74
    .line 75
    move-result-object p1

    .line 76
    const/4 v0, 0x6

    .line 77
    invoke-static {p0, p1, v0}, Lly0/p;->Y(Ljava/lang/CharSequence;[Ljava/lang/String;I)Ljava/util/List;

    .line 78
    .line 79
    .line 80
    move-result-object p0

    .line 81
    invoke-static {p0}, Lmx0/q;->T(Ljava/util/List;)Ljava/lang/Object;

    .line 82
    .line 83
    .line 84
    move-result-object p0

    .line 85
    check-cast p0, Ljava/lang/String;

    .line 86
    .line 87
    invoke-virtual {v3}, Ljava/lang/StackTraceElement;->getLineNumber()I

    .line 88
    .line 89
    .line 90
    move-result p1

    .line 91
    invoke-static {}, Ljava/lang/Thread;->currentThread()Ljava/lang/Thread;

    .line 92
    .line 93
    .line 94
    move-result-object v2

    .line 95
    invoke-virtual {v2}, Ljava/lang/Thread;->getName()Ljava/lang/String;

    .line 96
    .line 97
    .line 98
    move-result-object v2

    .line 99
    const-string v3, "$"

    .line 100
    .line 101
    invoke-static {p0, v3, v1}, Lly0/p;->A(Ljava/lang/CharSequence;Ljava/lang/CharSequence;Z)Z

    .line 102
    .line 103
    .line 104
    move-result v1

    .line 105
    if-eqz v1, :cond_2

    .line 106
    .line 107
    filled-new-array {v3}, [Ljava/lang/String;

    .line 108
    .line 109
    .line 110
    move-result-object v1

    .line 111
    invoke-static {p0, v1, v0}, Lly0/p;->Y(Ljava/lang/CharSequence;[Ljava/lang/String;I)Ljava/util/List;

    .line 112
    .line 113
    .line 114
    move-result-object p0

    .line 115
    check-cast p0, Ljava/lang/Iterable;

    .line 116
    .line 117
    invoke-static {p0}, Lmx0/q;->z(Ljava/lang/Iterable;)Lky0/m;

    .line 118
    .line 119
    .line 120
    move-result-object p0

    .line 121
    new-instance v0, Lvb/a;

    .line 122
    .line 123
    const/16 v1, 0x18

    .line 124
    .line 125
    invoke-direct {v0, v1}, Lvb/a;-><init>(I)V

    .line 126
    .line 127
    .line 128
    invoke-static {p0, v0}, Lky0/l;->e(Lky0/j;Lay0/k;)Lky0/g;

    .line 129
    .line 130
    .line 131
    move-result-object p0

    .line 132
    invoke-static {p0, v3}, Lky0/l;->l(Lky0/j;Ljava/lang/String;)Ljava/lang/String;

    .line 133
    .line 134
    .line 135
    move-result-object p0

    .line 136
    :cond_2
    new-instance v0, Lw51/a;

    .line 137
    .line 138
    invoke-static {v2}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 139
    .line 140
    .line 141
    invoke-direct {v0, p0, p1, v2}, Lw51/a;-><init>(Ljava/lang/String;ILjava/lang/String;)V

    .line 142
    .line 143
    .line 144
    return-object v0

    .line 145
    :cond_3
    new-instance p1, Ljava/lang/IllegalStateException;

    .line 146
    .line 147
    const-string v0, "Only calls from L or "

    .line 148
    .line 149
    const-string v1, " are not expected"

    .line 150
    .line 151
    invoke-static {v0, p0, v1}, Lp3/m;->j(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 152
    .line 153
    .line 154
    move-result-object p0

    .line 155
    invoke-direct {p1, p0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 156
    .line 157
    .line 158
    throw p1

    .line 159
    :cond_4
    new-instance p0, Lw51/a;

    .line 160
    .line 161
    new-instance v0, Ljava/lang/StringBuilder;

    .line 162
    .line 163
    const-string v1, "Logging of "

    .line 164
    .line 165
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 166
    .line 167
    .line 168
    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 169
    .line 170
    .line 171
    const-string p1, " is disabled"

    .line 172
    .line 173
    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 174
    .line 175
    .line 176
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 177
    .line 178
    .line 179
    move-result-object p1

    .line 180
    const-string v0, "getName(...)"

    .line 181
    .line 182
    invoke-static {v0}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 183
    .line 184
    .line 185
    move-result-object v0

    .line 186
    const/4 v1, -0x1

    .line 187
    invoke-direct {p0, p1, v1, v0}, Lw51/a;-><init>(Ljava/lang/String;ILjava/lang/String;)V

    .line 188
    .line 189
    .line 190
    return-object p0
.end method

.method public static final d()Z
    .locals 1

    .line 1
    sget-boolean v0, Lw51/c;->d:Z

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    sget-object v0, Lw51/c;->b:Ljava/util/concurrent/CopyOnWriteArraySet;

    .line 6
    .line 7
    invoke-static {v0}, Lmx0/q;->C0(Ljava/lang/Iterable;)Ljava/util/Set;

    .line 8
    .line 9
    .line 10
    move-result-object v0

    .line 11
    check-cast v0, Ljava/util/Collection;

    .line 12
    .line 13
    invoke-interface {v0}, Ljava/util/Collection;->isEmpty()Z

    .line 14
    .line 15
    .line 16
    move-result v0

    .line 17
    if-nez v0, :cond_0

    .line 18
    .line 19
    const/4 v0, 0x1

    .line 20
    return v0

    .line 21
    :cond_0
    const/4 v0, 0x0

    .line 22
    return v0
.end method

.method public static e(Lay0/a;)Ljava/lang/String;
    .locals 2

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    :try_start_0
    invoke-interface {p0}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 7
    .line 8
    .line 9
    move-result-object p0

    .line 10
    if-eqz p0, :cond_0

    .line 11
    .line 12
    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 13
    .line 14
    .line 15
    move-result-object p0

    .line 16
    goto :goto_0

    .line 17
    :cond_0
    const/4 p0, 0x0

    .line 18
    :goto_0
    if-nez p0, :cond_1

    .line 19
    .line 20
    const-string p0, ""
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    .line 21
    .line 22
    :cond_1
    return-object p0

    .line 23
    :catch_0
    move-exception p0

    .line 24
    new-instance v0, Ljava/lang/StringBuilder;

    .line 25
    .line 26
    const-string v1, "Log message invocation failed: "

    .line 27
    .line 28
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 29
    .line 30
    .line 31
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 32
    .line 33
    .line 34
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 35
    .line 36
    .line 37
    move-result-object p0

    .line 38
    return-object p0
.end method

.method public static final f(Lw51/b;Ljava/lang/Throwable;Lay0/a;)V
    .locals 2

    .line 1
    const-string v0, "moduleName"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    sget-object v0, Lw51/e;->e:Lw51/e;

    .line 7
    .line 8
    const-class v1, Lw51/c;

    .line 9
    .line 10
    invoke-virtual {v1}, Ljava/lang/Class;->getName()Ljava/lang/String;

    .line 11
    .line 12
    .line 13
    move-result-object v1

    .line 14
    invoke-static {v1, v0}, Lw51/c;->c(Ljava/lang/String;Lw51/e;)Lw51/a;

    .line 15
    .line 16
    .line 17
    move-result-object v0

    .line 18
    invoke-static {p0, v0, p1, p2}, Lw51/c;->g(Lw51/b;Lw51/a;Ljava/lang/Throwable;Lay0/a;)V

    .line 19
    .line 20
    .line 21
    return-void
.end method

.method public static g(Lw51/b;Lw51/a;Ljava/lang/Throwable;Lay0/a;)V
    .locals 9

    .line 1
    const-string v0, "moduleName"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    sget-object v3, Lw51/e;->e:Lw51/e;

    .line 7
    .line 8
    invoke-static {}, Lw51/c;->d()Z

    .line 9
    .line 10
    .line 11
    move-result v0

    .line 12
    if-eqz v0, :cond_0

    .line 13
    .line 14
    new-instance v1, Lw51/f;

    .line 15
    .line 16
    iget-object v5, p1, Lw51/a;->a:Ljava/lang/String;

    .line 17
    .line 18
    iget v6, p1, Lw51/a;->b:I

    .line 19
    .line 20
    iget-object v7, p1, Lw51/a;->c:Ljava/lang/String;

    .line 21
    .line 22
    move-object v2, p0

    .line 23
    move-object v8, p2

    .line 24
    move-object v4, p3

    .line 25
    invoke-direct/range {v1 .. v8}, Lw51/f;-><init>(Lw51/b;Lw51/e;Lay0/a;Ljava/lang/String;ILjava/lang/String;Ljava/lang/Throwable;)V

    .line 26
    .line 27
    .line 28
    invoke-static {}, Lw51/c;->d()Z

    .line 29
    .line 30
    .line 31
    move-result p0

    .line 32
    if-eqz p0, :cond_0

    .line 33
    .line 34
    new-instance p0, Lvp/g4;

    .line 35
    .line 36
    const/4 p1, 0x3

    .line 37
    invoke-direct {p0, v1, p1}, Lvp/g4;-><init>(Ljava/lang/Object;I)V

    .line 38
    .line 39
    .line 40
    sget-object p1, Lw51/c;->c:Lw51/d;

    .line 41
    .line 42
    invoke-virtual {p1, p0}, Ljava/util/concurrent/AbstractExecutorService;->submit(Ljava/lang/Runnable;)Ljava/util/concurrent/Future;

    .line 43
    .line 44
    .line 45
    :cond_0
    return-void
.end method
