.class public final Ltechnology/cariad/cat/genx/GenXDispatcherKt;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000(\n\u0002\u0018\u0002\n\u0002\u0010\t\n\u0002\u0008\u0002\n\u0002\u0010\u0008\n\u0002\u0008\u0005\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0004\n\u0002\u0018\u0002\n\u0002\u0008\u0003\u001a#\u0010\u0005\u001a\u00020\u0004*\u00020\u00002\u0006\u0010\u0002\u001a\u00020\u00012\u0006\u0010\u0003\u001a\u00020\u0001H\u0001\u00a2\u0006\u0004\u0008\u0005\u0010\u0006\u001a(\u0010\u0008\u001a\u00020\u00042\u0006\u0010\u0007\u001a\u00020\u00002\u0006\u0010\u0002\u001a\u00020\u00012\u0006\u0010\u0003\u001a\u00020\u0001H\u0083 \u00a2\u0006\u0004\u0008\u0008\u0010\u0006\u001a4\u0010\r\u001a\u0008\u0012\u0004\u0012\u00028\u00000\u000b\"\u0004\u0008\u0000\u0010\t*\u00020\u00002\u0012\u0010\u000c\u001a\u000e\u0012\n\u0012\u0008\u0012\u0004\u0012\u00028\u00000\u000b0\nH\u0080@\u00a2\u0006\u0004\u0008\r\u0010\u000e\u001a*\u0010\u000f\u001a\u0004\u0018\u00018\u0000\"\u0004\u0008\u0000\u0010\t*\u00020\u00002\u000c\u0010\u000c\u001a\u0008\u0012\u0004\u0012\u00028\u00000\nH\u0080@\u00a2\u0006\u0004\u0008\u000f\u0010\u000e\u001a\"\u0010\u0011\u001a\u00020\u0010*\u00020\u00002\u000c\u0010\u000c\u001a\u0008\u0012\u0004\u0012\u00020\u00100\nH\u0080@\u00a2\u0006\u0004\u0008\u0011\u0010\u000e\u001a*\u0010\u0012\u001a\u0008\u0012\u0004\u0012\u00020\u00100\u000b*\u00020\u00002\u000e\u0008\u0008\u0010\u000c\u001a\u0008\u0012\u0004\u0012\u00020\u00040\nH\u0080H\u00a2\u0006\u0004\u0008\u0012\u0010\u000e\u00a8\u0006\u0013"
    }
    d2 = {
        "Ltechnology/cariad/cat/genx/GenXDispatcher;",
        "",
        "nativeFunc",
        "context",
        "",
        "nativeExecute",
        "(Ltechnology/cariad/cat/genx/GenXDispatcher;JJ)I",
        "genXDispatcher",
        "extNativeExecute",
        "T",
        "Lkotlin/Function0;",
        "Llx0/o;",
        "function",
        "dispatchSuspendedWithResult",
        "(Ltechnology/cariad/cat/genx/GenXDispatcher;Lay0/a;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;",
        "dispatchSuspendedWithValue",
        "Llx0/b0;",
        "dispatchSuspended",
        "checkStatusDispatched",
        "genx_release"
    }
    k = 0x2
    mv = {
        0x2,
        0x2,
        0x0
    }
    xi = 0x30
.end annotation


# direct methods
.method public static final checkStatusDispatched(Ltechnology/cariad/cat/genx/GenXDispatcher;Lay0/a;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 9
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ltechnology/cariad/cat/genx/GenXDispatcher;",
            "Lay0/a;",
            "Lkotlin/coroutines/Continuation<",
            "-",
            "Llx0/o;",
            ">;)",
            "Ljava/lang/Object;"
        }
    .end annotation

    .line 1
    instance-of v0, p2, Ltechnology/cariad/cat/genx/GenXDispatcherKt$checkStatusDispatched$1;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p2

    .line 6
    check-cast v0, Ltechnology/cariad/cat/genx/GenXDispatcherKt$checkStatusDispatched$1;

    .line 7
    .line 8
    iget v1, v0, Ltechnology/cariad/cat/genx/GenXDispatcherKt$checkStatusDispatched$1;->label:I

    .line 9
    .line 10
    const/high16 v2, -0x80000000

    .line 11
    .line 12
    and-int v3, v1, v2

    .line 13
    .line 14
    if-eqz v3, :cond_0

    .line 15
    .line 16
    sub-int/2addr v1, v2

    .line 17
    iput v1, v0, Ltechnology/cariad/cat/genx/GenXDispatcherKt$checkStatusDispatched$1;->label:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Ltechnology/cariad/cat/genx/GenXDispatcherKt$checkStatusDispatched$1;

    .line 21
    .line 22
    invoke-direct {v0, p2}, Ltechnology/cariad/cat/genx/GenXDispatcherKt$checkStatusDispatched$1;-><init>(Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p2, v0, Ltechnology/cariad/cat/genx/GenXDispatcherKt$checkStatusDispatched$1;->result:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Ltechnology/cariad/cat/genx/GenXDispatcherKt$checkStatusDispatched$1;->label:I

    .line 30
    .line 31
    const/4 v3, 0x1

    .line 32
    if-eqz v2, :cond_2

    .line 33
    .line 34
    if-ne v2, v3, :cond_1

    .line 35
    .line 36
    iget-object p0, v0, Ltechnology/cariad/cat/genx/GenXDispatcherKt$checkStatusDispatched$1;->L$1:Ljava/lang/Object;

    .line 37
    .line 38
    check-cast p0, Lay0/a;

    .line 39
    .line 40
    iget-object p0, v0, Ltechnology/cariad/cat/genx/GenXDispatcherKt$checkStatusDispatched$1;->L$0:Ljava/lang/Object;

    .line 41
    .line 42
    check-cast p0, Ltechnology/cariad/cat/genx/GenXDispatcher;

    .line 43
    .line 44
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 45
    .line 46
    .line 47
    goto :goto_2

    .line 48
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 49
    .line 50
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 51
    .line 52
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 53
    .line 54
    .line 55
    throw p0

    .line 56
    :cond_2
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 57
    .line 58
    .line 59
    iput-object p0, v0, Ltechnology/cariad/cat/genx/GenXDispatcherKt$checkStatusDispatched$1;->L$0:Ljava/lang/Object;

    .line 60
    .line 61
    iput-object p1, v0, Ltechnology/cariad/cat/genx/GenXDispatcherKt$checkStatusDispatched$1;->L$1:Ljava/lang/Object;

    .line 62
    .line 63
    const/4 p2, 0x0

    .line 64
    iput p2, v0, Ltechnology/cariad/cat/genx/GenXDispatcherKt$checkStatusDispatched$1;->I$0:I

    .line 65
    .line 66
    iput v3, v0, Ltechnology/cariad/cat/genx/GenXDispatcherKt$checkStatusDispatched$1;->label:I

    .line 67
    .line 68
    new-instance p2, Lpx0/i;

    .line 69
    .line 70
    invoke-static {v0}, Ljp/hg;->b(Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 71
    .line 72
    .line 73
    move-result-object v0

    .line 74
    invoke-direct {p2, v0}, Lpx0/i;-><init>(Lkotlin/coroutines/Continuation;)V

    .line 75
    .line 76
    .line 77
    :try_start_0
    new-instance v0, Ltechnology/cariad/cat/genx/GenXDispatcherKt$checkStatusDispatched$2$1;

    .line 78
    .line 79
    invoke-direct {v0, p2, p1}, Ltechnology/cariad/cat/genx/GenXDispatcherKt$checkStatusDispatched$2$1;-><init>(Lkotlin/coroutines/Continuation;Lay0/a;)V

    .line 80
    .line 81
    .line 82
    invoke-interface {p0, v0}, Ltechnology/cariad/cat/genx/GenXDispatcher;->dispatch(Lay0/a;)V
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    .line 83
    .line 84
    .line 85
    goto :goto_1

    .line 86
    :catch_0
    move-exception v0

    .line 87
    move-object p1, v0

    .line 88
    move-object v6, p1

    .line 89
    sget-object v5, Ltechnology/cariad/cat/genx/GenXDispatcherKt$checkStatusDispatched$2$2;->INSTANCE:Ltechnology/cariad/cat/genx/GenXDispatcherKt$checkStatusDispatched$2$2;

    .line 90
    .line 91
    new-instance v2, Lt51/j;

    .line 92
    .line 93
    invoke-static {p0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 94
    .line 95
    .line 96
    move-result-object v7

    .line 97
    const-string p0, "getName(...)"

    .line 98
    .line 99
    invoke-static {p0}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 100
    .line 101
    .line 102
    move-result-object v8

    .line 103
    const-string v3, "GenX"

    .line 104
    .line 105
    sget-object v4, Lt51/e;->a:Lt51/e;

    .line 106
    .line 107
    invoke-direct/range {v2 .. v8}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 108
    .line 109
    .line 110
    invoke-static {v2}, Lt51/a;->a(Lt51/j;)V

    .line 111
    .line 112
    .line 113
    new-instance p0, Ltechnology/cariad/cat/genx/GenXError$CoreGenX;

    .line 114
    .line 115
    sget-object p1, Ltechnology/cariad/cat/genx/CoreGenXStatus;->Companion:Ltechnology/cariad/cat/genx/CoreGenXStatus$Companion;

    .line 116
    .line 117
    invoke-virtual {p1}, Ltechnology/cariad/cat/genx/CoreGenXStatus$Companion;->getInternal()Ltechnology/cariad/cat/genx/CoreGenXStatus;

    .line 118
    .line 119
    .line 120
    move-result-object p1

    .line 121
    invoke-virtual {v6}, Ljava/lang/Throwable;->getMessage()Ljava/lang/String;

    .line 122
    .line 123
    .line 124
    move-result-object v0

    .line 125
    if-nez v0, :cond_3

    .line 126
    .line 127
    const-string v0, "Internal error on the Dispatcher"

    .line 128
    .line 129
    :cond_3
    invoke-direct {p0, p1, v0}, Ltechnology/cariad/cat/genx/GenXError$CoreGenX;-><init>(Ltechnology/cariad/cat/genx/CoreGenXStatus;Ljava/lang/String;)V

    .line 130
    .line 131
    .line 132
    invoke-static {p0}, Lps/t1;->a(Ljava/lang/Throwable;)Llx0/n;

    .line 133
    .line 134
    .line 135
    move-result-object p0

    .line 136
    invoke-virtual {p2, p0}, Lpx0/i;->resumeWith(Ljava/lang/Object;)V

    .line 137
    .line 138
    .line 139
    :goto_1
    invoke-virtual {p2}, Lpx0/i;->a()Ljava/lang/Object;

    .line 140
    .line 141
    .line 142
    move-result-object p2

    .line 143
    sget-object p0, Lqx0/a;->d:Lqx0/a;

    .line 144
    .line 145
    if-ne p2, v1, :cond_4

    .line 146
    .line 147
    return-object v1

    .line 148
    :cond_4
    :goto_2
    check-cast p2, Llx0/o;

    .line 149
    .line 150
    iget-object p0, p2, Llx0/o;->d:Ljava/lang/Object;

    .line 151
    .line 152
    return-object p0
.end method

.method private static final checkStatusDispatched$$forInline(Ltechnology/cariad/cat/genx/GenXDispatcher;Lay0/a;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 9
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ltechnology/cariad/cat/genx/GenXDispatcher;",
            "Lay0/a;",
            "Lkotlin/coroutines/Continuation<",
            "-",
            "Llx0/o;",
            ">;)",
            "Ljava/lang/Object;"
        }
    .end annotation

    .line 1
    new-instance v1, Lpx0/i;

    .line 2
    .line 3
    invoke-static {p2}, Ljp/hg;->b(Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 4
    .line 5
    .line 6
    move-result-object p2

    .line 7
    invoke-direct {v1, p2}, Lpx0/i;-><init>(Lkotlin/coroutines/Continuation;)V

    .line 8
    .line 9
    .line 10
    :try_start_0
    new-instance p2, Ltechnology/cariad/cat/genx/GenXDispatcherKt$checkStatusDispatched$2$1;

    .line 11
    .line 12
    invoke-direct {p2, v1, p1}, Ltechnology/cariad/cat/genx/GenXDispatcherKt$checkStatusDispatched$2$1;-><init>(Lkotlin/coroutines/Continuation;Lay0/a;)V

    .line 13
    .line 14
    .line 15
    invoke-interface {p0, p2}, Ltechnology/cariad/cat/genx/GenXDispatcher;->dispatch(Lay0/a;)V
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    .line 16
    .line 17
    .line 18
    goto :goto_1

    .line 19
    :catch_0
    move-exception v0

    .line 20
    move-object p1, v0

    .line 21
    move-object v6, p1

    .line 22
    sget-object v5, Ltechnology/cariad/cat/genx/GenXDispatcherKt$checkStatusDispatched$2$2;->INSTANCE:Ltechnology/cariad/cat/genx/GenXDispatcherKt$checkStatusDispatched$2$2;

    .line 23
    .line 24
    new-instance v2, Lt51/j;

    .line 25
    .line 26
    invoke-static {p0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 27
    .line 28
    .line 29
    move-result-object v7

    .line 30
    const-string p0, "getName(...)"

    .line 31
    .line 32
    invoke-static {p0}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 33
    .line 34
    .line 35
    move-result-object v8

    .line 36
    const-string v3, "GenX"

    .line 37
    .line 38
    sget-object v4, Lt51/e;->a:Lt51/e;

    .line 39
    .line 40
    invoke-direct/range {v2 .. v8}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 41
    .line 42
    .line 43
    invoke-static {v2}, Lt51/a;->a(Lt51/j;)V

    .line 44
    .line 45
    .line 46
    new-instance p0, Ltechnology/cariad/cat/genx/GenXError$CoreGenX;

    .line 47
    .line 48
    sget-object p1, Ltechnology/cariad/cat/genx/CoreGenXStatus;->Companion:Ltechnology/cariad/cat/genx/CoreGenXStatus$Companion;

    .line 49
    .line 50
    invoke-virtual {p1}, Ltechnology/cariad/cat/genx/CoreGenXStatus$Companion;->getInternal()Ltechnology/cariad/cat/genx/CoreGenXStatus;

    .line 51
    .line 52
    .line 53
    move-result-object p1

    .line 54
    invoke-virtual {v6}, Ljava/lang/Throwable;->getMessage()Ljava/lang/String;

    .line 55
    .line 56
    .line 57
    move-result-object p2

    .line 58
    if-eqz p2, :cond_0

    .line 59
    .line 60
    goto :goto_0

    .line 61
    :cond_0
    const-string p2, "Internal error on the Dispatcher"

    .line 62
    .line 63
    :goto_0
    invoke-direct {p0, p1, p2}, Ltechnology/cariad/cat/genx/GenXError$CoreGenX;-><init>(Ltechnology/cariad/cat/genx/CoreGenXStatus;Ljava/lang/String;)V

    .line 64
    .line 65
    .line 66
    invoke-static {p0}, Lps/t1;->a(Ljava/lang/Throwable;)Llx0/n;

    .line 67
    .line 68
    .line 69
    move-result-object p0

    .line 70
    invoke-virtual {v1, p0}, Lpx0/i;->resumeWith(Ljava/lang/Object;)V

    .line 71
    .line 72
    .line 73
    :goto_1
    invoke-virtual {v1}, Lpx0/i;->a()Ljava/lang/Object;

    .line 74
    .line 75
    .line 76
    move-result-object p0

    .line 77
    sget-object p1, Lqx0/a;->d:Lqx0/a;

    .line 78
    .line 79
    check-cast p0, Llx0/o;

    .line 80
    .line 81
    iget-object p0, p0, Llx0/o;->d:Ljava/lang/Object;

    .line 82
    .line 83
    return-object p0
.end method

.method public static final dispatchSuspended(Ltechnology/cariad/cat/genx/GenXDispatcher;Lay0/a;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 9
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ltechnology/cariad/cat/genx/GenXDispatcher;",
            "Lay0/a;",
            "Lkotlin/coroutines/Continuation<",
            "-",
            "Llx0/b0;",
            ">;)",
            "Ljava/lang/Object;"
        }
    .end annotation

    .line 1
    new-instance v1, Lpx0/i;

    .line 2
    .line 3
    invoke-static {p2}, Ljp/hg;->b(Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 4
    .line 5
    .line 6
    move-result-object p2

    .line 7
    invoke-direct {v1, p2}, Lpx0/i;-><init>(Lkotlin/coroutines/Continuation;)V

    .line 8
    .line 9
    .line 10
    :try_start_0
    new-instance p2, Ltechnology/cariad/cat/genx/GenXDispatcherKt$dispatchSuspended$2$1;

    .line 11
    .line 12
    invoke-direct {p2, p1, v1}, Ltechnology/cariad/cat/genx/GenXDispatcherKt$dispatchSuspended$2$1;-><init>(Lay0/a;Lkotlin/coroutines/Continuation;)V

    .line 13
    .line 14
    .line 15
    invoke-interface {p0, p2}, Ltechnology/cariad/cat/genx/GenXDispatcher;->dispatch(Lay0/a;)V
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    .line 16
    .line 17
    .line 18
    goto :goto_0

    .line 19
    :catch_0
    move-exception v0

    .line 20
    move-object p1, v0

    .line 21
    move-object v6, p1

    .line 22
    sget-object v5, Ltechnology/cariad/cat/genx/GenXDispatcherKt$dispatchSuspended$2$2;->INSTANCE:Ltechnology/cariad/cat/genx/GenXDispatcherKt$dispatchSuspended$2$2;

    .line 23
    .line 24
    new-instance v2, Lt51/j;

    .line 25
    .line 26
    invoke-static {p0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 27
    .line 28
    .line 29
    move-result-object v7

    .line 30
    const-string p0, "getName(...)"

    .line 31
    .line 32
    invoke-static {p0}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 33
    .line 34
    .line 35
    move-result-object v8

    .line 36
    const-string v3, "GenX"

    .line 37
    .line 38
    sget-object v4, Lt51/e;->a:Lt51/e;

    .line 39
    .line 40
    invoke-direct/range {v2 .. v8}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 41
    .line 42
    .line 43
    invoke-static {v2}, Lt51/a;->a(Lt51/j;)V

    .line 44
    .line 45
    .line 46
    :goto_0
    invoke-virtual {v1}, Lpx0/i;->a()Ljava/lang/Object;

    .line 47
    .line 48
    .line 49
    move-result-object p0

    .line 50
    sget-object p1, Lqx0/a;->d:Lqx0/a;

    .line 51
    .line 52
    if-ne p0, p1, :cond_0

    .line 53
    .line 54
    return-object p0

    .line 55
    :cond_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 56
    .line 57
    return-object p0
.end method

.method public static final dispatchSuspendedWithResult(Ltechnology/cariad/cat/genx/GenXDispatcher;Lay0/a;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 9
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "<T:",
            "Ljava/lang/Object;",
            ">(",
            "Ltechnology/cariad/cat/genx/GenXDispatcher;",
            "Lay0/a;",
            "Lkotlin/coroutines/Continuation<",
            "-",
            "Llx0/o;",
            ">;)",
            "Ljava/lang/Object;"
        }
    .end annotation

    .line 1
    instance-of v0, p2, Ltechnology/cariad/cat/genx/GenXDispatcherKt$dispatchSuspendedWithResult$1;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p2

    .line 6
    check-cast v0, Ltechnology/cariad/cat/genx/GenXDispatcherKt$dispatchSuspendedWithResult$1;

    .line 7
    .line 8
    iget v1, v0, Ltechnology/cariad/cat/genx/GenXDispatcherKt$dispatchSuspendedWithResult$1;->label:I

    .line 9
    .line 10
    const/high16 v2, -0x80000000

    .line 11
    .line 12
    and-int v3, v1, v2

    .line 13
    .line 14
    if-eqz v3, :cond_0

    .line 15
    .line 16
    sub-int/2addr v1, v2

    .line 17
    iput v1, v0, Ltechnology/cariad/cat/genx/GenXDispatcherKt$dispatchSuspendedWithResult$1;->label:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Ltechnology/cariad/cat/genx/GenXDispatcherKt$dispatchSuspendedWithResult$1;

    .line 21
    .line 22
    invoke-direct {v0, p2}, Ltechnology/cariad/cat/genx/GenXDispatcherKt$dispatchSuspendedWithResult$1;-><init>(Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p2, v0, Ltechnology/cariad/cat/genx/GenXDispatcherKt$dispatchSuspendedWithResult$1;->result:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Ltechnology/cariad/cat/genx/GenXDispatcherKt$dispatchSuspendedWithResult$1;->label:I

    .line 30
    .line 31
    const/4 v3, 0x1

    .line 32
    if-eqz v2, :cond_2

    .line 33
    .line 34
    if-ne v2, v3, :cond_1

    .line 35
    .line 36
    iget-object p0, v0, Ltechnology/cariad/cat/genx/GenXDispatcherKt$dispatchSuspendedWithResult$1;->L$1:Ljava/lang/Object;

    .line 37
    .line 38
    check-cast p0, Lay0/a;

    .line 39
    .line 40
    iget-object p0, v0, Ltechnology/cariad/cat/genx/GenXDispatcherKt$dispatchSuspendedWithResult$1;->L$0:Ljava/lang/Object;

    .line 41
    .line 42
    check-cast p0, Ltechnology/cariad/cat/genx/GenXDispatcher;

    .line 43
    .line 44
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 45
    .line 46
    .line 47
    goto :goto_2

    .line 48
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 49
    .line 50
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 51
    .line 52
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 53
    .line 54
    .line 55
    throw p0

    .line 56
    :cond_2
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 57
    .line 58
    .line 59
    iput-object p0, v0, Ltechnology/cariad/cat/genx/GenXDispatcherKt$dispatchSuspendedWithResult$1;->L$0:Ljava/lang/Object;

    .line 60
    .line 61
    iput-object p1, v0, Ltechnology/cariad/cat/genx/GenXDispatcherKt$dispatchSuspendedWithResult$1;->L$1:Ljava/lang/Object;

    .line 62
    .line 63
    iput v3, v0, Ltechnology/cariad/cat/genx/GenXDispatcherKt$dispatchSuspendedWithResult$1;->label:I

    .line 64
    .line 65
    new-instance p2, Lpx0/i;

    .line 66
    .line 67
    invoke-static {v0}, Ljp/hg;->b(Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 68
    .line 69
    .line 70
    move-result-object v0

    .line 71
    invoke-direct {p2, v0}, Lpx0/i;-><init>(Lkotlin/coroutines/Continuation;)V

    .line 72
    .line 73
    .line 74
    :try_start_0
    new-instance v0, Ltechnology/cariad/cat/genx/GenXDispatcherKt$dispatchSuspendedWithResult$2$1;

    .line 75
    .line 76
    invoke-direct {v0, p1, p2}, Ltechnology/cariad/cat/genx/GenXDispatcherKt$dispatchSuspendedWithResult$2$1;-><init>(Lay0/a;Lkotlin/coroutines/Continuation;)V

    .line 77
    .line 78
    .line 79
    invoke-interface {p0, v0}, Ltechnology/cariad/cat/genx/GenXDispatcher;->dispatch(Lay0/a;)V
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    .line 80
    .line 81
    .line 82
    goto :goto_1

    .line 83
    :catch_0
    move-exception v0

    .line 84
    move-object p1, v0

    .line 85
    move-object v6, p1

    .line 86
    sget-object v5, Ltechnology/cariad/cat/genx/GenXDispatcherKt$dispatchSuspendedWithResult$2$2;->INSTANCE:Ltechnology/cariad/cat/genx/GenXDispatcherKt$dispatchSuspendedWithResult$2$2;

    .line 87
    .line 88
    new-instance v2, Lt51/j;

    .line 89
    .line 90
    invoke-static {p0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 91
    .line 92
    .line 93
    move-result-object v7

    .line 94
    const-string p0, "getName(...)"

    .line 95
    .line 96
    invoke-static {p0}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 97
    .line 98
    .line 99
    move-result-object v8

    .line 100
    const-string v3, "GenX"

    .line 101
    .line 102
    sget-object v4, Lt51/e;->a:Lt51/e;

    .line 103
    .line 104
    invoke-direct/range {v2 .. v8}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 105
    .line 106
    .line 107
    invoke-static {v2}, Lt51/a;->a(Lt51/j;)V

    .line 108
    .line 109
    .line 110
    invoke-static {v6}, Lps/t1;->a(Ljava/lang/Throwable;)Llx0/n;

    .line 111
    .line 112
    .line 113
    move-result-object p0

    .line 114
    new-instance p1, Llx0/o;

    .line 115
    .line 116
    invoke-direct {p1, p0}, Llx0/o;-><init>(Ljava/lang/Object;)V

    .line 117
    .line 118
    .line 119
    invoke-virtual {p2, p1}, Lpx0/i;->resumeWith(Ljava/lang/Object;)V

    .line 120
    .line 121
    .line 122
    :goto_1
    invoke-virtual {p2}, Lpx0/i;->a()Ljava/lang/Object;

    .line 123
    .line 124
    .line 125
    move-result-object p2

    .line 126
    sget-object p0, Lqx0/a;->d:Lqx0/a;

    .line 127
    .line 128
    if-ne p2, v1, :cond_3

    .line 129
    .line 130
    return-object v1

    .line 131
    :cond_3
    :goto_2
    check-cast p2, Llx0/o;

    .line 132
    .line 133
    iget-object p0, p2, Llx0/o;->d:Ljava/lang/Object;

    .line 134
    .line 135
    return-object p0
.end method

.method public static final dispatchSuspendedWithValue(Ltechnology/cariad/cat/genx/GenXDispatcher;Lay0/a;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 9
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "<T:",
            "Ljava/lang/Object;",
            ">(",
            "Ltechnology/cariad/cat/genx/GenXDispatcher;",
            "Lay0/a;",
            "Lkotlin/coroutines/Continuation<",
            "-TT;>;)",
            "Ljava/lang/Object;"
        }
    .end annotation

    .line 1
    new-instance v1, Lpx0/i;

    .line 2
    .line 3
    invoke-static {p2}, Ljp/hg;->b(Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 4
    .line 5
    .line 6
    move-result-object p2

    .line 7
    invoke-direct {v1, p2}, Lpx0/i;-><init>(Lkotlin/coroutines/Continuation;)V

    .line 8
    .line 9
    .line 10
    :try_start_0
    new-instance p2, Ltechnology/cariad/cat/genx/GenXDispatcherKt$dispatchSuspendedWithValue$2$1;

    .line 11
    .line 12
    invoke-direct {p2, p1, v1}, Ltechnology/cariad/cat/genx/GenXDispatcherKt$dispatchSuspendedWithValue$2$1;-><init>(Lay0/a;Lkotlin/coroutines/Continuation;)V

    .line 13
    .line 14
    .line 15
    invoke-interface {p0, p2}, Ltechnology/cariad/cat/genx/GenXDispatcher;->dispatch(Lay0/a;)V
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    .line 16
    .line 17
    .line 18
    goto :goto_0

    .line 19
    :catch_0
    move-exception v0

    .line 20
    move-object p1, v0

    .line 21
    move-object v6, p1

    .line 22
    sget-object v5, Ltechnology/cariad/cat/genx/GenXDispatcherKt$dispatchSuspendedWithValue$2$2;->INSTANCE:Ltechnology/cariad/cat/genx/GenXDispatcherKt$dispatchSuspendedWithValue$2$2;

    .line 23
    .line 24
    new-instance v2, Lt51/j;

    .line 25
    .line 26
    invoke-static {p0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 27
    .line 28
    .line 29
    move-result-object v7

    .line 30
    const-string p0, "getName(...)"

    .line 31
    .line 32
    invoke-static {p0}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 33
    .line 34
    .line 35
    move-result-object v8

    .line 36
    const-string v3, "GenX"

    .line 37
    .line 38
    sget-object v4, Lt51/e;->a:Lt51/e;

    .line 39
    .line 40
    invoke-direct/range {v2 .. v8}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 41
    .line 42
    .line 43
    invoke-static {v2}, Lt51/a;->a(Lt51/j;)V

    .line 44
    .line 45
    .line 46
    const/4 p0, 0x0

    .line 47
    invoke-virtual {v1, p0}, Lpx0/i;->resumeWith(Ljava/lang/Object;)V

    .line 48
    .line 49
    .line 50
    :goto_0
    invoke-virtual {v1}, Lpx0/i;->a()Ljava/lang/Object;

    .line 51
    .line 52
    .line 53
    move-result-object p0

    .line 54
    sget-object p1, Lqx0/a;->d:Lqx0/a;

    .line 55
    .line 56
    return-object p0
.end method

.method private static final native extNativeExecute(Ltechnology/cariad/cat/genx/GenXDispatcher;JJ)I
    .annotation build Ltechnology/cariad/cat/genx/RequiresGenXDispatch;
    .end annotation
.end method

.method public static final nativeExecute(Ltechnology/cariad/cat/genx/GenXDispatcher;JJ)I
    .locals 1
    .annotation build Ltechnology/cariad/cat/genx/RequiresGenXDispatch;
    .end annotation

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-static {p0, p1, p2, p3, p4}, Ltechnology/cariad/cat/genx/GenXDispatcherKt;->extNativeExecute(Ltechnology/cariad/cat/genx/GenXDispatcher;JJ)I

    .line 7
    .line 8
    .line 9
    move-result p0

    .line 10
    return p0
.end method
