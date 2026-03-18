.class final Ltechnology/cariad/cat/genx/VehicleManagerImpl$stopScanningForToken$1;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# annotations
.annotation system Ldalvik/annotation/EnclosingMethod;
    value = Ltechnology/cariad/cat/genx/VehicleManagerImpl;->stopScanningForToken$genx_release(Ltechnology/cariad/cat/genx/ScanningManager$ScanningToken;)V
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = null
.end annotation

.annotation system Ldalvik/annotation/Signature;
    value = {
        "Lrx0/i;",
        "Lay0/n;"
    }
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000\u000c\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0002\u0010\u0002\u001a\u00020\u0001*\u00020\u0000H\n\u00a2\u0006\u0004\u0008\u0002\u0010\u0003"
    }
    d2 = {
        "Lvy0/b0;",
        "Llx0/b0;",
        "<anonymous>",
        "(Lvy0/b0;)V"
    }
    k = 0x3
    mv = {
        0x2,
        0x2,
        0x0
    }
.end annotation

.annotation runtime Lrx0/e;
    c = "technology.cariad.cat.genx.VehicleManagerImpl$stopScanningForToken$1"
    f = "VehicleManagerImpl.kt"
    l = {
        0x3f5
    }
    m = "invokeSuspend"
    v = 0x1
.end annotation


# instance fields
.field final synthetic $token:Ltechnology/cariad/cat/genx/ScanningManager$ScanningToken;

.field I$0:I

.field private synthetic L$0:Ljava/lang/Object;

.field L$1:Ljava/lang/Object;

.field L$2:Ljava/lang/Object;

.field L$3:Ljava/lang/Object;

.field label:I

.field final synthetic this$0:Ltechnology/cariad/cat/genx/VehicleManagerImpl;


# direct methods
.method public constructor <init>(Ltechnology/cariad/cat/genx/VehicleManagerImpl;Ltechnology/cariad/cat/genx/ScanningManager$ScanningToken;Lkotlin/coroutines/Continuation;)V
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ltechnology/cariad/cat/genx/VehicleManagerImpl;",
            "Ltechnology/cariad/cat/genx/ScanningManager$ScanningToken;",
            "Lkotlin/coroutines/Continuation<",
            "-",
            "Ltechnology/cariad/cat/genx/VehicleManagerImpl$stopScanningForToken$1;",
            ">;)V"
        }
    .end annotation

    .line 1
    iput-object p1, p0, Ltechnology/cariad/cat/genx/VehicleManagerImpl$stopScanningForToken$1;->this$0:Ltechnology/cariad/cat/genx/VehicleManagerImpl;

    .line 2
    .line 3
    iput-object p2, p0, Ltechnology/cariad/cat/genx/VehicleManagerImpl$stopScanningForToken$1;->$token:Ltechnology/cariad/cat/genx/ScanningManager$ScanningToken;

    .line 4
    .line 5
    const/4 p1, 0x2

    .line 6
    invoke-direct {p0, p1, p3}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 7
    .line 8
    .line 9
    return-void
.end method

.method public static synthetic b(Ltechnology/cariad/cat/genx/VehicleManagerImpl;Lvy0/b0;)Llx0/b0;
    .locals 0

    .line 1
    invoke-static {p0, p1}, Ltechnology/cariad/cat/genx/VehicleManagerImpl$stopScanningForToken$1;->invokeSuspend$lambda$0$1(Ltechnology/cariad/cat/genx/VehicleManagerImpl;Lvy0/b0;)Llx0/b0;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic d()Ljava/lang/String;
    .locals 1

    .line 1
    invoke-static {}, Ltechnology/cariad/cat/genx/VehicleManagerImpl$stopScanningForToken$1;->invokeSuspend$lambda$0$0()Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    return-object v0
.end method

.method public static synthetic e()Ljava/lang/String;
    .locals 1

    .line 1
    invoke-static {}, Ltechnology/cariad/cat/genx/VehicleManagerImpl$stopScanningForToken$1;->invokeSuspend$lambda$0$1$1$0()Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    return-object v0
.end method

.method public static synthetic f(Ltechnology/cariad/cat/genx/VehicleManagerImpl;)I
    .locals 0

    .line 1
    invoke-static {p0}, Ltechnology/cariad/cat/genx/VehicleManagerImpl$stopScanningForToken$1;->invokeSuspend$lambda$0$1$0(Ltechnology/cariad/cat/genx/VehicleManagerImpl;)I

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    return p0
.end method

.method private static final invokeSuspend$lambda$0$0()Ljava/lang/String;
    .locals 1

    .line 1
    const-string v0, "stopScanningForToken(): No tokens are registered anymore -> stop Scanning"

    .line 2
    .line 3
    return-object v0
.end method

.method private static final invokeSuspend$lambda$0$1(Ltechnology/cariad/cat/genx/VehicleManagerImpl;Lvy0/b0;)Llx0/b0;
    .locals 2

    .line 1
    new-instance v0, Ltechnology/cariad/cat/genx/v0;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-direct {v0, p0, v1}, Ltechnology/cariad/cat/genx/v0;-><init>(Ltechnology/cariad/cat/genx/VehicleManagerImpl;I)V

    .line 5
    .line 6
    .line 7
    invoke-static {v0}, Ltechnology/cariad/cat/genx/GenXErrorKt;->checkStatus(Lay0/a;)Ltechnology/cariad/cat/genx/GenXError$CoreGenX;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    if-eqz p0, :cond_0

    .line 12
    .line 13
    new-instance v0, Ltechnology/cariad/cat/genx/s0;

    .line 14
    .line 15
    const/4 v1, 0x7

    .line 16
    invoke-direct {v0, v1}, Ltechnology/cariad/cat/genx/s0;-><init>(I)V

    .line 17
    .line 18
    .line 19
    const-string v1, "GenX"

    .line 20
    .line 21
    invoke-static {p1, v1, p0, v0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->logWarn(Ljava/lang/Object;Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;)V

    .line 22
    .line 23
    .line 24
    :cond_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 25
    .line 26
    return-object p0
.end method

.method private static final invokeSuspend$lambda$0$1$0(Ltechnology/cariad/cat/genx/VehicleManagerImpl;)I
    .locals 0

    .line 1
    invoke-static {p0}, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->access$nativeStopScanningForClients(Ltechnology/cariad/cat/genx/VehicleManagerImpl;)I

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    return p0
.end method

.method private static final invokeSuspend$lambda$0$1$1$0()Ljava/lang/String;
    .locals 1

    .line 1
    const-string v0, "stopScanningForToken(): Error during stopScanning"

    .line 2
    .line 3
    return-object v0
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;
    .locals 2
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/lang/Object;",
            "Lkotlin/coroutines/Continuation<",
            "*>;)",
            "Lkotlin/coroutines/Continuation<",
            "Llx0/b0;",
            ">;"
        }
    .end annotation

    .line 1
    new-instance v0, Ltechnology/cariad/cat/genx/VehicleManagerImpl$stopScanningForToken$1;

    .line 2
    .line 3
    iget-object v1, p0, Ltechnology/cariad/cat/genx/VehicleManagerImpl$stopScanningForToken$1;->this$0:Ltechnology/cariad/cat/genx/VehicleManagerImpl;

    .line 4
    .line 5
    iget-object p0, p0, Ltechnology/cariad/cat/genx/VehicleManagerImpl$stopScanningForToken$1;->$token:Ltechnology/cariad/cat/genx/ScanningManager$ScanningToken;

    .line 6
    .line 7
    invoke-direct {v0, v1, p0, p2}, Ltechnology/cariad/cat/genx/VehicleManagerImpl$stopScanningForToken$1;-><init>(Ltechnology/cariad/cat/genx/VehicleManagerImpl;Ltechnology/cariad/cat/genx/ScanningManager$ScanningToken;Lkotlin/coroutines/Continuation;)V

    .line 8
    .line 9
    .line 10
    iput-object p1, v0, Ltechnology/cariad/cat/genx/VehicleManagerImpl$stopScanningForToken$1;->L$0:Ljava/lang/Object;

    .line 11
    .line 12
    return-object v0
.end method

.method public bridge synthetic invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Lvy0/b0;

    check-cast p2, Lkotlin/coroutines/Continuation;

    invoke-virtual {p0, p1, p2}, Ltechnology/cariad/cat/genx/VehicleManagerImpl$stopScanningForToken$1;->invoke(Lvy0/b0;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    move-result-object p0

    return-object p0
.end method

.method public final invoke(Lvy0/b0;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lvy0/b0;",
            "Lkotlin/coroutines/Continuation<",
            "-",
            "Llx0/b0;",
            ">;)",
            "Ljava/lang/Object;"
        }
    .end annotation

    .line 2
    invoke-virtual {p0, p1, p2}, Ltechnology/cariad/cat/genx/VehicleManagerImpl$stopScanningForToken$1;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    move-result-object p0

    check-cast p0, Ltechnology/cariad/cat/genx/VehicleManagerImpl$stopScanningForToken$1;

    sget-object p1, Llx0/b0;->a:Llx0/b0;

    invoke-virtual {p0, p1}, Ltechnology/cariad/cat/genx/VehicleManagerImpl$stopScanningForToken$1;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p0

    return-object p0
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 10

    .line 1
    iget-object v0, p0, Ltechnology/cariad/cat/genx/VehicleManagerImpl$stopScanningForToken$1;->L$0:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Lvy0/b0;

    .line 4
    .line 5
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 6
    .line 7
    iget v2, p0, Ltechnology/cariad/cat/genx/VehicleManagerImpl$stopScanningForToken$1;->label:I

    .line 8
    .line 9
    const/4 v3, 0x1

    .line 10
    if-eqz v2, :cond_1

    .line 11
    .line 12
    if-ne v2, v3, :cond_0

    .line 13
    .line 14
    iget-object v1, p0, Ltechnology/cariad/cat/genx/VehicleManagerImpl$stopScanningForToken$1;->L$3:Ljava/lang/Object;

    .line 15
    .line 16
    check-cast v1, Ltechnology/cariad/cat/genx/ScanningManager$ScanningToken;

    .line 17
    .line 18
    iget-object v2, p0, Ltechnology/cariad/cat/genx/VehicleManagerImpl$stopScanningForToken$1;->L$2:Ljava/lang/Object;

    .line 19
    .line 20
    check-cast v2, Ltechnology/cariad/cat/genx/VehicleManagerImpl;

    .line 21
    .line 22
    iget-object p0, p0, Ltechnology/cariad/cat/genx/VehicleManagerImpl$stopScanningForToken$1;->L$1:Ljava/lang/Object;

    .line 23
    .line 24
    check-cast p0, Lez0/a;

    .line 25
    .line 26
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 27
    .line 28
    .line 29
    goto :goto_0

    .line 30
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 31
    .line 32
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 33
    .line 34
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 35
    .line 36
    .line 37
    throw p0

    .line 38
    :cond_1
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 39
    .line 40
    .line 41
    iget-object p1, p0, Ltechnology/cariad/cat/genx/VehicleManagerImpl$stopScanningForToken$1;->this$0:Ltechnology/cariad/cat/genx/VehicleManagerImpl;

    .line 42
    .line 43
    invoke-static {p1}, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->access$getScanningMutex$p(Ltechnology/cariad/cat/genx/VehicleManagerImpl;)Lez0/a;

    .line 44
    .line 45
    .line 46
    move-result-object p1

    .line 47
    iget-object v2, p0, Ltechnology/cariad/cat/genx/VehicleManagerImpl$stopScanningForToken$1;->this$0:Ltechnology/cariad/cat/genx/VehicleManagerImpl;

    .line 48
    .line 49
    iget-object v4, p0, Ltechnology/cariad/cat/genx/VehicleManagerImpl$stopScanningForToken$1;->$token:Ltechnology/cariad/cat/genx/ScanningManager$ScanningToken;

    .line 50
    .line 51
    iput-object v0, p0, Ltechnology/cariad/cat/genx/VehicleManagerImpl$stopScanningForToken$1;->L$0:Ljava/lang/Object;

    .line 52
    .line 53
    iput-object p1, p0, Ltechnology/cariad/cat/genx/VehicleManagerImpl$stopScanningForToken$1;->L$1:Ljava/lang/Object;

    .line 54
    .line 55
    iput-object v2, p0, Ltechnology/cariad/cat/genx/VehicleManagerImpl$stopScanningForToken$1;->L$2:Ljava/lang/Object;

    .line 56
    .line 57
    iput-object v4, p0, Ltechnology/cariad/cat/genx/VehicleManagerImpl$stopScanningForToken$1;->L$3:Ljava/lang/Object;

    .line 58
    .line 59
    const/4 v5, 0x0

    .line 60
    iput v5, p0, Ltechnology/cariad/cat/genx/VehicleManagerImpl$stopScanningForToken$1;->I$0:I

    .line 61
    .line 62
    iput v3, p0, Ltechnology/cariad/cat/genx/VehicleManagerImpl$stopScanningForToken$1;->label:I

    .line 63
    .line 64
    invoke-interface {p1, p0}, Lez0/a;->a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 65
    .line 66
    .line 67
    move-result-object p0

    .line 68
    if-ne p0, v1, :cond_2

    .line 69
    .line 70
    return-object v1

    .line 71
    :cond_2
    move-object p0, p1

    .line 72
    move-object v1, v4

    .line 73
    :goto_0
    const/4 p1, 0x0

    .line 74
    :try_start_0
    invoke-virtual {v2}, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->getActiveScanningTokens$genx_release()Ljava/util/concurrent/CopyOnWriteArrayList;

    .line 75
    .line 76
    .line 77
    move-result-object v3

    .line 78
    invoke-virtual {v3, v1}, Ljava/util/concurrent/CopyOnWriteArrayList;->remove(Ljava/lang/Object;)Z

    .line 79
    .line 80
    .line 81
    move-result v1

    .line 82
    if-eqz v1, :cond_3

    .line 83
    .line 84
    invoke-virtual {v2}, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->getActiveScanningTokens$genx_release()Ljava/util/concurrent/CopyOnWriteArrayList;

    .line 85
    .line 86
    .line 87
    move-result-object v1

    .line 88
    invoke-virtual {v1}, Ljava/util/concurrent/CopyOnWriteArrayList;->isEmpty()Z

    .line 89
    .line 90
    .line 91
    move-result v1

    .line 92
    if-eqz v1, :cond_3

    .line 93
    .line 94
    new-instance v6, Ltechnology/cariad/cat/genx/s0;

    .line 95
    .line 96
    const/4 v1, 0x6

    .line 97
    invoke-direct {v6, v1}, Ltechnology/cariad/cat/genx/s0;-><init>(I)V

    .line 98
    .line 99
    .line 100
    const-string v4, "GenX"

    .line 101
    .line 102
    new-instance v3, Lt51/j;

    .line 103
    .line 104
    sget-object v5, Lt51/g;->a:Lt51/g;

    .line 105
    .line 106
    invoke-static {v0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 107
    .line 108
    .line 109
    move-result-object v8

    .line 110
    invoke-static {}, Ljava/lang/Thread;->currentThread()Ljava/lang/Thread;

    .line 111
    .line 112
    .line 113
    move-result-object v1

    .line 114
    invoke-virtual {v1}, Ljava/lang/Thread;->getName()Ljava/lang/String;

    .line 115
    .line 116
    .line 117
    move-result-object v9

    .line 118
    const-string v1, "getName(...)"

    .line 119
    .line 120
    invoke-static {v9, v1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 121
    .line 122
    .line 123
    const/4 v7, 0x0

    .line 124
    invoke-direct/range {v3 .. v9}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 125
    .line 126
    .line 127
    invoke-static {v3}, Lt51/a;->a(Lt51/j;)V

    .line 128
    .line 129
    .line 130
    invoke-virtual {v2}, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->getGenXDispatcher()Ltechnology/cariad/cat/genx/GenXDispatcher;

    .line 131
    .line 132
    .line 133
    move-result-object v1

    .line 134
    new-instance v3, Ltechnology/cariad/cat/genx/u0;

    .line 135
    .line 136
    const/4 v4, 0x0

    .line 137
    invoke-direct {v3, v4, v2, v0}, Ltechnology/cariad/cat/genx/u0;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 138
    .line 139
    .line 140
    invoke-interface {v1, v3}, Ltechnology/cariad/cat/genx/GenXDispatcher;->dispatch(Lay0/a;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 141
    .line 142
    .line 143
    goto :goto_1

    .line 144
    :catchall_0
    move-exception v0

    .line 145
    goto :goto_2

    .line 146
    :cond_3
    :goto_1
    invoke-interface {p0, p1}, Lez0/a;->d(Ljava/lang/Object;)V

    .line 147
    .line 148
    .line 149
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 150
    .line 151
    return-object p0

    .line 152
    :goto_2
    invoke-interface {p0, p1}, Lez0/a;->d(Ljava/lang/Object;)V

    .line 153
    .line 154
    .line 155
    throw v0
.end method
