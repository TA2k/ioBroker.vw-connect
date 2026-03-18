.class final Ltechnology/cariad/cat/genx/wifi/WifiClientManager$3;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# annotations
.annotation system Ldalvik/annotation/EnclosingMethod;
    value = Ltechnology/cariad/cat/genx/wifi/WifiClientManager;-><init>(Landroid/content/Context;Ltechnology/cariad/cat/genx/GenXDispatcher;Lvy0/b0;Ltechnology/cariad/cat/genx/wifi/BonjourDiscoveryManager;Ltechnology/cariad/cat/genx/wifi/WifiManager;)V
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
        "\u0000\u000e\n\u0002\u0010\u000b\n\u0000\n\u0002\u0018\u0002\n\u0002\u0008\u0002\u0010\u0003\u001a\u00020\u00022\u0006\u0010\u0001\u001a\u00020\u0000H\n\u00a2\u0006\u0004\u0008\u0003\u0010\u0004"
    }
    d2 = {
        "",
        "isWifiEnabled",
        "Llx0/b0;",
        "<anonymous>",
        "(Z)V"
    }
    k = 0x3
    mv = {
        0x2,
        0x2,
        0x0
    }
.end annotation

.annotation runtime Lrx0/e;
    c = "technology.cariad.cat.genx.wifi.WifiClientManager$3"
    f = "WifiClientManager.kt"
    l = {
        0xae
    }
    m = "invokeSuspend"
    v = 0x1
.end annotation


# instance fields
.field I$0:I

.field L$0:Ljava/lang/Object;

.field L$1:Ljava/lang/Object;

.field synthetic Z$0:Z

.field label:I

.field final synthetic this$0:Ltechnology/cariad/cat/genx/wifi/WifiClientManager;


# direct methods
.method public constructor <init>(Ltechnology/cariad/cat/genx/wifi/WifiClientManager;Lkotlin/coroutines/Continuation;)V
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ltechnology/cariad/cat/genx/wifi/WifiClientManager;",
            "Lkotlin/coroutines/Continuation<",
            "-",
            "Ltechnology/cariad/cat/genx/wifi/WifiClientManager$3;",
            ">;)V"
        }
    .end annotation

    .line 1
    iput-object p1, p0, Ltechnology/cariad/cat/genx/wifi/WifiClientManager$3;->this$0:Ltechnology/cariad/cat/genx/wifi/WifiClientManager;

    .line 2
    .line 3
    const/4 p1, 0x2

    .line 4
    invoke-direct {p0, p1, p2}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 5
    .line 6
    .line 7
    return-void
.end method

.method public static synthetic b()Ljava/lang/String;
    .locals 1

    .line 1
    invoke-static {}, Ltechnology/cariad/cat/genx/wifi/WifiClientManager$3;->invokeSuspend$lambda$1$1$0()Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    return-object v0
.end method

.method public static synthetic d()Ljava/lang/String;
    .locals 1

    .line 1
    invoke-static {}, Ltechnology/cariad/cat/genx/wifi/WifiClientManager$3;->invokeSuspend$lambda$2()Ljava/lang/String;

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
    invoke-static {}, Ltechnology/cariad/cat/genx/wifi/WifiClientManager$3;->invokeSuspend$lambda$1$0()Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    return-object v0
.end method

.method public static synthetic f(Ltechnology/cariad/cat/genx/wifi/WifiClientManager;Z)Llx0/b0;
    .locals 0

    .line 1
    invoke-static {p0, p1}, Ltechnology/cariad/cat/genx/wifi/WifiClientManager$3;->invokeSuspend$lambda$0(Ltechnology/cariad/cat/genx/wifi/WifiClientManager;Z)Llx0/b0;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method private static final invokeSuspend$lambda$0(Ltechnology/cariad/cat/genx/wifi/WifiClientManager;Z)Llx0/b0;
    .locals 1

    .line 1
    invoke-virtual {p0}, Ltechnology/cariad/cat/genx/wifi/WifiClientManager;->getDelegate()Ltechnology/cariad/cat/genx/ClientManagerDelegate;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    if-eqz p0, :cond_0

    .line 6
    .line 7
    sget-object v0, Ltechnology/cariad/cat/genx/TransportType;->WiFi:Ltechnology/cariad/cat/genx/TransportType;

    .line 8
    .line 9
    invoke-interface {p0, p1, v0}, Ltechnology/cariad/cat/genx/ClientManagerDelegate;->clientManagerDidUpdatedState(ZLtechnology/cariad/cat/genx/TransportType;)V

    .line 10
    .line 11
    .line 12
    :cond_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 13
    .line 14
    return-object p0
.end method

.method private static final invokeSuspend$lambda$1$0()Ljava/lang/String;
    .locals 1

    .line 1
    const-string v0, "onWifiStateChanged(): Start bonjour discovery"

    .line 2
    .line 3
    return-object v0
.end method

.method private static final invokeSuspend$lambda$1$1$0()Ljava/lang/String;
    .locals 1

    .line 1
    const-string v0, "onWifiStateChanged(): Failed to start bonjour discovery"

    .line 2
    .line 3
    return-object v0
.end method

.method private static final invokeSuspend$lambda$2()Ljava/lang/String;
    .locals 1

    .line 1
    const-string v0, "onWifiStateChanged(): Stop bonjour discovery"

    .line 2
    .line 3
    return-object v0
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;
    .locals 1
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
    new-instance v0, Ltechnology/cariad/cat/genx/wifi/WifiClientManager$3;

    .line 2
    .line 3
    iget-object p0, p0, Ltechnology/cariad/cat/genx/wifi/WifiClientManager$3;->this$0:Ltechnology/cariad/cat/genx/wifi/WifiClientManager;

    .line 4
    .line 5
    invoke-direct {v0, p0, p2}, Ltechnology/cariad/cat/genx/wifi/WifiClientManager$3;-><init>(Ltechnology/cariad/cat/genx/wifi/WifiClientManager;Lkotlin/coroutines/Continuation;)V

    .line 6
    .line 7
    .line 8
    check-cast p1, Ljava/lang/Boolean;

    .line 9
    .line 10
    invoke-virtual {p1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 11
    .line 12
    .line 13
    move-result p0

    .line 14
    iput-boolean p0, v0, Ltechnology/cariad/cat/genx/wifi/WifiClientManager$3;->Z$0:Z

    .line 15
    .line 16
    return-object v0
.end method

.method public bridge synthetic invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Ljava/lang/Boolean;

    invoke-virtual {p1}, Ljava/lang/Boolean;->booleanValue()Z

    move-result p1

    check-cast p2, Lkotlin/coroutines/Continuation;

    invoke-virtual {p0, p1, p2}, Ltechnology/cariad/cat/genx/wifi/WifiClientManager$3;->invoke(ZLkotlin/coroutines/Continuation;)Ljava/lang/Object;

    move-result-object p0

    return-object p0
.end method

.method public final invoke(ZLkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(Z",
            "Lkotlin/coroutines/Continuation<",
            "-",
            "Llx0/b0;",
            ">;)",
            "Ljava/lang/Object;"
        }
    .end annotation

    .line 2
    invoke-static {p1}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    move-result-object p1

    invoke-virtual {p0, p1, p2}, Ltechnology/cariad/cat/genx/wifi/WifiClientManager$3;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    move-result-object p0

    check-cast p0, Ltechnology/cariad/cat/genx/wifi/WifiClientManager$3;

    sget-object p1, Llx0/b0;->a:Llx0/b0;

    invoke-virtual {p0, p1}, Ltechnology/cariad/cat/genx/wifi/WifiClientManager$3;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p0

    return-object p0
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 11

    .line 1
    iget-boolean v0, p0, Ltechnology/cariad/cat/genx/wifi/WifiClientManager$3;->Z$0:Z

    .line 2
    .line 3
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 4
    .line 5
    iget v2, p0, Ltechnology/cariad/cat/genx/wifi/WifiClientManager$3;->label:I

    .line 6
    .line 7
    const-string v3, "getName(...)"

    .line 8
    .line 9
    sget-object v6, Lt51/g;->a:Lt51/g;

    .line 10
    .line 11
    const/4 v4, 0x1

    .line 12
    if-eqz v2, :cond_1

    .line 13
    .line 14
    if-ne v2, v4, :cond_0

    .line 15
    .line 16
    iget-object v0, p0, Ltechnology/cariad/cat/genx/wifi/WifiClientManager$3;->L$1:Ljava/lang/Object;

    .line 17
    .line 18
    check-cast v0, Ltechnology/cariad/cat/genx/wifi/WifiClientManager;

    .line 19
    .line 20
    iget-object p0, p0, Ltechnology/cariad/cat/genx/wifi/WifiClientManager$3;->L$0:Ljava/lang/Object;

    .line 21
    .line 22
    check-cast p0, Lez0/a;

    .line 23
    .line 24
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 25
    .line 26
    .line 27
    goto :goto_0

    .line 28
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 29
    .line 30
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 31
    .line 32
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 33
    .line 34
    .line 35
    throw p0

    .line 36
    :cond_1
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 37
    .line 38
    .line 39
    iget-object p1, p0, Ltechnology/cariad/cat/genx/wifi/WifiClientManager$3;->this$0:Ltechnology/cariad/cat/genx/wifi/WifiClientManager;

    .line 40
    .line 41
    invoke-virtual {p1}, Ltechnology/cariad/cat/genx/wifi/WifiClientManager;->getGenXDispatcher()Ltechnology/cariad/cat/genx/GenXDispatcher;

    .line 42
    .line 43
    .line 44
    move-result-object p1

    .line 45
    iget-object v2, p0, Ltechnology/cariad/cat/genx/wifi/WifiClientManager$3;->this$0:Ltechnology/cariad/cat/genx/wifi/WifiClientManager;

    .line 46
    .line 47
    new-instance v5, Ltechnology/cariad/cat/genx/wifi/h;

    .line 48
    .line 49
    invoke-direct {v5, v2, v0}, Ltechnology/cariad/cat/genx/wifi/h;-><init>(Ltechnology/cariad/cat/genx/wifi/WifiClientManager;Z)V

    .line 50
    .line 51
    .line 52
    invoke-interface {p1, v5}, Ltechnology/cariad/cat/genx/GenXDispatcher;->dispatch(Lay0/a;)V

    .line 53
    .line 54
    .line 55
    if-eqz v0, :cond_4

    .line 56
    .line 57
    iget-object p1, p0, Ltechnology/cariad/cat/genx/wifi/WifiClientManager$3;->this$0:Ltechnology/cariad/cat/genx/wifi/WifiClientManager;

    .line 58
    .line 59
    invoke-static {p1}, Ltechnology/cariad/cat/genx/wifi/WifiClientManager;->access$getStartScanningMutex$p(Ltechnology/cariad/cat/genx/wifi/WifiClientManager;)Lez0/a;

    .line 60
    .line 61
    .line 62
    move-result-object p1

    .line 63
    iget-object v2, p0, Ltechnology/cariad/cat/genx/wifi/WifiClientManager$3;->this$0:Ltechnology/cariad/cat/genx/wifi/WifiClientManager;

    .line 64
    .line 65
    iput-object p1, p0, Ltechnology/cariad/cat/genx/wifi/WifiClientManager$3;->L$0:Ljava/lang/Object;

    .line 66
    .line 67
    iput-object v2, p0, Ltechnology/cariad/cat/genx/wifi/WifiClientManager$3;->L$1:Ljava/lang/Object;

    .line 68
    .line 69
    iput-boolean v0, p0, Ltechnology/cariad/cat/genx/wifi/WifiClientManager$3;->Z$0:Z

    .line 70
    .line 71
    const/4 v0, 0x0

    .line 72
    iput v0, p0, Ltechnology/cariad/cat/genx/wifi/WifiClientManager$3;->I$0:I

    .line 73
    .line 74
    iput v4, p0, Ltechnology/cariad/cat/genx/wifi/WifiClientManager$3;->label:I

    .line 75
    .line 76
    invoke-interface {p1, p0}, Lez0/a;->a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 77
    .line 78
    .line 79
    move-result-object p0

    .line 80
    if-ne p0, v1, :cond_2

    .line 81
    .line 82
    return-object v1

    .line 83
    :cond_2
    move-object p0, p1

    .line 84
    move-object v0, v2

    .line 85
    :goto_0
    const/4 p1, 0x0

    .line 86
    :try_start_0
    invoke-static {v0}, Ltechnology/cariad/cat/genx/wifi/WifiClientManager;->access$getScanningWasRequested$p(Ltechnology/cariad/cat/genx/wifi/WifiClientManager;)Z

    .line 87
    .line 88
    .line 89
    move-result v1

    .line 90
    if-eqz v1, :cond_3

    .line 91
    .line 92
    invoke-static {v0}, Ltechnology/cariad/cat/genx/wifi/WifiClientManager;->access$getBonjourManager$p(Ltechnology/cariad/cat/genx/wifi/WifiClientManager;)Ltechnology/cariad/cat/genx/wifi/BonjourDiscoveryManager;

    .line 93
    .line 94
    .line 95
    move-result-object v1

    .line 96
    invoke-interface {v1}, Ltechnology/cariad/cat/genx/wifi/BonjourDiscoveryManager;->isBonjourScanningActive()Z

    .line 97
    .line 98
    .line 99
    move-result v1

    .line 100
    if-nez v1, :cond_3

    .line 101
    .line 102
    new-instance v7, Ltechnology/cariad/cat/genx/wifi/i;

    .line 103
    .line 104
    const/4 v1, 0x0

    .line 105
    invoke-direct {v7, v1}, Ltechnology/cariad/cat/genx/wifi/i;-><init>(I)V

    .line 106
    .line 107
    .line 108
    const-string v5, "GenX"

    .line 109
    .line 110
    new-instance v4, Lt51/j;

    .line 111
    .line 112
    invoke-static {v0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 113
    .line 114
    .line 115
    move-result-object v9

    .line 116
    invoke-static {}, Ljava/lang/Thread;->currentThread()Ljava/lang/Thread;

    .line 117
    .line 118
    .line 119
    move-result-object v1

    .line 120
    invoke-virtual {v1}, Ljava/lang/Thread;->getName()Ljava/lang/String;

    .line 121
    .line 122
    .line 123
    move-result-object v10

    .line 124
    invoke-static {v10, v3}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 125
    .line 126
    .line 127
    const/4 v8, 0x0

    .line 128
    invoke-direct/range {v4 .. v10}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 129
    .line 130
    .line 131
    invoke-static {v4}, Lt51/a;->a(Lt51/j;)V

    .line 132
    .line 133
    .line 134
    invoke-static {v0}, Ltechnology/cariad/cat/genx/wifi/WifiClientManager;->access$getBonjourManager$p(Ltechnology/cariad/cat/genx/wifi/WifiClientManager;)Ltechnology/cariad/cat/genx/wifi/BonjourDiscoveryManager;

    .line 135
    .line 136
    .line 137
    move-result-object v1

    .line 138
    invoke-interface {v1}, Ltechnology/cariad/cat/genx/wifi/BonjourDiscoveryManager;->startBonjourDiscovery-d1pmJ48()Ljava/lang/Object;

    .line 139
    .line 140
    .line 141
    move-result-object v1

    .line 142
    invoke-static {v1}, Llx0/o;->a(Ljava/lang/Object;)Ljava/lang/Throwable;

    .line 143
    .line 144
    .line 145
    move-result-object v1

    .line 146
    if-eqz v1, :cond_3

    .line 147
    .line 148
    new-instance v2, Ltechnology/cariad/cat/genx/wifi/i;

    .line 149
    .line 150
    const/4 v3, 0x1

    .line 151
    invoke-direct {v2, v3}, Ltechnology/cariad/cat/genx/wifi/i;-><init>(I)V

    .line 152
    .line 153
    .line 154
    const-string v3, "GenX"

    .line 155
    .line 156
    invoke-static {v0, v3, v1, v2}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->logWarn(Ljava/lang/Object;Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 157
    .line 158
    .line 159
    goto :goto_1

    .line 160
    :catchall_0
    move-exception v0

    .line 161
    goto :goto_2

    .line 162
    :cond_3
    :goto_1
    invoke-interface {p0, p1}, Lez0/a;->d(Ljava/lang/Object;)V

    .line 163
    .line 164
    .line 165
    goto :goto_3

    .line 166
    :goto_2
    invoke-interface {p0, p1}, Lez0/a;->d(Ljava/lang/Object;)V

    .line 167
    .line 168
    .line 169
    throw v0

    .line 170
    :cond_4
    iget-object p1, p0, Ltechnology/cariad/cat/genx/wifi/WifiClientManager$3;->this$0:Ltechnology/cariad/cat/genx/wifi/WifiClientManager;

    .line 171
    .line 172
    invoke-static {p1}, Ltechnology/cariad/cat/genx/wifi/WifiClientManager;->access$getBonjourManager$p(Ltechnology/cariad/cat/genx/wifi/WifiClientManager;)Ltechnology/cariad/cat/genx/wifi/BonjourDiscoveryManager;

    .line 173
    .line 174
    .line 175
    move-result-object p1

    .line 176
    invoke-interface {p1}, Ltechnology/cariad/cat/genx/wifi/BonjourDiscoveryManager;->isBonjourScanningActive()Z

    .line 177
    .line 178
    .line 179
    move-result p1

    .line 180
    if-eqz p1, :cond_5

    .line 181
    .line 182
    iget-object p1, p0, Ltechnology/cariad/cat/genx/wifi/WifiClientManager$3;->this$0:Ltechnology/cariad/cat/genx/wifi/WifiClientManager;

    .line 183
    .line 184
    new-instance v7, Ltechnology/cariad/cat/genx/wifi/i;

    .line 185
    .line 186
    const/4 v0, 0x2

    .line 187
    invoke-direct {v7, v0}, Ltechnology/cariad/cat/genx/wifi/i;-><init>(I)V

    .line 188
    .line 189
    .line 190
    new-instance v4, Lt51/j;

    .line 191
    .line 192
    invoke-static {p1}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 193
    .line 194
    .line 195
    move-result-object v9

    .line 196
    invoke-static {v3}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 197
    .line 198
    .line 199
    move-result-object v10

    .line 200
    const-string v5, "GenX"

    .line 201
    .line 202
    const/4 v8, 0x0

    .line 203
    invoke-direct/range {v4 .. v10}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 204
    .line 205
    .line 206
    invoke-static {v4}, Lt51/a;->a(Lt51/j;)V

    .line 207
    .line 208
    .line 209
    iget-object p0, p0, Ltechnology/cariad/cat/genx/wifi/WifiClientManager$3;->this$0:Ltechnology/cariad/cat/genx/wifi/WifiClientManager;

    .line 210
    .line 211
    invoke-static {p0}, Ltechnology/cariad/cat/genx/wifi/WifiClientManager;->access$getBonjourManager$p(Ltechnology/cariad/cat/genx/wifi/WifiClientManager;)Ltechnology/cariad/cat/genx/wifi/BonjourDiscoveryManager;

    .line 212
    .line 213
    .line 214
    move-result-object p0

    .line 215
    invoke-interface {p0}, Ltechnology/cariad/cat/genx/wifi/BonjourDiscoveryManager;->stopBonjourDiscovery()V

    .line 216
    .line 217
    .line 218
    :cond_5
    :goto_3
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 219
    .line 220
    return-object p0
.end method
