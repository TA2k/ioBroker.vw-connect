.class final Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl$wifiBroadcastReceiver$1$onWifiChanged$2;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# annotations
.annotation system Ldalvik/annotation/EnclosingMethod;
    value = Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl$wifiBroadcastReceiver$1;->onWifiChanged(Landroid/content/Context;)V
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
    c = "technology.cariad.cat.genx.wifi.WifiManagerImpl$wifiBroadcastReceiver$1$onWifiChanged$2"
    f = "WifiManagerImpl.kt"
    l = {
        0x155
    }
    m = "invokeSuspend"
    v = 0x1
.end annotation


# instance fields
.field final synthetic $context:Landroid/content/Context;

.field I$0:I

.field private synthetic L$0:Ljava/lang/Object;

.field L$1:Ljava/lang/Object;

.field L$2:Ljava/lang/Object;

.field L$3:Ljava/lang/Object;

.field label:I

.field final synthetic this$0:Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl$wifiBroadcastReceiver$1;

.field final synthetic this$1:Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl;


# direct methods
.method public constructor <init>(Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl$wifiBroadcastReceiver$1;Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl;Landroid/content/Context;Lkotlin/coroutines/Continuation;)V
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl$wifiBroadcastReceiver$1;",
            "Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl;",
            "Landroid/content/Context;",
            "Lkotlin/coroutines/Continuation<",
            "-",
            "Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl$wifiBroadcastReceiver$1$onWifiChanged$2;",
            ">;)V"
        }
    .end annotation

    .line 1
    iput-object p1, p0, Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl$wifiBroadcastReceiver$1$onWifiChanged$2;->this$0:Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl$wifiBroadcastReceiver$1;

    .line 2
    .line 3
    iput-object p2, p0, Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl$wifiBroadcastReceiver$1$onWifiChanged$2;->this$1:Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl;

    .line 4
    .line 5
    iput-object p3, p0, Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl$wifiBroadcastReceiver$1$onWifiChanged$2;->$context:Landroid/content/Context;

    .line 6
    .line 7
    const/4 p1, 0x2

    .line 8
    invoke-direct {p0, p1, p4}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 9
    .line 10
    .line 11
    return-void
.end method

.method public static synthetic b(Ltechnology/cariad/cat/genx/wifi/WifiManager$WifiState;Ltechnology/cariad/cat/genx/wifi/WifiManager$WifiState;)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p0, p1}, Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl$wifiBroadcastReceiver$1$onWifiChanged$2;->invokeSuspend$lambda$0$0(Ltechnology/cariad/cat/genx/wifi/WifiManager$WifiState;Ltechnology/cariad/cat/genx/wifi/WifiManager$WifiState;)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method private static final invokeSuspend$lambda$0$0(Ltechnology/cariad/cat/genx/wifi/WifiManager$WifiState;Ltechnology/cariad/cat/genx/wifi/WifiManager$WifiState;)Ljava/lang/String;
    .locals 3

    .line 1
    invoke-virtual {p0}, Ljava/lang/Enum;->name()Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    invoke-virtual {p1}, Ljava/lang/Enum;->name()Ljava/lang/String;

    .line 6
    .line 7
    .line 8
    move-result-object p1

    .line 9
    const-string v0, "\' to \'"

    .line 10
    .line 11
    const-string v1, "\'"

    .line 12
    .line 13
    const-string v2, "onWifiChanged(): Wifi state changed from \'"

    .line 14
    .line 15
    invoke-static {v2, p0, v0, p1, v1}, Lu/w;->g(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 16
    .line 17
    .line 18
    move-result-object p0

    .line 19
    return-object p0
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;
    .locals 3
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
    new-instance v0, Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl$wifiBroadcastReceiver$1$onWifiChanged$2;

    .line 2
    .line 3
    iget-object v1, p0, Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl$wifiBroadcastReceiver$1$onWifiChanged$2;->this$0:Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl$wifiBroadcastReceiver$1;

    .line 4
    .line 5
    iget-object v2, p0, Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl$wifiBroadcastReceiver$1$onWifiChanged$2;->this$1:Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl;

    .line 6
    .line 7
    iget-object p0, p0, Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl$wifiBroadcastReceiver$1$onWifiChanged$2;->$context:Landroid/content/Context;

    .line 8
    .line 9
    invoke-direct {v0, v1, v2, p0, p2}, Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl$wifiBroadcastReceiver$1$onWifiChanged$2;-><init>(Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl$wifiBroadcastReceiver$1;Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl;Landroid/content/Context;Lkotlin/coroutines/Continuation;)V

    .line 10
    .line 11
    .line 12
    iput-object p1, v0, Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl$wifiBroadcastReceiver$1$onWifiChanged$2;->L$0:Ljava/lang/Object;

    .line 13
    .line 14
    return-object v0
.end method

.method public bridge synthetic invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Lvy0/b0;

    check-cast p2, Lkotlin/coroutines/Continuation;

    invoke-virtual {p0, p1, p2}, Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl$wifiBroadcastReceiver$1$onWifiChanged$2;->invoke(Lvy0/b0;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

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
    invoke-virtual {p0, p1, p2}, Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl$wifiBroadcastReceiver$1$onWifiChanged$2;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    move-result-object p0

    check-cast p0, Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl$wifiBroadcastReceiver$1$onWifiChanged$2;

    sget-object p1, Llx0/b0;->a:Llx0/b0;

    invoke-virtual {p0, p1}, Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl$wifiBroadcastReceiver$1$onWifiChanged$2;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p0

    return-object p0
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 11

    .line 1
    iget-object v0, p0, Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl$wifiBroadcastReceiver$1$onWifiChanged$2;->L$0:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Lvy0/b0;

    .line 4
    .line 5
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 6
    .line 7
    iget v2, p0, Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl$wifiBroadcastReceiver$1$onWifiChanged$2;->label:I

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
    iget-object v1, p0, Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl$wifiBroadcastReceiver$1$onWifiChanged$2;->L$3:Ljava/lang/Object;

    .line 15
    .line 16
    check-cast v1, Landroid/content/Context;

    .line 17
    .line 18
    iget-object v2, p0, Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl$wifiBroadcastReceiver$1$onWifiChanged$2;->L$2:Ljava/lang/Object;

    .line 19
    .line 20
    check-cast v2, Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl;

    .line 21
    .line 22
    iget-object p0, p0, Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl$wifiBroadcastReceiver$1$onWifiChanged$2;->L$1:Ljava/lang/Object;

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
    iget-object p1, p0, Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl$wifiBroadcastReceiver$1$onWifiChanged$2;->this$0:Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl$wifiBroadcastReceiver$1;

    .line 42
    .line 43
    invoke-virtual {p1}, Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl$wifiBroadcastReceiver$1;->getMutex()Lez0/a;

    .line 44
    .line 45
    .line 46
    move-result-object p1

    .line 47
    iget-object v2, p0, Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl$wifiBroadcastReceiver$1$onWifiChanged$2;->this$1:Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl;

    .line 48
    .line 49
    iget-object v4, p0, Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl$wifiBroadcastReceiver$1$onWifiChanged$2;->$context:Landroid/content/Context;

    .line 50
    .line 51
    iput-object v0, p0, Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl$wifiBroadcastReceiver$1$onWifiChanged$2;->L$0:Ljava/lang/Object;

    .line 52
    .line 53
    iput-object p1, p0, Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl$wifiBroadcastReceiver$1$onWifiChanged$2;->L$1:Ljava/lang/Object;

    .line 54
    .line 55
    iput-object v2, p0, Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl$wifiBroadcastReceiver$1$onWifiChanged$2;->L$2:Ljava/lang/Object;

    .line 56
    .line 57
    iput-object v4, p0, Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl$wifiBroadcastReceiver$1$onWifiChanged$2;->L$3:Ljava/lang/Object;

    .line 58
    .line 59
    const/4 v5, 0x0

    .line 60
    iput v5, p0, Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl$wifiBroadcastReceiver$1$onWifiChanged$2;->I$0:I

    .line 61
    .line 62
    iput v3, p0, Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl$wifiBroadcastReceiver$1$onWifiChanged$2;->label:I

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
    invoke-static {v2}, Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl;->access$get_wifiState$p(Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl;)Lyy0/j1;

    .line 75
    .line 76
    .line 77
    move-result-object v3

    .line 78
    check-cast v3, Lyy0/c2;

    .line 79
    .line 80
    invoke-virtual {v3}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 81
    .line 82
    .line 83
    move-result-object v3

    .line 84
    check-cast v3, Ltechnology/cariad/cat/genx/wifi/WifiManager$WifiState;

    .line 85
    .line 86
    sget-object v4, Ltechnology/cariad/cat/genx/wifi/WifiManager$WifiState;->Companion:Ltechnology/cariad/cat/genx/wifi/WifiManager$WifiState$Companion;

    .line 87
    .line 88
    invoke-virtual {v4, v1}, Ltechnology/cariad/cat/genx/wifi/WifiManager$WifiState$Companion;->getWifiState$genx_release(Landroid/content/Context;)Ltechnology/cariad/cat/genx/wifi/WifiManager$WifiState;

    .line 89
    .line 90
    .line 91
    move-result-object v1

    .line 92
    if-eq v3, v1, :cond_3

    .line 93
    .line 94
    new-instance v7, Ltechnology/cariad/cat/genx/wifi/n;

    .line 95
    .line 96
    invoke-direct {v7, v3, v1}, Ltechnology/cariad/cat/genx/wifi/n;-><init>(Ltechnology/cariad/cat/genx/wifi/WifiManager$WifiState;Ltechnology/cariad/cat/genx/wifi/WifiManager$WifiState;)V

    .line 97
    .line 98
    .line 99
    const-string v5, "GenX"

    .line 100
    .line 101
    new-instance v4, Lt51/j;

    .line 102
    .line 103
    sget-object v6, Lt51/f;->a:Lt51/f;

    .line 104
    .line 105
    invoke-static {v0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 106
    .line 107
    .line 108
    move-result-object v9

    .line 109
    invoke-static {}, Ljava/lang/Thread;->currentThread()Ljava/lang/Thread;

    .line 110
    .line 111
    .line 112
    move-result-object v0

    .line 113
    invoke-virtual {v0}, Ljava/lang/Thread;->getName()Ljava/lang/String;

    .line 114
    .line 115
    .line 116
    move-result-object v10

    .line 117
    const-string v0, "getName(...)"

    .line 118
    .line 119
    invoke-static {v10, v0}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 120
    .line 121
    .line 122
    const/4 v8, 0x0

    .line 123
    invoke-direct/range {v4 .. v10}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 124
    .line 125
    .line 126
    invoke-static {v4}, Lt51/a;->a(Lt51/j;)V

    .line 127
    .line 128
    .line 129
    invoke-static {v2}, Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl;->access$get_wifiState$p(Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl;)Lyy0/j1;

    .line 130
    .line 131
    .line 132
    move-result-object v0

    .line 133
    check-cast v0, Lyy0/c2;

    .line 134
    .line 135
    invoke-virtual {v0, v1}, Lyy0/c2;->j(Ljava/lang/Object;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 136
    .line 137
    .line 138
    goto :goto_1

    .line 139
    :catchall_0
    move-exception v0

    .line 140
    goto :goto_2

    .line 141
    :cond_3
    :goto_1
    invoke-interface {p0, p1}, Lez0/a;->d(Ljava/lang/Object;)V

    .line 142
    .line 143
    .line 144
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 145
    .line 146
    return-object p0

    .line 147
    :goto_2
    invoke-interface {p0, p1}, Lez0/a;->d(Ljava/lang/Object;)V

    .line 148
    .line 149
    .line 150
    throw v0
.end method
