.class final Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl$wifiBroadcastReceiver$1$onNetworkChanged$2;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# annotations
.annotation system Ldalvik/annotation/EnclosingMethod;
    value = Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl$wifiBroadcastReceiver$1;->onNetworkChanged(Landroid/content/Context;)V
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
    c = "technology.cariad.cat.genx.wifi.WifiManagerImpl$wifiBroadcastReceiver$1$onNetworkChanged$2"
    f = "WifiManagerImpl.kt"
    l = {
        0x155,
        0x53
    }
    m = "invokeSuspend"
    v = 0x1
.end annotation


# instance fields
.field final synthetic $context:Landroid/content/Context;

.field I$0:I

.field I$1:I

.field L$0:Ljava/lang/Object;

.field L$1:Ljava/lang/Object;

.field L$2:Ljava/lang/Object;

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
            "Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl$wifiBroadcastReceiver$1$onNetworkChanged$2;",
            ">;)V"
        }
    .end annotation

    .line 1
    iput-object p1, p0, Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl$wifiBroadcastReceiver$1$onNetworkChanged$2;->this$0:Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl$wifiBroadcastReceiver$1;

    .line 2
    .line 3
    iput-object p2, p0, Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl$wifiBroadcastReceiver$1$onNetworkChanged$2;->this$1:Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl;

    .line 4
    .line 5
    iput-object p3, p0, Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl$wifiBroadcastReceiver$1$onNetworkChanged$2;->$context:Landroid/content/Context;

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
    new-instance p1, Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl$wifiBroadcastReceiver$1$onNetworkChanged$2;

    .line 2
    .line 3
    iget-object v0, p0, Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl$wifiBroadcastReceiver$1$onNetworkChanged$2;->this$0:Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl$wifiBroadcastReceiver$1;

    .line 4
    .line 5
    iget-object v1, p0, Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl$wifiBroadcastReceiver$1$onNetworkChanged$2;->this$1:Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl;

    .line 6
    .line 7
    iget-object p0, p0, Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl$wifiBroadcastReceiver$1$onNetworkChanged$2;->$context:Landroid/content/Context;

    .line 8
    .line 9
    invoke-direct {p1, v0, v1, p0, p2}, Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl$wifiBroadcastReceiver$1$onNetworkChanged$2;-><init>(Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl$wifiBroadcastReceiver$1;Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl;Landroid/content/Context;Lkotlin/coroutines/Continuation;)V

    .line 10
    .line 11
    .line 12
    return-object p1
.end method

.method public bridge synthetic invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Lvy0/b0;

    check-cast p2, Lkotlin/coroutines/Continuation;

    invoke-virtual {p0, p1, p2}, Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl$wifiBroadcastReceiver$1$onNetworkChanged$2;->invoke(Lvy0/b0;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

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
    invoke-virtual {p0, p1, p2}, Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl$wifiBroadcastReceiver$1$onNetworkChanged$2;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    move-result-object p0

    check-cast p0, Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl$wifiBroadcastReceiver$1$onNetworkChanged$2;

    sget-object p1, Llx0/b0;->a:Llx0/b0;

    invoke-virtual {p0, p1}, Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl$wifiBroadcastReceiver$1$onNetworkChanged$2;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p0

    return-object p0
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 9

    .line 1
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 2
    .line 3
    iget v1, p0, Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl$wifiBroadcastReceiver$1$onNetworkChanged$2;->label:I

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    const/4 v3, 0x2

    .line 7
    const/4 v4, 0x1

    .line 8
    const/4 v5, 0x0

    .line 9
    if-eqz v1, :cond_2

    .line 10
    .line 11
    if-eq v1, v4, :cond_1

    .line 12
    .line 13
    if-ne v1, v3, :cond_0

    .line 14
    .line 15
    iget-object p0, p0, Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl$wifiBroadcastReceiver$1$onNetworkChanged$2;->L$0:Ljava/lang/Object;

    .line 16
    .line 17
    check-cast p0, Lez0/a;

    .line 18
    .line 19
    :try_start_0
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 20
    .line 21
    .line 22
    goto :goto_2

    .line 23
    :catchall_0
    move-exception p1

    .line 24
    goto :goto_3

    .line 25
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 26
    .line 27
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 28
    .line 29
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 30
    .line 31
    .line 32
    throw p0

    .line 33
    :cond_1
    iget v1, p0, Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl$wifiBroadcastReceiver$1$onNetworkChanged$2;->I$0:I

    .line 34
    .line 35
    iget-object v4, p0, Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl$wifiBroadcastReceiver$1$onNetworkChanged$2;->L$2:Ljava/lang/Object;

    .line 36
    .line 37
    check-cast v4, Landroid/content/Context;

    .line 38
    .line 39
    iget-object v6, p0, Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl$wifiBroadcastReceiver$1$onNetworkChanged$2;->L$1:Ljava/lang/Object;

    .line 40
    .line 41
    check-cast v6, Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl;

    .line 42
    .line 43
    iget-object v7, p0, Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl$wifiBroadcastReceiver$1$onNetworkChanged$2;->L$0:Ljava/lang/Object;

    .line 44
    .line 45
    check-cast v7, Lez0/a;

    .line 46
    .line 47
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 48
    .line 49
    .line 50
    move-object p1, v7

    .line 51
    goto :goto_0

    .line 52
    :cond_2
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 53
    .line 54
    .line 55
    iget-object p1, p0, Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl$wifiBroadcastReceiver$1$onNetworkChanged$2;->this$0:Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl$wifiBroadcastReceiver$1;

    .line 56
    .line 57
    invoke-virtual {p1}, Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl$wifiBroadcastReceiver$1;->getMutex()Lez0/a;

    .line 58
    .line 59
    .line 60
    move-result-object p1

    .line 61
    iget-object v6, p0, Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl$wifiBroadcastReceiver$1$onNetworkChanged$2;->this$1:Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl;

    .line 62
    .line 63
    iget-object v1, p0, Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl$wifiBroadcastReceiver$1$onNetworkChanged$2;->$context:Landroid/content/Context;

    .line 64
    .line 65
    iput-object p1, p0, Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl$wifiBroadcastReceiver$1$onNetworkChanged$2;->L$0:Ljava/lang/Object;

    .line 66
    .line 67
    iput-object v6, p0, Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl$wifiBroadcastReceiver$1$onNetworkChanged$2;->L$1:Ljava/lang/Object;

    .line 68
    .line 69
    iput-object v1, p0, Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl$wifiBroadcastReceiver$1$onNetworkChanged$2;->L$2:Ljava/lang/Object;

    .line 70
    .line 71
    iput v2, p0, Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl$wifiBroadcastReceiver$1$onNetworkChanged$2;->I$0:I

    .line 72
    .line 73
    iput v4, p0, Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl$wifiBroadcastReceiver$1$onNetworkChanged$2;->label:I

    .line 74
    .line 75
    invoke-interface {p1, p0}, Lez0/a;->a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 76
    .line 77
    .line 78
    move-result-object v4

    .line 79
    if-ne v4, v0, :cond_3

    .line 80
    .line 81
    goto :goto_1

    .line 82
    :cond_3
    move-object v4, v1

    .line 83
    move v1, v2

    .line 84
    :goto_0
    :try_start_1
    iput-object p1, p0, Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl$wifiBroadcastReceiver$1$onNetworkChanged$2;->L$0:Ljava/lang/Object;

    .line 85
    .line 86
    iput-object v5, p0, Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl$wifiBroadcastReceiver$1$onNetworkChanged$2;->L$1:Ljava/lang/Object;

    .line 87
    .line 88
    iput-object v5, p0, Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl$wifiBroadcastReceiver$1$onNetworkChanged$2;->L$2:Ljava/lang/Object;

    .line 89
    .line 90
    iput v1, p0, Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl$wifiBroadcastReceiver$1$onNetworkChanged$2;->I$0:I

    .line 91
    .line 92
    iput v2, p0, Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl$wifiBroadcastReceiver$1$onNetworkChanged$2;->I$1:I

    .line 93
    .line 94
    iput v3, p0, Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl$wifiBroadcastReceiver$1$onNetworkChanged$2;->label:I

    .line 95
    .line 96
    invoke-virtual {v6, v4, p0}, Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl;->connectedWifi$genx_release(Landroid/content/Context;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 97
    .line 98
    .line 99
    move-result-object p0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 100
    if-ne p0, v0, :cond_4

    .line 101
    .line 102
    :goto_1
    return-object v0

    .line 103
    :cond_4
    move-object p0, p1

    .line 104
    :goto_2
    invoke-interface {p0, v5}, Lez0/a;->d(Ljava/lang/Object;)V

    .line 105
    .line 106
    .line 107
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 108
    .line 109
    return-object p0

    .line 110
    :catchall_1
    move-exception p0

    .line 111
    move-object v8, p1

    .line 112
    move-object p1, p0

    .line 113
    move-object p0, v8

    .line 114
    :goto_3
    invoke-interface {p0, v5}, Lez0/a;->d(Ljava/lang/Object;)V

    .line 115
    .line 116
    .line 117
    throw p1
.end method
