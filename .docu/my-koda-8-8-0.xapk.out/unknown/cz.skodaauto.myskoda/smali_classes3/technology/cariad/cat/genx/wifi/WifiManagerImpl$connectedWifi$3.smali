.class final Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl$connectedWifi$3;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# annotations
.annotation system Ldalvik/annotation/EnclosingMethod;
    value = Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl;->connectedWifi$genx_release(Landroid/content/Context;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
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
        "\u0000\u000c\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0002\u0010\u0002\u001a\u0004\u0018\u00010\u0001*\u00020\u0000H\n\u00a2\u0006\u0004\u0008\u0002\u0010\u0003"
    }
    d2 = {
        "Lvy0/b0;",
        "Ltechnology/cariad/cat/genx/wifi/Wifi;",
        "<anonymous>",
        "(Lvy0/b0;)Ltechnology/cariad/cat/genx/wifi/Wifi;"
    }
    k = 0x3
    mv = {
        0x2,
        0x2,
        0x0
    }
.end annotation

.annotation runtime Lrx0/e;
    c = "technology.cariad.cat.genx.wifi.WifiManagerImpl$connectedWifi$3"
    f = "WifiManagerImpl.kt"
    l = {
        0x150
    }
    m = "invokeSuspend"
    v = 0x1
.end annotation


# instance fields
.field final synthetic $connectivityManager:Landroid/net/ConnectivityManager;

.field final synthetic $context:Landroid/content/Context;

.field I$0:I

.field L$0:Ljava/lang/Object;

.field L$1:Ljava/lang/Object;

.field L$2:Ljava/lang/Object;

.field label:I

.field final synthetic this$0:Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl;


# direct methods
.method public constructor <init>(Landroid/net/ConnectivityManager;Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl;Landroid/content/Context;Lkotlin/coroutines/Continuation;)V
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Landroid/net/ConnectivityManager;",
            "Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl;",
            "Landroid/content/Context;",
            "Lkotlin/coroutines/Continuation<",
            "-",
            "Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl$connectedWifi$3;",
            ">;)V"
        }
    .end annotation

    .line 1
    iput-object p1, p0, Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl$connectedWifi$3;->$connectivityManager:Landroid/net/ConnectivityManager;

    .line 2
    .line 3
    iput-object p2, p0, Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl$connectedWifi$3;->this$0:Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl;

    .line 4
    .line 5
    iput-object p3, p0, Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl$connectedWifi$3;->$context:Landroid/content/Context;

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
    new-instance p1, Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl$connectedWifi$3;

    .line 2
    .line 3
    iget-object v0, p0, Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl$connectedWifi$3;->$connectivityManager:Landroid/net/ConnectivityManager;

    .line 4
    .line 5
    iget-object v1, p0, Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl$connectedWifi$3;->this$0:Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl;

    .line 6
    .line 7
    iget-object p0, p0, Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl$connectedWifi$3;->$context:Landroid/content/Context;

    .line 8
    .line 9
    invoke-direct {p1, v0, v1, p0, p2}, Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl$connectedWifi$3;-><init>(Landroid/net/ConnectivityManager;Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl;Landroid/content/Context;Lkotlin/coroutines/Continuation;)V

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

    invoke-virtual {p0, p1, p2}, Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl$connectedWifi$3;->invoke(Lvy0/b0;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

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
            "Ltechnology/cariad/cat/genx/wifi/Wifi;",
            ">;)",
            "Ljava/lang/Object;"
        }
    .end annotation

    .line 2
    invoke-virtual {p0, p1, p2}, Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl$connectedWifi$3;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    move-result-object p0

    check-cast p0, Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl$connectedWifi$3;

    sget-object p1, Llx0/b0;->a:Llx0/b0;

    invoke-virtual {p0, p1}, Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl$connectedWifi$3;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p0

    return-object p0
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 5

    .line 1
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 2
    .line 3
    iget v1, p0, Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl$connectedWifi$3;->label:I

    .line 4
    .line 5
    const/4 v2, 0x1

    .line 6
    if-eqz v1, :cond_1

    .line 7
    .line 8
    if-ne v1, v2, :cond_0

    .line 9
    .line 10
    iget-object v0, p0, Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl$connectedWifi$3;->L$2:Ljava/lang/Object;

    .line 11
    .line 12
    check-cast v0, Landroid/content/Context;

    .line 13
    .line 14
    iget-object v0, p0, Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl$connectedWifi$3;->L$1:Ljava/lang/Object;

    .line 15
    .line 16
    check-cast v0, Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl;

    .line 17
    .line 18
    iget-object p0, p0, Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl$connectedWifi$3;->L$0:Ljava/lang/Object;

    .line 19
    .line 20
    check-cast p0, Landroid/net/ConnectivityManager;

    .line 21
    .line 22
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 23
    .line 24
    .line 25
    return-object p1

    .line 26
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 27
    .line 28
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 29
    .line 30
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 31
    .line 32
    .line 33
    throw p0

    .line 34
    :cond_1
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 35
    .line 36
    .line 37
    iget-object p1, p0, Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl$connectedWifi$3;->$connectivityManager:Landroid/net/ConnectivityManager;

    .line 38
    .line 39
    iget-object v1, p0, Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl$connectedWifi$3;->this$0:Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl;

    .line 40
    .line 41
    iget-object v3, p0, Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl$connectedWifi$3;->$context:Landroid/content/Context;

    .line 42
    .line 43
    iput-object p1, p0, Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl$connectedWifi$3;->L$0:Ljava/lang/Object;

    .line 44
    .line 45
    iput-object v1, p0, Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl$connectedWifi$3;->L$1:Ljava/lang/Object;

    .line 46
    .line 47
    iput-object v3, p0, Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl$connectedWifi$3;->L$2:Ljava/lang/Object;

    .line 48
    .line 49
    const/4 v4, 0x0

    .line 50
    iput v4, p0, Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl$connectedWifi$3;->I$0:I

    .line 51
    .line 52
    iput v2, p0, Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl$connectedWifi$3;->label:I

    .line 53
    .line 54
    new-instance v4, Lvy0/l;

    .line 55
    .line 56
    invoke-static {p0}, Ljp/hg;->b(Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 57
    .line 58
    .line 59
    move-result-object p0

    .line 60
    invoke-direct {v4, v2, p0}, Lvy0/l;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 61
    .line 62
    .line 63
    invoke-virtual {v4}, Lvy0/l;->q()V

    .line 64
    .line 65
    .line 66
    new-instance p0, Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl$connectedWifi$3$1$networkCallback$1;

    .line 67
    .line 68
    invoke-direct {p0, v1, v3, v4, p1}, Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl$connectedWifi$3$1$networkCallback$1;-><init>(Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl;Landroid/content/Context;Lvy0/k;Landroid/net/ConnectivityManager;)V

    .line 69
    .line 70
    .line 71
    new-instance v1, Landroid/net/NetworkRequest$Builder;

    .line 72
    .line 73
    invoke-direct {v1}, Landroid/net/NetworkRequest$Builder;-><init>()V

    .line 74
    .line 75
    .line 76
    invoke-virtual {v1, v2}, Landroid/net/NetworkRequest$Builder;->addTransportType(I)Landroid/net/NetworkRequest$Builder;

    .line 77
    .line 78
    .line 79
    move-result-object v1

    .line 80
    invoke-virtual {v1}, Landroid/net/NetworkRequest$Builder;->build()Landroid/net/NetworkRequest;

    .line 81
    .line 82
    .line 83
    move-result-object v1

    .line 84
    invoke-virtual {p1, v1, p0}, Landroid/net/ConnectivityManager;->registerNetworkCallback(Landroid/net/NetworkRequest;Landroid/net/ConnectivityManager$NetworkCallback;)V

    .line 85
    .line 86
    .line 87
    new-instance p1, Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl$connectedWifi$3$1$1;

    .line 88
    .line 89
    invoke-direct {p1, p0}, Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl$connectedWifi$3$1$1;-><init>(Ltechnology/cariad/cat/genx/wifi/WifiManagerImpl$connectedWifi$3$1$networkCallback$1;)V

    .line 90
    .line 91
    .line 92
    invoke-virtual {v4, p1}, Lvy0/l;->s(Lay0/k;)V

    .line 93
    .line 94
    .line 95
    invoke-virtual {v4}, Lvy0/l;->p()Ljava/lang/Object;

    .line 96
    .line 97
    .line 98
    move-result-object p0

    .line 99
    if-ne p0, v0, :cond_2

    .line 100
    .line 101
    return-object v0

    .line 102
    :cond_2
    return-object p0
.end method
