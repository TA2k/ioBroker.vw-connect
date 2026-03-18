.class final Ltechnology/cariad/cat/genx/keyexchange/KeyExchangeManager$startScanningIfNecessary$3;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# annotations
.annotation system Ldalvik/annotation/EnclosingMethod;
    value = Ltechnology/cariad/cat/genx/keyexchange/KeyExchangeManager;->startScanningIfNecessary(Lay0/a;Lay0/k;)V
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
    c = "technology.cariad.cat.genx.keyexchange.KeyExchangeManager$startScanningIfNecessary$3"
    f = "KeyExchangeManager.kt"
    l = {
        0x18a
    }
    m = "invokeSuspend"
    v = 0x1
.end annotation


# instance fields
.field final synthetic $scanningManager:Ltechnology/cariad/cat/genx/ScanningManager;

.field final synthetic $startScanningFailed:Lay0/k;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lay0/k;"
        }
    .end annotation
.end field

.field final synthetic $startScanningSucceeded:Lay0/a;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lay0/a;"
        }
    .end annotation
.end field

.field private synthetic L$0:Ljava/lang/Object;

.field label:I

.field final synthetic this$0:Ltechnology/cariad/cat/genx/keyexchange/KeyExchangeManager;


# direct methods
.method public constructor <init>(Ltechnology/cariad/cat/genx/ScanningManager;Ltechnology/cariad/cat/genx/keyexchange/KeyExchangeManager;Lay0/a;Lay0/k;Lkotlin/coroutines/Continuation;)V
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ltechnology/cariad/cat/genx/ScanningManager;",
            "Ltechnology/cariad/cat/genx/keyexchange/KeyExchangeManager;",
            "Lay0/a;",
            "Lay0/k;",
            "Lkotlin/coroutines/Continuation<",
            "-",
            "Ltechnology/cariad/cat/genx/keyexchange/KeyExchangeManager$startScanningIfNecessary$3;",
            ">;)V"
        }
    .end annotation

    .line 1
    iput-object p1, p0, Ltechnology/cariad/cat/genx/keyexchange/KeyExchangeManager$startScanningIfNecessary$3;->$scanningManager:Ltechnology/cariad/cat/genx/ScanningManager;

    .line 2
    .line 3
    iput-object p2, p0, Ltechnology/cariad/cat/genx/keyexchange/KeyExchangeManager$startScanningIfNecessary$3;->this$0:Ltechnology/cariad/cat/genx/keyexchange/KeyExchangeManager;

    .line 4
    .line 5
    iput-object p3, p0, Ltechnology/cariad/cat/genx/keyexchange/KeyExchangeManager$startScanningIfNecessary$3;->$startScanningSucceeded:Lay0/a;

    .line 6
    .line 7
    iput-object p4, p0, Ltechnology/cariad/cat/genx/keyexchange/KeyExchangeManager$startScanningIfNecessary$3;->$startScanningFailed:Lay0/k;

    .line 8
    .line 9
    const/4 p1, 0x2

    .line 10
    invoke-direct {p0, p1, p5}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 11
    .line 12
    .line 13
    return-void
.end method

.method public static synthetic b()Ljava/lang/String;
    .locals 1

    .line 1
    invoke-static {}, Ltechnology/cariad/cat/genx/keyexchange/KeyExchangeManager$startScanningIfNecessary$3;->invokeSuspend$lambda$1$0()Ljava/lang/String;

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
    invoke-static {}, Ltechnology/cariad/cat/genx/keyexchange/KeyExchangeManager$startScanningIfNecessary$3;->invokeSuspend$lambda$0$0()Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    return-object v0
.end method

.method private static final invokeSuspend$lambda$0$0()Ljava/lang/String;
    .locals 1

    .line 1
    const-string v0, "startScanningIfNecessary(): Scanning started"

    .line 2
    .line 3
    return-object v0
.end method

.method private static final invokeSuspend$lambda$1$0()Ljava/lang/String;
    .locals 1

    .line 1
    const-string v0, "startScanningIfNecessary(): Could not start Scanning"

    .line 2
    .line 3
    return-object v0
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;
    .locals 6
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
    new-instance v0, Ltechnology/cariad/cat/genx/keyexchange/KeyExchangeManager$startScanningIfNecessary$3;

    .line 2
    .line 3
    iget-object v1, p0, Ltechnology/cariad/cat/genx/keyexchange/KeyExchangeManager$startScanningIfNecessary$3;->$scanningManager:Ltechnology/cariad/cat/genx/ScanningManager;

    .line 4
    .line 5
    iget-object v2, p0, Ltechnology/cariad/cat/genx/keyexchange/KeyExchangeManager$startScanningIfNecessary$3;->this$0:Ltechnology/cariad/cat/genx/keyexchange/KeyExchangeManager;

    .line 6
    .line 7
    iget-object v3, p0, Ltechnology/cariad/cat/genx/keyexchange/KeyExchangeManager$startScanningIfNecessary$3;->$startScanningSucceeded:Lay0/a;

    .line 8
    .line 9
    iget-object v4, p0, Ltechnology/cariad/cat/genx/keyexchange/KeyExchangeManager$startScanningIfNecessary$3;->$startScanningFailed:Lay0/k;

    .line 10
    .line 11
    move-object v5, p2

    .line 12
    invoke-direct/range {v0 .. v5}, Ltechnology/cariad/cat/genx/keyexchange/KeyExchangeManager$startScanningIfNecessary$3;-><init>(Ltechnology/cariad/cat/genx/ScanningManager;Ltechnology/cariad/cat/genx/keyexchange/KeyExchangeManager;Lay0/a;Lay0/k;Lkotlin/coroutines/Continuation;)V

    .line 13
    .line 14
    .line 15
    iput-object p1, v0, Ltechnology/cariad/cat/genx/keyexchange/KeyExchangeManager$startScanningIfNecessary$3;->L$0:Ljava/lang/Object;

    .line 16
    .line 17
    return-object v0
.end method

.method public bridge synthetic invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Lvy0/b0;

    check-cast p2, Lkotlin/coroutines/Continuation;

    invoke-virtual {p0, p1, p2}, Ltechnology/cariad/cat/genx/keyexchange/KeyExchangeManager$startScanningIfNecessary$3;->invoke(Lvy0/b0;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

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
    invoke-virtual {p0, p1, p2}, Ltechnology/cariad/cat/genx/keyexchange/KeyExchangeManager$startScanningIfNecessary$3;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    move-result-object p0

    check-cast p0, Ltechnology/cariad/cat/genx/keyexchange/KeyExchangeManager$startScanningIfNecessary$3;

    sget-object p1, Llx0/b0;->a:Llx0/b0;

    invoke-virtual {p0, p1}, Ltechnology/cariad/cat/genx/keyexchange/KeyExchangeManager$startScanningIfNecessary$3;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p0

    return-object p0
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 10

    .line 1
    iget-object v0, p0, Ltechnology/cariad/cat/genx/keyexchange/KeyExchangeManager$startScanningIfNecessary$3;->L$0:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Lvy0/b0;

    .line 4
    .line 5
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 6
    .line 7
    iget v2, p0, Ltechnology/cariad/cat/genx/keyexchange/KeyExchangeManager$startScanningIfNecessary$3;->label:I

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
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 15
    .line 16
    .line 17
    check-cast p1, Llx0/o;

    .line 18
    .line 19
    iget-object p1, p1, Llx0/o;->d:Ljava/lang/Object;

    .line 20
    .line 21
    goto :goto_0

    .line 22
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 23
    .line 24
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 25
    .line 26
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 27
    .line 28
    .line 29
    throw p0

    .line 30
    :cond_1
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 31
    .line 32
    .line 33
    iget-object p1, p0, Ltechnology/cariad/cat/genx/keyexchange/KeyExchangeManager$startScanningIfNecessary$3;->$scanningManager:Ltechnology/cariad/cat/genx/ScanningManager;

    .line 34
    .line 35
    iput-object v0, p0, Ltechnology/cariad/cat/genx/keyexchange/KeyExchangeManager$startScanningIfNecessary$3;->L$0:Ljava/lang/Object;

    .line 36
    .line 37
    iput v3, p0, Ltechnology/cariad/cat/genx/keyexchange/KeyExchangeManager$startScanningIfNecessary$3;->label:I

    .line 38
    .line 39
    invoke-interface {p1, p0}, Ltechnology/cariad/cat/genx/ScanningManager;->startScanningForClients-IoAF18A(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 40
    .line 41
    .line 42
    move-result-object p1

    .line 43
    if-ne p1, v1, :cond_2

    .line 44
    .line 45
    return-object v1

    .line 46
    :cond_2
    :goto_0
    iget-object v1, p0, Ltechnology/cariad/cat/genx/keyexchange/KeyExchangeManager$startScanningIfNecessary$3;->this$0:Ltechnology/cariad/cat/genx/keyexchange/KeyExchangeManager;

    .line 47
    .line 48
    iget-object v2, p0, Ltechnology/cariad/cat/genx/keyexchange/KeyExchangeManager$startScanningIfNecessary$3;->$startScanningSucceeded:Lay0/a;

    .line 49
    .line 50
    iget-object p0, p0, Ltechnology/cariad/cat/genx/keyexchange/KeyExchangeManager$startScanningIfNecessary$3;->$startScanningFailed:Lay0/k;

    .line 51
    .line 52
    invoke-static {p1}, Llx0/o;->a(Ljava/lang/Object;)Ljava/lang/Throwable;

    .line 53
    .line 54
    .line 55
    move-result-object v3

    .line 56
    if-nez v3, :cond_3

    .line 57
    .line 58
    check-cast p1, Ltechnology/cariad/cat/genx/ScanningManager$ScanningToken;

    .line 59
    .line 60
    new-instance v6, Ltechnology/cariad/cat/genx/keyexchange/g;

    .line 61
    .line 62
    const/4 p0, 0x0

    .line 63
    invoke-direct {v6, p0}, Ltechnology/cariad/cat/genx/keyexchange/g;-><init>(I)V

    .line 64
    .line 65
    .line 66
    new-instance v3, Lt51/j;

    .line 67
    .line 68
    invoke-static {v0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 69
    .line 70
    .line 71
    move-result-object v8

    .line 72
    const-string p0, "getName(...)"

    .line 73
    .line 74
    invoke-static {p0}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 75
    .line 76
    .line 77
    move-result-object v9

    .line 78
    const-string v4, "GenX"

    .line 79
    .line 80
    sget-object v5, Lt51/g;->a:Lt51/g;

    .line 81
    .line 82
    const/4 v7, 0x0

    .line 83
    invoke-direct/range {v3 .. v9}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 84
    .line 85
    .line 86
    invoke-static {v3}, Lt51/a;->a(Lt51/j;)V

    .line 87
    .line 88
    .line 89
    invoke-static {v1, p1}, Ltechnology/cariad/cat/genx/keyexchange/KeyExchangeManager;->access$setScanningToken$p(Ltechnology/cariad/cat/genx/keyexchange/KeyExchangeManager;Ltechnology/cariad/cat/genx/ScanningManager$ScanningToken;)V

    .line 90
    .line 91
    .line 92
    invoke-interface {v2}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 93
    .line 94
    .line 95
    goto :goto_1

    .line 96
    :cond_3
    new-instance p1, Ltechnology/cariad/cat/genx/keyexchange/g;

    .line 97
    .line 98
    const/4 v1, 0x1

    .line 99
    invoke-direct {p1, v1}, Ltechnology/cariad/cat/genx/keyexchange/g;-><init>(I)V

    .line 100
    .line 101
    .line 102
    const-string v1, "GenX"

    .line 103
    .line 104
    invoke-static {v0, v1, v3, p1}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->logWarn(Ljava/lang/Object;Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;)V

    .line 105
    .line 106
    .line 107
    instance-of p1, v3, Ltechnology/cariad/cat/genx/GenXError;

    .line 108
    .line 109
    if-eqz p1, :cond_4

    .line 110
    .line 111
    invoke-interface {p0, v3}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 112
    .line 113
    .line 114
    :cond_4
    :goto_1
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 115
    .line 116
    return-object p0
.end method
