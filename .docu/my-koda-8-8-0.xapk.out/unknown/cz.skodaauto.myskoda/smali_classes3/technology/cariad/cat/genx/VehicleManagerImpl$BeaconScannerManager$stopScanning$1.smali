.class final Ltechnology/cariad/cat/genx/VehicleManagerImpl$BeaconScannerManager$stopScanning$1;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# annotations
.annotation system Ldalvik/annotation/EnclosingMethod;
    value = Ltechnology/cariad/cat/genx/VehicleManagerImpl$BeaconScannerManager;->stopScanning$genx_release(Z)V
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
    c = "technology.cariad.cat.genx.VehicleManagerImpl$BeaconScannerManager$stopScanning$1"
    f = "VehicleManagerImpl.kt"
    l = {
        0x3ab
    }
    m = "invokeSuspend"
    v = 0x1
.end annotation


# instance fields
.field final synthetic $noVehicleRegistered:Z

.field label:I

.field final synthetic this$0:Ltechnology/cariad/cat/genx/VehicleManagerImpl$BeaconScannerManager;


# direct methods
.method public constructor <init>(ZLtechnology/cariad/cat/genx/VehicleManagerImpl$BeaconScannerManager;Lkotlin/coroutines/Continuation;)V
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(Z",
            "Ltechnology/cariad/cat/genx/VehicleManagerImpl$BeaconScannerManager;",
            "Lkotlin/coroutines/Continuation<",
            "-",
            "Ltechnology/cariad/cat/genx/VehicleManagerImpl$BeaconScannerManager$stopScanning$1;",
            ">;)V"
        }
    .end annotation

    .line 1
    iput-boolean p1, p0, Ltechnology/cariad/cat/genx/VehicleManagerImpl$BeaconScannerManager$stopScanning$1;->$noVehicleRegistered:Z

    .line 2
    .line 3
    iput-object p2, p0, Ltechnology/cariad/cat/genx/VehicleManagerImpl$BeaconScannerManager$stopScanning$1;->this$0:Ltechnology/cariad/cat/genx/VehicleManagerImpl$BeaconScannerManager;

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

.method public static synthetic b()Ljava/lang/String;
    .locals 1

    .line 1
    invoke-static {}, Ltechnology/cariad/cat/genx/VehicleManagerImpl$BeaconScannerManager$stopScanning$1;->invokeSuspend$lambda$0()Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    return-object v0
.end method

.method private static final invokeSuspend$lambda$0()Ljava/lang/String;
    .locals 1

    .line 1
    const-string v0, "unregisterGenTwoVehicle(): No vehicle registered. -> Stop beacon scanning."

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
    new-instance p1, Ltechnology/cariad/cat/genx/VehicleManagerImpl$BeaconScannerManager$stopScanning$1;

    .line 2
    .line 3
    iget-boolean v0, p0, Ltechnology/cariad/cat/genx/VehicleManagerImpl$BeaconScannerManager$stopScanning$1;->$noVehicleRegistered:Z

    .line 4
    .line 5
    iget-object p0, p0, Ltechnology/cariad/cat/genx/VehicleManagerImpl$BeaconScannerManager$stopScanning$1;->this$0:Ltechnology/cariad/cat/genx/VehicleManagerImpl$BeaconScannerManager;

    .line 6
    .line 7
    invoke-direct {p1, v0, p0, p2}, Ltechnology/cariad/cat/genx/VehicleManagerImpl$BeaconScannerManager$stopScanning$1;-><init>(ZLtechnology/cariad/cat/genx/VehicleManagerImpl$BeaconScannerManager;Lkotlin/coroutines/Continuation;)V

    .line 8
    .line 9
    .line 10
    return-object p1
.end method

.method public bridge synthetic invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Lvy0/b0;

    check-cast p2, Lkotlin/coroutines/Continuation;

    invoke-virtual {p0, p1, p2}, Ltechnology/cariad/cat/genx/VehicleManagerImpl$BeaconScannerManager$stopScanning$1;->invoke(Lvy0/b0;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

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
    invoke-virtual {p0, p1, p2}, Ltechnology/cariad/cat/genx/VehicleManagerImpl$BeaconScannerManager$stopScanning$1;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    move-result-object p0

    check-cast p0, Ltechnology/cariad/cat/genx/VehicleManagerImpl$BeaconScannerManager$stopScanning$1;

    sget-object p1, Llx0/b0;->a:Llx0/b0;

    invoke-virtual {p0, p1}, Ltechnology/cariad/cat/genx/VehicleManagerImpl$BeaconScannerManager$stopScanning$1;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p0

    return-object p0
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 10

    .line 1
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 2
    .line 3
    iget v1, p0, Ltechnology/cariad/cat/genx/VehicleManagerImpl$BeaconScannerManager$stopScanning$1;->label:I

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
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 11
    .line 12
    .line 13
    goto :goto_0

    .line 14
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 15
    .line 16
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 17
    .line 18
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 19
    .line 20
    .line 21
    throw p0

    .line 22
    :cond_1
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 23
    .line 24
    .line 25
    iget-boolean p1, p0, Ltechnology/cariad/cat/genx/VehicleManagerImpl$BeaconScannerManager$stopScanning$1;->$noVehicleRegistered:Z

    .line 26
    .line 27
    if-eqz p1, :cond_2

    .line 28
    .line 29
    iget-object p1, p0, Ltechnology/cariad/cat/genx/VehicleManagerImpl$BeaconScannerManager$stopScanning$1;->this$0:Ltechnology/cariad/cat/genx/VehicleManagerImpl$BeaconScannerManager;

    .line 30
    .line 31
    new-instance v6, Ltechnology/cariad/cat/genx/s0;

    .line 32
    .line 33
    const/4 v1, 0x5

    .line 34
    invoke-direct {v6, v1}, Ltechnology/cariad/cat/genx/s0;-><init>(I)V

    .line 35
    .line 36
    .line 37
    new-instance v3, Lt51/j;

    .line 38
    .line 39
    invoke-static {p1}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 40
    .line 41
    .line 42
    move-result-object v8

    .line 43
    const-string p1, "getName(...)"

    .line 44
    .line 45
    invoke-static {p1}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 46
    .line 47
    .line 48
    move-result-object v9

    .line 49
    const-string v4, "GenX"

    .line 50
    .line 51
    sget-object v5, Lt51/f;->a:Lt51/f;

    .line 52
    .line 53
    const/4 v7, 0x0

    .line 54
    invoke-direct/range {v3 .. v9}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 55
    .line 56
    .line 57
    invoke-static {v3}, Lt51/a;->a(Lt51/j;)V

    .line 58
    .line 59
    .line 60
    iget-object p1, p0, Ltechnology/cariad/cat/genx/VehicleManagerImpl$BeaconScannerManager$stopScanning$1;->this$0:Ltechnology/cariad/cat/genx/VehicleManagerImpl$BeaconScannerManager;

    .line 61
    .line 62
    invoke-static {p1}, Ltechnology/cariad/cat/genx/VehicleManagerImpl$BeaconScannerManager;->access$resetScanningState(Ltechnology/cariad/cat/genx/VehicleManagerImpl$BeaconScannerManager;)V

    .line 63
    .line 64
    .line 65
    iget-object p1, p0, Ltechnology/cariad/cat/genx/VehicleManagerImpl$BeaconScannerManager$stopScanning$1;->this$0:Ltechnology/cariad/cat/genx/VehicleManagerImpl$BeaconScannerManager;

    .line 66
    .line 67
    invoke-static {p1}, Ltechnology/cariad/cat/genx/VehicleManagerImpl$BeaconScannerManager;->access$getBeaconScanner$p(Ltechnology/cariad/cat/genx/VehicleManagerImpl$BeaconScannerManager;)Lt41/o;

    .line 68
    .line 69
    .line 70
    move-result-object p1

    .line 71
    iput v2, p0, Ltechnology/cariad/cat/genx/VehicleManagerImpl$BeaconScannerManager$stopScanning$1;->label:I

    .line 72
    .line 73
    check-cast p1, Lt41/z;

    .line 74
    .line 75
    invoke-virtual {p1, p0}, Lt41/z;->j(Lrx0/c;)Ljava/lang/Object;

    .line 76
    .line 77
    .line 78
    move-result-object p0

    .line 79
    if-ne p0, v0, :cond_2

    .line 80
    .line 81
    return-object v0

    .line 82
    :cond_2
    :goto_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 83
    .line 84
    return-object p0
.end method
