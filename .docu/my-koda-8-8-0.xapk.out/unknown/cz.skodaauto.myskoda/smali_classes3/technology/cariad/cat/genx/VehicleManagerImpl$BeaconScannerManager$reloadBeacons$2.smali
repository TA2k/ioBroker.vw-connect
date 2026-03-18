.class final Ltechnology/cariad/cat/genx/VehicleManagerImpl$BeaconScannerManager$reloadBeacons$2;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# annotations
.annotation system Ldalvik/annotation/EnclosingMethod;
    value = Ltechnology/cariad/cat/genx/VehicleManagerImpl$BeaconScannerManager;->reloadBeacons$genx_release()V
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
    c = "technology.cariad.cat.genx.VehicleManagerImpl$BeaconScannerManager$reloadBeacons$2"
    f = "VehicleManagerImpl.kt"
    l = {
        0x37c,
        0x37e
    }
    m = "invokeSuspend"
    v = 0x1
.end annotation


# instance fields
.field label:I

.field final synthetic this$0:Ltechnology/cariad/cat/genx/VehicleManagerImpl;

.field final synthetic this$1:Ltechnology/cariad/cat/genx/VehicleManagerImpl$BeaconScannerManager;


# direct methods
.method public constructor <init>(Ltechnology/cariad/cat/genx/VehicleManagerImpl;Ltechnology/cariad/cat/genx/VehicleManagerImpl$BeaconScannerManager;Lkotlin/coroutines/Continuation;)V
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ltechnology/cariad/cat/genx/VehicleManagerImpl;",
            "Ltechnology/cariad/cat/genx/VehicleManagerImpl$BeaconScannerManager;",
            "Lkotlin/coroutines/Continuation<",
            "-",
            "Ltechnology/cariad/cat/genx/VehicleManagerImpl$BeaconScannerManager$reloadBeacons$2;",
            ">;)V"
        }
    .end annotation

    .line 1
    iput-object p1, p0, Ltechnology/cariad/cat/genx/VehicleManagerImpl$BeaconScannerManager$reloadBeacons$2;->this$0:Ltechnology/cariad/cat/genx/VehicleManagerImpl;

    .line 2
    .line 3
    iput-object p2, p0, Ltechnology/cariad/cat/genx/VehicleManagerImpl$BeaconScannerManager$reloadBeacons$2;->this$1:Ltechnology/cariad/cat/genx/VehicleManagerImpl$BeaconScannerManager;

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
    new-instance p1, Ltechnology/cariad/cat/genx/VehicleManagerImpl$BeaconScannerManager$reloadBeacons$2;

    .line 2
    .line 3
    iget-object v0, p0, Ltechnology/cariad/cat/genx/VehicleManagerImpl$BeaconScannerManager$reloadBeacons$2;->this$0:Ltechnology/cariad/cat/genx/VehicleManagerImpl;

    .line 4
    .line 5
    iget-object p0, p0, Ltechnology/cariad/cat/genx/VehicleManagerImpl$BeaconScannerManager$reloadBeacons$2;->this$1:Ltechnology/cariad/cat/genx/VehicleManagerImpl$BeaconScannerManager;

    .line 6
    .line 7
    invoke-direct {p1, v0, p0, p2}, Ltechnology/cariad/cat/genx/VehicleManagerImpl$BeaconScannerManager$reloadBeacons$2;-><init>(Ltechnology/cariad/cat/genx/VehicleManagerImpl;Ltechnology/cariad/cat/genx/VehicleManagerImpl$BeaconScannerManager;Lkotlin/coroutines/Continuation;)V

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

    invoke-virtual {p0, p1, p2}, Ltechnology/cariad/cat/genx/VehicleManagerImpl$BeaconScannerManager$reloadBeacons$2;->invoke(Lvy0/b0;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

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
    invoke-virtual {p0, p1, p2}, Ltechnology/cariad/cat/genx/VehicleManagerImpl$BeaconScannerManager$reloadBeacons$2;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    move-result-object p0

    check-cast p0, Ltechnology/cariad/cat/genx/VehicleManagerImpl$BeaconScannerManager$reloadBeacons$2;

    sget-object p1, Llx0/b0;->a:Llx0/b0;

    invoke-virtual {p0, p1}, Ltechnology/cariad/cat/genx/VehicleManagerImpl$BeaconScannerManager$reloadBeacons$2;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p0

    return-object p0
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 5

    .line 1
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 2
    .line 3
    iget v1, p0, Ltechnology/cariad/cat/genx/VehicleManagerImpl$BeaconScannerManager$reloadBeacons$2;->label:I

    .line 4
    .line 5
    const/4 v2, 0x2

    .line 6
    const/4 v3, 0x1

    .line 7
    if-eqz v1, :cond_2

    .line 8
    .line 9
    if-eq v1, v3, :cond_0

    .line 10
    .line 11
    if-ne v1, v2, :cond_1

    .line 12
    .line 13
    :cond_0
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 14
    .line 15
    .line 16
    goto :goto_2

    .line 17
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 18
    .line 19
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 20
    .line 21
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 22
    .line 23
    .line 24
    throw p0

    .line 25
    :cond_2
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 26
    .line 27
    .line 28
    iget-object p1, p0, Ltechnology/cariad/cat/genx/VehicleManagerImpl$BeaconScannerManager$reloadBeacons$2;->this$0:Ltechnology/cariad/cat/genx/VehicleManagerImpl;

    .line 29
    .line 30
    invoke-virtual {p1}, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->getAllBeaconsToScanFor$genx_release()Ljava/util/List;

    .line 31
    .line 32
    .line 33
    move-result-object p1

    .line 34
    check-cast p1, Ljava/lang/Iterable;

    .line 35
    .line 36
    instance-of v1, p1, Ljava/util/Collection;

    .line 37
    .line 38
    if-eqz v1, :cond_3

    .line 39
    .line 40
    move-object v1, p1

    .line 41
    check-cast v1, Ljava/util/Collection;

    .line 42
    .line 43
    invoke-interface {v1}, Ljava/util/Collection;->isEmpty()Z

    .line 44
    .line 45
    .line 46
    move-result v1

    .line 47
    if-eqz v1, :cond_3

    .line 48
    .line 49
    goto :goto_0

    .line 50
    :cond_3
    invoke-interface {p1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 51
    .line 52
    .line 53
    move-result-object p1

    .line 54
    :cond_4
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    .line 55
    .line 56
    .line 57
    move-result v1

    .line 58
    if-eqz v1, :cond_5

    .line 59
    .line 60
    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 61
    .line 62
    .line 63
    move-result-object v1

    .line 64
    check-cast v1, Lt41/b;

    .line 65
    .line 66
    iget-object v1, v1, Lt41/b;->d:Ljava/util/UUID;

    .line 67
    .line 68
    sget-object v4, Ltechnology/cariad/cat/genx/VehicleManager;->Companion:Ltechnology/cariad/cat/genx/VehicleManager$Companion;

    .line 69
    .line 70
    invoke-virtual {v4}, Ltechnology/cariad/cat/genx/VehicleManager$Companion;->getPairingBeaconUUID()Ljava/util/UUID;

    .line 71
    .line 72
    .line 73
    move-result-object v4

    .line 74
    invoke-static {v1, v4}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 75
    .line 76
    .line 77
    move-result v1

    .line 78
    if-nez v1, :cond_4

    .line 79
    .line 80
    iget-object p1, p0, Ltechnology/cariad/cat/genx/VehicleManagerImpl$BeaconScannerManager$reloadBeacons$2;->this$1:Ltechnology/cariad/cat/genx/VehicleManagerImpl$BeaconScannerManager;

    .line 81
    .line 82
    invoke-static {p1}, Ltechnology/cariad/cat/genx/VehicleManagerImpl$BeaconScannerManager;->access$getBeaconScanner$p(Ltechnology/cariad/cat/genx/VehicleManagerImpl$BeaconScannerManager;)Lt41/o;

    .line 83
    .line 84
    .line 85
    move-result-object p1

    .line 86
    iget-object v1, p0, Ltechnology/cariad/cat/genx/VehicleManagerImpl$BeaconScannerManager$reloadBeacons$2;->this$0:Ltechnology/cariad/cat/genx/VehicleManagerImpl;

    .line 87
    .line 88
    invoke-virtual {v1}, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->getAllBeaconsToScanFor$genx_release()Ljava/util/List;

    .line 89
    .line 90
    .line 91
    move-result-object v1

    .line 92
    iput v2, p0, Ltechnology/cariad/cat/genx/VehicleManagerImpl$BeaconScannerManager$reloadBeacons$2;->label:I

    .line 93
    .line 94
    check-cast p1, Lt41/z;

    .line 95
    .line 96
    invoke-virtual {p1, v1, p0}, Lt41/z;->g(Ljava/util/List;Lrx0/c;)Ljava/lang/Object;

    .line 97
    .line 98
    .line 99
    move-result-object p0

    .line 100
    if-ne p0, v0, :cond_6

    .line 101
    .line 102
    goto :goto_1

    .line 103
    :cond_5
    :goto_0
    iget-object p1, p0, Ltechnology/cariad/cat/genx/VehicleManagerImpl$BeaconScannerManager$reloadBeacons$2;->this$1:Ltechnology/cariad/cat/genx/VehicleManagerImpl$BeaconScannerManager;

    .line 104
    .line 105
    invoke-static {p1}, Ltechnology/cariad/cat/genx/VehicleManagerImpl$BeaconScannerManager;->access$getBeaconScanner$p(Ltechnology/cariad/cat/genx/VehicleManagerImpl$BeaconScannerManager;)Lt41/o;

    .line 106
    .line 107
    .line 108
    move-result-object p1

    .line 109
    iput v3, p0, Ltechnology/cariad/cat/genx/VehicleManagerImpl$BeaconScannerManager$reloadBeacons$2;->label:I

    .line 110
    .line 111
    check-cast p1, Lt41/z;

    .line 112
    .line 113
    sget-object v1, Lmx0/s;->d:Lmx0/s;

    .line 114
    .line 115
    invoke-virtual {p1, v1, p0}, Lt41/z;->g(Ljava/util/List;Lrx0/c;)Ljava/lang/Object;

    .line 116
    .line 117
    .line 118
    move-result-object p0

    .line 119
    if-ne p0, v0, :cond_6

    .line 120
    .line 121
    :goto_1
    return-object v0

    .line 122
    :cond_6
    :goto_2
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 123
    .line 124
    return-object p0
.end method
