.class final Ltechnology/cariad/cat/genx/VehicleManagerImpl$BeaconScannerManager$1;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# annotations
.annotation system Ldalvik/annotation/EnclosingMethod;
    value = Ltechnology/cariad/cat/genx/VehicleManagerImpl$BeaconScannerManager;-><init>(Ltechnology/cariad/cat/genx/VehicleManagerImpl;Lt41/o;)V
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
        "\u0000\u0012\n\u0002\u0010\"\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0008\u0002\u0010\u0004\u001a\u00020\u00032\u000c\u0010\u0002\u001a\u0008\u0012\u0004\u0012\u00020\u00010\u0000H\n\u00a2\u0006\u0004\u0008\u0004\u0010\u0005"
    }
    d2 = {
        "",
        "Lt41/g;",
        "it",
        "Llx0/b0;",
        "<anonymous>",
        "(Ljava/util/Set;)V"
    }
    k = 0x3
    mv = {
        0x2,
        0x2,
        0x0
    }
.end annotation

.annotation runtime Lrx0/e;
    c = "technology.cariad.cat.genx.VehicleManagerImpl$BeaconScannerManager$1"
    f = "VehicleManagerImpl.kt"
    l = {}
    m = "invokeSuspend"
    v = 0x1
.end annotation


# instance fields
.field synthetic L$0:Ljava/lang/Object;

.field label:I

.field final synthetic this$0:Ltechnology/cariad/cat/genx/VehicleManagerImpl$BeaconScannerManager;


# direct methods
.method public constructor <init>(Ltechnology/cariad/cat/genx/VehicleManagerImpl$BeaconScannerManager;Lkotlin/coroutines/Continuation;)V
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ltechnology/cariad/cat/genx/VehicleManagerImpl$BeaconScannerManager;",
            "Lkotlin/coroutines/Continuation<",
            "-",
            "Ltechnology/cariad/cat/genx/VehicleManagerImpl$BeaconScannerManager$1;",
            ">;)V"
        }
    .end annotation

    .line 1
    iput-object p1, p0, Ltechnology/cariad/cat/genx/VehicleManagerImpl$BeaconScannerManager$1;->this$0:Ltechnology/cariad/cat/genx/VehicleManagerImpl$BeaconScannerManager;

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
    new-instance v0, Ltechnology/cariad/cat/genx/VehicleManagerImpl$BeaconScannerManager$1;

    .line 2
    .line 3
    iget-object p0, p0, Ltechnology/cariad/cat/genx/VehicleManagerImpl$BeaconScannerManager$1;->this$0:Ltechnology/cariad/cat/genx/VehicleManagerImpl$BeaconScannerManager;

    .line 4
    .line 5
    invoke-direct {v0, p0, p2}, Ltechnology/cariad/cat/genx/VehicleManagerImpl$BeaconScannerManager$1;-><init>(Ltechnology/cariad/cat/genx/VehicleManagerImpl$BeaconScannerManager;Lkotlin/coroutines/Continuation;)V

    .line 6
    .line 7
    .line 8
    iput-object p1, v0, Ltechnology/cariad/cat/genx/VehicleManagerImpl$BeaconScannerManager$1;->L$0:Ljava/lang/Object;

    .line 9
    .line 10
    return-object v0
.end method

.method public bridge synthetic invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Ljava/util/Set;

    check-cast p2, Lkotlin/coroutines/Continuation;

    invoke-virtual {p0, p1, p2}, Ltechnology/cariad/cat/genx/VehicleManagerImpl$BeaconScannerManager$1;->invoke(Ljava/util/Set;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    move-result-object p0

    return-object p0
.end method

.method public final invoke(Ljava/util/Set;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/Set<",
            "+",
            "Lt41/g;",
            ">;",
            "Lkotlin/coroutines/Continuation<",
            "-",
            "Llx0/b0;",
            ">;)",
            "Ljava/lang/Object;"
        }
    .end annotation

    .line 2
    invoke-virtual {p0, p1, p2}, Ltechnology/cariad/cat/genx/VehicleManagerImpl$BeaconScannerManager$1;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    move-result-object p0

    check-cast p0, Ltechnology/cariad/cat/genx/VehicleManagerImpl$BeaconScannerManager$1;

    sget-object p1, Llx0/b0;->a:Llx0/b0;

    invoke-virtual {p0, p1}, Ltechnology/cariad/cat/genx/VehicleManagerImpl$BeaconScannerManager$1;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p0

    return-object p0
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 2

    .line 1
    iget-object v0, p0, Ltechnology/cariad/cat/genx/VehicleManagerImpl$BeaconScannerManager$1;->L$0:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Ljava/util/Set;

    .line 4
    .line 5
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 6
    .line 7
    iget v1, p0, Ltechnology/cariad/cat/genx/VehicleManagerImpl$BeaconScannerManager$1;->label:I

    .line 8
    .line 9
    if-nez v1, :cond_0

    .line 10
    .line 11
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 12
    .line 13
    .line 14
    iget-object p0, p0, Ltechnology/cariad/cat/genx/VehicleManagerImpl$BeaconScannerManager$1;->this$0:Ltechnology/cariad/cat/genx/VehicleManagerImpl$BeaconScannerManager;

    .line 15
    .line 16
    invoke-static {p0, v0}, Ltechnology/cariad/cat/genx/VehicleManagerImpl$BeaconScannerManager;->access$onBeaconsUpdated(Ltechnology/cariad/cat/genx/VehicleManagerImpl$BeaconScannerManager;Ljava/util/Set;)V

    .line 17
    .line 18
    .line 19
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 20
    .line 21
    return-object p0

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
.end method
