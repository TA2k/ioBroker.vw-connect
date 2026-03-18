.class final Ltechnology/cariad/cat/genx/VehicleManagerImpl$startScanningForClients$1;
.super Lrx0/c;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingMethod;
    value = Ltechnology/cariad/cat/genx/VehicleManagerImpl;->startScanningForClients-IoAF18A(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = null
.end annotation

.annotation runtime Lkotlin/Metadata;
    k = 0x3
    mv = {
        0x2,
        0x2,
        0x0
    }
    xi = 0x30
.end annotation

.annotation runtime Lrx0/e;
    c = "technology.cariad.cat.genx.VehicleManagerImpl"
    f = "VehicleManagerImpl.kt"
    l = {
        0x3f7,
        0x231
    }
    m = "startScanningForClients-IoAF18A"
    v = 0x1
.end annotation


# instance fields
.field I$0:I

.field I$1:I

.field I$2:I

.field L$0:Ljava/lang/Object;

.field L$1:Ljava/lang/Object;

.field label:I

.field synthetic result:Ljava/lang/Object;

.field final synthetic this$0:Ltechnology/cariad/cat/genx/VehicleManagerImpl;


# direct methods
.method public constructor <init>(Ltechnology/cariad/cat/genx/VehicleManagerImpl;Lkotlin/coroutines/Continuation;)V
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ltechnology/cariad/cat/genx/VehicleManagerImpl;",
            "Lkotlin/coroutines/Continuation<",
            "-",
            "Ltechnology/cariad/cat/genx/VehicleManagerImpl$startScanningForClients$1;",
            ">;)V"
        }
    .end annotation

    .line 1
    iput-object p1, p0, Ltechnology/cariad/cat/genx/VehicleManagerImpl$startScanningForClients$1;->this$0:Ltechnology/cariad/cat/genx/VehicleManagerImpl;

    .line 2
    .line 3
    invoke-direct {p0, p2}, Lrx0/c;-><init>(Lkotlin/coroutines/Continuation;)V

    .line 4
    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    iput-object p1, p0, Ltechnology/cariad/cat/genx/VehicleManagerImpl$startScanningForClients$1;->result:Ljava/lang/Object;

    .line 2
    .line 3
    iget p1, p0, Ltechnology/cariad/cat/genx/VehicleManagerImpl$startScanningForClients$1;->label:I

    .line 4
    .line 5
    const/high16 v0, -0x80000000

    .line 6
    .line 7
    or-int/2addr p1, v0

    .line 8
    iput p1, p0, Ltechnology/cariad/cat/genx/VehicleManagerImpl$startScanningForClients$1;->label:I

    .line 9
    .line 10
    iget-object p1, p0, Ltechnology/cariad/cat/genx/VehicleManagerImpl$startScanningForClients$1;->this$0:Ltechnology/cariad/cat/genx/VehicleManagerImpl;

    .line 11
    .line 12
    invoke-virtual {p1, p0}, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->startScanningForClients-IoAF18A(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 13
    .line 14
    .line 15
    move-result-object p0

    .line 16
    sget-object p1, Lqx0/a;->d:Lqx0/a;

    .line 17
    .line 18
    if-ne p0, p1, :cond_0

    .line 19
    .line 20
    return-object p0

    .line 21
    :cond_0
    new-instance p1, Llx0/o;

    .line 22
    .line 23
    invoke-direct {p1, p0}, Llx0/o;-><init>(Ljava/lang/Object;)V

    .line 24
    .line 25
    .line 26
    return-object p1
.end method
