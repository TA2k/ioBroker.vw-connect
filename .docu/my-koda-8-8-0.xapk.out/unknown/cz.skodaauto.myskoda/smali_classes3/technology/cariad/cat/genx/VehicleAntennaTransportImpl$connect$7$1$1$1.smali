.class final Ltechnology/cariad/cat/genx/VehicleAntennaTransportImpl$connect$7$1$1$1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# annotations
.annotation system Ldalvik/annotation/EnclosingMethod;
    value = Ltechnology/cariad/cat/genx/VehicleAntennaTransportImpl$connect$7$1;->invoke()V
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = null
.end annotation

.annotation system Ldalvik/annotation/Signature;
    value = {
        "Ljava/lang/Object;",
        "Lay0/k;"
    }
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


# instance fields
.field final synthetic $addresses:Ljava/util/Set;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/Set<",
            "Ltechnology/cariad/cat/genx/protocol/Address;",
            ">;"
        }
    .end annotation
.end field

.field final synthetic $connectionDelegate:Ltechnology/cariad/cat/genx/VehicleAntennaTransport$Connection$Delegate;

.field final synthetic $continuation:Lkotlin/coroutines/Continuation;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lkotlin/coroutines/Continuation<",
            "Llx0/o;",
            ">;"
        }
    .end annotation
.end field

.field final synthetic $newToken:Ltechnology/cariad/cat/genx/ScanningManager$ScanningToken;

.field final synthetic this$0:Ltechnology/cariad/cat/genx/VehicleAntennaTransportImpl;


# direct methods
.method public constructor <init>(Ltechnology/cariad/cat/genx/VehicleAntennaTransportImpl;Ltechnology/cariad/cat/genx/VehicleAntennaTransport$Connection$Delegate;Ljava/util/Set;Ltechnology/cariad/cat/genx/ScanningManager$ScanningToken;Lkotlin/coroutines/Continuation;)V
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ltechnology/cariad/cat/genx/VehicleAntennaTransportImpl;",
            "Ltechnology/cariad/cat/genx/VehicleAntennaTransport$Connection$Delegate;",
            "Ljava/util/Set<",
            "Ltechnology/cariad/cat/genx/protocol/Address;",
            ">;",
            "Ltechnology/cariad/cat/genx/ScanningManager$ScanningToken;",
            "Lkotlin/coroutines/Continuation<",
            "-",
            "Llx0/o;",
            ">;)V"
        }
    .end annotation

    .line 1
    iput-object p1, p0, Ltechnology/cariad/cat/genx/VehicleAntennaTransportImpl$connect$7$1$1$1;->this$0:Ltechnology/cariad/cat/genx/VehicleAntennaTransportImpl;

    .line 2
    .line 3
    iput-object p2, p0, Ltechnology/cariad/cat/genx/VehicleAntennaTransportImpl$connect$7$1$1$1;->$connectionDelegate:Ltechnology/cariad/cat/genx/VehicleAntennaTransport$Connection$Delegate;

    .line 4
    .line 5
    iput-object p3, p0, Ltechnology/cariad/cat/genx/VehicleAntennaTransportImpl$connect$7$1$1$1;->$addresses:Ljava/util/Set;

    .line 6
    .line 7
    iput-object p4, p0, Ltechnology/cariad/cat/genx/VehicleAntennaTransportImpl$connect$7$1$1$1;->$newToken:Ltechnology/cariad/cat/genx/ScanningManager$ScanningToken;

    .line 8
    .line 9
    iput-object p5, p0, Ltechnology/cariad/cat/genx/VehicleAntennaTransportImpl$connect$7$1$1$1;->$continuation:Lkotlin/coroutines/Continuation;

    .line 10
    .line 11
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 12
    .line 13
    .line 14
    return-void
.end method


# virtual methods
.method public bridge synthetic invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Ltechnology/cariad/cat/genx/GenXError;

    invoke-virtual {p0, p1}, Ltechnology/cariad/cat/genx/VehicleAntennaTransportImpl$connect$7$1$1$1;->invoke(Ltechnology/cariad/cat/genx/GenXError;)V

    sget-object p0, Llx0/b0;->a:Llx0/b0;

    return-object p0
.end method

.method public final invoke(Ltechnology/cariad/cat/genx/GenXError;)V
    .locals 6

    if-nez p1, :cond_0

    .line 2
    new-instance v0, Ltechnology/cariad/cat/genx/ConnectionImpl;

    .line 3
    iget-object v1, p0, Ltechnology/cariad/cat/genx/VehicleAntennaTransportImpl$connect$7$1$1$1;->this$0:Ltechnology/cariad/cat/genx/VehicleAntennaTransportImpl;

    .line 4
    invoke-static {v1}, Ltechnology/cariad/cat/genx/VehicleAntennaTransportImpl;->access$getGenXDispatcher$p(Ltechnology/cariad/cat/genx/VehicleAntennaTransportImpl;)Ltechnology/cariad/cat/genx/GenXDispatcher;

    move-result-object v2

    .line 5
    iget-object v3, p0, Ltechnology/cariad/cat/genx/VehicleAntennaTransportImpl$connect$7$1$1$1;->$connectionDelegate:Ltechnology/cariad/cat/genx/VehicleAntennaTransport$Connection$Delegate;

    .line 6
    iget-object v4, p0, Ltechnology/cariad/cat/genx/VehicleAntennaTransportImpl$connect$7$1$1$1;->$addresses:Ljava/util/Set;

    .line 7
    iget-object v5, p0, Ltechnology/cariad/cat/genx/VehicleAntennaTransportImpl$connect$7$1$1$1;->$newToken:Ltechnology/cariad/cat/genx/ScanningManager$ScanningToken;

    .line 8
    invoke-direct/range {v0 .. v5}, Ltechnology/cariad/cat/genx/ConnectionImpl;-><init>(Ltechnology/cariad/cat/genx/InternalVehicleAntennaTransport;Ltechnology/cariad/cat/genx/GenXDispatcher;Ltechnology/cariad/cat/genx/VehicleAntennaTransport$Connection$Delegate;Ljava/util/Set;Ltechnology/cariad/cat/genx/ScanningManager$ScanningToken;)V

    .line 9
    iget-object p1, p0, Ltechnology/cariad/cat/genx/VehicleAntennaTransportImpl$connect$7$1$1$1;->this$0:Ltechnology/cariad/cat/genx/VehicleAntennaTransportImpl;

    invoke-static {p1}, Ltechnology/cariad/cat/genx/VehicleAntennaTransportImpl;->access$getConnections$p(Ltechnology/cariad/cat/genx/VehicleAntennaTransportImpl;)Ljava/util/concurrent/CopyOnWriteArrayList;

    move-result-object p1

    invoke-virtual {p1, v0}, Ljava/util/concurrent/CopyOnWriteArrayList;->add(Ljava/lang/Object;)Z

    .line 10
    iget-object p0, p0, Ltechnology/cariad/cat/genx/VehicleAntennaTransportImpl$connect$7$1$1$1;->$continuation:Lkotlin/coroutines/Continuation;

    .line 11
    new-instance p1, Llx0/o;

    invoke-direct {p1, v0}, Llx0/o;-><init>(Ljava/lang/Object;)V

    .line 12
    invoke-interface {p0, p1}, Lkotlin/coroutines/Continuation;->resumeWith(Ljava/lang/Object;)V

    return-void

    .line 13
    :cond_0
    iget-object p0, p0, Ltechnology/cariad/cat/genx/VehicleAntennaTransportImpl$connect$7$1$1$1;->$continuation:Lkotlin/coroutines/Continuation;

    invoke-static {p1}, Lps/t1;->a(Ljava/lang/Throwable;)Llx0/n;

    move-result-object p1

    .line 14
    new-instance v0, Llx0/o;

    invoke-direct {v0, p1}, Llx0/o;-><init>(Ljava/lang/Object;)V

    .line 15
    invoke-interface {p0, v0}, Lkotlin/coroutines/Continuation;->resumeWith(Ljava/lang/Object;)V

    return-void
.end method
