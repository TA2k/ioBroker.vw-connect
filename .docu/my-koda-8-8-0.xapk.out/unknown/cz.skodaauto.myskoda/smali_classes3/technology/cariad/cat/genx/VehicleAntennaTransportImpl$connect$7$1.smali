.class final Ltechnology/cariad/cat/genx/VehicleAntennaTransportImpl$connect$7$1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/a;


# annotations
.annotation system Ldalvik/annotation/EnclosingMethod;
    value = Ltechnology/cariad/cat/genx/VehicleAntennaTransportImpl;->connect-0E7RQCE(Ltechnology/cariad/cat/genx/VehicleAntennaTransport$Connection$Delegate;Ljava/util/Set;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = null
.end annotation

.annotation system Ldalvik/annotation/Signature;
    value = {
        "Ljava/lang/Object;",
        "Lay0/a;"
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
.method public constructor <init>(Ltechnology/cariad/cat/genx/ScanningManager$ScanningToken;Lkotlin/coroutines/Continuation;Ltechnology/cariad/cat/genx/VehicleAntennaTransportImpl;Ltechnology/cariad/cat/genx/VehicleAntennaTransport$Connection$Delegate;Ljava/util/Set;)V
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ltechnology/cariad/cat/genx/ScanningManager$ScanningToken;",
            "Lkotlin/coroutines/Continuation<",
            "-",
            "Llx0/o;",
            ">;",
            "Ltechnology/cariad/cat/genx/VehicleAntennaTransportImpl;",
            "Ltechnology/cariad/cat/genx/VehicleAntennaTransport$Connection$Delegate;",
            "Ljava/util/Set<",
            "Ltechnology/cariad/cat/genx/protocol/Address;",
            ">;)V"
        }
    .end annotation

    .line 1
    iput-object p1, p0, Ltechnology/cariad/cat/genx/VehicleAntennaTransportImpl$connect$7$1;->$newToken:Ltechnology/cariad/cat/genx/ScanningManager$ScanningToken;

    .line 2
    .line 3
    iput-object p2, p0, Ltechnology/cariad/cat/genx/VehicleAntennaTransportImpl$connect$7$1;->$continuation:Lkotlin/coroutines/Continuation;

    .line 4
    .line 5
    iput-object p3, p0, Ltechnology/cariad/cat/genx/VehicleAntennaTransportImpl$connect$7$1;->this$0:Ltechnology/cariad/cat/genx/VehicleAntennaTransportImpl;

    .line 6
    .line 7
    iput-object p4, p0, Ltechnology/cariad/cat/genx/VehicleAntennaTransportImpl$connect$7$1;->$connectionDelegate:Ltechnology/cariad/cat/genx/VehicleAntennaTransport$Connection$Delegate;

    .line 8
    .line 9
    iput-object p5, p0, Ltechnology/cariad/cat/genx/VehicleAntennaTransportImpl$connect$7$1;->$addresses:Ljava/util/Set;

    .line 10
    .line 11
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 12
    .line 13
    .line 14
    return-void
.end method


# virtual methods
.method public bridge synthetic invoke()Ljava/lang/Object;
    .locals 0

    .line 1
    invoke-virtual {p0}, Ltechnology/cariad/cat/genx/VehicleAntennaTransportImpl$connect$7$1;->invoke()V

    sget-object p0, Llx0/b0;->a:Llx0/b0;

    return-object p0
.end method

.method public final invoke()V
    .locals 8

    .line 2
    new-instance v0, Ltechnology/cariad/cat/genx/VehicleAntennaTransportImpl$connect$7$1$nativeConnectError$1;

    iget-object v1, p0, Ltechnology/cariad/cat/genx/VehicleAntennaTransportImpl$connect$7$1;->this$0:Ltechnology/cariad/cat/genx/VehicleAntennaTransportImpl;

    invoke-direct {v0, v1}, Ltechnology/cariad/cat/genx/VehicleAntennaTransportImpl$connect$7$1$nativeConnectError$1;-><init>(Ltechnology/cariad/cat/genx/VehicleAntennaTransportImpl;)V

    invoke-static {v0}, Ltechnology/cariad/cat/genx/GenXErrorKt;->checkStatus(Lay0/a;)Ltechnology/cariad/cat/genx/GenXError$CoreGenX;

    move-result-object v0

    if-eqz v0, :cond_1

    .line 3
    iget-object v1, p0, Ltechnology/cariad/cat/genx/VehicleAntennaTransportImpl$connect$7$1;->$newToken:Ltechnology/cariad/cat/genx/ScanningManager$ScanningToken;

    if-eqz v1, :cond_0

    invoke-interface {v1}, Ltechnology/cariad/cat/genx/ScanningManager$ScanningToken;->close()V

    .line 4
    :cond_0
    iget-object p0, p0, Ltechnology/cariad/cat/genx/VehicleAntennaTransportImpl$connect$7$1;->$continuation:Lkotlin/coroutines/Continuation;

    invoke-static {v0}, Lps/t1;->a(Ljava/lang/Throwable;)Llx0/n;

    move-result-object v0

    .line 5
    new-instance v1, Llx0/o;

    invoke-direct {v1, v0}, Llx0/o;-><init>(Ljava/lang/Object;)V

    .line 6
    invoke-interface {p0, v1}, Lkotlin/coroutines/Continuation;->resumeWith(Ljava/lang/Object;)V

    return-void

    .line 7
    :cond_1
    iget-object v0, p0, Ltechnology/cariad/cat/genx/VehicleAntennaTransportImpl$connect$7$1;->this$0:Ltechnology/cariad/cat/genx/VehicleAntennaTransportImpl;

    invoke-virtual {v0}, Ltechnology/cariad/cat/genx/VehicleAntennaTransportImpl;->getTransportState()Lyy0/j1;

    move-result-object v0

    check-cast v0, Lyy0/c2;

    invoke-virtual {v0}, Lyy0/c2;->getValue()Ljava/lang/Object;

    move-result-object v0

    sget-object v1, Ltechnology/cariad/cat/genx/TransportState;->CONNECTED:Ltechnology/cariad/cat/genx/TransportState;

    if-ne v0, v1, :cond_2

    .line 8
    new-instance v2, Ltechnology/cariad/cat/genx/ConnectionImpl;

    .line 9
    iget-object v3, p0, Ltechnology/cariad/cat/genx/VehicleAntennaTransportImpl$connect$7$1;->this$0:Ltechnology/cariad/cat/genx/VehicleAntennaTransportImpl;

    .line 10
    invoke-static {v3}, Ltechnology/cariad/cat/genx/VehicleAntennaTransportImpl;->access$getGenXDispatcher$p(Ltechnology/cariad/cat/genx/VehicleAntennaTransportImpl;)Ltechnology/cariad/cat/genx/GenXDispatcher;

    move-result-object v4

    .line 11
    iget-object v5, p0, Ltechnology/cariad/cat/genx/VehicleAntennaTransportImpl$connect$7$1;->$connectionDelegate:Ltechnology/cariad/cat/genx/VehicleAntennaTransport$Connection$Delegate;

    .line 12
    iget-object v6, p0, Ltechnology/cariad/cat/genx/VehicleAntennaTransportImpl$connect$7$1;->$addresses:Ljava/util/Set;

    .line 13
    iget-object v7, p0, Ltechnology/cariad/cat/genx/VehicleAntennaTransportImpl$connect$7$1;->$newToken:Ltechnology/cariad/cat/genx/ScanningManager$ScanningToken;

    .line 14
    invoke-direct/range {v2 .. v7}, Ltechnology/cariad/cat/genx/ConnectionImpl;-><init>(Ltechnology/cariad/cat/genx/InternalVehicleAntennaTransport;Ltechnology/cariad/cat/genx/GenXDispatcher;Ltechnology/cariad/cat/genx/VehicleAntennaTransport$Connection$Delegate;Ljava/util/Set;Ltechnology/cariad/cat/genx/ScanningManager$ScanningToken;)V

    .line 15
    iget-object v0, p0, Ltechnology/cariad/cat/genx/VehicleAntennaTransportImpl$connect$7$1;->this$0:Ltechnology/cariad/cat/genx/VehicleAntennaTransportImpl;

    invoke-static {v0}, Ltechnology/cariad/cat/genx/VehicleAntennaTransportImpl;->access$getConnections$p(Ltechnology/cariad/cat/genx/VehicleAntennaTransportImpl;)Ljava/util/concurrent/CopyOnWriteArrayList;

    move-result-object v0

    invoke-virtual {v0, v2}, Ljava/util/concurrent/CopyOnWriteArrayList;->add(Ljava/lang/Object;)Z

    .line 16
    iget-object p0, p0, Ltechnology/cariad/cat/genx/VehicleAntennaTransportImpl$connect$7$1;->$continuation:Lkotlin/coroutines/Continuation;

    .line 17
    new-instance v0, Llx0/o;

    invoke-direct {v0, v2}, Llx0/o;-><init>(Ljava/lang/Object;)V

    .line 18
    invoke-interface {p0, v0}, Lkotlin/coroutines/Continuation;->resumeWith(Ljava/lang/Object;)V

    return-void

    .line 19
    :cond_2
    iget-object v0, p0, Ltechnology/cariad/cat/genx/VehicleAntennaTransportImpl$connect$7$1;->this$0:Ltechnology/cariad/cat/genx/VehicleAntennaTransportImpl;

    invoke-static {v0}, Ltechnology/cariad/cat/genx/VehicleAntennaTransportImpl;->access$getConnectCompletionsLock$p(Ltechnology/cariad/cat/genx/VehicleAntennaTransportImpl;)Ljava/util/concurrent/locks/ReentrantLock;

    move-result-object v1

    iget-object v3, p0, Ltechnology/cariad/cat/genx/VehicleAntennaTransportImpl$connect$7$1;->this$0:Ltechnology/cariad/cat/genx/VehicleAntennaTransportImpl;

    iget-object v4, p0, Ltechnology/cariad/cat/genx/VehicleAntennaTransportImpl$connect$7$1;->$connectionDelegate:Ltechnology/cariad/cat/genx/VehicleAntennaTransport$Connection$Delegate;

    iget-object v5, p0, Ltechnology/cariad/cat/genx/VehicleAntennaTransportImpl$connect$7$1;->$addresses:Ljava/util/Set;

    iget-object v6, p0, Ltechnology/cariad/cat/genx/VehicleAntennaTransportImpl$connect$7$1;->$newToken:Ltechnology/cariad/cat/genx/ScanningManager$ScanningToken;

    iget-object v7, p0, Ltechnology/cariad/cat/genx/VehicleAntennaTransportImpl$connect$7$1;->$continuation:Lkotlin/coroutines/Continuation;

    invoke-interface {v1}, Ljava/util/concurrent/locks/Lock;->lock()V

    .line 20
    :try_start_0
    invoke-static {v3}, Ltechnology/cariad/cat/genx/VehicleAntennaTransportImpl;->access$getConnectCompletions$p(Ltechnology/cariad/cat/genx/VehicleAntennaTransportImpl;)Ljava/util/List;

    move-result-object p0

    new-instance v2, Ltechnology/cariad/cat/genx/VehicleAntennaTransportImpl$connect$7$1$1$1;

    invoke-direct/range {v2 .. v7}, Ltechnology/cariad/cat/genx/VehicleAntennaTransportImpl$connect$7$1$1$1;-><init>(Ltechnology/cariad/cat/genx/VehicleAntennaTransportImpl;Ltechnology/cariad/cat/genx/VehicleAntennaTransport$Connection$Delegate;Ljava/util/Set;Ltechnology/cariad/cat/genx/ScanningManager$ScanningToken;Lkotlin/coroutines/Continuation;)V

    invoke-interface {p0, v2}, Ljava/util/List;->add(Ljava/lang/Object;)Z
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 21
    invoke-interface {v1}, Ljava/util/concurrent/locks/Lock;->unlock()V

    return-void

    :catchall_0
    move-exception v0

    move-object p0, v0

    invoke-interface {v1}, Ljava/util/concurrent/locks/Lock;->unlock()V

    throw p0
.end method
