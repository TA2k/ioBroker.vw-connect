.class public final Ltechnology/cariad/cat/genx/VehicleAntennaTransportImpl$special$$inlined$CoroutineExceptionHandler$1;
.super Lpx0/a;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lvy0/z;


# annotations
.annotation system Ldalvik/annotation/EnclosingMethod;
    value = Ltechnology/cariad/cat/genx/VehicleAntennaTransportImpl;-><init>(JLandroid/content/Context;Ltechnology/cariad/cat/genx/TransportType;Ltechnology/cariad/cat/genx/protocol/data/LinkParameters$RequestValues;Ltechnology/cariad/cat/genx/GenXDispatcher;Ltechnology/cariad/cat/genx/InternalVehicleAntenna;Ljava/lang/ref/WeakReference;Lvy0/b0;Z)V
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = null
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000!\n\u0000\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0003\n\u0000\n\u0002\u0018\u0002\n\u0002\u0008\u0003*\u0001\u0000\u0008\n\u0018\u00002\u00020\u00012\u00020\u0002J\u001f\u0010\u0008\u001a\u00020\u00072\u0006\u0010\u0004\u001a\u00020\u00032\u0006\u0010\u0006\u001a\u00020\u0005H\u0016\u00a2\u0006\u0004\u0008\u0008\u0010\t\u00a8\u0006\n"
    }
    d2 = {
        "technology/cariad/cat/genx/VehicleAntennaTransportImpl$special$$inlined$CoroutineExceptionHandler$1",
        "Lpx0/a;",
        "Lvy0/z;",
        "Lpx0/g;",
        "context",
        "",
        "exception",
        "Llx0/b0;",
        "handleException",
        "(Lpx0/g;Ljava/lang/Throwable;)V",
        "kotlinx-coroutines-core"
    }
    k = 0x1
    mv = {
        0x2,
        0x2,
        0x0
    }
    xi = 0x30
.end annotation


# instance fields
.field final synthetic this$0:Ltechnology/cariad/cat/genx/VehicleAntennaTransportImpl;


# direct methods
.method public constructor <init>(Lvy0/y;Ltechnology/cariad/cat/genx/VehicleAntennaTransportImpl;)V
    .locals 0

    .line 1
    iput-object p2, p0, Ltechnology/cariad/cat/genx/VehicleAntennaTransportImpl$special$$inlined$CoroutineExceptionHandler$1;->this$0:Ltechnology/cariad/cat/genx/VehicleAntennaTransportImpl;

    .line 2
    .line 3
    invoke-direct {p0, p1}, Lpx0/a;-><init>(Lpx0/f;)V

    .line 4
    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public handleException(Lpx0/g;Ljava/lang/Throwable;)V
    .locals 1

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/genx/VehicleAntennaTransportImpl$special$$inlined$CoroutineExceptionHandler$1;->this$0:Ltechnology/cariad/cat/genx/VehicleAntennaTransportImpl;

    .line 2
    .line 3
    sget-object p1, Ltechnology/cariad/cat/genx/VehicleAntennaTransportImpl$transportCoroutineScope$1$1;->INSTANCE:Ltechnology/cariad/cat/genx/VehicleAntennaTransportImpl$transportCoroutineScope$1$1;

    .line 4
    .line 5
    const-string v0, "GenX"

    .line 6
    .line 7
    invoke-static {p0, v0, p2, p1}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->logWarn(Ljava/lang/Object;Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;)V

    .line 8
    .line 9
    .line 10
    throw p2
.end method
