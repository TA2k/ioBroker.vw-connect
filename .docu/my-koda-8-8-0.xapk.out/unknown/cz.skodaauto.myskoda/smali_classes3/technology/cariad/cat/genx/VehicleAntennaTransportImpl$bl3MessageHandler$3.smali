.class final synthetic Ltechnology/cariad/cat/genx/VehicleAntennaTransportImpl$bl3MessageHandler$3;
.super Lkotlin/jvm/internal/k;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# annotations
.annotation system Ldalvik/annotation/EnclosingMethod;
    value = Ltechnology/cariad/cat/genx/VehicleAntennaTransportImpl;-><init>(JLandroid/content/Context;Ltechnology/cariad/cat/genx/TransportType;Ltechnology/cariad/cat/genx/protocol/data/LinkParameters$RequestValues;Ltechnology/cariad/cat/genx/GenXDispatcher;Ltechnology/cariad/cat/genx/InternalVehicleAntenna;Ljava/lang/ref/WeakReference;Lvy0/b0;Z)V
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x1019
    name = null
.end annotation

.annotation system Ldalvik/annotation/Signature;
    value = {
        "Lkotlin/jvm/internal/k;",
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


# direct methods
.method public constructor <init>(Ljava/lang/Object;)V
    .locals 7

    .line 1
    const-string v6, "sendNonDispatched(Ltechnology/cariad/cat/genx/protocol/Message;)Ltechnology/cariad/cat/genx/GenXError;"

    .line 2
    .line 3
    const/4 v2, 0x0

    .line 4
    const/4 v1, 0x1

    .line 5
    const-class v3, Ltechnology/cariad/cat/genx/VehicleAntennaTransportImpl;

    .line 6
    .line 7
    const-string v5, "sendNonDispatched"

    .line 8
    .line 9
    move-object v0, p0

    .line 10
    move-object v4, p1

    .line 11
    invoke-direct/range {v0 .. v6}, Lkotlin/jvm/internal/j;-><init>(IILjava/lang/Class;Ljava/lang/Object;Ljava/lang/String;Ljava/lang/String;)V

    .line 12
    .line 13
    .line 14
    return-void
.end method


# virtual methods
.method public bridge synthetic invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Ltechnology/cariad/cat/genx/protocol/Message;

    invoke-virtual {p0, p1}, Ltechnology/cariad/cat/genx/VehicleAntennaTransportImpl$bl3MessageHandler$3;->invoke(Ltechnology/cariad/cat/genx/protocol/Message;)Ltechnology/cariad/cat/genx/GenXError;

    move-result-object p0

    return-object p0
.end method

.method public final invoke(Ltechnology/cariad/cat/genx/protocol/Message;)Ltechnology/cariad/cat/genx/GenXError;
    .locals 1

    const-string v0, "p0"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 2
    iget-object p0, p0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    check-cast p0, Ltechnology/cariad/cat/genx/VehicleAntennaTransportImpl;

    invoke-virtual {p0, p1}, Ltechnology/cariad/cat/genx/VehicleAntennaTransportImpl;->sendNonDispatched(Ltechnology/cariad/cat/genx/protocol/Message;)Ltechnology/cariad/cat/genx/GenXError;

    move-result-object p0

    return-object p0
.end method
