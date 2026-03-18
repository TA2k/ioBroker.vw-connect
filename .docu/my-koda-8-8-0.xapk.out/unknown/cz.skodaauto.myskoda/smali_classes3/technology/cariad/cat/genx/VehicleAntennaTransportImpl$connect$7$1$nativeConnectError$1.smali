.class final Ltechnology/cariad/cat/genx/VehicleAntennaTransportImpl$connect$7$1$nativeConnectError$1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/a;


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
.field final synthetic this$0:Ltechnology/cariad/cat/genx/VehicleAntennaTransportImpl;


# direct methods
.method public constructor <init>(Ltechnology/cariad/cat/genx/VehicleAntennaTransportImpl;)V
    .locals 0

    .line 1
    iput-object p1, p0, Ltechnology/cariad/cat/genx/VehicleAntennaTransportImpl$connect$7$1$nativeConnectError$1;->this$0:Ltechnology/cariad/cat/genx/VehicleAntennaTransportImpl;

    .line 2
    .line 3
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Integer;
    .locals 0

    .line 2
    iget-object p0, p0, Ltechnology/cariad/cat/genx/VehicleAntennaTransportImpl$connect$7$1$nativeConnectError$1;->this$0:Ltechnology/cariad/cat/genx/VehicleAntennaTransportImpl;

    invoke-static {p0}, Ltechnology/cariad/cat/genx/VehicleAntennaTransportImpl;->access$nativeConnect(Ltechnology/cariad/cat/genx/VehicleAntennaTransportImpl;)I

    move-result p0

    invoke-static {p0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object p0

    return-object p0
.end method

.method public bridge synthetic invoke()Ljava/lang/Object;
    .locals 0

    .line 1
    invoke-virtual {p0}, Ltechnology/cariad/cat/genx/VehicleAntennaTransportImpl$connect$7$1$nativeConnectError$1;->invoke()Ljava/lang/Integer;

    move-result-object p0

    return-object p0
.end method
