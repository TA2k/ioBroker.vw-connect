.class public final Ltechnology/cariad/cat/genx/protocol/Address$Companion;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Ltechnology/cariad/cat/genx/protocol/Address;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = "Companion"
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000\u0014\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0002\u0008\u0005\u0008\u0086\u0003\u0018\u00002\u00020\u0001B\t\u0008\u0002\u00a2\u0006\u0004\u0008\u0002\u0010\u0003R\u0011\u0010\u0004\u001a\u00020\u0005\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008\u0006\u0010\u0007R\u0011\u0010\u0008\u001a\u00020\u0005\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008\t\u0010\u0007\u00a8\u0006\n"
    }
    d2 = {
        "Ltechnology/cariad/cat/genx/protocol/Address$Companion;",
        "",
        "<init>",
        "()V",
        "vehicleDataRequest",
        "Ltechnology/cariad/cat/genx/protocol/Address;",
        "getVehicleDataRequest",
        "()Ltechnology/cariad/cat/genx/protocol/Address;",
        "vehicleDataResponse",
        "getVehicleDataResponse",
        "genx_release"
    }
    k = 0x1
    mv = {
        0x2,
        0x2,
        0x0
    }
    xi = 0x30
.end annotation


# direct methods
.method private constructor <init>()V
    .locals 0

    .line 2
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(Lkotlin/jvm/internal/g;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ltechnology/cariad/cat/genx/protocol/Address$Companion;-><init>()V

    return-void
.end method


# virtual methods
.method public final getVehicleDataRequest()Ltechnology/cariad/cat/genx/protocol/Address;
    .locals 0

    .line 1
    invoke-static {}, Ltechnology/cariad/cat/genx/protocol/Address;->access$getVehicleDataRequest$cp()Ltechnology/cariad/cat/genx/protocol/Address;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public final getVehicleDataResponse()Ltechnology/cariad/cat/genx/protocol/Address;
    .locals 0

    .line 1
    invoke-static {}, Ltechnology/cariad/cat/genx/protocol/Address;->access$getVehicleDataResponse$cp()Ltechnology/cariad/cat/genx/protocol/Address;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method
