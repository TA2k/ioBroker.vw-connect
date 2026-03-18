.class public final Ltechnology/cariad/cat/genx/Vehicle$AntennaEvent$AntennaAdded;
.super Ltechnology/cariad/cat/genx/Vehicle$AntennaEvent;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Ltechnology/cariad/cat/genx/Vehicle$AntennaEvent;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = "AntennaAdded"
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000\u0018\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0008\u0007\u0018\u00002\u00020\u0001B\u0017\u0012\u0006\u0010\u0002\u001a\u00020\u0003\u0012\u0006\u0010\u0004\u001a\u00020\u0005\u00a2\u0006\u0004\u0008\u0006\u0010\u0007R\u0011\u0010\u0002\u001a\u00020\u0003\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008\u0008\u0010\tR\u0011\u0010\u0004\u001a\u00020\u0005\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008\n\u0010\u000b\u00a8\u0006\u000c"
    }
    d2 = {
        "Ltechnology/cariad/cat/genx/Vehicle$AntennaEvent$AntennaAdded;",
        "Ltechnology/cariad/cat/genx/Vehicle$AntennaEvent;",
        "antenna",
        "Ltechnology/cariad/cat/genx/Antenna;",
        "information",
        "Ltechnology/cariad/cat/genx/VehicleAntenna$Information;",
        "<init>",
        "(Ltechnology/cariad/cat/genx/Antenna;Ltechnology/cariad/cat/genx/VehicleAntenna$Information;)V",
        "getAntenna",
        "()Ltechnology/cariad/cat/genx/Antenna;",
        "getInformation",
        "()Ltechnology/cariad/cat/genx/VehicleAntenna$Information;",
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


# instance fields
.field private final antenna:Ltechnology/cariad/cat/genx/Antenna;

.field private final information:Ltechnology/cariad/cat/genx/VehicleAntenna$Information;


# direct methods
.method public constructor <init>(Ltechnology/cariad/cat/genx/Antenna;Ltechnology/cariad/cat/genx/VehicleAntenna$Information;)V
    .locals 1

    .line 1
    const-string v0, "antenna"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "information"

    .line 7
    .line 8
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    const/4 v0, 0x0

    .line 12
    invoke-direct {p0, v0}, Ltechnology/cariad/cat/genx/Vehicle$AntennaEvent;-><init>(Lkotlin/jvm/internal/g;)V

    .line 13
    .line 14
    .line 15
    iput-object p1, p0, Ltechnology/cariad/cat/genx/Vehicle$AntennaEvent$AntennaAdded;->antenna:Ltechnology/cariad/cat/genx/Antenna;

    .line 16
    .line 17
    iput-object p2, p0, Ltechnology/cariad/cat/genx/Vehicle$AntennaEvent$AntennaAdded;->information:Ltechnology/cariad/cat/genx/VehicleAntenna$Information;

    .line 18
    .line 19
    return-void
.end method


# virtual methods
.method public final getAntenna()Ltechnology/cariad/cat/genx/Antenna;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/genx/Vehicle$AntennaEvent$AntennaAdded;->antenna:Ltechnology/cariad/cat/genx/Antenna;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getInformation()Ltechnology/cariad/cat/genx/VehicleAntenna$Information;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/genx/Vehicle$AntennaEvent$AntennaAdded;->information:Ltechnology/cariad/cat/genx/VehicleAntenna$Information;

    .line 2
    .line 3
    return-object p0
.end method
