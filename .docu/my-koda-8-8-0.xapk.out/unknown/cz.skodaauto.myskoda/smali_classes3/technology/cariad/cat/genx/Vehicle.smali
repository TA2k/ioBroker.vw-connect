.class public interface abstract Ltechnology/cariad/cat/genx/Vehicle;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Ltechnology/cariad/cat/genx/Vehicle$AntennaEvent;,
        Ltechnology/cariad/cat/genx/Vehicle$Information;
    }
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000<\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0010\u000e\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0002\u0010\u000b\n\u0002\u0008\u0006\u0008f\u0018\u00002\u00020\u0001:\u0002\u0019\u001aR\u0018\u0010\u0006\u001a\u00060\u0002j\u0002`\u00038&X\u00a6\u0004\u00a2\u0006\u0006\u001a\u0004\u0008\u0004\u0010\u0005R\u0016\u0010\n\u001a\u0004\u0018\u00010\u00078&X\u00a6\u0004\u00a2\u0006\u0006\u001a\u0004\u0008\u0008\u0010\tR\u0016\u0010\u000e\u001a\u0004\u0018\u00010\u000b8&X\u00a6\u0004\u00a2\u0006\u0006\u001a\u0004\u0008\u000c\u0010\rR\u001a\u0010\u0013\u001a\u0008\u0012\u0004\u0012\u00020\u00100\u000f8&X\u00a6\u0004\u00a2\u0006\u0006\u001a\u0004\u0008\u0011\u0010\u0012R\u001a\u0010\u0016\u001a\u0008\u0012\u0004\u0012\u00020\u00150\u00148&X\u00a6\u0004\u00a2\u0006\u0006\u001a\u0004\u0008\u0016\u0010\u0017R\u001a\u0010\u0018\u001a\u0008\u0012\u0004\u0012\u00020\u00150\u00148&X\u00a6\u0004\u00a2\u0006\u0006\u001a\u0004\u0008\u0018\u0010\u0017\u00a8\u0006\u001b\u00c0\u0006\u0003"
    }
    d2 = {
        "Ltechnology/cariad/cat/genx/Vehicle;",
        "",
        "",
        "Ltechnology/cariad/cat/genx/VIN;",
        "getVin",
        "()Ljava/lang/String;",
        "vin",
        "Ltechnology/cariad/cat/genx/VehicleAntenna$Inner;",
        "getInnerAntenna",
        "()Ltechnology/cariad/cat/genx/VehicleAntenna$Inner;",
        "innerAntenna",
        "Ltechnology/cariad/cat/genx/VehicleAntenna$Outer;",
        "getOuterAntenna",
        "()Ltechnology/cariad/cat/genx/VehicleAntenna$Outer;",
        "outerAntenna",
        "Lyy0/i;",
        "Ltechnology/cariad/cat/genx/Vehicle$AntennaEvent;",
        "getAntennasChanged",
        "()Lyy0/i;",
        "antennasChanged",
        "Lyy0/a2;",
        "",
        "isWifiEnabled",
        "()Lyy0/a2;",
        "isBluetoothEnabled",
        "AntennaEvent",
        "Information",
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


# virtual methods
.method public abstract getAntennasChanged()Lyy0/i;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Lyy0/i;"
        }
    .end annotation
.end method

.method public abstract getInnerAntenna()Ltechnology/cariad/cat/genx/VehicleAntenna$Inner;
.end method

.method public abstract getOuterAntenna()Ltechnology/cariad/cat/genx/VehicleAntenna$Outer;
.end method

.method public abstract getVin()Ljava/lang/String;
.end method

.method public abstract isBluetoothEnabled()Lyy0/a2;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Lyy0/a2;"
        }
    .end annotation
.end method

.method public abstract isWifiEnabled()Lyy0/a2;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Lyy0/a2;"
        }
    .end annotation
.end method
