.class public interface abstract Ltechnology/cariad/cat/genx/VehicleAntenna;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Ltechnology/cariad/cat/genx/VehicleAntenna$Identifier;,
        Ltechnology/cariad/cat/genx/VehicleAntenna$Information;,
        Ltechnology/cariad/cat/genx/VehicleAntenna$Inner;,
        Ltechnology/cariad/cat/genx/VehicleAntenna$Outer;
    }
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000^\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0018\u0002\n\u0002\u0010\u0008\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0002\u0010\"\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0018\u0002\n\u0002\u0008\t\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\u0008v\u0018\u00002\u00020\u0001:\u0004 !\"#J\u0016\u0010\u0006\u001a\u0008\u0012\u0004\u0012\u00020\u00030\u0002H\u00a6@\u00a2\u0006\u0004\u0008\u0004\u0010\u0005R \u0010\u000c\u001a\u000e\u0012\n\u0012\u0008\u0012\u0004\u0012\u00020\t0\u00080\u00078&X\u00a6\u0004\u00a2\u0006\u0006\u001a\u0004\u0008\n\u0010\u000bR&\u0010\u0013\u001a\u0014\u0012\u0010\u0012\u000e\u0012\u0004\u0012\u00020\u000f\u0012\u0004\u0012\u00020\u00100\u000e0\r8&X\u00a6\u0004\u00a2\u0006\u0006\u001a\u0004\u0008\u0011\u0010\u0012R\u001a\u0010\u0016\u001a\u0008\u0012\u0004\u0012\u00020\u00140\u00078&X\u00a6\u0004\u00a2\u0006\u0006\u001a\u0004\u0008\u0015\u0010\u000bR\u001a\u0010\u0019\u001a\u0008\u0012\u0004\u0012\u00020\u00170\r8&X\u00a6\u0004\u00a2\u0006\u0006\u001a\u0004\u0008\u0018\u0010\u0012R\u001a\u0010\u001c\u001a\u0008\u0012\u0004\u0012\u00020\u001a0\r8&X\u00a6\u0004\u00a2\u0006\u0006\u001a\u0004\u0008\u001b\u0010\u0012R\u0014\u0010\u001f\u001a\u00020\u001a8&X\u00a6\u0004\u00a2\u0006\u0006\u001a\u0004\u0008\u001d\u0010\u001e\u0082\u0001\u0003$%&\u00a8\u0006\'\u00c0\u0006\u0003"
    }
    d2 = {
        "Ltechnology/cariad/cat/genx/VehicleAntenna;",
        "",
        "Llx0/o;",
        "",
        "getLamVersion-IoAF18A",
        "(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;",
        "getLamVersion",
        "Lyy0/a2;",
        "",
        "Lt41/g;",
        "getFoundBeacons",
        "()Lyy0/a2;",
        "foundBeacons",
        "Lyy0/i;",
        "Llx0/l;",
        "Ltechnology/cariad/cat/genx/TransportType;",
        "Ltechnology/cariad/cat/genx/GenXError;",
        "getEncounteredError",
        "()Lyy0/i;",
        "encounteredError",
        "Ltechnology/cariad/cat/genx/Reachability;",
        "getReachability",
        "reachability",
        "Ltechnology/cariad/cat/genx/SoftwareStackIncompatibility;",
        "getSoftwareStackIncompatibility",
        "softwareStackIncompatibility",
        "Ltechnology/cariad/cat/genx/VehicleAntenna$Information;",
        "getInformationUpdated",
        "informationUpdated",
        "getInformation",
        "()Ltechnology/cariad/cat/genx/VehicleAntenna$Information;",
        "information",
        "Identifier",
        "Information",
        "Outer",
        "Inner",
        "Ltechnology/cariad/cat/genx/InternalVehicleAntenna;",
        "Ltechnology/cariad/cat/genx/VehicleAntenna$Inner;",
        "Ltechnology/cariad/cat/genx/VehicleAntenna$Outer;",
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
.method public abstract getEncounteredError()Lyy0/i;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Lyy0/i;"
        }
    .end annotation
.end method

.method public abstract getFoundBeacons()Lyy0/a2;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Lyy0/a2;"
        }
    .end annotation
.end method

.method public abstract getInformation()Ltechnology/cariad/cat/genx/VehicleAntenna$Information;
.end method

.method public abstract getInformationUpdated()Lyy0/i;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Lyy0/i;"
        }
    .end annotation
.end method

.method public abstract getLamVersion-IoAF18A(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lkotlin/coroutines/Continuation<",
            "-",
            "Llx0/o;",
            ">;)",
            "Ljava/lang/Object;"
        }
    .end annotation
.end method

.method public abstract getReachability()Lyy0/a2;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Lyy0/a2;"
        }
    .end annotation
.end method

.method public abstract getSoftwareStackIncompatibility()Lyy0/i;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Lyy0/i;"
        }
    .end annotation
.end method
