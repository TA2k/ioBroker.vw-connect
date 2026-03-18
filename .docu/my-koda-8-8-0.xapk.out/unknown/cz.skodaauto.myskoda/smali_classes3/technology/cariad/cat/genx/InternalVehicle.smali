.class public interface abstract Ltechnology/cariad/cat/genx/InternalVehicle;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltechnology/cariad/cat/genx/Vehicle;
.implements Ltechnology/cariad/cat/genx/Referencing;


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Ltechnology/cariad/cat/genx/InternalVehicle$DefaultImpls;
    }
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000j\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0008\u0005\n\u0002\u0010\u0008\n\u0000\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u000b\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0002\u0008\u0004\u0008`\u0018\u00002\u00020\u00012\u00020\u0002J\u0019\u0010\u0006\u001a\u0004\u0018\u00010\u00052\u0006\u0010\u0004\u001a\u00020\u0003H\'\u00a2\u0006\u0004\u0008\u0006\u0010\u0007J+\u0010\u000e\u001a\u0004\u0018\u00010\u00052\u0006\u0010\t\u001a\u00020\u00082\u0008\u0008\u0002\u0010\u000b\u001a\u00020\n2\u0006\u0010\r\u001a\u00020\u000cH\'\u00a2\u0006\u0004\u0008\u000e\u0010\u000fJ!\u0010\u0010\u001a\u0004\u0018\u00010\u00052\u0006\u0010\t\u001a\u00020\u00082\u0006\u0010\r\u001a\u00020\u000cH\'\u00a2\u0006\u0004\u0008\u0010\u0010\u0011J\u0017\u0010\u0015\u001a\u00020\u00142\u0006\u0010\u0013\u001a\u00020\u0012H&\u00a2\u0006\u0004\u0008\u0015\u0010\u0016J\u0017\u0010\u0017\u001a\u00020\u00142\u0006\u0010\u0013\u001a\u00020\u0012H&\u00a2\u0006\u0004\u0008\u0017\u0010\u0016J\u001f\u0010\u001c\u001a\u00020\u00142\u0006\u0010\u0019\u001a\u00020\u00182\u0006\u0010\u001b\u001a\u00020\u001aH&\u00a2\u0006\u0004\u0008\u001c\u0010\u001dR\u0014\u0010!\u001a\u00020\u001e8&X\u00a6\u0004\u00a2\u0006\u0006\u001a\u0004\u0008\u001f\u0010 R\u0014\u0010%\u001a\u00020\"8&X\u00a6\u0004\u00a2\u0006\u0006\u001a\u0004\u0008#\u0010$R\u0016\u0010)\u001a\u0004\u0018\u00010&8&X\u00a6\u0004\u00a2\u0006\u0006\u001a\u0004\u0008\'\u0010(R\u0016\u0010-\u001a\u0004\u0018\u00010*8&X\u00a6\u0004\u00a2\u0006\u0006\u001a\u0004\u0008+\u0010,\u00a8\u0006.\u00c0\u0006\u0003"
    }
    d2 = {
        "Ltechnology/cariad/cat/genx/InternalVehicle;",
        "Ltechnology/cariad/cat/genx/Vehicle;",
        "Ltechnology/cariad/cat/genx/Referencing;",
        "Ltechnology/cariad/cat/genx/Antenna;",
        "antenna",
        "Ltechnology/cariad/cat/genx/GenXError;",
        "removeAntenna",
        "(Ltechnology/cariad/cat/genx/Antenna;)Ltechnology/cariad/cat/genx/GenXError;",
        "Ltechnology/cariad/cat/genx/VehicleAntenna$Information;",
        "antennaInformation",
        "Ltechnology/cariad/cat/genx/protocol/data/LinkParameters$RequestValues;",
        "linkedParameterRequestValues",
        "Ltechnology/cariad/cat/genx/crypto/CredentialStore;",
        "credentialStore",
        "addAntenna",
        "(Ltechnology/cariad/cat/genx/VehicleAntenna$Information;Ltechnology/cariad/cat/genx/protocol/data/LinkParameters$RequestValues;Ltechnology/cariad/cat/genx/crypto/CredentialStore;)Ltechnology/cariad/cat/genx/GenXError;",
        "updateAntenna",
        "(Ltechnology/cariad/cat/genx/VehicleAntenna$Information;Ltechnology/cariad/cat/genx/crypto/CredentialStore;)Ltechnology/cariad/cat/genx/GenXError;",
        "",
        "cgxAntenna",
        "Llx0/b0;",
        "onAntennaAdded",
        "(I)V",
        "onAntennaRemoved",
        "Ltechnology/cariad/cat/genx/TransportType;",
        "transportType",
        "",
        "enabled",
        "setClientManagerState",
        "(Ltechnology/cariad/cat/genx/TransportType;Z)V",
        "Ltechnology/cariad/cat/genx/DeviceInformation;",
        "getDeviceInformation",
        "()Ltechnology/cariad/cat/genx/DeviceInformation;",
        "deviceInformation",
        "Ltechnology/cariad/cat/genx/GenXDispatcher;",
        "getGenXDispatcher",
        "()Ltechnology/cariad/cat/genx/GenXDispatcher;",
        "genXDispatcher",
        "Ltechnology/cariad/cat/genx/InternalVehicleAntenna$Inner;",
        "getInnerAntenna",
        "()Ltechnology/cariad/cat/genx/InternalVehicleAntenna$Inner;",
        "innerAntenna",
        "Ltechnology/cariad/cat/genx/InternalVehicleAntenna$Outer;",
        "getOuterAntenna",
        "()Ltechnology/cariad/cat/genx/InternalVehicleAntenna$Outer;",
        "outerAntenna",
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
.method public static synthetic addAntenna$default(Ltechnology/cariad/cat/genx/InternalVehicle;Ltechnology/cariad/cat/genx/VehicleAntenna$Information;Ltechnology/cariad/cat/genx/protocol/data/LinkParameters$RequestValues;Ltechnology/cariad/cat/genx/crypto/CredentialStore;ILjava/lang/Object;)Ltechnology/cariad/cat/genx/GenXError;
    .locals 7

    .line 1
    if-nez p5, :cond_1

    .line 2
    .line 3
    and-int/lit8 p4, p4, 0x2

    .line 4
    .line 5
    if-eqz p4, :cond_0

    .line 6
    .line 7
    new-instance v0, Ltechnology/cariad/cat/genx/protocol/data/LinkParameters$RequestValues;

    .line 8
    .line 9
    const/16 v5, 0xf

    .line 10
    .line 11
    const/4 v6, 0x0

    .line 12
    const/4 v1, 0x0

    .line 13
    const/4 v2, 0x0

    .line 14
    const/4 v3, 0x0

    .line 15
    const/4 v4, 0x0

    .line 16
    invoke-direct/range {v0 .. v6}, Ltechnology/cariad/cat/genx/protocol/data/LinkParameters$RequestValues;-><init>(IIIIILkotlin/jvm/internal/g;)V

    .line 17
    .line 18
    .line 19
    move-object p2, v0

    .line 20
    :cond_0
    invoke-interface {p0, p1, p2, p3}, Ltechnology/cariad/cat/genx/InternalVehicle;->addAntenna(Ltechnology/cariad/cat/genx/VehicleAntenna$Information;Ltechnology/cariad/cat/genx/protocol/data/LinkParameters$RequestValues;Ltechnology/cariad/cat/genx/crypto/CredentialStore;)Ltechnology/cariad/cat/genx/GenXError;

    .line 21
    .line 22
    .line 23
    move-result-object p0

    .line 24
    return-object p0

    .line 25
    :cond_1
    new-instance p0, Ljava/lang/UnsupportedOperationException;

    .line 26
    .line 27
    const-string p1, "Super calls with default arguments not supported in this target, function: addAntenna"

    .line 28
    .line 29
    invoke-direct {p0, p1}, Ljava/lang/UnsupportedOperationException;-><init>(Ljava/lang/String;)V

    .line 30
    .line 31
    .line 32
    throw p0
.end method


# virtual methods
.method public abstract addAntenna(Ltechnology/cariad/cat/genx/VehicleAntenna$Information;Ltechnology/cariad/cat/genx/protocol/data/LinkParameters$RequestValues;Ltechnology/cariad/cat/genx/crypto/CredentialStore;)Ltechnology/cariad/cat/genx/GenXError;
    .annotation build Ltechnology/cariad/cat/genx/RequiresGenXDispatch;
    .end annotation
.end method

.method public abstract getDeviceInformation()Ltechnology/cariad/cat/genx/DeviceInformation;
.end method

.method public abstract getGenXDispatcher()Ltechnology/cariad/cat/genx/GenXDispatcher;
.end method

.method public abstract getInnerAntenna()Ltechnology/cariad/cat/genx/InternalVehicleAntenna$Inner;
.end method

.method public abstract getOuterAntenna()Ltechnology/cariad/cat/genx/InternalVehicleAntenna$Outer;
.end method

.method public abstract onAntennaAdded(I)V
.end method

.method public abstract onAntennaRemoved(I)V
.end method

.method public abstract removeAntenna(Ltechnology/cariad/cat/genx/Antenna;)Ltechnology/cariad/cat/genx/GenXError;
    .annotation build Ltechnology/cariad/cat/genx/RequiresGenXDispatch;
    .end annotation
.end method

.method public abstract setClientManagerState(Ltechnology/cariad/cat/genx/TransportType;Z)V
.end method

.method public abstract updateAntenna(Ltechnology/cariad/cat/genx/VehicleAntenna$Information;Ltechnology/cariad/cat/genx/crypto/CredentialStore;)Ltechnology/cariad/cat/genx/GenXError;
    .annotation build Ltechnology/cariad/cat/genx/RequiresGenXDispatch;
    .end annotation
.end method
