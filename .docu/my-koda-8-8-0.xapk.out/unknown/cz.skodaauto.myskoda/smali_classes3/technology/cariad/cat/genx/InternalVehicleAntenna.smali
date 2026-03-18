.class public interface abstract Ltechnology/cariad/cat/genx/InternalVehicleAntenna;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltechnology/cariad/cat/genx/VehicleAntenna;
.implements Ltechnology/cariad/cat/genx/Referencing;


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Ltechnology/cariad/cat/genx/InternalVehicleAntenna$Inner;,
        Ltechnology/cariad/cat/genx/InternalVehicleAntenna$Outer;
    }
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000r\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0010\"\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0010\u0012\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0010\u0005\n\u0002\u0008\u0007\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u000b\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0002\u0010 \n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0002\u0008\u0008\u0008`\u0018\u00002\u00020\u00012\u00020\u0002:\u000245J\u001d\u0010\u0007\u001a\u00020\u00062\u000c\u0010\u0005\u001a\u0008\u0012\u0004\u0012\u00020\u00040\u0003H&\u00a2\u0006\u0004\u0008\u0007\u0010\u0008J\u001a\u0010\u000b\u001a\u0004\u0018\u00010\t2\u0006\u0010\n\u001a\u00020\tH\u00a6@\u00a2\u0006\u0004\u0008\u000b\u0010\u000cJ\u0019\u0010\u0010\u001a\u0004\u0018\u00010\u000f2\u0006\u0010\u000e\u001a\u00020\rH\'\u00a2\u0006\u0004\u0008\u0010\u0010\u0011J\u001f\u0010\u0015\u001a\u00020\u00062\u0006\u0010\u0013\u001a\u00020\u00122\u0006\u0010\u0014\u001a\u00020\u000fH&\u00a2\u0006\u0004\u0008\u0015\u0010\u0016J\u000f\u0010\u0017\u001a\u00020\u0006H&\u00a2\u0006\u0004\u0008\u0017\u0010\u0018J\u000f\u0010\u0019\u001a\u00020\u0006H&\u00a2\u0006\u0004\u0008\u0019\u0010\u0018J\u001f\u0010\u001e\u001a\u00020\u00062\u0006\u0010\u001b\u001a\u00020\u001a2\u0006\u0010\u001d\u001a\u00020\u001cH&\u00a2\u0006\u0004\u0008\u001e\u0010\u001fR\u0014\u0010#\u001a\u00020 8&X\u00a6\u0004\u00a2\u0006\u0006\u001a\u0004\u0008!\u0010\"R \u0010)\u001a\u000e\u0012\n\u0012\u0008\u0012\u0004\u0012\u00020&0%0$8&X\u00a6\u0004\u00a2\u0006\u0006\u001a\u0004\u0008\'\u0010(R\u0014\u0010-\u001a\u00020*8&X\u00a6\u0004\u00a2\u0006\u0006\u001a\u0004\u0008+\u0010,R\u0014\u00101\u001a\u00020.8&X\u00a6\u0004\u00a2\u0006\u0006\u001a\u0004\u0008/\u00100R\u001a\u00102\u001a\u0008\u0012\u0004\u0012\u00020\u001c0$8&X\u00a6\u0004\u00a2\u0006\u0006\u001a\u0004\u00082\u0010(R\u001a\u00103\u001a\u0008\u0012\u0004\u0012\u00020\u001c0$8&X\u00a6\u0004\u00a2\u0006\u0006\u001a\u0004\u00083\u0010(\u00a8\u00066\u00c0\u0006\u0003"
    }
    d2 = {
        "Ltechnology/cariad/cat/genx/InternalVehicleAntenna;",
        "Ltechnology/cariad/cat/genx/VehicleAntenna;",
        "Ltechnology/cariad/cat/genx/Referencing;",
        "",
        "Lt41/g;",
        "beaconProximities",
        "Llx0/b0;",
        "updateBeaconProximities",
        "(Ljava/util/Set;)V",
        "",
        "lamSecret",
        "calculateQPM1",
        "([BLkotlin/coroutines/Continuation;)Ljava/lang/Object;",
        "Ltechnology/cariad/cat/genx/VehicleAntenna$Information;",
        "information",
        "Ltechnology/cariad/cat/genx/GenXError;",
        "update",
        "(Ltechnology/cariad/cat/genx/VehicleAntenna$Information;)Ltechnology/cariad/cat/genx/GenXError;",
        "",
        "cgxTransportType",
        "error",
        "onErrorEncountered",
        "(BLtechnology/cariad/cat/genx/GenXError;)V",
        "onIncompatibleAntennaVersion",
        "()V",
        "onIncompatibleAppVersion",
        "Ltechnology/cariad/cat/genx/TransportType;",
        "transportType",
        "",
        "enabled",
        "setClientManagerState",
        "(Ltechnology/cariad/cat/genx/TransportType;Z)V",
        "Ltechnology/cariad/cat/genx/crypto/CredentialStore;",
        "getCredentialsStore",
        "()Ltechnology/cariad/cat/genx/crypto/CredentialStore;",
        "credentialsStore",
        "Lyy0/a2;",
        "",
        "Lt41/b;",
        "getBeaconsToSearch",
        "()Lyy0/a2;",
        "beaconsToSearch",
        "Ltechnology/cariad/cat/genx/DeviceInformation;",
        "getDeviceInformation",
        "()Ltechnology/cariad/cat/genx/DeviceInformation;",
        "deviceInformation",
        "Ltechnology/cariad/cat/genx/GenXDispatcher;",
        "getGenXDispatcher",
        "()Ltechnology/cariad/cat/genx/GenXDispatcher;",
        "genXDispatcher",
        "isBluetoothEnabled",
        "isWifiEnabled",
        "Inner",
        "Outer",
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
.method public abstract calculateQPM1([BLkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "([B",
            "Lkotlin/coroutines/Continuation<",
            "-[B>;)",
            "Ljava/lang/Object;"
        }
    .end annotation
.end method

.method public abstract getBeaconsToSearch()Lyy0/a2;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Lyy0/a2;"
        }
    .end annotation
.end method

.method public abstract getCredentialsStore()Ltechnology/cariad/cat/genx/crypto/CredentialStore;
.end method

.method public abstract getDeviceInformation()Ltechnology/cariad/cat/genx/DeviceInformation;
.end method

.method public abstract getGenXDispatcher()Ltechnology/cariad/cat/genx/GenXDispatcher;
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

.method public abstract onErrorEncountered(BLtechnology/cariad/cat/genx/GenXError;)V
.end method

.method public abstract onIncompatibleAntennaVersion()V
.end method

.method public abstract onIncompatibleAppVersion()V
.end method

.method public abstract setClientManagerState(Ltechnology/cariad/cat/genx/TransportType;Z)V
.end method

.method public abstract update(Ltechnology/cariad/cat/genx/VehicleAntenna$Information;)Ltechnology/cariad/cat/genx/GenXError;
    .annotation build Ltechnology/cariad/cat/genx/RequiresGenXDispatch;
    .end annotation
.end method

.method public abstract updateBeaconProximities(Ljava/util/Set;)V
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/Set<",
            "+",
            "Lt41/g;",
            ">;)V"
        }
    .end annotation
.end method
