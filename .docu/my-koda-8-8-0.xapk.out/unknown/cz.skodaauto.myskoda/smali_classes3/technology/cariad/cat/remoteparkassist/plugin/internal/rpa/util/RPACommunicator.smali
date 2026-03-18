.class public final Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPACommunicator;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lk71/d;
.implements Lvy0/b0;
.implements Ljava/io/Closeable;


# annotations
.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000\u00b1\u0001\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u000b\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0002\u0008\u0004\n\u0002\u0010\u0012\n\u0000\n\u0002\u0010\t\n\u0000\n\u0002\u0010\u0005\n\u0002\u0008\u0007\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0010\u000e\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0002\u0008\u0011\n\u0002\u0018\u0002\n\u0002\u0008\u0004\n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0007\n\u0002\u0018\u0002\n\u0002\u0008\u0006\n\u0002\u0018\u0002\n\u0002\u0008\u0006\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0002\u0008\u0004*\u0001a\u0008\u0001\u0018\u00002\u00020\u00012\u00020\u00022\u00020\u0003:\u0001HB9\u0012\u0006\u0010\u0005\u001a\u00020\u0004\u0012\u0006\u0010\u0007\u001a\u00020\u0006\u0012\u0006\u0010\t\u001a\u00020\u0008\u0012\u0008\u0010\u000b\u001a\u0004\u0018\u00010\n\u0012\u0006\u0010\r\u001a\u00020\u000c\u0012\u0006\u0010\u000f\u001a\u00020\u000e\u00a2\u0006\u0004\u0008\u0010\u0010\u0011J\u000f\u0010\u0013\u001a\u00020\u0012H\u0016\u00a2\u0006\u0004\u0008\u0013\u0010\u0014J\u000f\u0010\u0015\u001a\u00020\u0012H\u0016\u00a2\u0006\u0004\u0008\u0015\u0010\u0014J\u000f\u0010\u0016\u001a\u00020\u0012H\u0016\u00a2\u0006\u0004\u0008\u0016\u0010\u0014J/\u0010\u001e\u001a\u00020\u00122\u0006\u0010\u0018\u001a\u00020\u00172\u0006\u0010\u001a\u001a\u00020\u00192\u0006\u0010\u001c\u001a\u00020\u001b2\u0006\u0010\u001d\u001a\u00020\u0008H\u0016\u00a2\u0006\u0004\u0008\u001e\u0010\u001fJ\u0017\u0010!\u001a\u00020\u00122\u0006\u0010 \u001a\u00020\u0008H\u0002\u00a2\u0006\u0004\u0008!\u0010\"J\u0017\u0010%\u001a\u00020\u00122\u0006\u0010$\u001a\u00020#H\u0002\u00a2\u0006\u0004\u0008%\u0010&J\u0019\u0010)\u001a\u00020\u00122\u0008\u0010(\u001a\u0004\u0018\u00010\'H\u0002\u00a2\u0006\u0004\u0008)\u0010*J#\u0010/\u001a\u00020\u00122\u0012\u0010.\u001a\u000e\u0012\u0004\u0012\u00020,\u0012\u0004\u0012\u00020-0+H\u0002\u00a2\u0006\u0004\u0008/\u00100J\u0017\u00103\u001a\u00020\u00122\u0006\u00102\u001a\u000201H\u0002\u00a2\u0006\u0004\u00083\u00104J\u0017\u00106\u001a\u00020\u00122\u0006\u00105\u001a\u00020\u0006H\u0002\u00a2\u0006\u0004\u00086\u00107J\u000f\u00108\u001a\u00020\u0012H\u0002\u00a2\u0006\u0004\u00088\u0010\u0014R\u0014\u0010\u0005\u001a\u00020\u00048\u0002X\u0082\u0004\u00a2\u0006\u0006\n\u0004\u0008\u0005\u00109R\u0017\u0010\u0007\u001a\u00020\u00068\u0006\u00a2\u0006\u000c\n\u0004\u0008\u0007\u0010:\u001a\u0004\u0008;\u0010<R\u0017\u0010\t\u001a\u00020\u00088\u0006\u00a2\u0006\u000c\n\u0004\u0008\t\u0010=\u001a\u0004\u0008>\u0010?R\u0017\u0010\u000f\u001a\u00020\u000e8\u0006\u00a2\u0006\u000c\n\u0004\u0008\u000f\u0010@\u001a\u0004\u0008A\u0010BR\u001a\u0010D\u001a\u00020C8\u0016X\u0096\u0004\u00a2\u0006\u000c\n\u0004\u0008D\u0010E\u001a\u0004\u0008F\u0010GR\u0016\u0010I\u001a\u00020H8\u0002@\u0002X\u0082\u000e\u00a2\u0006\u0006\n\u0004\u0008I\u0010JR.\u0010M\u001a\u0004\u0018\u00010K2\u0008\u0010L\u001a\u0004\u0018\u00010K8\u0000@@X\u0080\u000e\u00a2\u0006\u0012\n\u0004\u0008M\u0010N\u001a\u0004\u0008O\u0010P\"\u0004\u0008Q\u0010RR$\u0010T\u001a\u00020S2\u0006\u0010L\u001a\u00020S8\u0002@BX\u0082\u000e\u00a2\u0006\u000c\n\u0004\u0008T\u0010U\"\u0004\u0008V\u0010WR\u0018\u0010X\u001a\u0004\u0018\u00010\n8\u0002@\u0002X\u0082\u000e\u00a2\u0006\u0006\n\u0004\u0008X\u0010YR.\u0010[\u001a\u0004\u0018\u00010Z2\u0008\u0010L\u001a\u0004\u0018\u00010Z8\u0000@@X\u0080\u000e\u00a2\u0006\u0012\n\u0004\u0008[\u0010\\\u001a\u0004\u0008]\u0010^\"\u0004\u0008_\u0010`R\u0016\u0010b\u001a\u00020a8\u0002@\u0002X\u0082\u000e\u00a2\u0006\u0006\n\u0004\u0008b\u0010cR\u0018\u0010e\u001a\u0004\u0018\u00010d8\u0002@\u0002X\u0082\u000e\u00a2\u0006\u0006\n\u0004\u0008e\u0010fR\u0016\u0010g\u001a\u00020\u00088\u0002@\u0002X\u0082\u000e\u00a2\u0006\u0006\n\u0004\u0008g\u0010=\u00a8\u0006h"
    }
    d2 = {
        "Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPACommunicator;",
        "Lk71/d;",
        "Lvy0/b0;",
        "Ljava/io/Closeable;",
        "Ltechnology/cariad/cat/genx/VehicleAntenna$Outer;",
        "vehicleAntenna",
        "Ltechnology/cariad/cat/genx/VehicleAntennaTransport;",
        "bleTransport",
        "",
        "disableTrajectoryMessages",
        "Lvy0/i1;",
        "supervisorJob",
        "Lvy0/x;",
        "ioDispatcher",
        "Ln71/a;",
        "rpaDispatcher",
        "<init>",
        "(Ltechnology/cariad/cat/genx/VehicleAntenna$Outer;Ltechnology/cariad/cat/genx/VehicleAntennaTransport;ZLvy0/i1;Lvy0/x;Ln71/a;)V",
        "Llx0/b0;",
        "close",
        "()V",
        "connect",
        "disconnect",
        "",
        "payload",
        "",
        "address",
        "",
        "priority",
        "requiresQueuing",
        "sendData",
        "([BJBZ)V",
        "isConnectionAllowed",
        "onCar2PhoneConnectionAllowanceChanged",
        "(Z)V",
        "Lt71/f;",
        "sendWindowStatus",
        "onSendWindowStatusReceived",
        "(Lt71/f;)V",
        "Ltechnology/cariad/cat/genx/Car2PhoneMode;",
        "car2PhoneMode",
        "onCar2PhoneModeReceived",
        "(Ltechnology/cariad/cat/genx/Car2PhoneMode;)V",
        "Llx0/l;",
        "Lt71/c;",
        "",
        "connectionErrorPair",
        "onConnectionErrorEncountered",
        "(Llx0/l;)V",
        "Ltechnology/cariad/cat/genx/SoftwareStackIncompatibility;",
        "softwareStackIncompatibility",
        "onSoftwareStackIncompatibilityEncountered",
        "(Ltechnology/cariad/cat/genx/SoftwareStackIncompatibility;)V",
        "transport",
        "startObserveBLETransportData",
        "(Ltechnology/cariad/cat/genx/VehicleAntennaTransport;)V",
        "sendLatestBLETransportData",
        "Ltechnology/cariad/cat/genx/VehicleAntenna$Outer;",
        "Ltechnology/cariad/cat/genx/VehicleAntennaTransport;",
        "getBleTransport",
        "()Ltechnology/cariad/cat/genx/VehicleAntennaTransport;",
        "Z",
        "getDisableTrajectoryMessages",
        "()Z",
        "Ln71/a;",
        "getRpaDispatcher",
        "()Ln71/a;",
        "Lpx0/g;",
        "coroutineContext",
        "Lpx0/g;",
        "getCoroutineContext",
        "()Lpx0/g;",
        "Lt61/e;",
        "currentTimestamp",
        "Lt61/e;",
        "Lk71/a;",
        "value",
        "c2pListener",
        "Lk71/a;",
        "getC2pListener$remoteparkassistplugin_release",
        "()Lk71/a;",
        "setC2pListener$remoteparkassistplugin_release",
        "(Lk71/a;)V",
        "Lk71/c;",
        "connectionStatus",
        "Lk71/c;",
        "setConnectionStatus",
        "(Lk71/c;)V",
        "rpaCommunicatorJob",
        "Lvy0/i1;",
        "Ltechnology/cariad/cat/genx/VehicleAntennaTransport$Connection;",
        "connection",
        "Ltechnology/cariad/cat/genx/VehicleAntennaTransport$Connection;",
        "getConnection$remoteparkassistplugin_release",
        "()Ltechnology/cariad/cat/genx/VehicleAntennaTransport$Connection;",
        "setConnection$remoteparkassistplugin_release",
        "(Ltechnology/cariad/cat/genx/VehicleAntennaTransport$Connection;)V",
        "t61/i",
        "connectionDelegate",
        "Lt61/i;",
        "Ltechnology/cariad/cat/genx/TransportState;",
        "latestGenXTransportState",
        "Ltechnology/cariad/cat/genx/TransportState;",
        "shouldDisconnectAfterConnectionFinished",
        "remoteparkassistplugin_release"
    }
    k = 0x1
    mv = {
        0x2,
        0x2,
        0x0
    }
    xi = 0x30
.end annotation


# static fields
.field public static final $stable:I = 0x8


# instance fields
.field private final bleTransport:Ltechnology/cariad/cat/genx/VehicleAntennaTransport;

.field private c2pListener:Lk71/a;

.field private connection:Ltechnology/cariad/cat/genx/VehicleAntennaTransport$Connection;

.field private connectionDelegate:Lt61/i;

.field private connectionStatus:Lk71/c;

.field private final coroutineContext:Lpx0/g;

.field private currentTimestamp:Lt61/e;

.field private final disableTrajectoryMessages:Z

.field private latestGenXTransportState:Ltechnology/cariad/cat/genx/TransportState;

.field private rpaCommunicatorJob:Lvy0/i1;

.field private final rpaDispatcher:Ln71/a;

.field private shouldDisconnectAfterConnectionFinished:Z

.field private final vehicleAntenna:Ltechnology/cariad/cat/genx/VehicleAntenna$Outer;


# direct methods
.method public constructor <init>(Ltechnology/cariad/cat/genx/VehicleAntenna$Outer;Ltechnology/cariad/cat/genx/VehicleAntennaTransport;ZLvy0/i1;Lvy0/x;Ln71/a;)V
    .locals 1

    .line 1
    const-string v0, "vehicleAntenna"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "bleTransport"

    .line 7
    .line 8
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    const-string v0, "ioDispatcher"

    .line 12
    .line 13
    invoke-static {p5, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    const-string v0, "rpaDispatcher"

    .line 17
    .line 18
    invoke-static {p6, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 19
    .line 20
    .line 21
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 22
    .line 23
    .line 24
    iput-object p1, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPACommunicator;->vehicleAntenna:Ltechnology/cariad/cat/genx/VehicleAntenna$Outer;

    .line 25
    .line 26
    iput-object p2, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPACommunicator;->bleTransport:Ltechnology/cariad/cat/genx/VehicleAntennaTransport;

    .line 27
    .line 28
    iput-boolean p3, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPACommunicator;->disableTrajectoryMessages:Z

    .line 29
    .line 30
    iput-object p6, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPACommunicator;->rpaDispatcher:Ln71/a;

    .line 31
    .line 32
    const-string p1, "RPACommunicator"

    .line 33
    .line 34
    invoke-static {p1, p5, p4}, Llp/h1;->a(Ljava/lang/String;Lvy0/x;Lvy0/i1;)Lpx0/g;

    .line 35
    .line 36
    .line 37
    move-result-object p1

    .line 38
    iput-object p1, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPACommunicator;->coroutineContext:Lpx0/g;

    .line 39
    .line 40
    new-instance p1, Lt61/e;

    .line 41
    .line 42
    const/4 p3, 0x0

    .line 43
    invoke-direct {p1, p3}, Lt61/e;-><init>(Ljava/lang/Long;)V

    .line 44
    .line 45
    .line 46
    iput-object p1, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPACommunicator;->currentTimestamp:Lt61/e;

    .line 47
    .line 48
    sget-object p1, Lk71/c;->f:Lk71/c;

    .line 49
    .line 50
    iput-object p1, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPACommunicator;->connectionStatus:Lk71/c;

    .line 51
    .line 52
    new-instance p1, Lt61/i;

    .line 53
    .line 54
    invoke-direct {p1, p0}, Lt61/i;-><init>(Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPACommunicator;)V

    .line 55
    .line 56
    .line 57
    iput-object p1, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPACommunicator;->connectionDelegate:Lt61/i;

    .line 58
    .line 59
    invoke-direct {p0, p2}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPACommunicator;->startObserveBLETransportData(Ltechnology/cariad/cat/genx/VehicleAntennaTransport;)V

    .line 60
    .line 61
    .line 62
    return-void
.end method

.method public static synthetic B(Lt71/f;Lkotlin/jvm/internal/f0;)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p0, p1}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPACommunicator;->onSendWindowStatusReceived$lambda$1(Lt71/f;Lkotlin/jvm/internal/f0;)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic E(Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPACommunicator;)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p0}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPACommunicator;->connect$lambda$0(Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPACommunicator;)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic H(Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPACommunicator;)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p0}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPACommunicator;->disconnect$lambda$0(Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPACommunicator;)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method private static final _set_connectionStatus_$lambda$0(Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPACommunicator;Lk71/c;)Ljava/lang/String;
    .locals 2

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPACommunicator;->connectionStatus:Lk71/c;

    .line 2
    .line 3
    new-instance v0, Ljava/lang/StringBuilder;

    .line 4
    .line 5
    const-string v1, "ConnectionStatus changed! From: "

    .line 6
    .line 7
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 8
    .line 9
    .line 10
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 11
    .line 12
    .line 13
    const-string p0, " to "

    .line 14
    .line 15
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 16
    .line 17
    .line 18
    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 19
    .line 20
    .line 21
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 22
    .line 23
    .line 24
    move-result-object p0

    .line 25
    return-object p0
.end method

.method public static synthetic a(Ltechnology/cariad/cat/genx/SoftwareStackIncompatibility;)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p0}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPACommunicator;->onSoftwareStackIncompatibilityEncountered$lambda$0(Ltechnology/cariad/cat/genx/SoftwareStackIncompatibility;)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static final synthetic access$getConnectionDelegate$p(Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPACommunicator;)Lt61/i;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPACommunicator;->connectionDelegate:Lt61/i;

    .line 2
    .line 3
    return-object p0
.end method

.method public static final synthetic access$getShouldDisconnectAfterConnectionFinished$p(Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPACommunicator;)Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPACommunicator;->shouldDisconnectAfterConnectionFinished:Z

    .line 2
    .line 3
    return p0
.end method

.method public static final synthetic access$getVehicleAntenna$p(Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPACommunicator;)Ltechnology/cariad/cat/genx/VehicleAntenna$Outer;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPACommunicator;->vehicleAntenna:Ltechnology/cariad/cat/genx/VehicleAntenna$Outer;

    .line 2
    .line 3
    return-object p0
.end method

.method public static final synthetic access$onCar2PhoneConnectionAllowanceChanged(Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPACommunicator;Z)V
    .locals 0

    .line 1
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPACommunicator;->onCar2PhoneConnectionAllowanceChanged(Z)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static final synthetic access$onCar2PhoneModeReceived(Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPACommunicator;Ltechnology/cariad/cat/genx/Car2PhoneMode;)V
    .locals 0

    .line 1
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPACommunicator;->onCar2PhoneModeReceived(Ltechnology/cariad/cat/genx/Car2PhoneMode;)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static final synthetic access$onConnectionErrorEncountered(Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPACommunicator;Llx0/l;)V
    .locals 0

    .line 1
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPACommunicator;->onConnectionErrorEncountered(Llx0/l;)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static final synthetic access$onSendWindowStatusReceived(Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPACommunicator;Lt71/f;)V
    .locals 0

    .line 1
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPACommunicator;->onSendWindowStatusReceived(Lt71/f;)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static final synthetic access$onSoftwareStackIncompatibilityEncountered(Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPACommunicator;Ltechnology/cariad/cat/genx/SoftwareStackIncompatibility;)V
    .locals 0

    .line 1
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPACommunicator;->onSoftwareStackIncompatibilityEncountered(Ltechnology/cariad/cat/genx/SoftwareStackIncompatibility;)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static final synthetic access$setConnectionStatus(Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPACommunicator;Lk71/c;)V
    .locals 0

    .line 1
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPACommunicator;->setConnectionStatus(Lk71/c;)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static synthetic b([BLtechnology/cariad/cat/genx/protocol/Address;Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPACommunicator;)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p0, p1, p2}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPACommunicator;->sendData$lambda$0$0([BLtechnology/cariad/cat/genx/protocol/Address;Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPACommunicator;)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method private static final close$lambda$0()Ljava/lang/String;
    .locals 1

    .line 1
    const-string v0, "close()"

    .line 2
    .line 3
    return-object v0
.end method

.method private static final connect$lambda$0(Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPACommunicator;)Ljava/lang/String;
    .locals 3

    .line 1
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPACommunicator;->vehicleAntenna:Ltechnology/cariad/cat/genx/VehicleAntenna$Outer;

    .line 2
    .line 3
    invoke-static {v0}, Ltechnology/cariad/cat/genx/VehicleAntennaKt;->getVin(Ltechnology/cariad/cat/genx/VehicleAntenna;)Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPACommunicator;->bleTransport:Ltechnology/cariad/cat/genx/VehicleAntennaTransport;

    .line 8
    .line 9
    new-instance v1, Ljava/lang/StringBuilder;

    .line 10
    .line 11
    const-string v2, "connect(): Connection to \'"

    .line 12
    .line 13
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 17
    .line 18
    .line 19
    const-string v0, "\' will be established on transport "

    .line 20
    .line 21
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 22
    .line 23
    .line 24
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 25
    .line 26
    .line 27
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 28
    .line 29
    .line 30
    move-result-object p0

    .line 31
    return-object p0
.end method

.method public static synthetic d(Z)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p0}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPACommunicator;->onCar2PhoneConnectionAllowanceChanged$lambda$0(Z)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method private static final disconnect$lambda$0(Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPACommunicator;)Ljava/lang/String;
    .locals 2

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPACommunicator;->vehicleAntenna:Ltechnology/cariad/cat/genx/VehicleAntenna$Outer;

    .line 2
    .line 3
    invoke-static {p0}, Ltechnology/cariad/cat/genx/VehicleAntennaKt;->getVin(Ltechnology/cariad/cat/genx/VehicleAntenna;)Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    const-string v0, "disconnect(): Disconnecting from \'"

    .line 8
    .line 9
    const-string v1, "\'..."

    .line 10
    .line 11
    invoke-static {v0, p0, v1}, Lp3/m;->j(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    return-object p0
.end method

.method private static final disconnect$lambda$1()Ljava/lang/String;
    .locals 1

    .line 1
    const-string v0, "disconnect(): close on Vehicle.Connection failed."

    .line 2
    .line 3
    return-object v0
.end method

.method public static synthetic f()Ljava/lang/String;
    .locals 1

    .line 1
    invoke-static {}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPACommunicator;->disconnect$lambda$1()Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    return-object v0
.end method

.method public static synthetic g(Llx0/l;Ljava/lang/String;)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p0, p1}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPACommunicator;->onConnectionErrorEncountered$lambda$0(Llx0/l;Ljava/lang/String;)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic h(Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPACommunicator;Lk71/c;)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p0, p1}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPACommunicator;->_set_connectionStatus_$lambda$0(Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPACommunicator;Lk71/c;)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic j(Ltechnology/cariad/cat/genx/Car2PhoneMode;)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p0}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPACommunicator;->onCar2PhoneModeReceived$lambda$0(Ltechnology/cariad/cat/genx/Car2PhoneMode;)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic k(Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPACommunicator;)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p0}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPACommunicator;->startObserveBLETransportData$lambda$0(Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPACommunicator;)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic l()Ljava/lang/String;
    .locals 1

    .line 1
    invoke-static {}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPACommunicator;->sendLatestBLETransportData$lambda$1$0()Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    return-object v0
.end method

.method private final onCar2PhoneConnectionAllowanceChanged(Z)V
    .locals 2

    .line 1
    new-instance v0, Lfw0/n;

    .line 2
    .line 3
    const/16 v1, 0x8

    .line 4
    .line 5
    invoke-direct {v0, v1, p1}, Lfw0/n;-><init>(IZ)V

    .line 6
    .line 7
    .line 8
    invoke-static {p0, v0}, Llp/i1;->e(Ljava/lang/Object;Lay0/a;)V

    .line 9
    .line 10
    .line 11
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPACommunicator;->c2pListener:Lk71/a;

    .line 12
    .line 13
    if-eqz p0, :cond_0

    .line 14
    .line 15
    invoke-interface {p0, p1}, Lk71/a;->carChangedConnectionAllowanceStatus(Z)V

    .line 16
    .line 17
    .line 18
    :cond_0
    return-void
.end method

.method private static final onCar2PhoneConnectionAllowanceChanged$lambda$0(Z)Ljava/lang/String;
    .locals 2

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "onCar2PhoneConnectionAllowanceChanged(): isConnectionAllowed = "

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    .line 9
    .line 10
    .line 11
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    return-object p0
.end method

.method private final onCar2PhoneModeReceived(Ltechnology/cariad/cat/genx/Car2PhoneMode;)V
    .locals 2

    .line 1
    new-instance v0, Lr1/b;

    .line 2
    .line 3
    const/16 v1, 0x14

    .line 4
    .line 5
    invoke-direct {v0, p1, v1}, Lr1/b;-><init>(Ljava/lang/Object;I)V

    .line 6
    .line 7
    .line 8
    invoke-static {p0, v0}, Llp/i1;->e(Ljava/lang/Object;Lay0/a;)V

    .line 9
    .line 10
    .line 11
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPACommunicator;->c2pListener:Lk71/a;

    .line 12
    .line 13
    if-eqz p0, :cond_1

    .line 14
    .line 15
    if-eqz p1, :cond_0

    .line 16
    .line 17
    invoke-virtual {p1}, Ltechnology/cariad/cat/genx/Car2PhoneMode;->getRawValue()I

    .line 18
    .line 19
    .line 20
    move-result p1

    .line 21
    goto :goto_0

    .line 22
    :cond_0
    const p1, 0x7fffffff

    .line 23
    .line 24
    .line 25
    :goto_0
    invoke-interface {p0, p1}, Lk71/a;->receivedAdvertisementFromCar(I)V

    .line 26
    .line 27
    .line 28
    :cond_1
    return-void
.end method

.method private static final onCar2PhoneModeReceived$lambda$0(Ltechnology/cariad/cat/genx/Car2PhoneMode;)Ljava/lang/String;
    .locals 2

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "onCar2PhoneModeReceived(): car2PhoneMode = "

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 9
    .line 10
    .line 11
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    return-object p0
.end method

.method private final onConnectionErrorEncountered(Llx0/l;)V
    .locals 4
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Llx0/l;",
            ")V"
        }
    .end annotation

    .line 1
    iget-object v0, p1, Llx0/l;->d:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Lt71/c;

    .line 4
    .line 5
    iget-object v1, p1, Llx0/l;->e:Ljava/lang/Object;

    .line 6
    .line 7
    check-cast v1, Ljava/lang/String;

    .line 8
    .line 9
    new-instance v2, Lo51/c;

    .line 10
    .line 11
    const/16 v3, 0x1d

    .line 12
    .line 13
    invoke-direct {v2, v3, p1, v1}, Lo51/c;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 14
    .line 15
    .line 16
    const/4 p1, 0x0

    .line 17
    invoke-static {p0, p1, v2}, Llp/i1;->c(Ljava/lang/Object;Ljava/io/IOException;Lay0/a;)V

    .line 18
    .line 19
    .line 20
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPACommunicator;->c2pListener:Lk71/a;

    .line 21
    .line 22
    if-eqz p0, :cond_0

    .line 23
    .line 24
    invoke-interface {p0, v0, v1}, Lk71/a;->carDidDetectConnectionError(Lt71/c;Ljava/lang/String;)V

    .line 25
    .line 26
    .line 27
    :cond_0
    return-void
.end method

.method private static final onConnectionErrorEncountered$lambda$0(Llx0/l;Ljava/lang/String;)Ljava/lang/String;
    .locals 2

    .line 1
    iget-object p0, p0, Llx0/l;->d:Ljava/lang/Object;

    .line 2
    .line 3
    new-instance v0, Ljava/lang/StringBuilder;

    .line 4
    .line 5
    const-string v1, "onConnectionErrorEncountered(): connectionErrorStatus = "

    .line 6
    .line 7
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 8
    .line 9
    .line 10
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 11
    .line 12
    .line 13
    const-string p0, ", connectionErrorDescription = "

    .line 14
    .line 15
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 16
    .line 17
    .line 18
    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 19
    .line 20
    .line 21
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 22
    .line 23
    .line 24
    move-result-object p0

    .line 25
    return-object p0
.end method

.method private final onSendWindowStatusReceived(Lt71/f;)V
    .locals 5

    .line 1
    new-instance v0, Lkotlin/jvm/internal/f0;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    invoke-static {}, Ljava/time/Instant;->now()Ljava/time/Instant;

    .line 7
    .line 8
    .line 9
    move-result-object v1

    .line 10
    invoke-virtual {v1}, Ljava/time/Instant;->toEpochMilli()J

    .line 11
    .line 12
    .line 13
    move-result-wide v1

    .line 14
    invoke-virtual {p1}, Ljava/lang/Enum;->ordinal()I

    .line 15
    .line 16
    .line 17
    move-result v3

    .line 18
    if-eqz v3, :cond_1

    .line 19
    .line 20
    const/4 v4, 0x1

    .line 21
    if-ne v3, v4, :cond_0

    .line 22
    .line 23
    iget-object v3, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPACommunicator;->currentTimestamp:Lt61/e;

    .line 24
    .line 25
    invoke-static {v1, v2}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 26
    .line 27
    .line 28
    move-result-object v1

    .line 29
    invoke-virtual {v3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 30
    .line 31
    .line 32
    new-instance v2, Lt61/e;

    .line 33
    .line 34
    invoke-direct {v2, v1}, Lt61/e;-><init>(Ljava/lang/Long;)V

    .line 35
    .line 36
    .line 37
    goto :goto_0

    .line 38
    :cond_0
    new-instance p0, La8/r0;

    .line 39
    .line 40
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 41
    .line 42
    .line 43
    throw p0

    .line 44
    :cond_1
    iget-object v3, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPACommunicator;->currentTimestamp:Lt61/e;

    .line 45
    .line 46
    iget-object v3, v3, Lt61/e;->a:Ljava/lang/Long;

    .line 47
    .line 48
    if-eqz v3, :cond_2

    .line 49
    .line 50
    invoke-virtual {v3}, Ljava/lang/Number;->longValue()J

    .line 51
    .line 52
    .line 53
    move-result-wide v3

    .line 54
    sub-long/2addr v1, v3

    .line 55
    invoke-static {v1, v2}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 56
    .line 57
    .line 58
    move-result-object v1

    .line 59
    iput-object v1, v0, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 60
    .line 61
    :cond_2
    iget-object v1, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPACommunicator;->currentTimestamp:Lt61/e;

    .line 62
    .line 63
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 64
    .line 65
    .line 66
    new-instance v2, Lt61/e;

    .line 67
    .line 68
    const/4 v1, 0x0

    .line 69
    invoke-direct {v2, v1}, Lt61/e;-><init>(Ljava/lang/Long;)V

    .line 70
    .line 71
    .line 72
    :goto_0
    iput-object v2, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPACommunicator;->currentTimestamp:Lt61/e;

    .line 73
    .line 74
    new-instance v1, Lo51/c;

    .line 75
    .line 76
    const/16 v2, 0x1c

    .line 77
    .line 78
    invoke-direct {v1, v2, p1, v0}, Lo51/c;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 79
    .line 80
    .line 81
    invoke-static {p0, v1}, Llp/i1;->b(Ljava/lang/Object;Lay0/a;)V

    .line 82
    .line 83
    .line 84
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPACommunicator;->c2pListener:Lk71/a;

    .line 85
    .line 86
    if-eqz p0, :cond_3

    .line 87
    .line 88
    invoke-interface {p0, p1}, Lk71/a;->sendWindowStatusChanged(Lt71/f;)V

    .line 89
    .line 90
    .line 91
    :cond_3
    return-void
.end method

.method private static final onSendWindowStatusReceived$lambda$1(Lt71/f;Lkotlin/jvm/internal/f0;)Ljava/lang/String;
    .locals 2

    .line 1
    iget-object p1, p1, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 2
    .line 3
    new-instance v0, Ljava/lang/StringBuilder;

    .line 4
    .line 5
    const-string v1, "onSendWindowStatusReceived(): sendWindowStatus = "

    .line 6
    .line 7
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 8
    .line 9
    .line 10
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 11
    .line 12
    .line 13
    const-string p0, " ("

    .line 14
    .line 15
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 16
    .line 17
    .line 18
    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 19
    .line 20
    .line 21
    const-string p0, " ms since SendWindowStatus.FULL)"

    .line 22
    .line 23
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 24
    .line 25
    .line 26
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 27
    .line 28
    .line 29
    move-result-object p0

    .line 30
    return-object p0
.end method

.method private final onSoftwareStackIncompatibilityEncountered(Ltechnology/cariad/cat/genx/SoftwareStackIncompatibility;)V
    .locals 2

    .line 1
    new-instance v0, Lr1/b;

    .line 2
    .line 3
    const/16 v1, 0x13

    .line 4
    .line 5
    invoke-direct {v0, p1, v1}, Lr1/b;-><init>(Ljava/lang/Object;I)V

    .line 6
    .line 7
    .line 8
    invoke-static {p0, v0}, Llp/i1;->e(Ljava/lang/Object;Lay0/a;)V

    .line 9
    .line 10
    .line 11
    sget-object v0, Lt61/f;->a:[I

    .line 12
    .line 13
    invoke-virtual {p1}, Ljava/lang/Enum;->ordinal()I

    .line 14
    .line 15
    .line 16
    move-result p1

    .line 17
    aget p1, v0, p1

    .line 18
    .line 19
    const/4 v0, 0x1

    .line 20
    if-eq p1, v0, :cond_1

    .line 21
    .line 22
    const/4 v0, 0x2

    .line 23
    if-ne p1, v0, :cond_0

    .line 24
    .line 25
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPACommunicator;->c2pListener:Lk71/a;

    .line 26
    .line 27
    if-eqz p0, :cond_2

    .line 28
    .line 29
    sget-object p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/status/ConnectionErrorStatus$AppVersionOutdated;->INSTANCE:Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/status/ConnectionErrorStatus$AppVersionOutdated;

    .line 30
    .line 31
    const-string v0, "Application version outdated."

    .line 32
    .line 33
    invoke-interface {p0, p1, v0}, Lk71/a;->carDidDetectConnectionError(Lt71/c;Ljava/lang/String;)V

    .line 34
    .line 35
    .line 36
    return-void

    .line 37
    :cond_0
    new-instance p0, La8/r0;

    .line 38
    .line 39
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 40
    .line 41
    .line 42
    throw p0

    .line 43
    :cond_1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPACommunicator;->c2pListener:Lk71/a;

    .line 44
    .line 45
    if-eqz p0, :cond_2

    .line 46
    .line 47
    sget-object p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/status/ConnectionErrorStatus$AntennaVersionOutdated;->INSTANCE:Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/status/ConnectionErrorStatus$AntennaVersionOutdated;

    .line 48
    .line 49
    const-string v0, "Antenna version outdated."

    .line 50
    .line 51
    invoke-interface {p0, p1, v0}, Lk71/a;->carDidDetectConnectionError(Lt71/c;Ljava/lang/String;)V

    .line 52
    .line 53
    .line 54
    :cond_2
    return-void
.end method

.method private static final onSoftwareStackIncompatibilityEncountered$lambda$0(Ltechnology/cariad/cat/genx/SoftwareStackIncompatibility;)Ljava/lang/String;
    .locals 2

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "onSoftwareStackIncompatibilityEncountered(): softwareStackIncompatibility = "

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 9
    .line 10
    .line 11
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    return-object p0
.end method

.method public static synthetic q()Ljava/lang/String;
    .locals 1

    .line 1
    invoke-static {}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPACommunicator;->close$lambda$0()Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    return-object v0
.end method

.method private static final sendData$lambda$0$0([BLtechnology/cariad/cat/genx/protocol/Address;Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPACommunicator;)Ljava/lang/String;
    .locals 2

    .line 1
    invoke-static {p0}, Lly0/d;->l([B)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    iget-object p2, p2, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPACommunicator;->vehicleAntenna:Ltechnology/cariad/cat/genx/VehicleAntenna$Outer;

    .line 6
    .line 7
    invoke-static {p2}, Ltechnology/cariad/cat/genx/VehicleAntennaKt;->getVin(Ltechnology/cariad/cat/genx/VehicleAntenna;)Ljava/lang/String;

    .line 8
    .line 9
    .line 10
    move-result-object p2

    .line 11
    new-instance v0, Ljava/lang/StringBuilder;

    .line 12
    .line 13
    const-string v1, "sendData(): Failed to send \'0x"

    .line 14
    .line 15
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 16
    .line 17
    .line 18
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 19
    .line 20
    .line 21
    const-string p0, "\' at \'"

    .line 22
    .line 23
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 24
    .line 25
    .line 26
    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 27
    .line 28
    .line 29
    const-string p0, "\' to \'"

    .line 30
    .line 31
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 32
    .line 33
    .line 34
    const-string p0, "\' due to missing connection"

    .line 35
    .line 36
    invoke-static {v0, p2, p0}, La7/g0;->k(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 37
    .line 38
    .line 39
    move-result-object p0

    .line 40
    return-object p0
.end method

.method private final sendLatestBLETransportData()V
    .locals 2

    .line 1
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPACommunicator;->c2pListener:Lk71/a;

    .line 2
    .line 3
    if-eqz v0, :cond_1

    .line 4
    .line 5
    iget-object v1, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPACommunicator;->bleTransport:Ltechnology/cariad/cat/genx/VehicleAntennaTransport;

    .line 6
    .line 7
    invoke-interface {v1}, Ltechnology/cariad/cat/genx/VehicleAntennaTransport;->isConnectable()Lyy0/a2;

    .line 8
    .line 9
    .line 10
    move-result-object v1

    .line 11
    invoke-interface {v1}, Lyy0/a2;->getValue()Ljava/lang/Object;

    .line 12
    .line 13
    .line 14
    move-result-object v1

    .line 15
    check-cast v1, Ljava/lang/Boolean;

    .line 16
    .line 17
    invoke-virtual {v1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 18
    .line 19
    .line 20
    move-result v1

    .line 21
    invoke-interface {v0, v1}, Lk71/a;->carChangedConnectionAllowanceStatus(Z)V

    .line 22
    .line 23
    .line 24
    iget-object v1, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPACommunicator;->connectionStatus:Lk71/c;

    .line 25
    .line 26
    invoke-interface {v0, v1}, Lk71/a;->carChangedConnectionStatus(Lk71/c;)V

    .line 27
    .line 28
    .line 29
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPACommunicator;->bleTransport:Ltechnology/cariad/cat/genx/VehicleAntennaTransport;

    .line 30
    .line 31
    invoke-interface {p0}, Ltechnology/cariad/cat/genx/VehicleAntennaTransport;->getCar2PhoneMode()Lyy0/a2;

    .line 32
    .line 33
    .line 34
    move-result-object p0

    .line 35
    invoke-interface {p0}, Lyy0/a2;->getValue()Ljava/lang/Object;

    .line 36
    .line 37
    .line 38
    move-result-object p0

    .line 39
    check-cast p0, Ltechnology/cariad/cat/genx/Car2PhoneMode;

    .line 40
    .line 41
    if-eqz p0, :cond_0

    .line 42
    .line 43
    invoke-virtual {p0}, Ltechnology/cariad/cat/genx/Car2PhoneMode;->getRawValue()I

    .line 44
    .line 45
    .line 46
    move-result p0

    .line 47
    goto :goto_0

    .line 48
    :cond_0
    const p0, 0x7fffffff

    .line 49
    .line 50
    .line 51
    :goto_0
    invoke-interface {v0, p0}, Lk71/a;->receivedAdvertisementFromCar(I)V

    .line 52
    .line 53
    .line 54
    return-void

    .line 55
    :cond_1
    new-instance v0, Lt61/d;

    .line 56
    .line 57
    const/4 v1, 0x1

    .line 58
    invoke-direct {v0, v1}, Lt61/d;-><init>(I)V

    .line 59
    .line 60
    .line 61
    invoke-static {p0, v0}, Llp/i1;->b(Ljava/lang/Object;Lay0/a;)V

    .line 62
    .line 63
    .line 64
    return-void
.end method

.method private static final sendLatestBLETransportData$lambda$1$0()Ljava/lang/String;
    .locals 1

    .line 1
    const-string v0, "sendLatestBLETransportData(): failed! c2pListener = null!"

    .line 2
    .line 3
    return-object v0
.end method

.method private final setConnectionStatus(Lk71/c;)V
    .locals 2

    .line 1
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPACommunicator;->connectionStatus:Lk71/c;

    .line 2
    .line 3
    if-eq v0, p1, :cond_0

    .line 4
    .line 5
    new-instance v0, Lo51/c;

    .line 6
    .line 7
    const/16 v1, 0x1b

    .line 8
    .line 9
    invoke-direct {v0, v1, p0, p1}, Lo51/c;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 10
    .line 11
    .line 12
    invoke-static {p0, v0}, Llp/i1;->b(Ljava/lang/Object;Lay0/a;)V

    .line 13
    .line 14
    .line 15
    iput-object p1, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPACommunicator;->connectionStatus:Lk71/c;

    .line 16
    .line 17
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPACommunicator;->c2pListener:Lk71/a;

    .line 18
    .line 19
    if-eqz p0, :cond_0

    .line 20
    .line 21
    invoke-interface {p0, p1}, Lk71/a;->carChangedConnectionStatus(Lk71/c;)V

    .line 22
    .line 23
    .line 24
    :cond_0
    return-void
.end method

.method private final startObserveBLETransportData(Ltechnology/cariad/cat/genx/VehicleAntennaTransport;)V
    .locals 2

    .line 1
    new-instance v0, Lt61/c;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-direct {v0, p0, v1}, Lt61/c;-><init>(Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPACommunicator;I)V

    .line 5
    .line 6
    .line 7
    invoke-static {p0, v0}, Llp/i1;->e(Ljava/lang/Object;Lay0/a;)V

    .line 8
    .line 9
    .line 10
    new-instance v0, Lt61/o;

    .line 11
    .line 12
    const/4 v1, 0x0

    .line 13
    invoke-direct {v0, p1, p0, v1}, Lt61/o;-><init>(Ltechnology/cariad/cat/genx/VehicleAntennaTransport;Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPACommunicator;Lkotlin/coroutines/Continuation;)V

    .line 14
    .line 15
    .line 16
    const/4 p1, 0x3

    .line 17
    invoke-static {p0, v1, v1, v0, p1}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 18
    .line 19
    .line 20
    move-result-object p1

    .line 21
    iput-object p1, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPACommunicator;->rpaCommunicatorJob:Lvy0/i1;

    .line 22
    .line 23
    return-void
.end method

.method private static final startObserveBLETransportData$lambda$0(Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPACommunicator;)Ljava/lang/String;
    .locals 2

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "startObserveTransportData() - "

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 9
    .line 10
    .line 11
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    return-object p0
.end method


# virtual methods
.method public close()V
    .locals 3

    .line 1
    new-instance v0, Lt61/d;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-direct {v0, v1}, Lt61/d;-><init>(I)V

    .line 5
    .line 6
    .line 7
    invoke-static {p0, v0}, Llp/i1;->b(Ljava/lang/Object;Lay0/a;)V

    .line 8
    .line 9
    .line 10
    invoke-virtual {p0}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPACommunicator;->disconnect()V

    .line 11
    .line 12
    .line 13
    const/4 v0, 0x0

    .line 14
    iput-object v0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPACommunicator;->latestGenXTransportState:Ltechnology/cariad/cat/genx/TransportState;

    .line 15
    .line 16
    iput-boolean v1, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPACommunicator;->shouldDisconnectAfterConnectionFinished:Z

    .line 17
    .line 18
    invoke-virtual {p0, v0}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPACommunicator;->setC2pListener$remoteparkassistplugin_release(Lk71/a;)V

    .line 19
    .line 20
    .line 21
    iget-object v1, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPACommunicator;->rpaCommunicatorJob:Lvy0/i1;

    .line 22
    .line 23
    if-eqz v1, :cond_0

    .line 24
    .line 25
    const-string v2, "RPA communicator is shutting down via close()"

    .line 26
    .line 27
    invoke-static {v2, v1}, Lvy0/e0;->k(Ljava/lang/String;Lvy0/i1;)V

    .line 28
    .line 29
    .line 30
    :cond_0
    iput-object v0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPACommunicator;->rpaCommunicatorJob:Lvy0/i1;

    .line 31
    .line 32
    const-string v0, "close"

    .line 33
    .line 34
    invoke-static {p0, v0}, Lvy0/e0;->l(Lvy0/b0;Ljava/lang/String;)V

    .line 35
    .line 36
    .line 37
    return-void
.end method

.method public connect()V
    .locals 10

    .line 1
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPACommunicator;->connectionStatus:Lk71/c;

    .line 2
    .line 3
    sget-object v1, Lk71/c;->d:Lk71/c;

    .line 4
    .line 5
    if-eq v0, v1, :cond_2

    .line 6
    .line 7
    sget-object v2, Lk71/c;->e:Lk71/c;

    .line 8
    .line 9
    if-ne v0, v2, :cond_0

    .line 10
    .line 11
    goto :goto_1

    .line 12
    :cond_0
    new-instance v0, Lt61/c;

    .line 13
    .line 14
    const/4 v2, 0x1

    .line 15
    invoke-direct {v0, p0, v2}, Lt61/c;-><init>(Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPACommunicator;I)V

    .line 16
    .line 17
    .line 18
    invoke-static {p0, v0}, Llp/i1;->d(Ljava/lang/Object;Lay0/a;)V

    .line 19
    .line 20
    .line 21
    const/4 v0, 0x0

    .line 22
    iput-boolean v0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPACommunicator;->shouldDisconnectAfterConnectionFinished:Z

    .line 23
    .line 24
    iget-boolean v0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPACommunicator;->disableTrajectoryMessages:Z

    .line 25
    .line 26
    const/4 v2, 0x0

    .line 27
    if-eqz v0, :cond_1

    .line 28
    .line 29
    sget-object v0, Ltechnology/cariad/cat/genx/protocol/Address;->Companion:Ltechnology/cariad/cat/genx/protocol/Address$Companion;

    .line 30
    .line 31
    const-string v3, "<this>"

    .line 32
    .line 33
    invoke-static {v0, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 34
    .line 35
    .line 36
    invoke-static {v0}, Lt61/b;->a(Ltechnology/cariad/cat/genx/protocol/Address$Companion;)Ljava/util/Set;

    .line 37
    .line 38
    .line 39
    move-result-object v0

    .line 40
    new-instance v3, Ltechnology/cariad/cat/genx/protocol/Address;

    .line 41
    .line 42
    sget-object v4, Ltechnology/cariad/cat/genx/protocol/GlobalServiceID;->Companion:Ltechnology/cariad/cat/genx/protocol/GlobalServiceID$Companion;

    .line 43
    .line 44
    invoke-static {v4}, Lt61/b;->b(Ltechnology/cariad/cat/genx/protocol/GlobalServiceID$Companion;)Ltechnology/cariad/cat/genx/protocol/GlobalServiceID;

    .line 45
    .line 46
    .line 47
    move-result-object v5

    .line 48
    sget-object v6, Ltechnology/cariad/cat/genx/protocol/AddressDirection$VehicleToPhone;->INSTANCE:Ltechnology/cariad/cat/genx/protocol/AddressDirection$VehicleToPhone;

    .line 49
    .line 50
    const/4 v7, 0x3

    .line 51
    invoke-direct {v3, v5, v7, v6, v2}, Ltechnology/cariad/cat/genx/protocol/Address;-><init>(Ltechnology/cariad/cat/genx/protocol/GlobalServiceID;BLtechnology/cariad/cat/genx/protocol/AddressDirection;Lkotlin/jvm/internal/g;)V

    .line 52
    .line 53
    .line 54
    new-instance v5, Ltechnology/cariad/cat/genx/protocol/Address;

    .line 55
    .line 56
    invoke-static {v4}, Lt61/b;->c(Ltechnology/cariad/cat/genx/protocol/GlobalServiceID$Companion;)Ltechnology/cariad/cat/genx/protocol/GlobalServiceID;

    .line 57
    .line 58
    .line 59
    move-result-object v8

    .line 60
    invoke-direct {v5, v8, v7, v6, v2}, Ltechnology/cariad/cat/genx/protocol/Address;-><init>(Ltechnology/cariad/cat/genx/protocol/GlobalServiceID;BLtechnology/cariad/cat/genx/protocol/AddressDirection;Lkotlin/jvm/internal/g;)V

    .line 61
    .line 62
    .line 63
    new-instance v7, Ltechnology/cariad/cat/genx/protocol/Address;

    .line 64
    .line 65
    invoke-static {v4}, Lt61/b;->b(Ltechnology/cariad/cat/genx/protocol/GlobalServiceID$Companion;)Ltechnology/cariad/cat/genx/protocol/GlobalServiceID;

    .line 66
    .line 67
    .line 68
    move-result-object v8

    .line 69
    const/4 v9, 0x5

    .line 70
    invoke-direct {v7, v8, v9, v6, v2}, Ltechnology/cariad/cat/genx/protocol/Address;-><init>(Ltechnology/cariad/cat/genx/protocol/GlobalServiceID;BLtechnology/cariad/cat/genx/protocol/AddressDirection;Lkotlin/jvm/internal/g;)V

    .line 71
    .line 72
    .line 73
    new-instance v8, Ltechnology/cariad/cat/genx/protocol/Address;

    .line 74
    .line 75
    invoke-static {v4}, Lt61/b;->c(Ltechnology/cariad/cat/genx/protocol/GlobalServiceID$Companion;)Ltechnology/cariad/cat/genx/protocol/GlobalServiceID;

    .line 76
    .line 77
    .line 78
    move-result-object v4

    .line 79
    invoke-direct {v8, v4, v9, v6, v2}, Ltechnology/cariad/cat/genx/protocol/Address;-><init>(Ltechnology/cariad/cat/genx/protocol/GlobalServiceID;BLtechnology/cariad/cat/genx/protocol/AddressDirection;Lkotlin/jvm/internal/g;)V

    .line 80
    .line 81
    .line 82
    filled-new-array {v3, v5, v7, v8}, [Ltechnology/cariad/cat/genx/protocol/Address;

    .line 83
    .line 84
    .line 85
    move-result-object v3

    .line 86
    invoke-static {v3}, Lmx0/n;->h0([Ljava/lang/Object;)Ljava/util/Set;

    .line 87
    .line 88
    .line 89
    move-result-object v3

    .line 90
    check-cast v3, Ljava/lang/Iterable;

    .line 91
    .line 92
    invoke-static {v0, v3}, Ljp/m1;->f(Ljava/util/Set;Ljava/lang/Iterable;)Ljava/util/Set;

    .line 93
    .line 94
    .line 95
    move-result-object v0

    .line 96
    goto :goto_0

    .line 97
    :cond_1
    sget-object v0, Ltechnology/cariad/cat/genx/protocol/Address;->Companion:Ltechnology/cariad/cat/genx/protocol/Address$Companion;

    .line 98
    .line 99
    invoke-static {v0}, Lt61/b;->a(Ltechnology/cariad/cat/genx/protocol/Address$Companion;)Ljava/util/Set;

    .line 100
    .line 101
    .line 102
    move-result-object v0

    .line 103
    :goto_0
    invoke-direct {p0, v1}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPACommunicator;->setConnectionStatus(Lk71/c;)V

    .line 104
    .line 105
    .line 106
    new-instance v1, Lt61/h;

    .line 107
    .line 108
    invoke-direct {v1, p0, v0, v2}, Lt61/h;-><init>(Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPACommunicator;Ljava/util/Set;Lkotlin/coroutines/Continuation;)V

    .line 109
    .line 110
    .line 111
    invoke-static {v1}, Lvy0/e0;->L(Lay0/n;)Ljava/lang/Object;

    .line 112
    .line 113
    .line 114
    :cond_2
    :goto_1
    return-void
.end method

.method public disconnect()V
    .locals 3

    .line 1
    new-instance v0, Lt61/c;

    .line 2
    .line 3
    const/4 v1, 0x2

    .line 4
    invoke-direct {v0, p0, v1}, Lt61/c;-><init>(Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPACommunicator;I)V

    .line 5
    .line 6
    .line 7
    invoke-static {p0, v0}, Llp/i1;->d(Ljava/lang/Object;Lay0/a;)V

    .line 8
    .line 9
    .line 10
    :try_start_0
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPACommunicator;->connection:Ltechnology/cariad/cat/genx/VehicleAntennaTransport$Connection;

    .line 11
    .line 12
    if-eqz v0, :cond_0

    .line 13
    .line 14
    invoke-interface {v0}, Ljava/io/Closeable;->close()V

    .line 15
    .line 16
    .line 17
    goto :goto_0

    .line 18
    :catch_0
    move-exception v0

    .line 19
    goto :goto_1

    .line 20
    :cond_0
    :goto_0
    const/4 v0, 0x0

    .line 21
    invoke-virtual {p0, v0}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPACommunicator;->setConnection$remoteparkassistplugin_release(Ltechnology/cariad/cat/genx/VehicleAntennaTransport$Connection;)V
    :try_end_0
    .catch Ljava/io/IOException; {:try_start_0 .. :try_end_0} :catch_0

    .line 22
    .line 23
    .line 24
    goto :goto_2

    .line 25
    :goto_1
    new-instance v1, Lqf0/d;

    .line 26
    .line 27
    const/16 v2, 0x1d

    .line 28
    .line 29
    invoke-direct {v1, v2}, Lqf0/d;-><init>(I)V

    .line 30
    .line 31
    .line 32
    invoke-static {p0, v0, v1}, Llp/i1;->c(Ljava/lang/Object;Ljava/io/IOException;Lay0/a;)V

    .line 33
    .line 34
    .line 35
    :goto_2
    const/4 v0, 0x1

    .line 36
    iput-boolean v0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPACommunicator;->shouldDisconnectAfterConnectionFinished:Z

    .line 37
    .line 38
    return-void
.end method

.method public final getBleTransport()Ltechnology/cariad/cat/genx/VehicleAntennaTransport;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPACommunicator;->bleTransport:Ltechnology/cariad/cat/genx/VehicleAntennaTransport;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getC2pListener$remoteparkassistplugin_release()Lk71/a;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPACommunicator;->c2pListener:Lk71/a;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getConnection$remoteparkassistplugin_release()Ltechnology/cariad/cat/genx/VehicleAntennaTransport$Connection;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPACommunicator;->connection:Ltechnology/cariad/cat/genx/VehicleAntennaTransport$Connection;

    .line 2
    .line 3
    return-object p0
.end method

.method public getCoroutineContext()Lpx0/g;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPACommunicator;->coroutineContext:Lpx0/g;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getDisableTrajectoryMessages()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPACommunicator;->disableTrajectoryMessages:Z

    .line 2
    .line 3
    return p0
.end method

.method public final getRpaDispatcher()Ln71/a;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPACommunicator;->rpaDispatcher:Ln71/a;

    .line 2
    .line 3
    return-object p0
.end method

.method public sendData([BJBZ)V
    .locals 9

    .line 1
    const-string v0, "payload"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    new-instance v3, Ltechnology/cariad/cat/genx/protocol/Address;

    .line 7
    .line 8
    invoke-direct {v3, p2, p3}, Ltechnology/cariad/cat/genx/protocol/Address;-><init>(J)V

    .line 9
    .line 10
    .line 11
    iget-object v2, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPACommunicator;->connection:Ltechnology/cariad/cat/genx/VehicleAntennaTransport$Connection;

    .line 12
    .line 13
    if-nez v2, :cond_0

    .line 14
    .line 15
    new-instance p2, Lc41/b;

    .line 16
    .line 17
    const/16 p3, 0x18

    .line 18
    .line 19
    invoke-direct {p2, p1, v3, p0, p3}, Lc41/b;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 20
    .line 21
    .line 22
    const/4 p1, 0x0

    .line 23
    invoke-static {p0, p1, p2}, Llp/i1;->c(Ljava/lang/Object;Ljava/io/IOException;Lay0/a;)V

    .line 24
    .line 25
    .line 26
    return-void

    .line 27
    :cond_0
    new-instance v1, Lt61/j;

    .line 28
    .line 29
    const/4 v8, 0x0

    .line 30
    move-object v7, p0

    .line 31
    move-object v6, p1

    .line 32
    move v4, p4

    .line 33
    move v5, p5

    .line 34
    invoke-direct/range {v1 .. v8}, Lt61/j;-><init>(Ltechnology/cariad/cat/genx/VehicleAntennaTransport$Connection;Ltechnology/cariad/cat/genx/protocol/Address;BZ[BLtechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPACommunicator;Lkotlin/coroutines/Continuation;)V

    .line 35
    .line 36
    .line 37
    invoke-static {v1}, Lvy0/e0;->L(Lay0/n;)Ljava/lang/Object;

    .line 38
    .line 39
    .line 40
    return-void
.end method

.method public final setC2pListener$remoteparkassistplugin_release(Lk71/a;)V
    .locals 1

    .line 1
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPACommunicator;->c2pListener:Lk71/a;

    .line 2
    .line 3
    invoke-static {v0, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    if-nez v0, :cond_0

    .line 8
    .line 9
    iput-object p1, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPACommunicator;->c2pListener:Lk71/a;

    .line 10
    .line 11
    :cond_0
    invoke-direct {p0}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPACommunicator;->sendLatestBLETransportData()V

    .line 12
    .line 13
    .line 14
    return-void
.end method

.method public final setConnection$remoteparkassistplugin_release(Ltechnology/cariad/cat/genx/VehicleAntennaTransport$Connection;)V
    .locals 1

    .line 1
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPACommunicator;->connection:Ltechnology/cariad/cat/genx/VehicleAntennaTransport$Connection;

    .line 2
    .line 3
    invoke-static {v0, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    if-nez v0, :cond_2

    .line 8
    .line 9
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPACommunicator;->connection:Ltechnology/cariad/cat/genx/VehicleAntennaTransport$Connection;

    .line 10
    .line 11
    if-eqz v0, :cond_0

    .line 12
    .line 13
    invoke-interface {v0}, Ljava/io/Closeable;->close()V

    .line 14
    .line 15
    .line 16
    :cond_0
    iput-object p1, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPACommunicator;->connection:Ltechnology/cariad/cat/genx/VehicleAntennaTransport$Connection;

    .line 17
    .line 18
    if-eqz p1, :cond_1

    .line 19
    .line 20
    sget-object p1, Lk71/c;->e:Lk71/c;

    .line 21
    .line 22
    goto :goto_0

    .line 23
    :cond_1
    sget-object p1, Lk71/c;->f:Lk71/c;

    .line 24
    .line 25
    :goto_0
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPACommunicator;->setConnectionStatus(Lk71/c;)V

    .line 26
    .line 27
    .line 28
    :cond_2
    return-void
.end method
