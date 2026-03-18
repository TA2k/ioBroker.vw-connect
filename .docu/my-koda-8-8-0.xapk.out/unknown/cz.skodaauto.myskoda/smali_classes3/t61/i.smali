.class public final Lt61/i;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltechnology/cariad/cat/genx/VehicleAntennaTransport$Connection$Delegate;


# instance fields
.field public final synthetic d:Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPACommunicator;


# direct methods
.method public constructor <init>(Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPACommunicator;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lt61/i;->d:Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPACommunicator;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final onConnectionDropped(Ltechnology/cariad/cat/genx/VehicleAntennaTransport$Connection;Ltechnology/cariad/cat/genx/GenXError;)V
    .locals 2

    .line 1
    const-string v0, "connection"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "error"

    .line 7
    .line 8
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    new-instance v0, Lt61/g;

    .line 12
    .line 13
    const/4 v1, 0x2

    .line 14
    invoke-direct {v0, v1, p1, p2}, Lt61/g;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 15
    .line 16
    .line 17
    invoke-static {p0, v0}, Llp/i1;->f(Ljava/lang/Object;Lay0/a;)V

    .line 18
    .line 19
    .line 20
    iget-object p0, p0, Lt61/i;->d:Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPACommunicator;

    .line 21
    .line 22
    const/4 p1, 0x0

    .line 23
    invoke-virtual {p0, p1}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPACommunicator;->setConnection$remoteparkassistplugin_release(Ltechnology/cariad/cat/genx/VehicleAntennaTransport$Connection;)V

    .line 24
    .line 25
    .line 26
    invoke-virtual {p0}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPACommunicator;->getC2pListener$remoteparkassistplugin_release()Lk71/a;

    .line 27
    .line 28
    .line 29
    move-result-object p0

    .line 30
    if-eqz p0, :cond_0

    .line 31
    .line 32
    sget-object p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/status/ConnectionErrorStatus$ConnectionLostError;->INSTANCE:Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/status/ConnectionErrorStatus$ConnectionLostError;

    .line 33
    .line 34
    invoke-virtual {p2}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 35
    .line 36
    .line 37
    move-result-object p2

    .line 38
    invoke-interface {p0, p1, p2}, Lk71/a;->carDidDetectConnectionError(Lt71/c;Ljava/lang/String;)V

    .line 39
    .line 40
    .line 41
    :cond_0
    return-void
.end method

.method public final onConnectionReceived(Ltechnology/cariad/cat/genx/VehicleAntennaTransport$Connection;Ltechnology/cariad/cat/genx/protocol/Message;)V
    .locals 6

    .line 1
    const-string v0, "connection"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "message"

    .line 7
    .line 8
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    new-instance v0, Lt61/g;

    .line 12
    .line 13
    const/4 v1, 0x1

    .line 14
    invoke-direct {v0, v1, p1, p2}, Lt61/g;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 15
    .line 16
    .line 17
    invoke-static {p0, v0}, Llp/i1;->e(Ljava/lang/Object;Lay0/a;)V

    .line 18
    .line 19
    .line 20
    iget-object p0, p0, Lt61/i;->d:Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPACommunicator;

    .line 21
    .line 22
    invoke-virtual {p0}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPACommunicator;->getC2pListener$remoteparkassistplugin_release()Lk71/a;

    .line 23
    .line 24
    .line 25
    move-result-object v0

    .line 26
    if-eqz v0, :cond_4

    .line 27
    .line 28
    invoke-virtual {p2}, Ltechnology/cariad/cat/genx/protocol/Message;->getData()[B

    .line 29
    .line 30
    .line 31
    move-result-object v1

    .line 32
    invoke-virtual {p2}, Ltechnology/cariad/cat/genx/protocol/Message;->getAddress()Ltechnology/cariad/cat/genx/protocol/Address;

    .line 33
    .line 34
    .line 35
    move-result-object p0

    .line 36
    invoke-virtual {p0}, Ltechnology/cariad/cat/genx/protocol/Address;->getRawValue()J

    .line 37
    .line 38
    .line 39
    move-result-wide v2

    .line 40
    invoke-virtual {p2}, Ltechnology/cariad/cat/genx/protocol/Message;->getPriority()Ltechnology/cariad/cat/genx/protocol/Priority;

    .line 41
    .line 42
    .line 43
    move-result-object p0

    .line 44
    const-string p1, "<this>"

    .line 45
    .line 46
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 47
    .line 48
    .line 49
    sget-object p1, Lt61/a;->b:[I

    .line 50
    .line 51
    invoke-virtual {p0}, Ljava/lang/Enum;->ordinal()I

    .line 52
    .line 53
    .line 54
    move-result p0

    .line 55
    aget p0, p1, p0

    .line 56
    .line 57
    const/4 p1, 0x1

    .line 58
    if-eq p0, p1, :cond_2

    .line 59
    .line 60
    const/4 v4, 0x2

    .line 61
    if-eq p0, v4, :cond_0

    .line 62
    .line 63
    const/4 p1, 0x3

    .line 64
    if-eq p0, p1, :cond_3

    .line 65
    .line 66
    const/4 v4, 0x4

    .line 67
    if-ne p0, v4, :cond_1

    .line 68
    .line 69
    :cond_0
    :goto_0
    move v4, p1

    .line 70
    goto :goto_1

    .line 71
    :cond_1
    new-instance p0, La8/r0;

    .line 72
    .line 73
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 74
    .line 75
    .line 76
    throw p0

    .line 77
    :cond_2
    const/4 p1, 0x0

    .line 78
    goto :goto_0

    .line 79
    :cond_3
    :goto_1
    invoke-virtual {p2}, Ltechnology/cariad/cat/genx/protocol/Message;->getRequiresQueuing()Z

    .line 80
    .line 81
    .line 82
    move-result v5

    .line 83
    invoke-interface/range {v0 .. v5}, Lk71/a;->receivedMessageFromCar([BJBZ)V

    .line 84
    .line 85
    .line 86
    :cond_4
    return-void
.end method
