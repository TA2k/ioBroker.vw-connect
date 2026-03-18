.class public final Lt61/o;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public synthetic d:Ljava/lang/Object;

.field public final synthetic e:Ltechnology/cariad/cat/genx/VehicleAntennaTransport;

.field public final synthetic f:Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPACommunicator;


# direct methods
.method public constructor <init>(Ltechnology/cariad/cat/genx/VehicleAntennaTransport;Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPACommunicator;Lkotlin/coroutines/Continuation;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lt61/o;->e:Ltechnology/cariad/cat/genx/VehicleAntennaTransport;

    .line 2
    .line 3
    iput-object p2, p0, Lt61/o;->f:Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPACommunicator;

    .line 4
    .line 5
    const/4 p1, 0x2

    .line 6
    invoke-direct {p0, p1, p3}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 7
    .line 8
    .line 9
    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;
    .locals 2

    .line 1
    new-instance v0, Lt61/o;

    .line 2
    .line 3
    iget-object v1, p0, Lt61/o;->e:Ltechnology/cariad/cat/genx/VehicleAntennaTransport;

    .line 4
    .line 5
    iget-object p0, p0, Lt61/o;->f:Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPACommunicator;

    .line 6
    .line 7
    invoke-direct {v0, v1, p0, p2}, Lt61/o;-><init>(Ltechnology/cariad/cat/genx/VehicleAntennaTransport;Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPACommunicator;Lkotlin/coroutines/Continuation;)V

    .line 8
    .line 9
    .line 10
    iput-object p1, v0, Lt61/o;->d:Ljava/lang/Object;

    .line 11
    .line 12
    return-object v0
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Lvy0/b0;

    .line 2
    .line 3
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 4
    .line 5
    invoke-virtual {p0, p1, p2}, Lt61/o;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    check-cast p0, Lt61/o;

    .line 10
    .line 11
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 12
    .line 13
    invoke-virtual {p0, p1}, Lt61/o;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 14
    .line 15
    .line 16
    return-object p1
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 6

    .line 1
    iget-object v0, p0, Lt61/o;->d:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Lvy0/b0;

    .line 4
    .line 5
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 6
    .line 7
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 8
    .line 9
    .line 10
    iget-object p1, p0, Lt61/o;->e:Ltechnology/cariad/cat/genx/VehicleAntennaTransport;

    .line 11
    .line 12
    invoke-interface {p1}, Ltechnology/cariad/cat/genx/VehicleAntennaTransport;->isConnectable()Lyy0/a2;

    .line 13
    .line 14
    .line 15
    move-result-object v1

    .line 16
    new-instance v2, Lc/m;

    .line 17
    .line 18
    const/4 v3, 0x7

    .line 19
    iget-object p0, p0, Lt61/o;->f:Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPACommunicator;

    .line 20
    .line 21
    const/4 v4, 0x0

    .line 22
    invoke-direct {v2, p0, v4, v3}, Lc/m;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 23
    .line 24
    .line 25
    new-instance v3, Lne0/n;

    .line 26
    .line 27
    const/4 v5, 0x5

    .line 28
    invoke-direct {v3, v1, v2, v5}, Lne0/n;-><init>(Lyy0/i;Lay0/n;I)V

    .line 29
    .line 30
    .line 31
    invoke-static {v3, v0}, Lyy0/u;->B(Lyy0/i;Lvy0/b0;)Lvy0/x1;

    .line 32
    .line 33
    .line 34
    invoke-interface {p1}, Ltechnology/cariad/cat/genx/VehicleAntennaTransport;->getSendWindowState()Lyy0/i;

    .line 35
    .line 36
    .line 37
    move-result-object v1

    .line 38
    new-instance v2, Lrz/k;

    .line 39
    .line 40
    const/4 v3, 0x4

    .line 41
    invoke-direct {v2, v1, v3}, Lrz/k;-><init>(Lyy0/i;I)V

    .line 42
    .line 43
    .line 44
    new-instance v1, Lt61/k;

    .line 45
    .line 46
    const/4 v3, 0x0

    .line 47
    invoke-direct {v1, p0, v4, v3}, Lt61/k;-><init>(Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPACommunicator;Lkotlin/coroutines/Continuation;I)V

    .line 48
    .line 49
    .line 50
    new-instance v3, Lne0/n;

    .line 51
    .line 52
    invoke-direct {v3, v2, v1, v5}, Lne0/n;-><init>(Lyy0/i;Lay0/n;I)V

    .line 53
    .line 54
    .line 55
    invoke-static {v3, v0}, Lyy0/u;->B(Lyy0/i;Lvy0/b0;)Lvy0/x1;

    .line 56
    .line 57
    .line 58
    invoke-interface {p1}, Ltechnology/cariad/cat/genx/VehicleAntennaTransport;->getCar2PhoneMode()Lyy0/a2;

    .line 59
    .line 60
    .line 61
    move-result-object v1

    .line 62
    new-instance v2, Lt61/k;

    .line 63
    .line 64
    const/4 v3, 0x1

    .line 65
    invoke-direct {v2, p0, v4, v3}, Lt61/k;-><init>(Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPACommunicator;Lkotlin/coroutines/Continuation;I)V

    .line 66
    .line 67
    .line 68
    new-instance v3, Lne0/n;

    .line 69
    .line 70
    invoke-direct {v3, v1, v2, v5}, Lne0/n;-><init>(Lyy0/i;Lay0/n;I)V

    .line 71
    .line 72
    .line 73
    invoke-static {v3, v0}, Lyy0/u;->B(Lyy0/i;Lvy0/b0;)Lvy0/x1;

    .line 74
    .line 75
    .line 76
    invoke-interface {p1}, Ltechnology/cariad/cat/genx/VehicleAntennaTransport;->getTransportErrors()Lyy0/i;

    .line 77
    .line 78
    .line 79
    move-result-object v1

    .line 80
    new-instance v2, Lrz/k;

    .line 81
    .line 82
    invoke-direct {v2, v1, v5}, Lrz/k;-><init>(Lyy0/i;I)V

    .line 83
    .line 84
    .line 85
    new-instance v1, Lt61/k;

    .line 86
    .line 87
    const/4 v3, 0x2

    .line 88
    invoke-direct {v1, p0, v4, v3}, Lt61/k;-><init>(Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPACommunicator;Lkotlin/coroutines/Continuation;I)V

    .line 89
    .line 90
    .line 91
    new-instance v3, Lne0/n;

    .line 92
    .line 93
    invoke-direct {v3, v2, v1, v5}, Lne0/n;-><init>(Lyy0/i;Lay0/n;I)V

    .line 94
    .line 95
    .line 96
    invoke-static {v3, v0}, Lyy0/u;->B(Lyy0/i;Lvy0/b0;)Lvy0/x1;

    .line 97
    .line 98
    .line 99
    invoke-interface {p1}, Ltechnology/cariad/cat/genx/VehicleAntennaTransport;->getLinkParameters()Lyy0/i;

    .line 100
    .line 101
    .line 102
    move-result-object p1

    .line 103
    new-instance v1, Lt61/l;

    .line 104
    .line 105
    invoke-direct {v1, p0, v0, v4}, Lt61/l;-><init>(Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPACommunicator;Lvy0/b0;Lkotlin/coroutines/Continuation;)V

    .line 106
    .line 107
    .line 108
    new-instance v2, Lne0/n;

    .line 109
    .line 110
    invoke-direct {v2, p1, v1, v5}, Lne0/n;-><init>(Lyy0/i;Lay0/n;I)V

    .line 111
    .line 112
    .line 113
    invoke-static {v2, v0}, Lyy0/u;->B(Lyy0/i;Lvy0/b0;)Lvy0/x1;

    .line 114
    .line 115
    .line 116
    invoke-static {p0}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPACommunicator;->access$getVehicleAntenna$p(Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPACommunicator;)Ltechnology/cariad/cat/genx/VehicleAntenna$Outer;

    .line 117
    .line 118
    .line 119
    move-result-object p1

    .line 120
    invoke-interface {p1}, Ltechnology/cariad/cat/genx/VehicleAntenna;->getSoftwareStackIncompatibility()Lyy0/i;

    .line 121
    .line 122
    .line 123
    move-result-object p1

    .line 124
    new-instance v1, Lt61/k;

    .line 125
    .line 126
    const/4 v2, 0x3

    .line 127
    invoke-direct {v1, p0, v4, v2}, Lt61/k;-><init>(Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPACommunicator;Lkotlin/coroutines/Continuation;I)V

    .line 128
    .line 129
    .line 130
    new-instance p0, Lne0/n;

    .line 131
    .line 132
    invoke-direct {p0, p1, v1, v5}, Lne0/n;-><init>(Lyy0/i;Lay0/n;I)V

    .line 133
    .line 134
    .line 135
    invoke-static {p0, v0}, Lyy0/u;->B(Lyy0/i;Lvy0/b0;)Lvy0/x1;

    .line 136
    .line 137
    .line 138
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 139
    .line 140
    return-object p0
.end method
