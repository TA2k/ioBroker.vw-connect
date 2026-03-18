.class public final Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/t;
.super Lv81/a;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final c:Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineDefinition;


# direct methods
.method public constructor <init>(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEParkingFinishedState;)V
    .locals 10

    .line 1
    invoke-direct {p0}, Lv81/a;-><init>()V

    .line 2
    .line 3
    .line 4
    new-instance v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineDefinition;

    .line 5
    .line 6
    sget-object v1, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 7
    .line 8
    const-class v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEParkingFinishedState$Init;

    .line 9
    .line 10
    invoke-virtual {v1, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 11
    .line 12
    .line 13
    move-result-object v2

    .line 14
    const-class v3, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEParkingFinishedState$WindowClosingPossible;

    .line 15
    .line 16
    invoke-virtual {v1, v3}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 17
    .line 18
    .line 19
    move-result-object v3

    .line 20
    const-class v4, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEParkingFinishedState$WindowClosingNotPossible;

    .line 21
    .line 22
    invoke-virtual {v1, v4}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 23
    .line 24
    .line 25
    move-result-object v4

    .line 26
    const-class v5, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEParkingFinishedState$ClosingWindows;

    .line 27
    .line 28
    invoke-virtual {v1, v5}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 29
    .line 30
    .line 31
    move-result-object v5

    .line 32
    const-class v6, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEParkingFinishedState$NotActive;

    .line 33
    .line 34
    invoke-virtual {v1, v6}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 35
    .line 36
    .line 37
    move-result-object v6

    .line 38
    const-class v7, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEParkingFinishedState$Timeout;

    .line 39
    .line 40
    invoke-virtual {v1, v7}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 41
    .line 42
    .line 43
    move-result-object v7

    .line 44
    const/4 v8, 0x6

    .line 45
    new-array v8, v8, [Lhy0/d;

    .line 46
    .line 47
    const/4 v9, 0x0

    .line 48
    aput-object v2, v8, v9

    .line 49
    .line 50
    const/4 v2, 0x1

    .line 51
    aput-object v3, v8, v2

    .line 52
    .line 53
    const/4 v3, 0x2

    .line 54
    aput-object v4, v8, v3

    .line 55
    .line 56
    const/4 v4, 0x3

    .line 57
    aput-object v5, v8, v4

    .line 58
    .line 59
    const/4 v5, 0x4

    .line 60
    aput-object v6, v8, v5

    .line 61
    .line 62
    const/4 v5, 0x5

    .line 63
    aput-object v7, v8, v5

    .line 64
    .line 65
    invoke-static {v8}, Lmx0/n;->h0([Ljava/lang/Object;)Ljava/util/Set;

    .line 66
    .line 67
    .line 68
    move-result-object v5

    .line 69
    const-class v6, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/MessageSentInput;

    .line 70
    .line 71
    invoke-virtual {v1, v6}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 72
    .line 73
    .line 74
    move-result-object v6

    .line 75
    const-class v7, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/MessageReceivedInput;

    .line 76
    .line 77
    invoke-virtual {v1, v7}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 78
    .line 79
    .line 80
    move-result-object v7

    .line 81
    const-class v8, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/TimeElapsedInput;

    .line 82
    .line 83
    invoke-virtual {v1, v8}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 84
    .line 85
    .line 86
    move-result-object v1

    .line 87
    new-array v4, v4, [Lhy0/d;

    .line 88
    .line 89
    aput-object v6, v4, v9

    .line 90
    .line 91
    aput-object v7, v4, v2

    .line 92
    .line 93
    aput-object v1, v4, v3

    .line 94
    .line 95
    invoke-static {v4}, Lmx0/n;->h0([Ljava/lang/Object;)Ljava/util/Set;

    .line 96
    .line 97
    .line 98
    move-result-object v2

    .line 99
    new-instance v3, Lw81/c;

    .line 100
    .line 101
    const/16 v1, 0xc

    .line 102
    .line 103
    invoke-direct {v3, p0, v1}, Lw81/c;-><init>(Ljava/lang/Object;I)V

    .line 104
    .line 105
    .line 106
    new-instance v4, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEParkingFinishedState$Init;

    .line 107
    .line 108
    invoke-virtual {p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEParkingFinishedState;->getInitialStateValues()Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEParkingFinishedStateValues;

    .line 109
    .line 110
    .line 111
    move-result-object p1

    .line 112
    invoke-direct {v4, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEParkingFinishedState$Init;-><init>(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEParkingFinishedStateValues;)V

    .line 113
    .line 114
    .line 115
    move-object v1, v5

    .line 116
    sget-object v5, Lmx0/u;->d:Lmx0/u;

    .line 117
    .line 118
    invoke-direct/range {v0 .. v5}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineDefinition;-><init>(Ljava/util/Set;Ljava/util/Set;Lay0/k;Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineState;Ljava/util/Set;)V

    .line 119
    .line 120
    .line 121
    iput-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/t;->c:Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineDefinition;

    .line 122
    .line 123
    return-void
.end method


# virtual methods
.method public final getDefinition$remoteparkassistcoremeb_release()Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineDefinition;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/t;->c:Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineDefinition;

    .line 2
    .line 3
    return-object p0
.end method
