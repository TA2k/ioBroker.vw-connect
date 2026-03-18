.class public final Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/h;
.super Lv81/a;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final c:Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineDefinition;


# direct methods
.method public constructor <init>(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/data/PPEStateValues;)V
    .locals 12

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
    const-class v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEDriveCorrectionState$Init;

    .line 9
    .line 10
    invoke-virtual {v1, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 11
    .line 12
    .line 13
    move-result-object v2

    .line 14
    const-class v3, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEDriveCorrectionState$RequestedParkingForward;

    .line 15
    .line 16
    invoke-virtual {v1, v3}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 17
    .line 18
    .line 19
    move-result-object v3

    .line 20
    const-class v4, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEDriveCorrectionState$ParkingForward;

    .line 21
    .line 22
    invoke-virtual {v1, v4}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 23
    .line 24
    .line 25
    move-result-object v4

    .line 26
    const-class v5, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEDriveCorrectionState$PausedParking;

    .line 27
    .line 28
    invoke-virtual {v1, v5}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 29
    .line 30
    .line 31
    move-result-object v5

    .line 32
    const-class v6, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEDriveCorrectionState$PausedAndHoldKeyInterruption;

    .line 33
    .line 34
    invoke-virtual {v1, v6}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 35
    .line 36
    .line 37
    move-result-object v6

    .line 38
    const-class v7, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEDriveCorrectionState$RequestedParkingBackward;

    .line 39
    .line 40
    invoke-virtual {v1, v7}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 41
    .line 42
    .line 43
    move-result-object v7

    .line 44
    const-class v8, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEDriveCorrectionState$ParkingBackward;

    .line 45
    .line 46
    invoke-virtual {v1, v8}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 47
    .line 48
    .line 49
    move-result-object v8

    .line 50
    const-class v9, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/screen/PPESubStateMachine$InvalidTouchState;

    .line 51
    .line 52
    invoke-virtual {v1, v9}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 53
    .line 54
    .line 55
    move-result-object v9

    .line 56
    const/16 v10, 0x8

    .line 57
    .line 58
    new-array v10, v10, [Lhy0/d;

    .line 59
    .line 60
    const/4 v11, 0x0

    .line 61
    aput-object v2, v10, v11

    .line 62
    .line 63
    const/4 v2, 0x1

    .line 64
    aput-object v3, v10, v2

    .line 65
    .line 66
    const/4 v3, 0x2

    .line 67
    aput-object v4, v10, v3

    .line 68
    .line 69
    const/4 v4, 0x3

    .line 70
    aput-object v5, v10, v4

    .line 71
    .line 72
    const/4 v4, 0x4

    .line 73
    aput-object v6, v10, v4

    .line 74
    .line 75
    const/4 v4, 0x5

    .line 76
    aput-object v7, v10, v4

    .line 77
    .line 78
    const/4 v5, 0x6

    .line 79
    aput-object v8, v10, v5

    .line 80
    .line 81
    const/4 v5, 0x7

    .line 82
    aput-object v9, v10, v5

    .line 83
    .line 84
    invoke-static {v10}, Lmx0/n;->h0([Ljava/lang/Object;)Ljava/util/Set;

    .line 85
    .line 86
    .line 87
    move-result-object v5

    .line 88
    const-class v6, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/MessageReceivedInput;

    .line 89
    .line 90
    invoke-virtual {v1, v6}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 91
    .line 92
    .line 93
    move-result-object v6

    .line 94
    const-class v7, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/MessageSentInput;

    .line 95
    .line 96
    invoke-virtual {v1, v7}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 97
    .line 98
    .line 99
    move-result-object v1

    .line 100
    new-array v3, v3, [Lhy0/d;

    .line 101
    .line 102
    aput-object v6, v3, v11

    .line 103
    .line 104
    aput-object v1, v3, v2

    .line 105
    .line 106
    invoke-static {v3}, Lmx0/n;->h0([Ljava/lang/Object;)Ljava/util/Set;

    .line 107
    .line 108
    .line 109
    move-result-object v2

    .line 110
    new-instance v3, Lw81/c;

    .line 111
    .line 112
    invoke-direct {v3, p0, v4}, Lw81/c;-><init>(Ljava/lang/Object;I)V

    .line 113
    .line 114
    .line 115
    new-instance v4, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEDriveCorrectionState$Init;

    .line 116
    .line 117
    invoke-direct {v4, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEDriveCorrectionState$Init;-><init>(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/data/PPEStateValues;)V

    .line 118
    .line 119
    .line 120
    move-object v1, v5

    .line 121
    sget-object v5, Lmx0/u;->d:Lmx0/u;

    .line 122
    .line 123
    invoke-direct/range {v0 .. v5}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineDefinition;-><init>(Ljava/util/Set;Ljava/util/Set;Lay0/k;Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineState;Ljava/util/Set;)V

    .line 124
    .line 125
    .line 126
    iput-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/h;->c:Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineDefinition;

    .line 127
    .line 128
    return-void
.end method


# virtual methods
.method public final getDefinition$remoteparkassistcoremeb_release()Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineDefinition;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/h;->c:Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineDefinition;

    .line 2
    .line 3
    return-object p0
.end method
