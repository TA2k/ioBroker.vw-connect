.class public final Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/n;
.super Lv81/a;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final c:Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineDefinition;


# direct methods
.method public constructor <init>(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEDriveState;)V
    .locals 14

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
    const-class v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEDriveState$Init;

    .line 9
    .line 10
    invoke-virtual {v1, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 11
    .line 12
    .line 13
    move-result-object v2

    .line 14
    const-class v3, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEDriveState$RequestedParking;

    .line 15
    .line 16
    invoke-virtual {v1, v3}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 17
    .line 18
    .line 19
    move-result-object v3

    .line 20
    const-class v4, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEDriveState$Parking;

    .line 21
    .line 22
    invoke-virtual {v1, v4}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 23
    .line 24
    .line 25
    move-result-object v4

    .line 26
    const-class v5, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEDriveState$RequestedUndoing;

    .line 27
    .line 28
    invoke-virtual {v1, v5}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 29
    .line 30
    .line 31
    move-result-object v5

    .line 32
    const-class v6, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEDriveState$Undoing;

    .line 33
    .line 34
    invoke-virtual {v1, v6}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 35
    .line 36
    .line 37
    move-result-object v6

    .line 38
    const-class v7, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEDriveState$PausedUndoingNotPossible;

    .line 39
    .line 40
    invoke-virtual {v1, v7}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 41
    .line 42
    .line 43
    move-result-object v7

    .line 44
    const-class v8, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEDriveState$Paused;

    .line 45
    .line 46
    invoke-virtual {v1, v8}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 47
    .line 48
    .line 49
    move-result-object v8

    .line 50
    const-class v9, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEDriveState$PausedAndHoldKeyInterruption;

    .line 51
    .line 52
    invoke-virtual {v1, v9}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 53
    .line 54
    .line 55
    move-result-object v9

    .line 56
    const-class v10, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEDriveState$BadConnection;

    .line 57
    .line 58
    invoke-virtual {v1, v10}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 59
    .line 60
    .line 61
    move-result-object v10

    .line 62
    const-class v11, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/screen/PPESubStateMachine$InvalidTouchState;

    .line 63
    .line 64
    invoke-virtual {v1, v11}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 65
    .line 66
    .line 67
    move-result-object v11

    .line 68
    const/16 v12, 0xa

    .line 69
    .line 70
    new-array v12, v12, [Lhy0/d;

    .line 71
    .line 72
    const/4 v13, 0x0

    .line 73
    aput-object v2, v12, v13

    .line 74
    .line 75
    const/4 v2, 0x1

    .line 76
    aput-object v3, v12, v2

    .line 77
    .line 78
    const/4 v3, 0x2

    .line 79
    aput-object v4, v12, v3

    .line 80
    .line 81
    const/4 v4, 0x3

    .line 82
    aput-object v5, v12, v4

    .line 83
    .line 84
    const/4 v4, 0x4

    .line 85
    aput-object v6, v12, v4

    .line 86
    .line 87
    const/4 v4, 0x5

    .line 88
    aput-object v7, v12, v4

    .line 89
    .line 90
    const/4 v4, 0x6

    .line 91
    aput-object v8, v12, v4

    .line 92
    .line 93
    const/4 v4, 0x7

    .line 94
    aput-object v9, v12, v4

    .line 95
    .line 96
    const/16 v4, 0x8

    .line 97
    .line 98
    aput-object v10, v12, v4

    .line 99
    .line 100
    const/16 v4, 0x9

    .line 101
    .line 102
    aput-object v11, v12, v4

    .line 103
    .line 104
    invoke-static {v12}, Lmx0/n;->h0([Ljava/lang/Object;)Ljava/util/Set;

    .line 105
    .line 106
    .line 107
    move-result-object v4

    .line 108
    const-class v5, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/MessageReceivedInput;

    .line 109
    .line 110
    invoke-virtual {v1, v5}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 111
    .line 112
    .line 113
    move-result-object v5

    .line 114
    const-class v6, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/MessageSentInput;

    .line 115
    .line 116
    invoke-virtual {v1, v6}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 117
    .line 118
    .line 119
    move-result-object v1

    .line 120
    new-array v3, v3, [Lhy0/d;

    .line 121
    .line 122
    aput-object v5, v3, v13

    .line 123
    .line 124
    aput-object v1, v3, v2

    .line 125
    .line 126
    invoke-static {v3}, Lmx0/n;->h0([Ljava/lang/Object;)Ljava/util/Set;

    .line 127
    .line 128
    .line 129
    move-result-object v2

    .line 130
    new-instance v3, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/n;

    .line 131
    .line 132
    const/16 v1, 0x16

    .line 133
    .line 134
    invoke-direct {v3, v1, p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/n;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 135
    .line 136
    .line 137
    move-object v1, v4

    .line 138
    new-instance v4, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEDriveState$Init;

    .line 139
    .line 140
    invoke-direct {v4}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEDriveState$Init;-><init>()V

    .line 141
    .line 142
    .line 143
    sget-object v5, Lmx0/u;->d:Lmx0/u;

    .line 144
    .line 145
    invoke-direct/range {v0 .. v5}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineDefinition;-><init>(Ljava/util/Set;Ljava/util/Set;Lay0/k;Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineState;Ljava/util/Set;)V

    .line 146
    .line 147
    .line 148
    iput-object v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/n;->c:Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineDefinition;

    .line 149
    .line 150
    return-void
.end method


# virtual methods
.method public final getDefinition$remoteparkassistcoremeb_release()Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineDefinition;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/n;->c:Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineDefinition;

    .line 2
    .line 3
    return-object p0
.end method
