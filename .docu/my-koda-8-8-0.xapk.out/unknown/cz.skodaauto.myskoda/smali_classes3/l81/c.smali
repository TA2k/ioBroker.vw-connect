.class public final Ll81/c;
.super Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/StateMachine;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final d:Ljava/util/Set;


# instance fields
.field public final a:J

.field public b:Z

.field public final c:Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineDefinition;


# direct methods
.method static constructor <clinit>()V
    .locals 15

    .line 1
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/data/MLBStateValues;->n:Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/data/MLBStateValues;

    .line 2
    .line 3
    new-instance v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBTouchDiagnosisState;

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    invoke-direct {v1, v0, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBTouchDiagnosisState;-><init>(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/data/MLBStateValues;Z)V

    .line 7
    .line 8
    .line 9
    new-instance v3, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBDriveActivationState;

    .line 10
    .line 11
    invoke-direct {v3, v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBDriveActivationState;-><init>(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/data/MLBStateValues;)V

    .line 12
    .line 13
    .line 14
    new-instance v4, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBScenarioSelectionState;

    .line 15
    .line 16
    invoke-direct {v4, v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBScenarioSelectionState;-><init>(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/data/MLBStateValues;)V

    .line 17
    .line 18
    .line 19
    new-instance v5, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBDriveState;

    .line 20
    .line 21
    invoke-direct {v5, v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBDriveState;-><init>(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/data/MLBStateValues;)V

    .line 22
    .line 23
    .line 24
    new-instance v6, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBDriveCorrectionState;

    .line 25
    .line 26
    invoke-direct {v6, v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBDriveCorrectionState;-><init>(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/data/MLBStateValues;)V

    .line 27
    .line 28
    .line 29
    new-instance v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBParkingFinishedState;

    .line 30
    .line 31
    sget-object v7, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBParkingFinishedStateValues;->h:Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBParkingFinishedStateValues;

    .line 32
    .line 33
    sget-object v8, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ParkingManeuverStatusMLB;->PARKING:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ParkingManeuverStatusMLB;

    .line 34
    .line 35
    invoke-static {v8}, Lkp/p;->a(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ParkingManeuverStatusMLB;)Ls71/h;

    .line 36
    .line 37
    .line 38
    move-result-object v8

    .line 39
    invoke-static {v7, v8}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBParkingFinishedStateValues;->c(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBParkingFinishedStateValues;Ls71/h;)Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBParkingFinishedStateValues;

    .line 40
    .line 41
    .line 42
    move-result-object v8

    .line 43
    invoke-direct {v0, v8}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBParkingFinishedState;-><init>(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBParkingFinishedStateValues;)V

    .line 44
    .line 45
    .line 46
    new-instance v8, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBParkingFinishedState;

    .line 47
    .line 48
    sget-object v9, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ParkingManeuverStatusMLB;->PULLOUT:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ParkingManeuverStatusMLB;

    .line 49
    .line 50
    invoke-static {v9}, Lkp/p;->a(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ParkingManeuverStatusMLB;)Ls71/h;

    .line 51
    .line 52
    .line 53
    move-result-object v9

    .line 54
    invoke-static {v7, v9}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBParkingFinishedStateValues;->c(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBParkingFinishedStateValues;Ls71/h;)Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBParkingFinishedStateValues;

    .line 55
    .line 56
    .line 57
    move-result-object v7

    .line 58
    invoke-direct {v8, v7}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBParkingFinishedState;-><init>(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBParkingFinishedStateValues;)V

    .line 59
    .line 60
    .line 61
    new-instance v9, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBParkingFailedState;

    .line 62
    .line 63
    sget-object v12, Lp81/a;->d:Lp81/a;

    .line 64
    .line 65
    const/4 v13, 0x3

    .line 66
    const/4 v14, 0x0

    .line 67
    const/4 v10, 0x0

    .line 68
    const/4 v11, 0x0

    .line 69
    invoke-direct/range {v9 .. v14}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBParkingFailedState;-><init>(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/StoppingReasonStatusExtendedMLB;Ll71/c;Lp81/a;ILkotlin/jvm/internal/g;)V

    .line 70
    .line 71
    .line 72
    const/16 v7, 0x8

    .line 73
    .line 74
    new-array v7, v7, [Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/screen/MLBScreenState;

    .line 75
    .line 76
    aput-object v1, v7, v2

    .line 77
    .line 78
    const/4 v1, 0x1

    .line 79
    aput-object v3, v7, v1

    .line 80
    .line 81
    const/4 v1, 0x2

    .line 82
    aput-object v4, v7, v1

    .line 83
    .line 84
    const/4 v1, 0x3

    .line 85
    aput-object v5, v7, v1

    .line 86
    .line 87
    const/4 v1, 0x4

    .line 88
    aput-object v6, v7, v1

    .line 89
    .line 90
    const/4 v1, 0x5

    .line 91
    aput-object v0, v7, v1

    .line 92
    .line 93
    const/4 v0, 0x6

    .line 94
    aput-object v8, v7, v0

    .line 95
    .line 96
    const/4 v0, 0x7

    .line 97
    aput-object v9, v7, v0

    .line 98
    .line 99
    invoke-static {v7}, Lmx0/n;->h0([Ljava/lang/Object;)Ljava/util/Set;

    .line 100
    .line 101
    .line 102
    move-result-object v0

    .line 103
    sput-object v0, Ll81/c;->d:Ljava/util/Set;

    .line 104
    .line 105
    return-void
.end method

.method public constructor <init>()V
    .locals 16

    .line 1
    move-object/from16 v2, p0

    .line 2
    .line 3
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/data/MLBStateValues;->n:Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/data/MLBStateValues;

    .line 4
    .line 5
    new-instance v8, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBTouchDiagnosisState;

    .line 6
    .line 7
    const/4 v9, 0x0

    .line 8
    invoke-direct {v8, v0, v9}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBTouchDiagnosisState;-><init>(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/data/MLBStateValues;Z)V

    .line 9
    .line 10
    .line 11
    invoke-direct {v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/StateMachine;-><init>()V

    .line 12
    .line 13
    .line 14
    sget-wide v0, Ln81/b;->f:J

    .line 15
    .line 16
    iput-wide v0, v2, Ll81/c;->a:J

    .line 17
    .line 18
    sget-object v0, Ll81/c;->d:Ljava/util/Set;

    .line 19
    .line 20
    check-cast v0, Ljava/lang/Iterable;

    .line 21
    .line 22
    new-instance v1, Ljava/util/ArrayList;

    .line 23
    .line 24
    const/16 v3, 0xa

    .line 25
    .line 26
    invoke-static {v0, v3}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 27
    .line 28
    .line 29
    move-result v3

    .line 30
    invoke-direct {v1, v3}, Ljava/util/ArrayList;-><init>(I)V

    .line 31
    .line 32
    .line 33
    invoke-interface {v0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 34
    .line 35
    .line 36
    move-result-object v0

    .line 37
    :goto_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 38
    .line 39
    .line 40
    move-result v3

    .line 41
    if-eqz v3, :cond_0

    .line 42
    .line 43
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 44
    .line 45
    .line 46
    move-result-object v3

    .line 47
    check-cast v3, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/screen/MLBScreenState;

    .line 48
    .line 49
    invoke-virtual {v3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 50
    .line 51
    .line 52
    move-result-object v3

    .line 53
    sget-object v4, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 54
    .line 55
    invoke-virtual {v4, v3}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 56
    .line 57
    .line 58
    move-result-object v3

    .line 59
    invoke-virtual {v1, v3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 60
    .line 61
    .line 62
    goto :goto_0

    .line 63
    :cond_0
    invoke-static {v1}, Lmx0/q;->C0(Ljava/lang/Iterable;)Ljava/util/Set;

    .line 64
    .line 65
    .line 66
    move-result-object v10

    .line 67
    new-instance v11, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineDefinition;

    .line 68
    .line 69
    sget-object v12, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 70
    .line 71
    const-class v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/MessageReceivedInput;

    .line 72
    .line 73
    invoke-virtual {v12, v0}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 74
    .line 75
    .line 76
    move-result-object v0

    .line 77
    const-class v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/MessageSentInput;

    .line 78
    .line 79
    invoke-virtual {v12, v1}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 80
    .line 81
    .line 82
    move-result-object v1

    .line 83
    const-class v3, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/TimeElapsedInput;

    .line 84
    .line 85
    invoke-virtual {v12, v3}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 86
    .line 87
    .line 88
    move-result-object v3

    .line 89
    const/4 v4, 0x3

    .line 90
    new-array v4, v4, [Lhy0/d;

    .line 91
    .line 92
    aput-object v0, v4, v9

    .line 93
    .line 94
    const/4 v13, 0x1

    .line 95
    aput-object v1, v4, v13

    .line 96
    .line 97
    const/4 v14, 0x2

    .line 98
    aput-object v3, v4, v14

    .line 99
    .line 100
    invoke-static {v4}, Lmx0/n;->h0([Ljava/lang/Object;)Ljava/util/Set;

    .line 101
    .line 102
    .line 103
    move-result-object v15

    .line 104
    new-instance v0, Ll20/g;

    .line 105
    .line 106
    const/4 v6, 0x0

    .line 107
    const/4 v7, 0x4

    .line 108
    const/4 v1, 0x1

    .line 109
    const-class v3, Ll81/c;

    .line 110
    .line 111
    const-string v4, "processNewlyProvidedStateMachineInput"

    .line 112
    .line 113
    const-string v5, "processNewlyProvidedStateMachineInput(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineInput;)Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/screen/MLBScreenState;"

    .line 114
    .line 115
    invoke-direct/range {v0 .. v7}, Ll20/g;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 116
    .line 117
    .line 118
    move-object v4, v0

    .line 119
    move-object v0, v2

    .line 120
    const-class v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBParkingFinishedState;

    .line 121
    .line 122
    invoke-virtual {v12, v1}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 123
    .line 124
    .line 125
    move-result-object v1

    .line 126
    const-class v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/state/MLBParkingFailedState;

    .line 127
    .line 128
    invoke-virtual {v12, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 129
    .line 130
    .line 131
    move-result-object v2

    .line 132
    new-array v3, v14, [Lhy0/d;

    .line 133
    .line 134
    aput-object v1, v3, v9

    .line 135
    .line 136
    aput-object v2, v3, v13

    .line 137
    .line 138
    invoke-static {v3}, Lmx0/n;->h0([Ljava/lang/Object;)Ljava/util/Set;

    .line 139
    .line 140
    .line 141
    move-result-object v6

    .line 142
    move-object v5, v8

    .line 143
    move-object v2, v10

    .line 144
    move-object v1, v11

    .line 145
    move-object v3, v15

    .line 146
    invoke-direct/range {v1 .. v6}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineDefinition;-><init>(Ljava/util/Set;Ljava/util/Set;Lay0/k;Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineState;Ljava/util/Set;)V

    .line 147
    .line 148
    .line 149
    iput-object v1, v0, Ll81/c;->c:Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineDefinition;

    .line 150
    .line 151
    return-void
.end method


# virtual methods
.method public final getDefinition$remoteparkassistcoremeb_release()Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineDefinition;
    .locals 0

    .line 1
    iget-object p0, p0, Ll81/c;->c:Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineDefinition;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getTickInterval-UwyO8pc$remoteparkassistcoremeb_release()J
    .locals 2

    .line 1
    iget-wide v0, p0, Ll81/c;->a:J

    .line 2
    .line 3
    return-wide v0
.end method
