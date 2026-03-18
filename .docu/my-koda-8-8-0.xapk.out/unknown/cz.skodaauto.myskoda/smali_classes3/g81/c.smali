.class public final Lg81/c;
.super Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/StateMachine;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final d:Ljava/util/Set;


# instance fields
.field public final a:J

.field public b:Lt71/e;

.field public final c:Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineDefinition;


# direct methods
.method static constructor <clinit>()V
    .locals 19

    .line 1
    new-instance v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBTouchDiagnosisState;

    .line 2
    .line 3
    sget-object v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/data/MEBStateValues;->j:Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/data/MEBStateValues;

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    invoke-direct {v0, v2, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBTouchDiagnosisState;-><init>(ZLtechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/data/MEBStateValues;)V

    .line 7
    .line 8
    .line 9
    new-instance v3, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBDriveActivationState;

    .line 10
    .line 11
    invoke-direct {v3, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBDriveActivationState;-><init>(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/data/MEBStateValues;)V

    .line 12
    .line 13
    .line 14
    new-instance v4, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBScenarioSelectionState;

    .line 15
    .line 16
    invoke-direct {v4, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBScenarioSelectionState;-><init>(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/data/MEBStateValues;)V

    .line 17
    .line 18
    .line 19
    new-instance v5, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBDriveState;

    .line 20
    .line 21
    invoke-direct {v5, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBDriveState;-><init>(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/data/MEBStateValues;)V

    .line 22
    .line 23
    .line 24
    new-instance v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBParkingFinishedState;

    .line 25
    .line 26
    sget-object v6, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBParkingFinishedStateValues;->h:Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBParkingFinishedStateValues;

    .line 27
    .line 28
    sget-object v7, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingManeuverActiveStatusMEB;->PARKING_IN:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/ParkingManeuverActiveStatusMEB;

    .line 29
    .line 30
    const-string v8, "<this>"

    .line 31
    .line 32
    invoke-static {v7, v8}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 33
    .line 34
    .line 35
    sget-object v8, Lk81/b;->a:[I

    .line 36
    .line 37
    invoke-virtual {v7}, Ljava/lang/Enum;->ordinal()I

    .line 38
    .line 39
    .line 40
    move-result v7

    .line 41
    aget v7, v8, v7

    .line 42
    .line 43
    const/4 v8, 0x3

    .line 44
    const/4 v9, 0x2

    .line 45
    const/4 v10, 0x1

    .line 46
    if-eq v7, v10, :cond_2

    .line 47
    .line 48
    if-eq v7, v9, :cond_1

    .line 49
    .line 50
    if-ne v7, v8, :cond_0

    .line 51
    .line 52
    sget-object v7, Ls71/h;->f:Ls71/h;

    .line 53
    .line 54
    :goto_0
    move-object v12, v7

    .line 55
    goto :goto_1

    .line 56
    :cond_0
    new-instance v0, La8/r0;

    .line 57
    .line 58
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 59
    .line 60
    .line 61
    throw v0

    .line 62
    :cond_1
    sget-object v7, Ls71/h;->e:Ls71/h;

    .line 63
    .line 64
    goto :goto_0

    .line 65
    :cond_2
    sget-object v7, Ls71/h;->d:Ls71/h;

    .line 66
    .line 67
    goto :goto_0

    .line 68
    :goto_1
    iget-boolean v13, v6, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBParkingFinishedStateValues;->b:Z

    .line 69
    .line 70
    iget-object v14, v6, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBParkingFinishedStateValues;->c:Ljava/lang/Boolean;

    .line 71
    .line 72
    iget-object v15, v6, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBParkingFinishedStateValues;->d:Ljava/lang/Boolean;

    .line 73
    .line 74
    iget-object v7, v6, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBParkingFinishedStateValues;->e:Ljava/lang/Boolean;

    .line 75
    .line 76
    iget-object v11, v6, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBParkingFinishedStateValues;->f:Ljava/lang/Boolean;

    .line 77
    .line 78
    iget-object v6, v6, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBParkingFinishedStateValues;->g:Ljava/lang/Boolean;

    .line 79
    .line 80
    move-object/from16 v17, v11

    .line 81
    .line 82
    new-instance v11, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBParkingFinishedStateValues;

    .line 83
    .line 84
    move-object/from16 v18, v6

    .line 85
    .line 86
    move-object/from16 v16, v7

    .line 87
    .line 88
    invoke-direct/range {v11 .. v18}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBParkingFinishedStateValues;-><init>(Ls71/h;ZLjava/lang/Boolean;Ljava/lang/Boolean;Ljava/lang/Boolean;Ljava/lang/Boolean;Ljava/lang/Boolean;)V

    .line 89
    .line 90
    .line 91
    invoke-direct {v1, v11}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBParkingFinishedState;-><init>(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBParkingFinishedStateValues;)V

    .line 92
    .line 93
    .line 94
    new-instance v12, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBParkingFailedState;

    .line 95
    .line 96
    sget-object v13, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/StoppingReasonStatusMEB;->MALFUNCTION:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/StoppingReasonStatusMEB;

    .line 97
    .line 98
    const/16 v16, 0x2

    .line 99
    .line 100
    const/16 v17, 0x0

    .line 101
    .line 102
    const/4 v14, 0x0

    .line 103
    const/4 v15, 0x0

    .line 104
    invoke-direct/range {v12 .. v17}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBParkingFailedState;-><init>(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/meb/StoppingReasonStatusMEB;Ll71/c;Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/a;ILkotlin/jvm/internal/g;)V

    .line 105
    .line 106
    .line 107
    const/4 v6, 0x6

    .line 108
    new-array v6, v6, [Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/screen/MEBScreenState;

    .line 109
    .line 110
    aput-object v0, v6, v2

    .line 111
    .line 112
    aput-object v3, v6, v10

    .line 113
    .line 114
    aput-object v4, v6, v9

    .line 115
    .line 116
    aput-object v5, v6, v8

    .line 117
    .line 118
    const/4 v0, 0x4

    .line 119
    aput-object v1, v6, v0

    .line 120
    .line 121
    const/4 v0, 0x5

    .line 122
    aput-object v12, v6, v0

    .line 123
    .line 124
    invoke-static {v6}, Lmx0/n;->h0([Ljava/lang/Object;)Ljava/util/Set;

    .line 125
    .line 126
    .line 127
    move-result-object v0

    .line 128
    check-cast v0, Ljava/lang/Iterable;

    .line 129
    .line 130
    new-instance v1, Ljava/util/ArrayList;

    .line 131
    .line 132
    const/16 v2, 0xa

    .line 133
    .line 134
    invoke-static {v0, v2}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 135
    .line 136
    .line 137
    move-result v2

    .line 138
    invoke-direct {v1, v2}, Ljava/util/ArrayList;-><init>(I)V

    .line 139
    .line 140
    .line 141
    invoke-interface {v0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 142
    .line 143
    .line 144
    move-result-object v0

    .line 145
    :goto_2
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 146
    .line 147
    .line 148
    move-result v2

    .line 149
    if-eqz v2, :cond_3

    .line 150
    .line 151
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 152
    .line 153
    .line 154
    move-result-object v2

    .line 155
    check-cast v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/screen/MEBScreenState;

    .line 156
    .line 157
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 158
    .line 159
    .line 160
    move-result-object v2

    .line 161
    sget-object v3, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 162
    .line 163
    invoke-virtual {v3, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 164
    .line 165
    .line 166
    move-result-object v2

    .line 167
    invoke-virtual {v1, v2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 168
    .line 169
    .line 170
    goto :goto_2

    .line 171
    :cond_3
    invoke-static {v1}, Lmx0/q;->C0(Ljava/lang/Iterable;)Ljava/util/Set;

    .line 172
    .line 173
    .line 174
    move-result-object v0

    .line 175
    sput-object v0, Lg81/c;->d:Ljava/util/Set;

    .line 176
    .line 177
    return-void
.end method

.method public constructor <init>()V
    .locals 13

    .line 1
    new-instance v4, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBTouchDiagnosisState;

    .line 2
    .line 3
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/data/MEBStateValues;->j:Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/data/MEBStateValues;

    .line 4
    .line 5
    const/4 v1, 0x0

    .line 6
    invoke-direct {v4, v1, v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBTouchDiagnosisState;-><init>(ZLtechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/data/MEBStateValues;)V

    .line 7
    .line 8
    .line 9
    invoke-direct {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/StateMachine;-><init>()V

    .line 10
    .line 11
    .line 12
    sget-wide v2, Li81/b;->d:J

    .line 13
    .line 14
    iput-wide v2, p0, Lg81/c;->a:J

    .line 15
    .line 16
    sget-object v0, Lt71/e;->d:Lt71/e;

    .line 17
    .line 18
    iput-object v0, p0, Lg81/c;->b:Lt71/e;

    .line 19
    .line 20
    new-instance v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineDefinition;

    .line 21
    .line 22
    sget-object v2, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 23
    .line 24
    const-class v3, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/MessageReceivedInput;

    .line 25
    .line 26
    invoke-virtual {v2, v3}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 27
    .line 28
    .line 29
    move-result-object v3

    .line 30
    const-class v5, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/MessageSentInput;

    .line 31
    .line 32
    invoke-virtual {v2, v5}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 33
    .line 34
    .line 35
    move-result-object v5

    .line 36
    const-class v6, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/TimeElapsedInput;

    .line 37
    .line 38
    invoke-virtual {v2, v6}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 39
    .line 40
    .line 41
    move-result-object v6

    .line 42
    const-class v7, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/SafetyInstructionInput;

    .line 43
    .line 44
    invoke-virtual {v2, v7}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 45
    .line 46
    .line 47
    move-result-object v7

    .line 48
    const/4 v8, 0x4

    .line 49
    new-array v8, v8, [Lhy0/d;

    .line 50
    .line 51
    aput-object v3, v8, v1

    .line 52
    .line 53
    const/4 v1, 0x1

    .line 54
    aput-object v5, v8, v1

    .line 55
    .line 56
    const/4 v1, 0x2

    .line 57
    aput-object v6, v8, v1

    .line 58
    .line 59
    const/4 v1, 0x3

    .line 60
    aput-object v7, v8, v1

    .line 61
    .line 62
    invoke-static {v8}, Lmx0/n;->h0([Ljava/lang/Object;)Ljava/util/Set;

    .line 63
    .line 64
    .line 65
    move-result-object v1

    .line 66
    new-instance v3, Lei/a;

    .line 67
    .line 68
    const/4 v11, 0x0

    .line 69
    const/16 v12, 0x11

    .line 70
    .line 71
    const/4 v6, 0x1

    .line 72
    const-class v8, Lg81/c;

    .line 73
    .line 74
    const-string v9, "processNewlyProvidedStateMachineInput"

    .line 75
    .line 76
    const-string v10, "processNewlyProvidedStateMachineInput(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineInput;)Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/screen/MEBScreenState;"

    .line 77
    .line 78
    move-object v7, p0

    .line 79
    move-object v5, v3

    .line 80
    invoke-direct/range {v5 .. v12}, Lei/a;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 81
    .line 82
    .line 83
    const-class p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/MEBParkingFailedState;

    .line 84
    .line 85
    invoke-virtual {v2, p0}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 86
    .line 87
    .line 88
    move-result-object p0

    .line 89
    invoke-static {p0}, Ljp/m1;->k(Ljava/lang/Object;)Ljava/util/Set;

    .line 90
    .line 91
    .line 92
    move-result-object v5

    .line 93
    move-object v2, v1

    .line 94
    sget-object v1, Lg81/c;->d:Ljava/util/Set;

    .line 95
    .line 96
    invoke-direct/range {v0 .. v5}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineDefinition;-><init>(Ljava/util/Set;Ljava/util/Set;Lay0/k;Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineState;Ljava/util/Set;)V

    .line 97
    .line 98
    .line 99
    iput-object v0, v7, Lg81/c;->c:Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineDefinition;

    .line 100
    .line 101
    return-void
.end method


# virtual methods
.method public final getDefinition$remoteparkassistcoremeb_release()Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineDefinition;
    .locals 0

    .line 1
    iget-object p0, p0, Lg81/c;->c:Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineDefinition;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getTickInterval-UwyO8pc$remoteparkassistcoremeb_release()J
    .locals 2

    .line 1
    iget-wide v0, p0, Lg81/c;->a:J

    .line 2
    .line 3
    return-wide v0
.end method
