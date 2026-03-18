.class public final Ls81/b;
.super Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/StateMachine;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final d:Ljava/util/Set;

.field public static final e:Ljava/util/Set;


# instance fields
.field public final a:J

.field public b:Z

.field public final c:Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineDefinition;


# direct methods
.method static constructor <clinit>()V
    .locals 16

    .line 1
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/data/PPEStateValues;->l:Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/data/PPEStateValues;

    .line 2
    .line 3
    new-instance v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPETouchDiagnosisState;

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    invoke-direct {v1, v0, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPETouchDiagnosisState;-><init>(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/data/PPEStateValues;Z)V

    .line 7
    .line 8
    .line 9
    new-instance v3, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEDriveActivationState;

    .line 10
    .line 11
    invoke-direct {v3, v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEDriveActivationState;-><init>(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/data/PPEStateValues;)V

    .line 12
    .line 13
    .line 14
    new-instance v4, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEScenarioSelectionState;

    .line 15
    .line 16
    sget-object v5, Ls71/k;->e:Ls71/k;

    .line 17
    .line 18
    invoke-static {v5}, Ljp/m1;->k(Ljava/lang/Object;)Ljava/util/Set;

    .line 19
    .line 20
    .line 21
    move-result-object v5

    .line 22
    invoke-direct {v4, v0, v5}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEScenarioSelectionState;-><init>(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/data/PPEStateValues;Ljava/util/Set;)V

    .line 23
    .line 24
    .line 25
    new-instance v5, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEDriveState;

    .line 26
    .line 27
    invoke-direct {v5, v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEDriveState;-><init>(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/data/PPEStateValues;)V

    .line 28
    .line 29
    .line 30
    new-instance v6, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEDriveCorrectionState;

    .line 31
    .line 32
    invoke-direct {v6, v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEDriveCorrectionState;-><init>(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/data/PPEStateValues;)V

    .line 33
    .line 34
    .line 35
    new-instance v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEParkingFinishedState;

    .line 36
    .line 37
    sget-object v7, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEParkingFinishedStateValues;->m:Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEParkingFinishedStateValues;

    .line 38
    .line 39
    sget-object v8, Ls71/h;->e:Ls71/h;

    .line 40
    .line 41
    invoke-static {v7, v8}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEParkingFinishedStateValues;->c(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEParkingFinishedStateValues;Ls71/h;)Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEParkingFinishedStateValues;

    .line 42
    .line 43
    .line 44
    move-result-object v8

    .line 45
    invoke-direct {v0, v8}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEParkingFinishedState;-><init>(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEParkingFinishedStateValues;)V

    .line 46
    .line 47
    .line 48
    new-instance v8, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEParkingFinishedState;

    .line 49
    .line 50
    sget-object v9, Ls71/h;->f:Ls71/h;

    .line 51
    .line 52
    invoke-static {v7, v9}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEParkingFinishedStateValues;->c(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEParkingFinishedStateValues;Ls71/h;)Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEParkingFinishedStateValues;

    .line 53
    .line 54
    .line 55
    move-result-object v7

    .line 56
    invoke-direct {v8, v7}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEParkingFinishedState;-><init>(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEParkingFinishedStateValues;)V

    .line 57
    .line 58
    .line 59
    new-instance v9, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEParkingFailedState;

    .line 60
    .line 61
    sget-object v13, Lw81/a;->d:Lw81/a;

    .line 62
    .line 63
    const/4 v14, 0x7

    .line 64
    const/4 v15, 0x0

    .line 65
    const/4 v10, 0x0

    .line 66
    const/4 v11, 0x0

    .line 67
    const/4 v12, 0x0

    .line 68
    invoke-direct/range {v9 .. v15}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEParkingFailedState;-><init>(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/StoppingReasonStatusPPE;Ll71/c;ZLw81/a;ILkotlin/jvm/internal/g;)V

    .line 69
    .line 70
    .line 71
    const/16 v7, 0x8

    .line 72
    .line 73
    new-array v7, v7, [Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/screen/PPEScreenState;

    .line 74
    .line 75
    aput-object v1, v7, v2

    .line 76
    .line 77
    const/4 v1, 0x1

    .line 78
    aput-object v3, v7, v1

    .line 79
    .line 80
    const/4 v1, 0x2

    .line 81
    aput-object v4, v7, v1

    .line 82
    .line 83
    const/4 v1, 0x3

    .line 84
    aput-object v5, v7, v1

    .line 85
    .line 86
    const/4 v1, 0x4

    .line 87
    aput-object v6, v7, v1

    .line 88
    .line 89
    const/4 v1, 0x5

    .line 90
    aput-object v0, v7, v1

    .line 91
    .line 92
    const/4 v0, 0x6

    .line 93
    aput-object v8, v7, v0

    .line 94
    .line 95
    const/4 v0, 0x7

    .line 96
    aput-object v9, v7, v0

    .line 97
    .line 98
    invoke-static {v7}, Lmx0/n;->h0([Ljava/lang/Object;)Ljava/util/Set;

    .line 99
    .line 100
    .line 101
    move-result-object v0

    .line 102
    sput-object v0, Ls81/b;->d:Ljava/util/Set;

    .line 103
    .line 104
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/FunctionStatusPPE;->FINISHED:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/FunctionStatusPPE;

    .line 105
    .line 106
    sget-object v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/FunctionStatusPPE;->CLAMP_OFF:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/FunctionStatusPPE;

    .line 107
    .line 108
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/FunctionStatusPPE;->NOT_ACTIVE:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/FunctionStatusPPE;

    .line 109
    .line 110
    filled-new-array {v0, v1, v2}, [Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/FunctionStatusPPE;

    .line 111
    .line 112
    .line 113
    move-result-object v0

    .line 114
    invoke-static {v0}, Lmx0/n;->h0([Ljava/lang/Object;)Ljava/util/Set;

    .line 115
    .line 116
    .line 117
    move-result-object v0

    .line 118
    sput-object v0, Ls81/b;->e:Ljava/util/Set;

    .line 119
    .line 120
    return-void
.end method

.method public constructor <init>()V
    .locals 16

    .line 1
    move-object/from16 v2, p0

    .line 2
    .line 3
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/data/PPEStateValues;->l:Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/data/PPEStateValues;

    .line 4
    .line 5
    new-instance v8, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPETouchDiagnosisState;

    .line 6
    .line 7
    const/4 v9, 0x0

    .line 8
    invoke-direct {v8, v0, v9}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPETouchDiagnosisState;-><init>(Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/data/PPEStateValues;Z)V

    .line 9
    .line 10
    .line 11
    invoke-direct {v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/StateMachine;-><init>()V

    .line 12
    .line 13
    .line 14
    sget-wide v0, Lu81/b;->e:J

    .line 15
    .line 16
    iput-wide v0, v2, Ls81/b;->a:J

    .line 17
    .line 18
    sget-object v0, Ls81/b;->d:Ljava/util/Set;

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
    check-cast v3, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/screen/PPEScreenState;

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
    new-instance v0, Ls60/h;

    .line 105
    .line 106
    const/4 v6, 0x0

    .line 107
    const/16 v7, 0xd

    .line 108
    .line 109
    const/4 v1, 0x1

    .line 110
    const-class v3, Ls81/b;

    .line 111
    .line 112
    const-string v4, "processNewlyProvidedStateMachineInput"

    .line 113
    .line 114
    const-string v5, "processNewlyProvidedStateMachineInput(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineInput;)Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/screen/PPEScreenState;"

    .line 115
    .line 116
    invoke-direct/range {v0 .. v7}, Ls60/h;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 117
    .line 118
    .line 119
    move-object v4, v0

    .line 120
    move-object v0, v2

    .line 121
    const-class v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEParkingFinishedState;

    .line 122
    .line 123
    invoke-virtual {v12, v1}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 124
    .line 125
    .line 126
    move-result-object v1

    .line 127
    const-class v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/state/PPEParkingFailedState;

    .line 128
    .line 129
    invoke-virtual {v12, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 130
    .line 131
    .line 132
    move-result-object v2

    .line 133
    new-array v3, v14, [Lhy0/d;

    .line 134
    .line 135
    aput-object v1, v3, v9

    .line 136
    .line 137
    aput-object v2, v3, v13

    .line 138
    .line 139
    invoke-static {v3}, Lmx0/n;->h0([Ljava/lang/Object;)Ljava/util/Set;

    .line 140
    .line 141
    .line 142
    move-result-object v6

    .line 143
    move-object v5, v8

    .line 144
    move-object v2, v10

    .line 145
    move-object v1, v11

    .line 146
    move-object v3, v15

    .line 147
    invoke-direct/range {v1 .. v6}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineDefinition;-><init>(Ljava/util/Set;Ljava/util/Set;Lay0/k;Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineState;Ljava/util/Set;)V

    .line 148
    .line 149
    .line 150
    iput-object v1, v0, Ls81/b;->c:Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineDefinition;

    .line 151
    .line 152
    return-void
.end method


# virtual methods
.method public final getDefinition$remoteparkassistcoremeb_release()Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineDefinition;
    .locals 0

    .line 1
    iget-object p0, p0, Ls81/b;->c:Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineDefinition;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getTickInterval-UwyO8pc$remoteparkassistcoremeb_release()J
    .locals 2

    .line 1
    iget-wide v0, p0, Ls81/b;->a:J

    .line 2
    .line 3
    return-wide v0
.end method
