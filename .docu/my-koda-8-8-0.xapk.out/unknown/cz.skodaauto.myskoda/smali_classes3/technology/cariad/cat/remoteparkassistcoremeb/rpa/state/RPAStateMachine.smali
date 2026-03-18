.class public final Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/state/RPAStateMachine;
.super Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/StateMachine;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000(\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0006\n\u0002\u0018\u0002\n\u0002\u0008\u0004\n\u0002\u0018\u0002\n\u0002\u0008\u0007\n\u0002\u0018\u0002\n\u0002\u0008\u0004\u0008\u0000\u0018\u00002\u00020\u0001B\u0011\u0012\u0008\u0008\u0002\u0010\u0003\u001a\u00020\u0002\u00a2\u0006\u0004\u0008\u0004\u0010\u0005J\u0019\u0010\u0007\u001a\u0004\u0018\u00010\u00022\u0006\u0010\u0006\u001a\u00020\u0002H\u0002\u00a2\u0006\u0004\u0008\u0007\u0010\u0008R\u001a\u0010\n\u001a\u00020\t8\u0010X\u0090\u0004\u00a2\u0006\u000c\n\u0004\u0008\n\u0010\u000b\u001a\u0004\u0008\u000c\u0010\rR\u001a\u0010\u000f\u001a\u00020\u000e8\u0010X\u0090\u0004\u00a2\u0006\u000c\n\u0004\u0008\u000f\u0010\u0010\u001a\u0004\u0008\u0011\u0010\u0012R\u0016\u0010\u0015\u001a\u0004\u0018\u00010\u00028@X\u0080\u0004\u00a2\u0006\u0006\u001a\u0004\u0008\u0013\u0010\u0014R\u0016\u0010\u0019\u001a\u0004\u0018\u00010\u00168@X\u0080\u0004\u00a2\u0006\u0006\u001a\u0004\u0008\u0017\u0010\u0018\u00a8\u0006\u001a"
    }
    d2 = {
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/state/RPAStateMachine;",
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/StateMachine;",
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/ScreenStateMachineState;",
        "initialState",
        "<init>",
        "(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/ScreenStateMachineState;)V",
        "screenState",
        "showIfNotAlreadyShown",
        "(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/ScreenStateMachineState;)Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/ScreenStateMachineState;",
        "Lmy0/c;",
        "tickInterval",
        "J",
        "getTickInterval-UwyO8pc$remoteparkassistcoremeb_release",
        "()J",
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineDefinition;",
        "definition",
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineDefinition;",
        "getDefinition$remoteparkassistcoremeb_release",
        "()Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineDefinition;",
        "getCurrentScreenState$remoteparkassistcoremeb_release",
        "()Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/ScreenStateMachineState;",
        "currentScreenState",
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/SubScreenStateMachineState;",
        "getCurrentSubScreenState$remoteparkassistcoremeb_release",
        "()Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/SubScreenStateMachineState;",
        "currentSubScreenState",
        "remoteparkassistcoremeb_release"
    }
    k = 0x1
    mv = {
        0x2,
        0x2,
        0x0
    }
    xi = 0x30
.end annotation


# instance fields
.field private final definition:Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineDefinition;

.field private final tickInterval:J


# direct methods
.method public constructor <init>()V
    .locals 2

    .line 1
    const/4 v0, 0x0

    const/4 v1, 0x1

    invoke-direct {p0, v0, v1, v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/state/RPAStateMachine;-><init>(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/ScreenStateMachineState;ILkotlin/jvm/internal/g;)V

    return-void
.end method

.method public constructor <init>(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/ScreenStateMachineState;)V
    .locals 17

    move-object/from16 v0, p0

    const-string v1, "initialState"

    move-object/from16 v6, p1

    invoke-static {v6, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 2
    invoke-direct {v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/StateMachine;-><init>()V

    .line 3
    sget-wide v1, La81/a;->a:J

    .line 4
    iput-wide v1, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/state/RPAStateMachine;->tickInterval:J

    .line 5
    new-instance v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineDefinition;

    .line 6
    sget-object v1, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    const-class v3, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/state/ConnectionEstablishmentState;

    invoke-virtual {v1, v3}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    move-result-object v3

    .line 7
    const-class v4, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/MEBParkingState;

    .line 8
    invoke-virtual {v1, v4}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    move-result-object v4

    .line 9
    const-class v5, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/MLBParkingState;

    .line 10
    invoke-virtual {v1, v5}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    move-result-object v5

    .line 11
    const-class v7, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/PPEParkingState;

    .line 12
    invoke-virtual {v1, v7}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    move-result-object v7

    .line 13
    const-class v8, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/state/ConnectionFailedState;

    .line 14
    invoke-virtual {v1, v8}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    move-result-object v8

    const-class v9, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StoppedState;

    invoke-virtual {v1, v9}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    move-result-object v10

    const/4 v11, 0x6

    .line 15
    new-array v11, v11, [Lhy0/d;

    const/4 v12, 0x0

    aput-object v3, v11, v12

    const/4 v3, 0x1

    aput-object v4, v11, v3

    const/4 v4, 0x2

    aput-object v5, v11, v4

    const/4 v5, 0x3

    aput-object v7, v11, v5

    const/4 v7, 0x4

    aput-object v8, v11, v7

    const/4 v8, 0x5

    aput-object v10, v11, v8

    .line 16
    invoke-static {v11}, Lmx0/n;->h0([Ljava/lang/Object;)Ljava/util/Set;

    move-result-object v10

    .line 17
    const-class v11, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/MessageReceivedInput;

    .line 18
    invoke-virtual {v1, v11}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    move-result-object v11

    .line 19
    const-class v13, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/MessageSentInput;

    .line 20
    invoke-virtual {v1, v13}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    move-result-object v13

    .line 21
    const-class v14, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/ConnectionChangedInput;

    .line 22
    invoke-virtual {v1, v14}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    move-result-object v14

    .line 23
    const-class v15, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/TimeElapsedInput;

    .line 24
    invoke-virtual {v1, v15}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    move-result-object v15

    move/from16 v16, v3

    .line 25
    const-class v3, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/SafetyInstructionInput;

    .line 26
    invoke-virtual {v1, v3}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    move-result-object v3

    .line 27
    new-array v8, v8, [Lhy0/d;

    aput-object v11, v8, v12

    aput-object v13, v8, v16

    aput-object v14, v8, v4

    aput-object v15, v8, v5

    aput-object v3, v8, v7

    .line 28
    invoke-static {v8}, Lmx0/n;->h0([Ljava/lang/Object;)Ljava/util/Set;

    move-result-object v4

    .line 29
    new-instance v5, La2/e;

    const/16 v3, 0x13

    invoke-direct {v5, v0, v3}, La2/e;-><init>(Ljava/lang/Object;I)V

    .line 30
    invoke-virtual {v1, v9}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    move-result-object v1

    .line 31
    invoke-static {v1}, Ljp/m1;->k(Ljava/lang/Object;)Ljava/util/Set;

    move-result-object v7

    move-object v3, v10

    .line 32
    invoke-direct/range {v2 .. v7}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineDefinition;-><init>(Ljava/util/Set;Ljava/util/Set;Lay0/k;Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineState;Ljava/util/Set;)V

    iput-object v2, v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/state/RPAStateMachine;->definition:Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineDefinition;

    return-void
.end method

.method public synthetic constructor <init>(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/ScreenStateMachineState;ILkotlin/jvm/internal/g;)V
    .locals 0

    and-int/lit8 p2, p2, 0x1

    if-eqz p2, :cond_0

    .line 33
    new-instance p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/state/ConnectionEstablishmentState;

    invoke-direct {p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/state/ConnectionEstablishmentState;-><init>()V

    .line 34
    :cond_0
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/state/RPAStateMachine;-><init>(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/ScreenStateMachineState;)V

    return-void
.end method

.method public static synthetic b(Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/state/RPAStateMachine;Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineInput;)Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineState;
    .locals 0

    .line 1
    invoke-static {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/state/RPAStateMachine;->definition$lambda$0(Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/state/RPAStateMachine;Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineInput;)Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineState;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method private static final definition$lambda$0(Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/state/RPAStateMachine;Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineInput;)Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineState;
    .locals 6

    .line 1
    const-string v0, "input"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    instance-of v0, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/MessageSentInput;

    .line 7
    .line 8
    const/4 v1, 0x0

    .line 9
    if-eqz v0, :cond_1

    .line 10
    .line 11
    check-cast p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/MessageSentInput;

    .line 12
    .line 13
    invoke-static {p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/util/StateMachineMessageSentInputExtensionsKt;->getUserAction(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/MessageSentInput;)Ls71/q;

    .line 14
    .line 15
    .line 16
    move-result-object p1

    .line 17
    sget-object v0, Ls71/p;->f:Ls71/p;

    .line 18
    .line 19
    if-ne p1, v0, :cond_0

    .line 20
    .line 21
    new-instance p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StoppedState;

    .line 22
    .line 23
    invoke-direct {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StoppedState;-><init>()V

    .line 24
    .line 25
    .line 26
    return-object p0

    .line 27
    :cond_0
    sget-object v0, Ls71/p;->D:Ls71/p;

    .line 28
    .line 29
    if-ne p1, v0, :cond_14

    .line 30
    .line 31
    new-instance p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/state/ConnectionEstablishmentState;

    .line 32
    .line 33
    invoke-direct {p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/state/ConnectionEstablishmentState;-><init>()V

    .line 34
    .line 35
    .line 36
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/state/RPAStateMachine;->showIfNotAlreadyShown(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/ScreenStateMachineState;)Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/ScreenStateMachineState;

    .line 37
    .line 38
    .line 39
    move-result-object p0

    .line 40
    return-object p0

    .line 41
    :cond_1
    instance-of v0, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/ConnectionChangedInput;

    .line 42
    .line 43
    if-eqz v0, :cond_d

    .line 44
    .line 45
    check-cast p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/ConnectionChangedInput;

    .line 46
    .line 47
    invoke-static {p1}, Ljp/xf;->a(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/ConnectionChangedInput;)Lt71/c;

    .line 48
    .line 49
    .line 50
    move-result-object v0

    .line 51
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/status/ConnectionErrorStatus$ConnectionLostError;->INSTANCE:Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/status/ConnectionErrorStatus$ConnectionLostError;

    .line 52
    .line 53
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 54
    .line 55
    .line 56
    move-result v2

    .line 57
    const/4 v3, 0x0

    .line 58
    const/4 v4, 0x1

    .line 59
    if-nez v2, :cond_b

    .line 60
    .line 61
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/status/ConnectionErrorStatus$ConnectionEstablishmentError;->INSTANCE:Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/status/ConnectionErrorStatus$ConnectionEstablishmentError;

    .line 62
    .line 63
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 64
    .line 65
    .line 66
    move-result v0

    .line 67
    if-eqz v0, :cond_2

    .line 68
    .line 69
    goto/16 :goto_3

    .line 70
    .line 71
    :cond_2
    invoke-virtual {p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/ConnectionChangedInput;->getData()Ljava/lang/Object;

    .line 72
    .line 73
    .line 74
    move-result-object v0

    .line 75
    instance-of v2, v0, Lk71/b;

    .line 76
    .line 77
    if-eqz v2, :cond_3

    .line 78
    .line 79
    check-cast v0, Lk71/b;

    .line 80
    .line 81
    goto :goto_0

    .line 82
    :cond_3
    move-object v0, v1

    .line 83
    :goto_0
    if-eqz v0, :cond_4

    .line 84
    .line 85
    iget-object v0, v0, Lk71/b;->b:Lk71/c;

    .line 86
    .line 87
    goto :goto_1

    .line 88
    :cond_4
    move-object v0, v1

    .line 89
    :goto_1
    const/4 v2, -0x1

    .line 90
    if-nez v0, :cond_5

    .line 91
    .line 92
    move v0, v2

    .line 93
    goto :goto_2

    .line 94
    :cond_5
    sget-object v5, Ld81/b;->a:[I

    .line 95
    .line 96
    invoke-virtual {v0}, Ljava/lang/Enum;->ordinal()I

    .line 97
    .line 98
    .line 99
    move-result v0

    .line 100
    aget v0, v5, v0

    .line 101
    .line 102
    :goto_2
    if-eq v0, v2, :cond_14

    .line 103
    .line 104
    if-eq v0, v4, :cond_a

    .line 105
    .line 106
    const/4 v2, 0x2

    .line 107
    if-eq v0, v2, :cond_9

    .line 108
    .line 109
    const/4 v2, 0x3

    .line 110
    if-ne v0, v2, :cond_8

    .line 111
    .line 112
    invoke-static {p1}, Ljp/xf;->a(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/ConnectionChangedInput;)Lt71/c;

    .line 113
    .line 114
    .line 115
    move-result-object v0

    .line 116
    if-nez v0, :cond_6

    .line 117
    .line 118
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/status/ConnectionErrorStatus$NoError;->INSTANCE:Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/status/ConnectionErrorStatus$NoError;

    .line 119
    .line 120
    :cond_6
    sget-object v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/status/ConnectionErrorStatus$NoError;->INSTANCE:Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/status/ConnectionErrorStatus$NoError;

    .line 121
    .line 122
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 123
    .line 124
    .line 125
    move-result v2

    .line 126
    if-nez v2, :cond_14

    .line 127
    .line 128
    new-instance v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/state/ConnectionFailedState;

    .line 129
    .line 130
    invoke-static {p1}, Ljp/xf;->c(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/ConnectionChangedInput;)Ljava/lang/Boolean;

    .line 131
    .line 132
    .line 133
    move-result-object v2

    .line 134
    sget-object v5, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 135
    .line 136
    invoke-static {v2, v5}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 137
    .line 138
    .line 139
    move-result v2

    .line 140
    if-eqz v2, :cond_7

    .line 141
    .line 142
    invoke-static {p1}, Ljp/xf;->b(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/ConnectionChangedInput;)Ljava/lang/Boolean;

    .line 143
    .line 144
    .line 145
    move-result-object p1

    .line 146
    invoke-static {p1, v5}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 147
    .line 148
    .line 149
    move-result p1

    .line 150
    if-eqz p1, :cond_7

    .line 151
    .line 152
    move v3, v4

    .line 153
    :cond_7
    invoke-direct {v1, v3, v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/state/ConnectionFailedState;-><init>(ZLt71/c;)V

    .line 154
    .line 155
    .line 156
    invoke-direct {p0, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/state/RPAStateMachine;->showIfNotAlreadyShown(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/ScreenStateMachineState;)Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/ScreenStateMachineState;

    .line 157
    .line 158
    .line 159
    move-result-object p0

    .line 160
    return-object p0

    .line 161
    :cond_8
    new-instance p0, La8/r0;

    .line 162
    .line 163
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 164
    .line 165
    .line 166
    throw p0

    .line 167
    :cond_9
    invoke-virtual {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/StateMachine;->getCurrentState()Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineState;

    .line 168
    .line 169
    .line 170
    move-result-object p1

    .line 171
    instance-of p1, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/MEBParkingState;

    .line 172
    .line 173
    if-nez p1, :cond_14

    .line 174
    .line 175
    invoke-virtual {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/StateMachine;->getCurrentState()Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineState;

    .line 176
    .line 177
    .line 178
    move-result-object p1

    .line 179
    instance-of p1, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/MLBParkingState;

    .line 180
    .line 181
    if-nez p1, :cond_14

    .line 182
    .line 183
    invoke-virtual {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/StateMachine;->getCurrentState()Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineState;

    .line 184
    .line 185
    .line 186
    move-result-object p1

    .line 187
    instance-of p1, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/PPEParkingState;

    .line 188
    .line 189
    if-nez p1, :cond_14

    .line 190
    .line 191
    new-instance p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/state/ConnectionEstablishmentState;

    .line 192
    .line 193
    invoke-direct {p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/state/ConnectionEstablishmentState;-><init>()V

    .line 194
    .line 195
    .line 196
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/state/RPAStateMachine;->showIfNotAlreadyShown(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/ScreenStateMachineState;)Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/ScreenStateMachineState;

    .line 197
    .line 198
    .line 199
    move-result-object p0

    .line 200
    return-object p0

    .line 201
    :cond_a
    new-instance p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/state/ConnectionEstablishmentState;

    .line 202
    .line 203
    invoke-direct {p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/state/ConnectionEstablishmentState;-><init>()V

    .line 204
    .line 205
    .line 206
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/state/RPAStateMachine;->showIfNotAlreadyShown(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/ScreenStateMachineState;)Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/ScreenStateMachineState;

    .line 207
    .line 208
    .line 209
    move-result-object p0

    .line 210
    return-object p0

    .line 211
    :cond_b
    :goto_3
    new-instance v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/state/ConnectionFailedState;

    .line 212
    .line 213
    invoke-static {p1}, Ljp/xf;->c(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/ConnectionChangedInput;)Ljava/lang/Boolean;

    .line 214
    .line 215
    .line 216
    move-result-object v1

    .line 217
    sget-object v2, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 218
    .line 219
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 220
    .line 221
    .line 222
    move-result v1

    .line 223
    if-eqz v1, :cond_c

    .line 224
    .line 225
    invoke-static {p1}, Ljp/xf;->b(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/ConnectionChangedInput;)Ljava/lang/Boolean;

    .line 226
    .line 227
    .line 228
    move-result-object p1

    .line 229
    invoke-static {p1, v2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 230
    .line 231
    .line 232
    move-result p1

    .line 233
    if-eqz p1, :cond_c

    .line 234
    .line 235
    move v3, v4

    .line 236
    :cond_c
    sget-object p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/status/ConnectionErrorStatus$ConnectionEstablishmentError;->INSTANCE:Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/status/ConnectionErrorStatus$ConnectionEstablishmentError;

    .line 237
    .line 238
    invoke-direct {v0, v3, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/state/ConnectionFailedState;-><init>(ZLt71/c;)V

    .line 239
    .line 240
    .line 241
    invoke-direct {p0, v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/state/RPAStateMachine;->showIfNotAlreadyShown(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/ScreenStateMachineState;)Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/ScreenStateMachineState;

    .line 242
    .line 243
    .line 244
    move-result-object p0

    .line 245
    return-object p0

    .line 246
    :cond_d
    instance-of v0, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/MessageReceivedInput;

    .line 247
    .line 248
    if-eqz v0, :cond_14

    .line 249
    .line 250
    check-cast p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/MessageReceivedInput;

    .line 251
    .line 252
    invoke-virtual {p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/MessageReceivedInput;->getData()Ljava/lang/Object;

    .line 253
    .line 254
    .line 255
    move-result-object p1

    .line 256
    instance-of v0, p1, Ll71/v;

    .line 257
    .line 258
    if-eqz v0, :cond_e

    .line 259
    .line 260
    check-cast p1, Ll71/v;

    .line 261
    .line 262
    goto :goto_4

    .line 263
    :cond_e
    move-object p1, v1

    .line 264
    :goto_4
    if-eqz p1, :cond_f

    .line 265
    .line 266
    iget-object p1, p1, Ll71/v;->a:Ll71/u;

    .line 267
    .line 268
    goto :goto_5

    .line 269
    :cond_f
    move-object p1, v1

    .line 270
    :goto_5
    instance-of v0, p1, Ll71/g;

    .line 271
    .line 272
    if-eqz v0, :cond_10

    .line 273
    .line 274
    new-instance p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/MEBParkingState;

    .line 275
    .line 276
    invoke-direct {p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/MEBParkingState;-><init>()V

    .line 277
    .line 278
    .line 279
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/state/RPAStateMachine;->showIfNotAlreadyShown(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/ScreenStateMachineState;)Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/ScreenStateMachineState;

    .line 280
    .line 281
    .line 282
    move-result-object p0

    .line 283
    return-object p0

    .line 284
    :cond_10
    instance-of v0, p1, Ll71/l;

    .line 285
    .line 286
    if-eqz v0, :cond_11

    .line 287
    .line 288
    new-instance p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/MLBParkingState;

    .line 289
    .line 290
    invoke-direct {p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/MLBParkingState;-><init>()V

    .line 291
    .line 292
    .line 293
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/state/RPAStateMachine;->showIfNotAlreadyShown(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/ScreenStateMachineState;)Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/ScreenStateMachineState;

    .line 294
    .line 295
    .line 296
    move-result-object p0

    .line 297
    return-object p0

    .line 298
    :cond_11
    instance-of v0, p1, Ll71/t;

    .line 299
    .line 300
    if-eqz v0, :cond_12

    .line 301
    .line 302
    new-instance p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/PPEParkingState;

    .line 303
    .line 304
    invoke-direct {p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/PPEParkingState;-><init>()V

    .line 305
    .line 306
    .line 307
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/state/RPAStateMachine;->showIfNotAlreadyShown(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/ScreenStateMachineState;)Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/ScreenStateMachineState;

    .line 308
    .line 309
    .line 310
    move-result-object p0

    .line 311
    return-object p0

    .line 312
    :cond_12
    instance-of p0, p1, Ll71/m;

    .line 313
    .line 314
    if-nez p0, :cond_14

    .line 315
    .line 316
    instance-of p0, p1, Ll71/n;

    .line 317
    .line 318
    if-nez p0, :cond_14

    .line 319
    .line 320
    if-nez p1, :cond_13

    .line 321
    .line 322
    goto :goto_6

    .line 323
    :cond_13
    new-instance p0, La8/r0;

    .line 324
    .line 325
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 326
    .line 327
    .line 328
    throw p0

    .line 329
    :cond_14
    :goto_6
    return-object v1
.end method

.method private final showIfNotAlreadyShown(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/ScreenStateMachineState;)Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/ScreenStateMachineState;
    .locals 1

    .line 1
    invoke-virtual {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/StateMachine;->getCurrentState()Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineState;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 10
    .line 11
    .line 12
    move-result-object v0

    .line 13
    if-eq p0, v0, :cond_0

    .line 14
    .line 15
    return-object p1

    .line 16
    :cond_0
    const/4 p0, 0x0

    .line 17
    return-object p0
.end method


# virtual methods
.method public final getCurrentScreenState$remoteparkassistcoremeb_release()Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/ScreenStateMachineState;
    .locals 2

    .line 1
    invoke-virtual {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/StateMachine;->getCurrentState()Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineState;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    instance-of v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/state/ConnectionFailedState;

    .line 6
    .line 7
    const/4 v1, 0x0

    .line 8
    if-nez v0, :cond_3

    .line 9
    .line 10
    instance-of v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/state/ConnectionEstablishmentState;

    .line 11
    .line 12
    if-eqz v0, :cond_0

    .line 13
    .line 14
    goto :goto_1

    .line 15
    :cond_0
    instance-of v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/MEBParkingState;

    .line 16
    .line 17
    if-nez v0, :cond_2

    .line 18
    .line 19
    instance-of v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/MLBParkingState;

    .line 20
    .line 21
    if-nez v0, :cond_2

    .line 22
    .line 23
    instance-of v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/ppe/PPEParkingState;

    .line 24
    .line 25
    if-eqz v0, :cond_1

    .line 26
    .line 27
    goto :goto_0

    .line 28
    :cond_1
    move-object p0, v1

    .line 29
    goto :goto_1

    .line 30
    :cond_2
    :goto_0
    invoke-virtual {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineState;->getStateMachine()Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/StateMachine;

    .line 31
    .line 32
    .line 33
    move-result-object p0

    .line 34
    if-eqz p0, :cond_1

    .line 35
    .line 36
    invoke-virtual {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/StateMachine;->getCurrentState()Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineState;

    .line 37
    .line 38
    .line 39
    move-result-object p0

    .line 40
    :cond_3
    :goto_1
    if-eqz p0, :cond_4

    .line 41
    .line 42
    check-cast p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/ScreenStateMachineState;

    .line 43
    .line 44
    return-object p0

    .line 45
    :cond_4
    return-object v1
.end method

.method public final getCurrentSubScreenState$remoteparkassistcoremeb_release()Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/SubScreenStateMachineState;
    .locals 0

    .line 1
    invoke-virtual {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/state/RPAStateMachine;->getCurrentScreenState$remoteparkassistcoremeb_release()Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/ScreenStateMachineState;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    if-eqz p0, :cond_0

    .line 6
    .line 7
    invoke-virtual {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineState;->getStateMachine()Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/StateMachine;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    if-eqz p0, :cond_0

    .line 12
    .line 13
    invoke-virtual {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/StateMachine;->getCurrentState()Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineState;

    .line 14
    .line 15
    .line 16
    move-result-object p0

    .line 17
    if-eqz p0, :cond_0

    .line 18
    .line 19
    check-cast p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/SubScreenStateMachineState;

    .line 20
    .line 21
    return-object p0

    .line 22
    :cond_0
    const/4 p0, 0x0

    .line 23
    return-object p0
.end method

.method public getDefinition$remoteparkassistcoremeb_release()Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineDefinition;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/state/RPAStateMachine;->definition:Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineDefinition;

    .line 2
    .line 3
    return-object p0
.end method

.method public getTickInterval-UwyO8pc$remoteparkassistcoremeb_release()J
    .locals 2

    .line 1
    iget-wide v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/state/RPAStateMachine;->tickInterval:J

    .line 2
    .line 3
    return-wide v0
.end method
