.class public abstract Lkp/q;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(Lcom/google/android/gms/internal/measurement/i4;Le2/i;)Le2/s;
    .locals 4

    .line 1
    invoke-virtual {p0}, Lcom/google/android/gms/internal/measurement/i4;->s()Le2/j;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    iget-object p0, p0, Lcom/google/android/gms/internal/measurement/i4;->g:Ljava/lang/Object;

    .line 6
    .line 7
    check-cast p0, Landroidx/collection/h;

    .line 8
    .line 9
    sget-object v1, Le2/j;->d:Le2/j;

    .line 10
    .line 11
    const/4 v2, 0x0

    .line 12
    const/4 v3, 0x1

    .line 13
    if-ne v0, v1, :cond_0

    .line 14
    .line 15
    move v0, v3

    .line 16
    goto :goto_0

    .line 17
    :cond_0
    move v0, v2

    .line 18
    :goto_0
    new-instance v1, Le2/s;

    .line 19
    .line 20
    invoke-static {p0, v0, v3, p1}, Lkp/q;->c(Landroidx/collection/h;ZZLe2/i;)Le2/r;

    .line 21
    .line 22
    .line 23
    move-result-object v3

    .line 24
    invoke-static {p0, v0, v2, p1}, Lkp/q;->c(Landroidx/collection/h;ZZLe2/i;)Le2/r;

    .line 25
    .line 26
    .line 27
    move-result-object p0

    .line 28
    invoke-direct {v1, v3, p0, v0}, Le2/s;-><init>(Le2/r;Le2/r;Z)V

    .line 29
    .line 30
    .line 31
    return-object v1
.end method

.method public static final b(Lcom/google/android/gms/internal/measurement/i4;Landroidx/collection/h;Le2/r;)Le2/r;
    .locals 16

    .line 1
    move-object/from16 v1, p1

    .line 2
    .line 3
    move-object/from16 v6, p2

    .line 4
    .line 5
    iget v7, v1, Landroidx/collection/h;->f:I

    .line 6
    .line 7
    iget v8, v1, Landroidx/collection/h;->e:I

    .line 8
    .line 9
    move-object/from16 v4, p0

    .line 10
    .line 11
    iget-boolean v9, v4, Lcom/google/android/gms/internal/measurement/i4;->e:Z

    .line 12
    .line 13
    if-eqz v9, :cond_0

    .line 14
    .line 15
    move v2, v8

    .line 16
    goto :goto_0

    .line 17
    :cond_0
    move v2, v7

    .line 18
    :goto_0
    iget-object v0, v1, Landroidx/collection/h;->h:Ljava/lang/Object;

    .line 19
    .line 20
    move-object v10, v0

    .line 21
    check-cast v10, Lg4/l0;

    .line 22
    .line 23
    iget v11, v1, Landroidx/collection/h;->g:I

    .line 24
    .line 25
    sget-object v12, Llx0/j;->f:Llx0/j;

    .line 26
    .line 27
    new-instance v0, Lba0/h;

    .line 28
    .line 29
    const/4 v13, 0x1

    .line 30
    invoke-direct {v0, v1, v2, v13}, Lba0/h;-><init>(Ljava/lang/Object;II)V

    .line 31
    .line 32
    .line 33
    invoke-static {v12, v0}, Lpm/a;->c(Llx0/j;Lay0/a;)Llx0/i;

    .line 34
    .line 35
    .line 36
    move-result-object v5

    .line 37
    if-eqz v9, :cond_1

    .line 38
    .line 39
    move v3, v7

    .line 40
    goto :goto_1

    .line 41
    :cond_1
    move v3, v8

    .line 42
    :goto_1
    new-instance v0, Le2/u;

    .line 43
    .line 44
    invoke-direct/range {v0 .. v5}, Le2/u;-><init>(Landroidx/collection/h;IILcom/google/android/gms/internal/measurement/i4;Llx0/i;)V

    .line 45
    .line 46
    .line 47
    invoke-static {v12, v0}, Lpm/a;->c(Llx0/j;Lay0/a;)Llx0/i;

    .line 48
    .line 49
    .line 50
    move-result-object v0

    .line 51
    const-wide/16 v3, 0x1

    .line 52
    .line 53
    iget-wide v14, v6, Le2/r;->c:J

    .line 54
    .line 55
    cmp-long v3, v3, v14

    .line 56
    .line 57
    if-eqz v3, :cond_2

    .line 58
    .line 59
    invoke-interface {v0}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 60
    .line 61
    .line 62
    move-result-object v0

    .line 63
    check-cast v0, Le2/r;

    .line 64
    .line 65
    return-object v0

    .line 66
    :cond_2
    if-ne v2, v11, :cond_3

    .line 67
    .line 68
    return-object v6

    .line 69
    :cond_3
    iget-object v3, v10, Lg4/l0;->b:Lg4/o;

    .line 70
    .line 71
    invoke-virtual {v3, v11}, Lg4/o;->d(I)I

    .line 72
    .line 73
    .line 74
    move-result v3

    .line 75
    invoke-interface {v5}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 76
    .line 77
    .line 78
    move-result-object v4

    .line 79
    check-cast v4, Ljava/lang/Number;

    .line 80
    .line 81
    invoke-virtual {v4}, Ljava/lang/Number;->intValue()I

    .line 82
    .line 83
    .line 84
    move-result v4

    .line 85
    if-eq v4, v3, :cond_4

    .line 86
    .line 87
    invoke-interface {v0}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 88
    .line 89
    .line 90
    move-result-object v0

    .line 91
    check-cast v0, Le2/r;

    .line 92
    .line 93
    return-object v0

    .line 94
    :cond_4
    iget v3, v6, Le2/r;->b:I

    .line 95
    .line 96
    invoke-virtual {v10, v3}, Lg4/l0;->j(I)J

    .line 97
    .line 98
    .line 99
    move-result-wide v4

    .line 100
    const/4 v6, -0x1

    .line 101
    if-ne v11, v6, :cond_5

    .line 102
    .line 103
    goto :goto_4

    .line 104
    :cond_5
    if-ne v2, v11, :cond_6

    .line 105
    .line 106
    goto :goto_6

    .line 107
    :cond_6
    if-ge v8, v7, :cond_7

    .line 108
    .line 109
    sget-object v6, Le2/j;->e:Le2/j;

    .line 110
    .line 111
    goto :goto_2

    .line 112
    :cond_7
    if-le v8, v7, :cond_8

    .line 113
    .line 114
    sget-object v6, Le2/j;->d:Le2/j;

    .line 115
    .line 116
    goto :goto_2

    .line 117
    :cond_8
    sget-object v6, Le2/j;->f:Le2/j;

    .line 118
    .line 119
    :goto_2
    sget-object v7, Le2/j;->d:Le2/j;

    .line 120
    .line 121
    if-ne v6, v7, :cond_9

    .line 122
    .line 123
    goto :goto_3

    .line 124
    :cond_9
    const/4 v13, 0x0

    .line 125
    :goto_3
    xor-int v6, v9, v13

    .line 126
    .line 127
    if-eqz v6, :cond_a

    .line 128
    .line 129
    if-ge v2, v11, :cond_d

    .line 130
    .line 131
    goto :goto_4

    .line 132
    :cond_a
    if-le v2, v11, :cond_d

    .line 133
    .line 134
    :goto_4
    sget v6, Lg4/o0;->c:I

    .line 135
    .line 136
    const/16 v6, 0x20

    .line 137
    .line 138
    shr-long v6, v4, v6

    .line 139
    .line 140
    long-to-int v6, v6

    .line 141
    if-eq v3, v6, :cond_c

    .line 142
    .line 143
    const-wide v6, 0xffffffffL

    .line 144
    .line 145
    .line 146
    .line 147
    .line 148
    and-long/2addr v4, v6

    .line 149
    long-to-int v4, v4

    .line 150
    if-ne v3, v4, :cond_b

    .line 151
    .line 152
    goto :goto_5

    .line 153
    :cond_b
    invoke-virtual {v1, v2}, Landroidx/collection/h;->b(I)Le2/r;

    .line 154
    .line 155
    .line 156
    move-result-object v0

    .line 157
    return-object v0

    .line 158
    :cond_c
    :goto_5
    invoke-interface {v0}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 159
    .line 160
    .line 161
    move-result-object v0

    .line 162
    check-cast v0, Le2/r;

    .line 163
    .line 164
    return-object v0

    .line 165
    :cond_d
    :goto_6
    invoke-virtual {v1, v2}, Landroidx/collection/h;->b(I)Le2/r;

    .line 166
    .line 167
    .line 168
    move-result-object v0

    .line 169
    return-object v0
.end method

.method public static final c(Landroidx/collection/h;ZZLe2/i;)Le2/r;
    .locals 2

    .line 1
    if-eqz p2, :cond_0

    .line 2
    .line 3
    iget v0, p0, Landroidx/collection/h;->e:I

    .line 4
    .line 5
    goto :goto_0

    .line 6
    :cond_0
    iget v0, p0, Landroidx/collection/h;->f:I

    .line 7
    .line 8
    :goto_0
    invoke-interface {p3, p0, v0}, Le2/i;->a(Landroidx/collection/h;I)J

    .line 9
    .line 10
    .line 11
    move-result-wide v0

    .line 12
    xor-int/2addr p1, p2

    .line 13
    if-eqz p1, :cond_1

    .line 14
    .line 15
    sget p1, Lg4/o0;->c:I

    .line 16
    .line 17
    const/16 p1, 0x20

    .line 18
    .line 19
    shr-long p1, v0, p1

    .line 20
    .line 21
    :goto_1
    long-to-int p1, p1

    .line 22
    goto :goto_2

    .line 23
    :cond_1
    sget p1, Lg4/o0;->c:I

    .line 24
    .line 25
    const-wide p1, 0xffffffffL

    .line 26
    .line 27
    .line 28
    .line 29
    .line 30
    and-long/2addr p1, v0

    .line 31
    goto :goto_1

    .line 32
    :goto_2
    invoke-virtual {p0, p1}, Landroidx/collection/h;->b(I)Le2/r;

    .line 33
    .line 34
    .line 35
    move-result-object p0

    .line 36
    return-object p0
.end method

.method public static final d(Le2/r;Landroidx/collection/h;I)Le2/r;
    .locals 2

    .line 1
    iget-object p1, p1, Landroidx/collection/h;->h:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p1, Lg4/l0;

    .line 4
    .line 5
    invoke-virtual {p1, p2}, Lg4/l0;->a(I)Lr4/j;

    .line 6
    .line 7
    .line 8
    move-result-object p1

    .line 9
    iget-wide v0, p0, Le2/r;->c:J

    .line 10
    .line 11
    new-instance p0, Le2/r;

    .line 12
    .line 13
    invoke-direct {p0, p1, p2, v0, v1}, Le2/r;-><init>(Lr4/j;IJ)V

    .line 14
    .line 15
    .line 16
    return-object p0
.end method

.method public static final e(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/MessageReceivedInput;)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/FunctionStatusMLB;
    .locals 1

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-static {p0}, Lkp/q;->f(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/MessageReceivedInput;)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PHighPrioMessageExtendedMLB;

    .line 7
    .line 8
    .line 9
    move-result-object p0

    .line 10
    invoke-virtual {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PHighPrioMessageExtendedMLB;->getFunctionStatus()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/FunctionStatusMLB;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    return-object p0
.end method

.method public static final f(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/MessageReceivedInput;)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PHighPrioMessageExtendedMLB;
    .locals 12

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-virtual {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/MessageReceivedInput;->getData()Ljava/lang/Object;

    .line 7
    .line 8
    .line 9
    move-result-object p0

    .line 10
    instance-of v0, p0, Ln81/a;

    .line 11
    .line 12
    if-eqz v0, :cond_0

    .line 13
    .line 14
    check-cast p0, Ln81/a;

    .line 15
    .line 16
    goto :goto_0

    .line 17
    :cond_0
    const/4 p0, 0x0

    .line 18
    :goto_0
    if-eqz p0, :cond_2

    .line 19
    .line 20
    iget-object p0, p0, Ln81/a;->a:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PHighPrioMessageExtendedMLB;

    .line 21
    .line 22
    if-nez p0, :cond_1

    .line 23
    .line 24
    goto :goto_1

    .line 25
    :cond_1
    return-object p0

    .line 26
    :cond_2
    :goto_1
    new-instance v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PHighPrioMessageExtendedMLB;

    .line 27
    .line 28
    const/16 v10, 0x1ff

    .line 29
    .line 30
    const/4 v11, 0x0

    .line 31
    const/4 v1, 0x0

    .line 32
    const/4 v2, 0x0

    .line 33
    const/4 v3, 0x0

    .line 34
    const/4 v4, 0x0

    .line 35
    const/4 v5, 0x0

    .line 36
    const/4 v6, 0x0

    .line 37
    const/4 v7, 0x0

    .line 38
    const/4 v8, 0x0

    .line 39
    const/4 v9, 0x0

    .line 40
    invoke-direct/range {v0 .. v11}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PHighPrioMessageExtendedMLB;-><init>(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/FunctionStatusMLB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ObstacleStatusMLB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/KeyStatusMLB;ZLtechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/StoppingReasonStatusExtendedMLB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/HandbrakeStatusMLB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/EngineStatusMLB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/GearStatusMLB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/DDAStatusMLB;ILkotlin/jvm/internal/g;)V

    .line 41
    .line 42
    .line 43
    return-object v0
.end method

.method public static final g(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/MessageReceivedInput;)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;
    .locals 25

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    move-object/from16 v1, p0

    .line 4
    .line 5
    invoke-static {v1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    invoke-virtual {v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/MessageReceivedInput;->getData()Ljava/lang/Object;

    .line 9
    .line 10
    .line 11
    move-result-object v0

    .line 12
    instance-of v1, v0, Ln81/a;

    .line 13
    .line 14
    if-eqz v1, :cond_0

    .line 15
    .line 16
    check-cast v0, Ln81/a;

    .line 17
    .line 18
    goto :goto_0

    .line 19
    :cond_0
    const/4 v0, 0x0

    .line 20
    :goto_0
    if-eqz v0, :cond_2

    .line 21
    .line 22
    iget-object v0, v0, Ln81/a;->c:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;

    .line 23
    .line 24
    if-nez v0, :cond_1

    .line 25
    .line 26
    goto :goto_1

    .line 27
    :cond_1
    return-object v0

    .line 28
    :cond_2
    :goto_1
    new-instance v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;

    .line 29
    .line 30
    const v23, 0x1fffff

    .line 31
    .line 32
    .line 33
    const/16 v24, 0x0

    .line 34
    .line 35
    const/4 v2, 0x0

    .line 36
    const/4 v3, 0x0

    .line 37
    const/4 v4, 0x0

    .line 38
    const/4 v5, 0x0

    .line 39
    const/4 v6, 0x0

    .line 40
    const/4 v7, 0x0

    .line 41
    const/4 v8, 0x0

    .line 42
    const/4 v9, 0x0

    .line 43
    const/4 v10, 0x0

    .line 44
    const/4 v11, 0x0

    .line 45
    const/4 v12, 0x0

    .line 46
    const/4 v13, 0x0

    .line 47
    const/4 v14, 0x0

    .line 48
    const/4 v15, 0x0

    .line 49
    const/16 v16, 0x0

    .line 50
    .line 51
    const/16 v17, 0x0

    .line 52
    .line 53
    const/16 v18, 0x0

    .line 54
    .line 55
    const/16 v19, 0x0

    .line 56
    .line 57
    const/16 v20, 0x0

    .line 58
    .line 59
    const/16 v21, 0x0

    .line 60
    .line 61
    const/16 v22, 0x0

    .line 62
    .line 63
    invoke-direct/range {v1 .. v24}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;-><init>(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ParkingSideStatusMLB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ParkingScenarioStatusMLB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ParkingManeuverStatusMLB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ParkingDirectionStatusMLB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ParkingReversibleStatusMLB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;BBLtechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;ZZZZZZZZILkotlin/jvm/internal/g;)V

    .line 64
    .line 65
    .line 66
    return-object v1
.end method

.method public static final h(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/MessageReceivedInput;)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;
    .locals 28

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    move-object/from16 v1, p0

    .line 4
    .line 5
    invoke-static {v1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    invoke-virtual {v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/MessageReceivedInput;->getData()Ljava/lang/Object;

    .line 9
    .line 10
    .line 11
    move-result-object v0

    .line 12
    instance-of v1, v0, Ln81/a;

    .line 13
    .line 14
    if-eqz v1, :cond_0

    .line 15
    .line 16
    check-cast v0, Ln81/a;

    .line 17
    .line 18
    goto :goto_0

    .line 19
    :cond_0
    const/4 v0, 0x0

    .line 20
    :goto_0
    if-eqz v0, :cond_2

    .line 21
    .line 22
    iget-object v0, v0, Ln81/a;->d:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;

    .line 23
    .line 24
    if-nez v0, :cond_1

    .line 25
    .line 26
    goto :goto_1

    .line 27
    :cond_1
    return-object v0

    .line 28
    :cond_2
    :goto_1
    new-instance v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;

    .line 29
    .line 30
    const v26, 0xffffff

    .line 31
    .line 32
    .line 33
    const/16 v27, 0x0

    .line 34
    .line 35
    const/4 v2, 0x0

    .line 36
    const/4 v3, 0x0

    .line 37
    const/4 v4, 0x0

    .line 38
    const/4 v5, 0x0

    .line 39
    const/4 v6, 0x0

    .line 40
    const/4 v7, 0x0

    .line 41
    const/4 v8, 0x0

    .line 42
    const/4 v9, 0x0

    .line 43
    const/4 v10, 0x0

    .line 44
    const/4 v11, 0x0

    .line 45
    const/4 v12, 0x0

    .line 46
    const/4 v13, 0x0

    .line 47
    const/4 v14, 0x0

    .line 48
    const/4 v15, 0x0

    .line 49
    const/16 v16, 0x0

    .line 50
    .line 51
    const/16 v17, 0x0

    .line 52
    .line 53
    const/16 v18, 0x0

    .line 54
    .line 55
    const/16 v19, 0x0

    .line 56
    .line 57
    const/16 v20, 0x0

    .line 58
    .line 59
    const/16 v21, 0x0

    .line 60
    .line 61
    const/16 v22, 0x0

    .line 62
    .line 63
    const/16 v23, 0x0

    .line 64
    .line 65
    const/16 v24, 0x0

    .line 66
    .line 67
    const/16 v25, 0x0

    .line 68
    .line 69
    invoke-direct/range {v1 .. v27}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;-><init>(ILtechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/TrajectoryLastMoveMLB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/TrajectoryDirectionMLB;IIIIIIIIIIIIIIIIIIIIIILkotlin/jvm/internal/g;)V

    .line 70
    .line 71
    .line 72
    return-object v1
.end method

.method public static final i(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/MessageReceivedInput;)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PVehicleDataResponseMessageMLB;
    .locals 10

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-virtual {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/MessageReceivedInput;->getData()Ljava/lang/Object;

    .line 7
    .line 8
    .line 9
    move-result-object p0

    .line 10
    instance-of v0, p0, Ln81/a;

    .line 11
    .line 12
    if-eqz v0, :cond_0

    .line 13
    .line 14
    check-cast p0, Ln81/a;

    .line 15
    .line 16
    goto :goto_0

    .line 17
    :cond_0
    const/4 p0, 0x0

    .line 18
    :goto_0
    if-eqz p0, :cond_2

    .line 19
    .line 20
    iget-object p0, p0, Ln81/a;->b:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PVehicleDataResponseMessageMLB;

    .line 21
    .line 22
    if-nez p0, :cond_1

    .line 23
    .line 24
    goto :goto_1

    .line 25
    :cond_1
    return-object p0

    .line 26
    :cond_2
    :goto_1
    new-instance v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PVehicleDataResponseMessageMLB;

    .line 27
    .line 28
    const/16 v8, 0x7f

    .line 29
    .line 30
    const/4 v9, 0x0

    .line 31
    const/4 v1, 0x0

    .line 32
    const/4 v2, 0x0

    .line 33
    const/4 v3, 0x0

    .line 34
    const/4 v4, 0x0

    .line 35
    const/4 v5, 0x0

    .line 36
    const/4 v6, 0x0

    .line 37
    const/4 v7, 0x0

    .line 38
    invoke-direct/range {v0 .. v9}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PVehicleDataResponseMessageMLB;-><init>(BBBZZZZILkotlin/jvm/internal/g;)V

    .line 39
    .line 40
    .line 41
    return-object v0
.end method

.method public static final j(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/MessageReceivedInput;)Z
    .locals 1

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-static {p0}, Lkp/q;->g(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/MessageReceivedInput;)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;

    .line 7
    .line 8
    .line 9
    move-result-object p0

    .line 10
    invoke-virtual {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->getParkingReversibleStatus()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ParkingReversibleStatusMLB;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ParkingReversibleStatusMLB;->REVERSIBLE:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ParkingReversibleStatusMLB;

    .line 15
    .line 16
    if-ne p0, v0, :cond_0

    .line 17
    .line 18
    const/4 p0, 0x1

    .line 19
    return p0

    .line 20
    :cond_0
    const/4 p0, 0x0

    .line 21
    return p0
.end method
