.class public abstract Ljp/fa;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static a(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/MessageReceivedInput;)Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/data/MLBStateValues;
    .locals 15

    .line 1
    const-string v0, "input"

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
    move-result-object v0

    .line 10
    invoke-virtual {v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PHighPrioMessageExtendedMLB;->getKeyStatus()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/KeyStatusMLB;

    .line 11
    .line 12
    .line 13
    move-result-object v6

    .line 14
    invoke-static {p0}, Lkp/q;->f(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/MessageReceivedInput;)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PHighPrioMessageExtendedMLB;

    .line 15
    .line 16
    .line 17
    move-result-object v0

    .line 18
    invoke-virtual {v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PHighPrioMessageExtendedMLB;->getGearStatus()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/GearStatusMLB;

    .line 19
    .line 20
    .line 21
    move-result-object v5

    .line 22
    invoke-static {p0}, Lkp/q;->f(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/MessageReceivedInput;)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PHighPrioMessageExtendedMLB;

    .line 23
    .line 24
    .line 25
    move-result-object v0

    .line 26
    invoke-virtual {v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PHighPrioMessageExtendedMLB;->getFunctionStatus()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/FunctionStatusMLB;

    .line 27
    .line 28
    .line 29
    move-result-object v4

    .line 30
    invoke-static {p0}, Lkp/q;->f(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/MessageReceivedInput;)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PHighPrioMessageExtendedMLB;

    .line 31
    .line 32
    .line 33
    move-result-object v0

    .line 34
    invoke-virtual {v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PHighPrioMessageExtendedMLB;->getObstacleStatus()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ObstacleStatusMLB;

    .line 35
    .line 36
    .line 37
    move-result-object v3

    .line 38
    invoke-static {p0}, Lkp/q;->f(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/MessageReceivedInput;)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PHighPrioMessageExtendedMLB;

    .line 39
    .line 40
    .line 41
    move-result-object v0

    .line 42
    invoke-virtual {v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PHighPrioMessageExtendedMLB;->getStoppingReasonStatusExtended()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/StoppingReasonStatusExtendedMLB;

    .line 43
    .line 44
    .line 45
    move-result-object v2

    .line 46
    invoke-static {p0}, Lkp/q;->g(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/MessageReceivedInput;)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;

    .line 47
    .line 48
    .line 49
    move-result-object v0

    .line 50
    invoke-virtual {v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->getParkingReversibleStatus()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ParkingReversibleStatusMLB;

    .line 51
    .line 52
    .line 53
    move-result-object v0

    .line 54
    sget-object v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ParkingReversibleStatusMLB;->REVERSIBLE:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ParkingReversibleStatusMLB;

    .line 55
    .line 56
    const/4 v7, 0x0

    .line 57
    const/4 v8, 0x1

    .line 58
    if-ne v0, v1, :cond_0

    .line 59
    .line 60
    move v0, v7

    .line 61
    move v7, v8

    .line 62
    goto :goto_0

    .line 63
    :cond_0
    move v0, v7

    .line 64
    :goto_0
    invoke-static {p0}, Lkp/q;->f(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/MessageReceivedInput;)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PHighPrioMessageExtendedMLB;

    .line 65
    .line 66
    .line 67
    move-result-object v1

    .line 68
    invoke-virtual {v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PHighPrioMessageExtendedMLB;->getFunctionStatus()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/FunctionStatusMLB;

    .line 69
    .line 70
    .line 71
    move-result-object v1

    .line 72
    sget-object v9, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/FunctionStatusMLB;->ABORTED_RESUMING_POSSIBLE:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/FunctionStatusMLB;

    .line 73
    .line 74
    if-ne v1, v9, :cond_1

    .line 75
    .line 76
    move v1, v8

    .line 77
    goto :goto_1

    .line 78
    :cond_1
    move v1, v8

    .line 79
    move v8, v0

    .line 80
    :goto_1
    invoke-static {p0}, Lkp/q;->g(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/MessageReceivedInput;)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;

    .line 81
    .line 82
    .line 83
    move-result-object v9

    .line 84
    invoke-virtual {v9}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->getParkingManeuverStatus()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ParkingManeuverStatusMLB;

    .line 85
    .line 86
    .line 87
    move-result-object v9

    .line 88
    invoke-static {p0}, Lkp/q;->i(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/MessageReceivedInput;)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PVehicleDataResponseMessageMLB;

    .line 89
    .line 90
    .line 91
    move-result-object v10

    .line 92
    invoke-virtual {v10}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PVehicleDataResponseMessageMLB;->isElectricalVehicle()Z

    .line 93
    .line 94
    .line 95
    move-result v10

    .line 96
    invoke-static {p0}, Lkp/q;->h(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/MessageReceivedInput;)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;

    .line 97
    .line 98
    .line 99
    move-result-object v11

    .line 100
    invoke-static {v11}, Ljp/te;->a(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioTrajectoryInfoMLB;)Lq81/b;

    .line 101
    .line 102
    .line 103
    move-result-object v11

    .line 104
    invoke-virtual {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/MessageReceivedInput;->getData()Ljava/lang/Object;

    .line 105
    .line 106
    .line 107
    move-result-object v12

    .line 108
    instance-of v13, v12, Ln81/a;

    .line 109
    .line 110
    if-eqz v13, :cond_2

    .line 111
    .line 112
    check-cast v12, Ln81/a;

    .line 113
    .line 114
    goto :goto_2

    .line 115
    :cond_2
    const/4 v12, 0x0

    .line 116
    :goto_2
    if-eqz v12, :cond_3

    .line 117
    .line 118
    iget-object v12, v12, Ln81/a;->e:Ll71/u;

    .line 119
    .line 120
    if-nez v12, :cond_4

    .line 121
    .line 122
    :cond_3
    sget-object v12, Ll71/m;->e:Ll71/m;

    .line 123
    .line 124
    :cond_4
    const/4 v13, 0x2

    .line 125
    new-array v13, v13, [Ll71/l;

    .line 126
    .line 127
    sget-object v14, Ll71/i;->e:Ll71/i;

    .line 128
    .line 129
    aput-object v14, v13, v0

    .line 130
    .line 131
    sget-object v0, Ll71/j;->e:Ll71/j;

    .line 132
    .line 133
    aput-object v0, v13, v1

    .line 134
    .line 135
    invoke-static {v13}, Lmx0/n;->h0([Ljava/lang/Object;)Ljava/util/Set;

    .line 136
    .line 137
    .line 138
    move-result-object v0

    .line 139
    check-cast v0, Ljava/lang/Iterable;

    .line 140
    .line 141
    invoke-static {v0, v12}, Lmx0/q;->A(Ljava/lang/Iterable;Ljava/lang/Object;)Z

    .line 142
    .line 143
    .line 144
    move-result v0

    .line 145
    xor-int/lit8 v12, v0, 0x1

    .line 146
    .line 147
    invoke-static {p0}, Lkp/q;->g(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/MessageReceivedInput;)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;

    .line 148
    .line 149
    .line 150
    move-result-object v0

    .line 151
    invoke-virtual {v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/C2PNormalPrioManeuverInfoMessageMLB;->getParkingSideStatus()Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ParkingSideStatusMLB;

    .line 152
    .line 153
    .line 154
    move-result-object v0

    .line 155
    invoke-static {v0}, Lkp/o;->h(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ParkingSideStatusMLB;)Ls71/j;

    .line 156
    .line 157
    .line 158
    move-result-object v13

    .line 159
    invoke-static {p0}, Lkp/o;->e(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/MessageReceivedInput;)Ls71/k;

    .line 160
    .line 161
    .line 162
    move-result-object v14

    .line 163
    new-instance v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/data/MLBStateValues;

    .line 164
    .line 165
    invoke-direct/range {v1 .. v14}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/mlb/data/MLBStateValues;-><init>(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/StoppingReasonStatusExtendedMLB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ObstacleStatusMLB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/FunctionStatusMLB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/GearStatusMLB;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/KeyStatusMLB;ZZLtechnology/cariad/cat/remoteparkassistcoremeb/messages/mlb/ParkingManeuverStatusMLB;ZLq81/b;ZLs71/j;Ls71/k;)V

    .line 166
    .line 167
    .line 168
    return-object v1
.end method

.method public static final b(IILl2/o;)Li3/c;
    .locals 9

    .line 1
    sget-object v0, Landroidx/compose/ui/platform/AndroidCompositionLocals_androidKt;->b:Ll2/u2;

    .line 2
    .line 3
    check-cast p2, Ll2/t;

    .line 4
    .line 5
    invoke-virtual {p2, v0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    check-cast v0, Landroid/content/Context;

    .line 10
    .line 11
    sget-object v1, Landroidx/compose/ui/platform/AndroidCompositionLocals_androidKt;->c:Ll2/e0;

    .line 12
    .line 13
    invoke-virtual {p2, v1}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 14
    .line 15
    .line 16
    move-result-object v1

    .line 17
    check-cast v1, Landroid/content/res/Resources;

    .line 18
    .line 19
    sget-object v2, Landroidx/compose/ui/platform/AndroidCompositionLocals_androidKt;->e:Ll2/u2;

    .line 20
    .line 21
    invoke-virtual {p2, v2}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 22
    .line 23
    .line 24
    move-result-object v2

    .line 25
    check-cast v2, Lb4/d;

    .line 26
    .line 27
    monitor-enter v2

    .line 28
    :try_start_0
    iget-object v3, v2, Lb4/d;->a:Landroidx/collection/b0;

    .line 29
    .line 30
    invoke-virtual {v3, p0}, Landroidx/collection/p;->b(I)Ljava/lang/Object;

    .line 31
    .line 32
    .line 33
    move-result-object v3

    .line 34
    check-cast v3, Landroid/util/TypedValue;

    .line 35
    .line 36
    const/4 v4, 0x1

    .line 37
    if-nez v3, :cond_0

    .line 38
    .line 39
    new-instance v3, Landroid/util/TypedValue;

    .line 40
    .line 41
    invoke-direct {v3}, Landroid/util/TypedValue;-><init>()V

    .line 42
    .line 43
    .line 44
    invoke-virtual {v1, p0, v3, v4}, Landroid/content/res/Resources;->getValue(ILandroid/util/TypedValue;Z)V

    .line 45
    .line 46
    .line 47
    iget-object v5, v2, Lb4/d;->a:Landroidx/collection/b0;

    .line 48
    .line 49
    invoke-virtual {v5, p0}, Landroidx/collection/b0;->d(I)I

    .line 50
    .line 51
    .line 52
    move-result v6

    .line 53
    iget-object v7, v5, Landroidx/collection/p;->c:[Ljava/lang/Object;

    .line 54
    .line 55
    aget-object v8, v7, v6

    .line 56
    .line 57
    iget-object v5, v5, Landroidx/collection/p;->b:[I

    .line 58
    .line 59
    aput p0, v5, v6

    .line 60
    .line 61
    aput-object v3, v7, v6
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 62
    .line 63
    goto :goto_0

    .line 64
    :catchall_0
    move-exception p0

    .line 65
    goto/16 :goto_4

    .line 66
    .line 67
    :cond_0
    :goto_0
    monitor-exit v2

    .line 68
    iget-object v2, v3, Landroid/util/TypedValue;->string:Ljava/lang/CharSequence;

    .line 69
    .line 70
    const/4 v5, 0x0

    .line 71
    const/4 v6, 0x0

    .line 72
    if-eqz v2, :cond_6

    .line 73
    .line 74
    const-string v7, ".xml"

    .line 75
    .line 76
    invoke-static {v2, v7}, Lly0/p;->E(Ljava/lang/CharSequence;Ljava/lang/CharSequence;)Z

    .line 77
    .line 78
    .line 79
    move-result v7

    .line 80
    if-ne v7, v4, :cond_6

    .line 81
    .line 82
    const p1, -0x699b5122

    .line 83
    .line 84
    .line 85
    invoke-virtual {p2, p1}, Ll2/t;->Y(I)V

    .line 86
    .line 87
    .line 88
    invoke-virtual {v0}, Landroid/content/Context;->getTheme()Landroid/content/res/Resources$Theme;

    .line 89
    .line 90
    .line 91
    move-result-object p1

    .line 92
    iget v0, v3, Landroid/util/TypedValue;->changingConfigurations:I

    .line 93
    .line 94
    sget-object v2, Landroidx/compose/ui/platform/AndroidCompositionLocals_androidKt;->d:Ll2/u2;

    .line 95
    .line 96
    invoke-virtual {p2, v2}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 97
    .line 98
    .line 99
    move-result-object v2

    .line 100
    check-cast v2, Lb4/c;

    .line 101
    .line 102
    new-instance v3, Lb4/b;

    .line 103
    .line 104
    invoke-direct {v3, p0, p1}, Lb4/b;-><init>(ILandroid/content/res/Resources$Theme;)V

    .line 105
    .line 106
    .line 107
    iget-object v7, v2, Lb4/c;->a:Ljava/util/HashMap;

    .line 108
    .line 109
    invoke-virtual {v7, v3}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 110
    .line 111
    .line 112
    move-result-object v7

    .line 113
    check-cast v7, Ljava/lang/ref/WeakReference;

    .line 114
    .line 115
    if-eqz v7, :cond_1

    .line 116
    .line 117
    invoke-virtual {v7}, Ljava/lang/ref/Reference;->get()Ljava/lang/Object;

    .line 118
    .line 119
    .line 120
    move-result-object v5

    .line 121
    check-cast v5, Lb4/a;

    .line 122
    .line 123
    :cond_1
    if-nez v5, :cond_5

    .line 124
    .line 125
    invoke-virtual {v1, p0}, Landroid/content/res/Resources;->getXml(I)Landroid/content/res/XmlResourceParser;

    .line 126
    .line 127
    .line 128
    move-result-object p0

    .line 129
    invoke-interface {p0}, Lorg/xmlpull/v1/XmlPullParser;->next()I

    .line 130
    .line 131
    .line 132
    move-result v5

    .line 133
    :goto_1
    const/4 v7, 0x2

    .line 134
    if-eq v5, v7, :cond_2

    .line 135
    .line 136
    if-eq v5, v4, :cond_2

    .line 137
    .line 138
    invoke-interface {p0}, Lorg/xmlpull/v1/XmlPullParser;->next()I

    .line 139
    .line 140
    .line 141
    move-result v5

    .line 142
    goto :goto_1

    .line 143
    :cond_2
    if-ne v5, v7, :cond_4

    .line 144
    .line 145
    invoke-interface {p0}, Lorg/xmlpull/v1/XmlPullParser;->getName()Ljava/lang/String;

    .line 146
    .line 147
    .line 148
    move-result-object v4

    .line 149
    const-string v5, "vector"

    .line 150
    .line 151
    invoke-static {v4, v5}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 152
    .line 153
    .line 154
    move-result v4

    .line 155
    if-eqz v4, :cond_3

    .line 156
    .line 157
    invoke-static {p1, v1, p0, v0}, Ljp/ha;->a(Landroid/content/res/Resources$Theme;Landroid/content/res/Resources;Landroid/content/res/XmlResourceParser;I)Lb4/a;

    .line 158
    .line 159
    .line 160
    move-result-object v5

    .line 161
    iget-object p0, v2, Lb4/c;->a:Ljava/util/HashMap;

    .line 162
    .line 163
    new-instance p1, Ljava/lang/ref/WeakReference;

    .line 164
    .line 165
    invoke-direct {p1, v5}, Ljava/lang/ref/WeakReference;-><init>(Ljava/lang/Object;)V

    .line 166
    .line 167
    .line 168
    invoke-virtual {p0, v3, p1}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 169
    .line 170
    .line 171
    goto :goto_2

    .line 172
    :cond_3
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 173
    .line 174
    const-string p1, "Only VectorDrawables and rasterized asset types are supported ex. PNG, JPG, WEBP"

    .line 175
    .line 176
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 177
    .line 178
    .line 179
    throw p0

    .line 180
    :cond_4
    new-instance p0, Lorg/xmlpull/v1/XmlPullParserException;

    .line 181
    .line 182
    const-string p1, "No start tag found"

    .line 183
    .line 184
    invoke-direct {p0, p1}, Lorg/xmlpull/v1/XmlPullParserException;-><init>(Ljava/lang/String;)V

    .line 185
    .line 186
    .line 187
    throw p0

    .line 188
    :cond_5
    :goto_2
    iget-object p0, v5, Lb4/a;->a:Lj3/f;

    .line 189
    .line 190
    invoke-static {p0, p2}, Lj3/b;->c(Lj3/f;Ll2/o;)Lj3/j0;

    .line 191
    .line 192
    .line 193
    move-result-object p0

    .line 194
    invoke-virtual {p2, v6}, Ll2/t;->q(Z)V

    .line 195
    .line 196
    .line 197
    return-object p0

    .line 198
    :cond_6
    const v3, -0x6998f1f8

    .line 199
    .line 200
    .line 201
    invoke-virtual {p2, v3}, Ll2/t;->Y(I)V

    .line 202
    .line 203
    .line 204
    invoke-virtual {v0}, Landroid/content/Context;->getTheme()Landroid/content/res/Resources$Theme;

    .line 205
    .line 206
    .line 207
    move-result-object v0

    .line 208
    invoke-virtual {p2, v2}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 209
    .line 210
    .line 211
    move-result v3

    .line 212
    and-int/lit8 v7, p1, 0xe

    .line 213
    .line 214
    xor-int/lit8 v7, v7, 0x6

    .line 215
    .line 216
    const/4 v8, 0x4

    .line 217
    if-le v7, v8, :cond_7

    .line 218
    .line 219
    invoke-virtual {p2, p0}, Ll2/t;->e(I)Z

    .line 220
    .line 221
    .line 222
    move-result v7

    .line 223
    if-nez v7, :cond_9

    .line 224
    .line 225
    :cond_7
    and-int/lit8 p1, p1, 0x6

    .line 226
    .line 227
    if-ne p1, v8, :cond_8

    .line 228
    .line 229
    goto :goto_3

    .line 230
    :cond_8
    move v4, v6

    .line 231
    :cond_9
    :goto_3
    or-int p1, v3, v4

    .line 232
    .line 233
    invoke-virtual {p2, v0}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 234
    .line 235
    .line 236
    move-result v0

    .line 237
    or-int/2addr p1, v0

    .line 238
    invoke-virtual {p2}, Ll2/t;->L()Ljava/lang/Object;

    .line 239
    .line 240
    .line 241
    move-result-object v0

    .line 242
    if-nez p1, :cond_a

    .line 243
    .line 244
    sget-object p1, Ll2/n;->a:Ll2/x0;

    .line 245
    .line 246
    if-ne v0, p1, :cond_b

    .line 247
    .line 248
    :cond_a
    :try_start_1
    invoke-virtual {v1, p0, v5}, Landroid/content/res/Resources;->getDrawable(ILandroid/content/res/Resources$Theme;)Landroid/graphics/drawable/Drawable;

    .line 249
    .line 250
    .line 251
    move-result-object p0

    .line 252
    const-string p1, "null cannot be cast to non-null type android.graphics.drawable.BitmapDrawable"

    .line 253
    .line 254
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 255
    .line 256
    .line 257
    check-cast p0, Landroid/graphics/drawable/BitmapDrawable;

    .line 258
    .line 259
    invoke-virtual {p0}, Landroid/graphics/drawable/BitmapDrawable;->getBitmap()Landroid/graphics/Bitmap;

    .line 260
    .line 261
    .line 262
    move-result-object p0

    .line 263
    new-instance v0, Le3/f;

    .line 264
    .line 265
    invoke-direct {v0, p0}, Le3/f;-><init>(Landroid/graphics/Bitmap;)V
    :try_end_1
    .catch Ljava/lang/Exception; {:try_start_1 .. :try_end_1} :catch_0

    .line 266
    .line 267
    .line 268
    invoke-virtual {p2, v0}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 269
    .line 270
    .line 271
    :cond_b
    check-cast v0, Le3/f;

    .line 272
    .line 273
    new-instance p0, Li3/a;

    .line 274
    .line 275
    invoke-direct {p0, v0}, Li3/a;-><init>(Le3/f;)V

    .line 276
    .line 277
    .line 278
    invoke-virtual {p2, v6}, Ll2/t;->q(Z)V

    .line 279
    .line 280
    .line 281
    return-object p0

    .line 282
    :catch_0
    move-exception p0

    .line 283
    new-instance p1, La8/r0;

    .line 284
    .line 285
    new-instance p2, Ljava/lang/StringBuilder;

    .line 286
    .line 287
    const-string v0, "Error attempting to load resource: "

    .line 288
    .line 289
    invoke-direct {p2, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 290
    .line 291
    .line 292
    invoke-virtual {p2, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 293
    .line 294
    .line 295
    invoke-virtual {p2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 296
    .line 297
    .line 298
    move-result-object p2

    .line 299
    invoke-direct {p1, p2, p0}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 300
    .line 301
    .line 302
    throw p1

    .line 303
    :goto_4
    monitor-exit v2

    .line 304
    throw p0
.end method
