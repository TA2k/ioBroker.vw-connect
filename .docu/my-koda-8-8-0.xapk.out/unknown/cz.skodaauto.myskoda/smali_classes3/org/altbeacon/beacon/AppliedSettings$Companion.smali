.class public final Lorg/altbeacon/beacon/AppliedSettings$Companion;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lorg/altbeacon/beacon/AppliedSettings;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = "Companion"
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000\u001c\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0008\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0004\u0008\u0086\u0003\u0018\u00002\u00020\u0001B\u0007\u0008\u0002\u00a2\u0006\u0002\u0010\u0002J\u0016\u0010\u0003\u001a\u00020\u00042\u0006\u0010\u0005\u001a\u00020\u00042\u0006\u0010\u0006\u001a\u00020\u0007J\u000e\u0010\u0008\u001a\u00020\u00042\u0006\u0010\t\u001a\u00020\u0004J\u0006\u0010\n\u001a\u00020\u0004\u00a8\u0006\u000b"
    }
    d2 = {
        "Lorg/altbeacon/beacon/AppliedSettings$Companion;",
        "",
        "()V",
        "fromDeltaSettings",
        "Lorg/altbeacon/beacon/AppliedSettings;",
        "settings",
        "delta",
        "Lorg/altbeacon/beacon/Settings;",
        "fromSettings",
        "other",
        "withDefaultValues",
        "android-beacon-library_release"
    }
    k = 0x1
    mv = {
        0x1,
        0x8,
        0x0
    }
    xi = 0x30
.end annotation


# direct methods
.method private constructor <init>()V
    .locals 0

    .line 2
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(Lkotlin/jvm/internal/g;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Lorg/altbeacon/beacon/AppliedSettings$Companion;-><init>()V

    return-void
.end method


# virtual methods
.method public final fromDeltaSettings(Lorg/altbeacon/beacon/AppliedSettings;Lorg/altbeacon/beacon/Settings;)Lorg/altbeacon/beacon/AppliedSettings;
    .locals 16

    .line 1
    const-string v0, "settings"

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    invoke-static {v1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    const-string v0, "delta"

    .line 9
    .line 10
    move-object/from16 v2, p2

    .line 11
    .line 12
    invoke-static {v2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 13
    .line 14
    .line 15
    invoke-virtual {v2}, Lorg/altbeacon/beacon/Settings;->getScanPeriods()Lorg/altbeacon/beacon/Settings$ScanPeriods;

    .line 16
    .line 17
    .line 18
    move-result-object v0

    .line 19
    if-nez v0, :cond_0

    .line 20
    .line 21
    invoke-virtual {v1}, Lorg/altbeacon/beacon/AppliedSettings;->getScanPeriods()Lorg/altbeacon/beacon/Settings$ScanPeriods;

    .line 22
    .line 23
    .line 24
    move-result-object v0

    .line 25
    :cond_0
    move-object v5, v0

    .line 26
    invoke-virtual {v2}, Lorg/altbeacon/beacon/Settings;->getDebug()Ljava/lang/Boolean;

    .line 27
    .line 28
    .line 29
    move-result-object v0

    .line 30
    if-eqz v0, :cond_1

    .line 31
    .line 32
    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 33
    .line 34
    .line 35
    move-result v0

    .line 36
    goto :goto_0

    .line 37
    :cond_1
    invoke-virtual {v1}, Lorg/altbeacon/beacon/AppliedSettings;->getDebug()Z

    .line 38
    .line 39
    .line 40
    move-result v0

    .line 41
    :goto_0
    invoke-virtual {v2}, Lorg/altbeacon/beacon/Settings;->getRegionStatePersistenceEnabled()Ljava/lang/Boolean;

    .line 42
    .line 43
    .line 44
    move-result-object v3

    .line 45
    if-eqz v3, :cond_2

    .line 46
    .line 47
    invoke-virtual {v3}, Ljava/lang/Boolean;->booleanValue()Z

    .line 48
    .line 49
    .line 50
    move-result v3

    .line 51
    goto :goto_1

    .line 52
    :cond_2
    invoke-virtual {v1}, Lorg/altbeacon/beacon/AppliedSettings;->getRegionStatePersistenceEnabled()Z

    .line 53
    .line 54
    .line 55
    move-result v3

    .line 56
    :goto_1
    invoke-virtual {v2}, Lorg/altbeacon/beacon/Settings;->getUseTrackingCache()Ljava/lang/Boolean;

    .line 57
    .line 58
    .line 59
    move-result-object v4

    .line 60
    if-eqz v4, :cond_3

    .line 61
    .line 62
    invoke-virtual {v4}, Ljava/lang/Boolean;->booleanValue()Z

    .line 63
    .line 64
    .line 65
    move-result v4

    .line 66
    :goto_2
    move v7, v4

    .line 67
    goto :goto_3

    .line 68
    :cond_3
    invoke-virtual {v1}, Lorg/altbeacon/beacon/AppliedSettings;->getUseTrackingCache()Z

    .line 69
    .line 70
    .line 71
    move-result v4

    .line 72
    goto :goto_2

    .line 73
    :goto_3
    invoke-virtual {v2}, Lorg/altbeacon/beacon/Settings;->getHardwareEqualityEnforced()Ljava/lang/Boolean;

    .line 74
    .line 75
    .line 76
    move-result-object v4

    .line 77
    if-eqz v4, :cond_4

    .line 78
    .line 79
    invoke-virtual {v4}, Ljava/lang/Boolean;->booleanValue()Z

    .line 80
    .line 81
    .line 82
    move-result v4

    .line 83
    goto :goto_4

    .line 84
    :cond_4
    invoke-virtual {v1}, Lorg/altbeacon/beacon/AppliedSettings;->getHardwareEqualityEnforced()Z

    .line 85
    .line 86
    .line 87
    move-result v4

    .line 88
    :goto_4
    invoke-virtual {v2}, Lorg/altbeacon/beacon/Settings;->getRegionExitPeriodMillis()Ljava/lang/Integer;

    .line 89
    .line 90
    .line 91
    move-result-object v6

    .line 92
    if-eqz v6, :cond_5

    .line 93
    .line 94
    invoke-virtual {v6}, Ljava/lang/Integer;->intValue()I

    .line 95
    .line 96
    .line 97
    move-result v6

    .line 98
    goto :goto_5

    .line 99
    :cond_5
    invoke-virtual {v1}, Lorg/altbeacon/beacon/AppliedSettings;->getRegionExitPeriodMillis()I

    .line 100
    .line 101
    .line 102
    move-result v6

    .line 103
    :goto_5
    invoke-virtual {v2}, Lorg/altbeacon/beacon/Settings;->getMaxTrackingAgeMillis()Ljava/lang/Integer;

    .line 104
    .line 105
    .line 106
    move-result-object v8

    .line 107
    if-eqz v8, :cond_6

    .line 108
    .line 109
    invoke-virtual {v8}, Ljava/lang/Integer;->intValue()I

    .line 110
    .line 111
    .line 112
    move-result v8

    .line 113
    goto :goto_6

    .line 114
    :cond_6
    invoke-virtual {v1}, Lorg/altbeacon/beacon/AppliedSettings;->getMaxTrackingAgeMillis()I

    .line 115
    .line 116
    .line 117
    move-result v8

    .line 118
    :goto_6
    invoke-virtual {v2}, Lorg/altbeacon/beacon/Settings;->getManifestCheckingDisabled()Ljava/lang/Boolean;

    .line 119
    .line 120
    .line 121
    move-result-object v9

    .line 122
    if-eqz v9, :cond_7

    .line 123
    .line 124
    invoke-virtual {v9}, Ljava/lang/Boolean;->booleanValue()Z

    .line 125
    .line 126
    .line 127
    move-result v9

    .line 128
    goto :goto_7

    .line 129
    :cond_7
    invoke-virtual {v1}, Lorg/altbeacon/beacon/AppliedSettings;->getManifestCheckingDisabled()Z

    .line 130
    .line 131
    .line 132
    move-result v9

    .line 133
    :goto_7
    invoke-virtual {v2}, Lorg/altbeacon/beacon/Settings;->getBeaconSimulator()Lorg/altbeacon/beacon/simulator/BeaconSimulator;

    .line 134
    .line 135
    .line 136
    move-result-object v10

    .line 137
    if-nez v10, :cond_8

    .line 138
    .line 139
    invoke-virtual {v1}, Lorg/altbeacon/beacon/AppliedSettings;->getBeaconSimulator()Lorg/altbeacon/beacon/simulator/BeaconSimulator;

    .line 140
    .line 141
    .line 142
    move-result-object v10

    .line 143
    :cond_8
    invoke-virtual {v2}, Lorg/altbeacon/beacon/Settings;->getRssiFilterClass()Ljava/lang/Class;

    .line 144
    .line 145
    .line 146
    move-result-object v11

    .line 147
    if-nez v11, :cond_9

    .line 148
    .line 149
    invoke-virtual {v1}, Lorg/altbeacon/beacon/AppliedSettings;->getRssiFilterImplClass()Ljava/lang/Class;

    .line 150
    .line 151
    .line 152
    move-result-object v11

    .line 153
    :cond_9
    invoke-virtual {v2}, Lorg/altbeacon/beacon/Settings;->getScanStrategy()Lorg/altbeacon/beacon/Settings$ScanStrategy;

    .line 154
    .line 155
    .line 156
    move-result-object v12

    .line 157
    if-eqz v12, :cond_b

    .line 158
    .line 159
    invoke-interface {v12}, Lorg/altbeacon/beacon/Settings$ScanStrategy;->clone()Lorg/altbeacon/beacon/Settings$ScanStrategy;

    .line 160
    .line 161
    .line 162
    move-result-object v12

    .line 163
    if-nez v12, :cond_a

    .line 164
    .line 165
    goto :goto_9

    .line 166
    :cond_a
    :goto_8
    move-object v14, v12

    .line 167
    goto :goto_a

    .line 168
    :cond_b
    :goto_9
    invoke-virtual {v1}, Lorg/altbeacon/beacon/AppliedSettings;->getScanStrategy()Lorg/altbeacon/beacon/Settings$ScanStrategy;

    .line 169
    .line 170
    .line 171
    move-result-object v12

    .line 172
    goto :goto_8

    .line 173
    :goto_a
    invoke-virtual {v2}, Lorg/altbeacon/beacon/Settings;->getLongScanForcingEnabled()Ljava/lang/Boolean;

    .line 174
    .line 175
    .line 176
    move-result-object v12

    .line 177
    if-eqz v12, :cond_c

    .line 178
    .line 179
    invoke-virtual {v12}, Ljava/lang/Boolean;->booleanValue()Z

    .line 180
    .line 181
    .line 182
    move-result v12

    .line 183
    :goto_b
    move v15, v12

    .line 184
    goto :goto_c

    .line 185
    :cond_c
    invoke-virtual {v1}, Lorg/altbeacon/beacon/AppliedSettings;->getLongScanForcingEnabled()Z

    .line 186
    .line 187
    .line 188
    move-result v12

    .line 189
    goto :goto_b

    .line 190
    :goto_c
    invoke-virtual {v2}, Lorg/altbeacon/beacon/Settings;->getDistanceModelUpdateUrl()Ljava/lang/String;

    .line 191
    .line 192
    .line 193
    move-result-object v12

    .line 194
    if-nez v12, :cond_d

    .line 195
    .line 196
    invoke-virtual {v1}, Lorg/altbeacon/beacon/AppliedSettings;->getDistanceModelUpdateUrl()Ljava/lang/String;

    .line 197
    .line 198
    .line 199
    move-result-object v12

    .line 200
    :cond_d
    invoke-virtual {v2}, Lorg/altbeacon/beacon/Settings;->getDistanceCalculatorFactory()Lorg/altbeacon/beacon/distance/DistanceCalculatorFactory;

    .line 201
    .line 202
    .line 203
    move-result-object v2

    .line 204
    if-nez v2, :cond_e

    .line 205
    .line 206
    invoke-virtual {v1}, Lorg/altbeacon/beacon/AppliedSettings;->getDistanceCalculatorFactory()Lorg/altbeacon/beacon/distance/DistanceCalculatorFactory;

    .line 207
    .line 208
    .line 209
    move-result-object v2

    .line 210
    :cond_e
    move-object v13, v2

    .line 211
    new-instance v1, Lorg/altbeacon/beacon/AppliedSettings;

    .line 212
    .line 213
    move v2, v0

    .line 214
    invoke-direct/range {v1 .. v15}, Lorg/altbeacon/beacon/AppliedSettings;-><init>(ZZZLorg/altbeacon/beacon/Settings$ScanPeriods;IZIZLorg/altbeacon/beacon/simulator/BeaconSimulator;Ljava/lang/Class;Ljava/lang/String;Lorg/altbeacon/beacon/distance/DistanceCalculatorFactory;Lorg/altbeacon/beacon/Settings$ScanStrategy;Z)V

    .line 215
    .line 216
    .line 217
    return-object v1
.end method

.method public final fromSettings(Lorg/altbeacon/beacon/AppliedSettings;)Lorg/altbeacon/beacon/AppliedSettings;
    .locals 16

    .line 1
    const-string v0, "other"

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    invoke-static {v1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    invoke-virtual {v1}, Lorg/altbeacon/beacon/AppliedSettings;->getScanPeriods()Lorg/altbeacon/beacon/Settings$ScanPeriods;

    .line 9
    .line 10
    .line 11
    move-result-object v5

    .line 12
    invoke-virtual {v1}, Lorg/altbeacon/beacon/AppliedSettings;->getDebug()Z

    .line 13
    .line 14
    .line 15
    move-result v2

    .line 16
    invoke-virtual {v1}, Lorg/altbeacon/beacon/AppliedSettings;->getRegionStatePersistenceEnabled()Z

    .line 17
    .line 18
    .line 19
    move-result v3

    .line 20
    invoke-virtual {v1}, Lorg/altbeacon/beacon/AppliedSettings;->getUseTrackingCache()Z

    .line 21
    .line 22
    .line 23
    move-result v7

    .line 24
    invoke-virtual {v1}, Lorg/altbeacon/beacon/AppliedSettings;->getHardwareEqualityEnforced()Z

    .line 25
    .line 26
    .line 27
    move-result v4

    .line 28
    invoke-virtual {v1}, Lorg/altbeacon/beacon/AppliedSettings;->getRegionExitPeriodMillis()I

    .line 29
    .line 30
    .line 31
    move-result v6

    .line 32
    invoke-virtual {v1}, Lorg/altbeacon/beacon/AppliedSettings;->getMaxTrackingAgeMillis()I

    .line 33
    .line 34
    .line 35
    move-result v8

    .line 36
    invoke-virtual {v1}, Lorg/altbeacon/beacon/AppliedSettings;->getManifestCheckingDisabled()Z

    .line 37
    .line 38
    .line 39
    move-result v9

    .line 40
    invoke-virtual {v1}, Lorg/altbeacon/beacon/AppliedSettings;->getBeaconSimulator()Lorg/altbeacon/beacon/simulator/BeaconSimulator;

    .line 41
    .line 42
    .line 43
    move-result-object v10

    .line 44
    invoke-virtual {v1}, Lorg/altbeacon/beacon/AppliedSettings;->getRssiFilterImplClass()Ljava/lang/Class;

    .line 45
    .line 46
    .line 47
    move-result-object v11

    .line 48
    invoke-virtual {v1}, Lorg/altbeacon/beacon/AppliedSettings;->getScanStrategy()Lorg/altbeacon/beacon/Settings$ScanStrategy;

    .line 49
    .line 50
    .line 51
    move-result-object v0

    .line 52
    invoke-interface {v0}, Lorg/altbeacon/beacon/Settings$ScanStrategy;->clone()Lorg/altbeacon/beacon/Settings$ScanStrategy;

    .line 53
    .line 54
    .line 55
    move-result-object v14

    .line 56
    invoke-virtual {v1}, Lorg/altbeacon/beacon/AppliedSettings;->getLongScanForcingEnabled()Z

    .line 57
    .line 58
    .line 59
    move-result v15

    .line 60
    invoke-virtual {v1}, Lorg/altbeacon/beacon/AppliedSettings;->getDistanceModelUpdateUrl()Ljava/lang/String;

    .line 61
    .line 62
    .line 63
    move-result-object v12

    .line 64
    invoke-virtual {v1}, Lorg/altbeacon/beacon/AppliedSettings;->getDistanceCalculatorFactory()Lorg/altbeacon/beacon/distance/DistanceCalculatorFactory;

    .line 65
    .line 66
    .line 67
    move-result-object v13

    .line 68
    new-instance v1, Lorg/altbeacon/beacon/AppliedSettings;

    .line 69
    .line 70
    invoke-direct/range {v1 .. v15}, Lorg/altbeacon/beacon/AppliedSettings;-><init>(ZZZLorg/altbeacon/beacon/Settings$ScanPeriods;IZIZLorg/altbeacon/beacon/simulator/BeaconSimulator;Ljava/lang/Class;Ljava/lang/String;Lorg/altbeacon/beacon/distance/DistanceCalculatorFactory;Lorg/altbeacon/beacon/Settings$ScanStrategy;Z)V

    .line 71
    .line 72
    .line 73
    return-object v1
.end method

.method public final withDefaultValues()Lorg/altbeacon/beacon/AppliedSettings;
    .locals 15

    .line 1
    sget-object p0, Lorg/altbeacon/beacon/Settings$Defaults;->INSTANCE:Lorg/altbeacon/beacon/Settings$Defaults;

    .line 2
    .line 3
    invoke-virtual {p0}, Lorg/altbeacon/beacon/Settings$Defaults;->getScanPeriods()Lorg/altbeacon/beacon/Settings$ScanPeriods;

    .line 4
    .line 5
    .line 6
    move-result-object v4

    .line 7
    invoke-virtual {p0}, Lorg/altbeacon/beacon/Settings$Defaults;->getBeaconSimulator()Lorg/altbeacon/beacon/Settings$DisabledBeaconSimulator;

    .line 8
    .line 9
    .line 10
    move-result-object v9

    .line 11
    invoke-virtual {p0}, Lorg/altbeacon/beacon/Settings$Defaults;->getRssiFilterImplClass()Ljava/lang/Class;

    .line 12
    .line 13
    .line 14
    move-result-object v10

    .line 15
    invoke-virtual {p0}, Lorg/altbeacon/beacon/Settings$Defaults;->getScanStrategy()Lorg/altbeacon/beacon/Settings$ScanStrategy;

    .line 16
    .line 17
    .line 18
    move-result-object v0

    .line 19
    invoke-interface {v0}, Lorg/altbeacon/beacon/Settings$ScanStrategy;->clone()Lorg/altbeacon/beacon/Settings$ScanStrategy;

    .line 20
    .line 21
    .line 22
    move-result-object v13

    .line 23
    invoke-virtual {p0}, Lorg/altbeacon/beacon/Settings$Defaults;->getDistanceCalculatorFactory()Lorg/altbeacon/beacon/distance/ModelSpecificDistanceCalculatorFactory;

    .line 24
    .line 25
    .line 26
    move-result-object v12

    .line 27
    new-instance v0, Lorg/altbeacon/beacon/AppliedSettings;

    .line 28
    .line 29
    const-string v11, ""

    .line 30
    .line 31
    const/4 v14, 0x0

    .line 32
    const/4 v1, 0x0

    .line 33
    const/4 v2, 0x1

    .line 34
    const/4 v3, 0x0

    .line 35
    const/16 v5, 0x7530

    .line 36
    .line 37
    const/4 v6, 0x1

    .line 38
    const/16 v7, 0x2710

    .line 39
    .line 40
    const/4 v8, 0x0

    .line 41
    invoke-direct/range {v0 .. v14}, Lorg/altbeacon/beacon/AppliedSettings;-><init>(ZZZLorg/altbeacon/beacon/Settings$ScanPeriods;IZIZLorg/altbeacon/beacon/simulator/BeaconSimulator;Ljava/lang/Class;Ljava/lang/String;Lorg/altbeacon/beacon/distance/DistanceCalculatorFactory;Lorg/altbeacon/beacon/Settings$ScanStrategy;Z)V

    .line 42
    .line 43
    .line 44
    return-object v0
.end method
