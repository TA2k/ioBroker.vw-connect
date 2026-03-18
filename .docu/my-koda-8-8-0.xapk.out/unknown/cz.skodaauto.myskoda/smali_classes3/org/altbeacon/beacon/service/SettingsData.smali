.class public Lorg/altbeacon/beacon/service/SettingsData;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/io/Serializable;


# static fields
.field private static final SETTINGS_DATA_KEY:Ljava/lang/String; = "SettingsData"

.field private static final TAG:Ljava/lang/String; = "SettingsData"


# instance fields
.field mAndroidLScanningDisabled:Ljava/lang/Boolean;

.field mBeaconParsers:Ljava/util/ArrayList;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/ArrayList<",
            "Lorg/altbeacon/beacon/BeaconParser;",
            ">;"
        }
    .end annotation
.end field

.field mHardwareEqualityEnforced:Ljava/lang/Boolean;

.field mRegionExitPeriod:Ljava/lang/Long;

.field mRegionStatePersistenceEnabled:Ljava/lang/Boolean;

.field mUseTrackingCache:Ljava/lang/Boolean;


# direct methods
.method public constructor <init>()V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static fromBundle(Landroid/os/Bundle;)Lorg/altbeacon/beacon/service/SettingsData;
    .locals 2

    .line 1
    const-class v0, Lorg/altbeacon/beacon/Region;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/Class;->getClassLoader()Ljava/lang/ClassLoader;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    invoke-virtual {p0, v0}, Landroid/os/Bundle;->setClassLoader(Ljava/lang/ClassLoader;)V

    .line 8
    .line 9
    .line 10
    const-string v0, "SettingsData"

    .line 11
    .line 12
    invoke-virtual {p0, v0}, Landroid/os/BaseBundle;->get(Ljava/lang/String;)Ljava/lang/Object;

    .line 13
    .line 14
    .line 15
    move-result-object v1

    .line 16
    if-eqz v1, :cond_0

    .line 17
    .line 18
    invoke-virtual {p0, v0}, Landroid/os/Bundle;->getSerializable(Ljava/lang/String;)Ljava/io/Serializable;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    check-cast p0, Lorg/altbeacon/beacon/service/SettingsData;

    .line 23
    .line 24
    return-object p0

    .line 25
    :cond_0
    const/4 p0, 0x0

    .line 26
    return-object p0
.end method


# virtual methods
.method public apply(Lorg/altbeacon/beacon/service/BeaconService;)V
    .locals 6

    .line 1
    invoke-static {p1}, Lorg/altbeacon/beacon/BeaconManager;->getInstanceForApplication(Landroid/content/Context;)Lorg/altbeacon/beacon/BeaconManager;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    invoke-virtual {v0}, Lorg/altbeacon/beacon/BeaconManager;->isMainProcess()Z

    .line 6
    .line 7
    .line 8
    move-result v1

    .line 9
    const/4 v2, 0x0

    .line 10
    if-eqz v1, :cond_0

    .line 11
    .line 12
    sget-object p0, Lorg/altbeacon/beacon/service/SettingsData;->TAG:Ljava/lang/String;

    .line 13
    .line 14
    const-string v0, "API Applying settings changes to scanner service"

    .line 15
    .line 16
    new-array v1, v2, [Ljava/lang/Object;

    .line 17
    .line 18
    invoke-static {p0, v0, v1}, Lorg/altbeacon/beacon/logging/LogManager;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 19
    .line 20
    .line 21
    invoke-virtual {p1}, Lorg/altbeacon/beacon/service/BeaconService;->reloadParsers()V

    .line 22
    .line 23
    .line 24
    return-void

    .line 25
    :cond_0
    sget-object v1, Lorg/altbeacon/beacon/service/SettingsData;->TAG:Ljava/lang/String;

    .line 26
    .line 27
    const-string v3, "API Applying settings changes to scanner in other process"

    .line 28
    .line 29
    new-array v4, v2, [Ljava/lang/Object;

    .line 30
    .line 31
    invoke-static {v1, v3, v4}, Lorg/altbeacon/beacon/logging/LogManager;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 32
    .line 33
    .line 34
    invoke-virtual {v0}, Lorg/altbeacon/beacon/BeaconManager;->getBeaconParsers()Ljava/util/List;

    .line 35
    .line 36
    .line 37
    move-result-object v3

    .line 38
    invoke-interface {v3}, Ljava/util/List;->size()I

    .line 39
    .line 40
    .line 41
    move-result v4

    .line 42
    iget-object v5, p0, Lorg/altbeacon/beacon/service/SettingsData;->mBeaconParsers:Ljava/util/ArrayList;

    .line 43
    .line 44
    invoke-virtual {v5}, Ljava/util/ArrayList;->size()I

    .line 45
    .line 46
    .line 47
    move-result v5

    .line 48
    if-ne v4, v5, :cond_3

    .line 49
    .line 50
    move v1, v2

    .line 51
    :goto_0
    invoke-interface {v3}, Ljava/util/List;->size()I

    .line 52
    .line 53
    .line 54
    move-result v4

    .line 55
    if-ge v1, v4, :cond_2

    .line 56
    .line 57
    invoke-interface {v3, v1}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 58
    .line 59
    .line 60
    move-result-object v4

    .line 61
    check-cast v4, Lorg/altbeacon/beacon/BeaconParser;

    .line 62
    .line 63
    iget-object v5, p0, Lorg/altbeacon/beacon/service/SettingsData;->mBeaconParsers:Ljava/util/ArrayList;

    .line 64
    .line 65
    invoke-virtual {v5, v1}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 66
    .line 67
    .line 68
    move-result-object v5

    .line 69
    invoke-virtual {v4, v5}, Lorg/altbeacon/beacon/BeaconParser;->equals(Ljava/lang/Object;)Z

    .line 70
    .line 71
    .line 72
    move-result v4

    .line 73
    if-nez v4, :cond_1

    .line 74
    .line 75
    sget-object v3, Lorg/altbeacon/beacon/service/SettingsData;->TAG:Ljava/lang/String;

    .line 76
    .line 77
    new-instance v4, Ljava/lang/StringBuilder;

    .line 78
    .line 79
    const-string v5, "Beacon parsers have changed to: "

    .line 80
    .line 81
    invoke-direct {v4, v5}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 82
    .line 83
    .line 84
    iget-object v5, p0, Lorg/altbeacon/beacon/service/SettingsData;->mBeaconParsers:Ljava/util/ArrayList;

    .line 85
    .line 86
    invoke-virtual {v5, v1}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 87
    .line 88
    .line 89
    move-result-object v1

    .line 90
    check-cast v1, Lorg/altbeacon/beacon/BeaconParser;

    .line 91
    .line 92
    invoke-virtual {v1}, Lorg/altbeacon/beacon/BeaconParser;->getLayout()Ljava/lang/String;

    .line 93
    .line 94
    .line 95
    move-result-object v1

    .line 96
    invoke-virtual {v4, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 97
    .line 98
    .line 99
    invoke-virtual {v4}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 100
    .line 101
    .line 102
    move-result-object v1

    .line 103
    new-array v4, v2, [Ljava/lang/Object;

    .line 104
    .line 105
    invoke-static {v3, v1, v4}, Lorg/altbeacon/beacon/logging/LogManager;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 106
    .line 107
    .line 108
    goto :goto_1

    .line 109
    :cond_1
    add-int/lit8 v1, v1, 0x1

    .line 110
    .line 111
    goto :goto_0

    .line 112
    :cond_2
    sget-object v0, Lorg/altbeacon/beacon/service/SettingsData;->TAG:Ljava/lang/String;

    .line 113
    .line 114
    const-string v1, "Beacon parsers unchanged."

    .line 115
    .line 116
    new-array v2, v2, [Ljava/lang/Object;

    .line 117
    .line 118
    invoke-static {v0, v1, v2}, Lorg/altbeacon/beacon/logging/LogManager;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 119
    .line 120
    .line 121
    goto :goto_2

    .line 122
    :cond_3
    const-string v3, "Beacon parsers have been added or removed."

    .line 123
    .line 124
    new-array v4, v2, [Ljava/lang/Object;

    .line 125
    .line 126
    invoke-static {v1, v3, v4}, Lorg/altbeacon/beacon/logging/LogManager;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 127
    .line 128
    .line 129
    :goto_1
    sget-object v1, Lorg/altbeacon/beacon/service/SettingsData;->TAG:Ljava/lang/String;

    .line 130
    .line 131
    const-string v3, "Updating beacon parsers"

    .line 132
    .line 133
    new-array v2, v2, [Ljava/lang/Object;

    .line 134
    .line 135
    invoke-static {v1, v3, v2}, Lorg/altbeacon/beacon/logging/LogManager;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 136
    .line 137
    .line 138
    invoke-virtual {v0}, Lorg/altbeacon/beacon/BeaconManager;->getBeaconParsers()Ljava/util/List;

    .line 139
    .line 140
    .line 141
    move-result-object v1

    .line 142
    invoke-interface {v1}, Ljava/util/List;->clear()V

    .line 143
    .line 144
    .line 145
    invoke-virtual {v0}, Lorg/altbeacon/beacon/BeaconManager;->getBeaconParsers()Ljava/util/List;

    .line 146
    .line 147
    .line 148
    move-result-object v0

    .line 149
    iget-object v1, p0, Lorg/altbeacon/beacon/service/SettingsData;->mBeaconParsers:Ljava/util/ArrayList;

    .line 150
    .line 151
    invoke-interface {v0, v1}, Ljava/util/List;->addAll(Ljava/util/Collection;)Z

    .line 152
    .line 153
    .line 154
    invoke-virtual {p1}, Lorg/altbeacon/beacon/service/BeaconService;->reloadParsers()V

    .line 155
    .line 156
    .line 157
    :goto_2
    invoke-static {p1}, Lorg/altbeacon/beacon/service/MonitoringStatus;->getInstanceForApplication(Landroid/content/Context;)Lorg/altbeacon/beacon/service/MonitoringStatus;

    .line 158
    .line 159
    .line 160
    move-result-object p1

    .line 161
    invoke-virtual {p1}, Lorg/altbeacon/beacon/service/MonitoringStatus;->isStatePreservationOn()Z

    .line 162
    .line 163
    .line 164
    move-result v0

    .line 165
    if-eqz v0, :cond_4

    .line 166
    .line 167
    iget-object v0, p0, Lorg/altbeacon/beacon/service/SettingsData;->mRegionStatePersistenceEnabled:Ljava/lang/Boolean;

    .line 168
    .line 169
    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 170
    .line 171
    .line 172
    move-result v0

    .line 173
    if-nez v0, :cond_4

    .line 174
    .line 175
    invoke-virtual {p1}, Lorg/altbeacon/beacon/service/MonitoringStatus;->stopStatusPreservation()V

    .line 176
    .line 177
    .line 178
    goto :goto_3

    .line 179
    :cond_4
    invoke-virtual {p1}, Lorg/altbeacon/beacon/service/MonitoringStatus;->isStatePreservationOn()Z

    .line 180
    .line 181
    .line 182
    move-result v0

    .line 183
    if-nez v0, :cond_5

    .line 184
    .line 185
    iget-object v0, p0, Lorg/altbeacon/beacon/service/SettingsData;->mRegionStatePersistenceEnabled:Ljava/lang/Boolean;

    .line 186
    .line 187
    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 188
    .line 189
    .line 190
    move-result v0

    .line 191
    if-eqz v0, :cond_5

    .line 192
    .line 193
    invoke-virtual {p1}, Lorg/altbeacon/beacon/service/MonitoringStatus;->startStatusPreservation()V

    .line 194
    .line 195
    .line 196
    :cond_5
    :goto_3
    iget-object p1, p0, Lorg/altbeacon/beacon/service/SettingsData;->mAndroidLScanningDisabled:Ljava/lang/Boolean;

    .line 197
    .line 198
    invoke-virtual {p1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 199
    .line 200
    .line 201
    move-result p1

    .line 202
    invoke-static {p1}, Lorg/altbeacon/beacon/BeaconManager;->setAndroidLScanningDisabled(Z)V

    .line 203
    .line 204
    .line 205
    iget-object p1, p0, Lorg/altbeacon/beacon/service/SettingsData;->mRegionExitPeriod:Ljava/lang/Long;

    .line 206
    .line 207
    invoke-virtual {p1}, Ljava/lang/Long;->longValue()J

    .line 208
    .line 209
    .line 210
    move-result-wide v0

    .line 211
    invoke-static {v0, v1}, Lorg/altbeacon/beacon/BeaconManager;->setRegionExitPeriod(J)V

    .line 212
    .line 213
    .line 214
    iget-object p1, p0, Lorg/altbeacon/beacon/service/SettingsData;->mUseTrackingCache:Ljava/lang/Boolean;

    .line 215
    .line 216
    invoke-virtual {p1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 217
    .line 218
    .line 219
    move-result p1

    .line 220
    invoke-static {p1}, Lorg/altbeacon/beacon/service/RangeState;->setUseTrackingCache(Z)V

    .line 221
    .line 222
    .line 223
    iget-object p0, p0, Lorg/altbeacon/beacon/service/SettingsData;->mHardwareEqualityEnforced:Ljava/lang/Boolean;

    .line 224
    .line 225
    invoke-virtual {p0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 226
    .line 227
    .line 228
    move-result p0

    .line 229
    invoke-static {p0}, Lorg/altbeacon/beacon/Beacon;->setHardwareEqualityEnforced(Z)V

    .line 230
    .line 231
    .line 232
    return-void
.end method

.method public collect(Landroid/content/Context;)Lorg/altbeacon/beacon/service/SettingsData;
    .locals 2

    .line 1
    invoke-static {p1}, Lorg/altbeacon/beacon/BeaconManager;->getInstanceForApplication(Landroid/content/Context;)Lorg/altbeacon/beacon/BeaconManager;

    .line 2
    .line 3
    .line 4
    move-result-object p1

    .line 5
    new-instance v0, Ljava/util/ArrayList;

    .line 6
    .line 7
    invoke-virtual {p1}, Lorg/altbeacon/beacon/BeaconManager;->getBeaconParsers()Ljava/util/List;

    .line 8
    .line 9
    .line 10
    move-result-object v1

    .line 11
    invoke-direct {v0, v1}, Ljava/util/ArrayList;-><init>(Ljava/util/Collection;)V

    .line 12
    .line 13
    .line 14
    iput-object v0, p0, Lorg/altbeacon/beacon/service/SettingsData;->mBeaconParsers:Ljava/util/ArrayList;

    .line 15
    .line 16
    invoke-virtual {p1}, Lorg/altbeacon/beacon/BeaconManager;->isRegionStatePersistenceEnabled()Z

    .line 17
    .line 18
    .line 19
    move-result p1

    .line 20
    invoke-static {p1}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 21
    .line 22
    .line 23
    move-result-object p1

    .line 24
    iput-object p1, p0, Lorg/altbeacon/beacon/service/SettingsData;->mRegionStatePersistenceEnabled:Ljava/lang/Boolean;

    .line 25
    .line 26
    invoke-static {}, Lorg/altbeacon/beacon/BeaconManager;->isAndroidLScanningDisabled()Z

    .line 27
    .line 28
    .line 29
    move-result p1

    .line 30
    invoke-static {p1}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 31
    .line 32
    .line 33
    move-result-object p1

    .line 34
    iput-object p1, p0, Lorg/altbeacon/beacon/service/SettingsData;->mAndroidLScanningDisabled:Ljava/lang/Boolean;

    .line 35
    .line 36
    invoke-static {}, Lorg/altbeacon/beacon/BeaconManager;->getRegionExitPeriod()J

    .line 37
    .line 38
    .line 39
    move-result-wide v0

    .line 40
    invoke-static {v0, v1}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 41
    .line 42
    .line 43
    move-result-object p1

    .line 44
    iput-object p1, p0, Lorg/altbeacon/beacon/service/SettingsData;->mRegionExitPeriod:Ljava/lang/Long;

    .line 45
    .line 46
    invoke-static {}, Lorg/altbeacon/beacon/service/RangeState;->getUseTrackingCache()Z

    .line 47
    .line 48
    .line 49
    move-result p1

    .line 50
    invoke-static {p1}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 51
    .line 52
    .line 53
    move-result-object p1

    .line 54
    iput-object p1, p0, Lorg/altbeacon/beacon/service/SettingsData;->mUseTrackingCache:Ljava/lang/Boolean;

    .line 55
    .line 56
    invoke-static {}, Lorg/altbeacon/beacon/Beacon;->getHardwareEqualityEnforced()Z

    .line 57
    .line 58
    .line 59
    move-result p1

    .line 60
    invoke-static {p1}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 61
    .line 62
    .line 63
    move-result-object p1

    .line 64
    iput-object p1, p0, Lorg/altbeacon/beacon/service/SettingsData;->mHardwareEqualityEnforced:Ljava/lang/Boolean;

    .line 65
    .line 66
    return-object p0
.end method

.method public toBundle()Landroid/os/Bundle;
    .locals 2

    .line 1
    new-instance v0, Landroid/os/Bundle;

    .line 2
    .line 3
    invoke-direct {v0}, Landroid/os/Bundle;-><init>()V

    .line 4
    .line 5
    .line 6
    const-string v1, "SettingsData"

    .line 7
    .line 8
    invoke-virtual {v0, v1, p0}, Landroid/os/Bundle;->putSerializable(Ljava/lang/String;Ljava/io/Serializable;)V

    .line 9
    .line 10
    .line 11
    return-object v0
.end method
