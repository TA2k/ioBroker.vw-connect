.class public Lorg/altbeacon/beacon/IntentHandler;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field private static final TAG:Ljava/lang/String; = "IntentHandler"


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


# virtual methods
.method public convertIntentsToCallbacks(Landroid/content/Context;Landroid/content/Intent;)V
    .locals 7

    .line 1
    const/4 p0, 0x0

    .line 2
    if-eqz p2, :cond_1

    .line 3
    .line 4
    invoke-virtual {p2}, Landroid/content/Intent;->getExtras()Landroid/os/Bundle;

    .line 5
    .line 6
    .line 7
    move-result-object v0

    .line 8
    if-eqz v0, :cond_1

    .line 9
    .line 10
    invoke-virtual {p2}, Landroid/content/Intent;->getExtras()Landroid/os/Bundle;

    .line 11
    .line 12
    .line 13
    move-result-object v0

    .line 14
    const-string v1, "monitoringData"

    .line 15
    .line 16
    invoke-virtual {v0, v1}, Landroid/os/Bundle;->getBundle(Ljava/lang/String;)Landroid/os/Bundle;

    .line 17
    .line 18
    .line 19
    move-result-object v0

    .line 20
    if-eqz v0, :cond_0

    .line 21
    .line 22
    invoke-virtual {p2}, Landroid/content/Intent;->getExtras()Landroid/os/Bundle;

    .line 23
    .line 24
    .line 25
    move-result-object v0

    .line 26
    invoke-virtual {v0, v1}, Landroid/os/Bundle;->getBundle(Ljava/lang/String;)Landroid/os/Bundle;

    .line 27
    .line 28
    .line 29
    move-result-object v0

    .line 30
    invoke-static {v0}, Lorg/altbeacon/beacon/service/MonitoringData;->fromBundle(Landroid/os/Bundle;)Lorg/altbeacon/beacon/service/MonitoringData;

    .line 31
    .line 32
    .line 33
    move-result-object v0

    .line 34
    goto :goto_0

    .line 35
    :cond_0
    move-object v0, p0

    .line 36
    :goto_0
    invoke-virtual {p2}, Landroid/content/Intent;->getExtras()Landroid/os/Bundle;

    .line 37
    .line 38
    .line 39
    move-result-object v1

    .line 40
    const-string v2, "rangingData"

    .line 41
    .line 42
    invoke-virtual {v1, v2}, Landroid/os/Bundle;->getBundle(Ljava/lang/String;)Landroid/os/Bundle;

    .line 43
    .line 44
    .line 45
    move-result-object v1

    .line 46
    if-eqz v1, :cond_2

    .line 47
    .line 48
    invoke-virtual {p2}, Landroid/content/Intent;->getExtras()Landroid/os/Bundle;

    .line 49
    .line 50
    .line 51
    move-result-object p0

    .line 52
    invoke-virtual {p0, v2}, Landroid/os/Bundle;->getBundle(Ljava/lang/String;)Landroid/os/Bundle;

    .line 53
    .line 54
    .line 55
    move-result-object p0

    .line 56
    invoke-static {p0}, Lorg/altbeacon/beacon/service/RangingData;->fromBundle(Landroid/os/Bundle;)Lorg/altbeacon/beacon/service/RangingData;

    .line 57
    .line 58
    .line 59
    move-result-object p0

    .line 60
    goto :goto_1

    .line 61
    :cond_1
    move-object v0, p0

    .line 62
    :cond_2
    :goto_1
    const/4 p2, 0x0

    .line 63
    if-eqz p0, :cond_7

    .line 64
    .line 65
    sget-object v1, Lorg/altbeacon/beacon/IntentHandler;->TAG:Ljava/lang/String;

    .line 66
    .line 67
    const-string v2, "got ranging data"

    .line 68
    .line 69
    new-array v3, p2, [Ljava/lang/Object;

    .line 70
    .line 71
    invoke-static {v1, v2, v3}, Lorg/altbeacon/beacon/logging/LogManager;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 72
    .line 73
    .line 74
    invoke-virtual {p0}, Lorg/altbeacon/beacon/service/RangingData;->getBeacons()Ljava/util/Collection;

    .line 75
    .line 76
    .line 77
    move-result-object v2

    .line 78
    if-nez v2, :cond_3

    .line 79
    .line 80
    const-string v2, "Ranging data has a null beacons collection"

    .line 81
    .line 82
    new-array v3, p2, [Ljava/lang/Object;

    .line 83
    .line 84
    invoke-static {v1, v2, v3}, Lorg/altbeacon/beacon/logging/LogManager;->w(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 85
    .line 86
    .line 87
    :cond_3
    invoke-static {p1}, Lorg/altbeacon/beacon/BeaconManager;->getInstanceForApplication(Landroid/content/Context;)Lorg/altbeacon/beacon/BeaconManager;

    .line 88
    .line 89
    .line 90
    move-result-object v2

    .line 91
    invoke-virtual {v2}, Lorg/altbeacon/beacon/BeaconManager;->getRangingNotifiers()Ljava/util/Set;

    .line 92
    .line 93
    .line 94
    move-result-object v2

    .line 95
    invoke-virtual {p0}, Lorg/altbeacon/beacon/service/RangingData;->getBeacons()Ljava/util/Collection;

    .line 96
    .line 97
    .line 98
    move-result-object v3

    .line 99
    if-eqz v2, :cond_4

    .line 100
    .line 101
    invoke-interface {v2}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 102
    .line 103
    .line 104
    move-result-object v1

    .line 105
    :goto_2
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 106
    .line 107
    .line 108
    move-result v2

    .line 109
    if-eqz v2, :cond_5

    .line 110
    .line 111
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 112
    .line 113
    .line 114
    move-result-object v2

    .line 115
    check-cast v2, Lorg/altbeacon/beacon/RangeNotifier;

    .line 116
    .line 117
    invoke-virtual {p0}, Lorg/altbeacon/beacon/service/RangingData;->getRegion()Lorg/altbeacon/beacon/Region;

    .line 118
    .line 119
    .line 120
    move-result-object v4

    .line 121
    invoke-interface {v2, v3, v4}, Lorg/altbeacon/beacon/RangeNotifier;->didRangeBeaconsInRegion(Ljava/util/Collection;Lorg/altbeacon/beacon/Region;)V

    .line 122
    .line 123
    .line 124
    goto :goto_2

    .line 125
    :cond_4
    const-string v2, "but ranging notifier is null, so we\'re dropping it."

    .line 126
    .line 127
    new-array v4, p2, [Ljava/lang/Object;

    .line 128
    .line 129
    invoke-static {v1, v2, v4}, Lorg/altbeacon/beacon/logging/LogManager;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 130
    .line 131
    .line 132
    :cond_5
    invoke-static {p1}, Lorg/altbeacon/beacon/BeaconManager;->getInstanceForApplication(Landroid/content/Context;)Lorg/altbeacon/beacon/BeaconManager;

    .line 133
    .line 134
    .line 135
    move-result-object v1

    .line 136
    invoke-virtual {v1}, Lorg/altbeacon/beacon/BeaconManager;->getDataRequestNotifier()Lorg/altbeacon/beacon/RangeNotifier;

    .line 137
    .line 138
    .line 139
    move-result-object v1

    .line 140
    if-eqz v1, :cond_6

    .line 141
    .line 142
    invoke-virtual {p0}, Lorg/altbeacon/beacon/service/RangingData;->getRegion()Lorg/altbeacon/beacon/Region;

    .line 143
    .line 144
    .line 145
    move-result-object v2

    .line 146
    invoke-interface {v1, v3, v2}, Lorg/altbeacon/beacon/RangeNotifier;->didRangeBeaconsInRegion(Ljava/util/Collection;Lorg/altbeacon/beacon/Region;)V

    .line 147
    .line 148
    .line 149
    :cond_6
    invoke-static {p1}, Lorg/altbeacon/beacon/BeaconManager;->getInstanceForApplication(Landroid/content/Context;)Lorg/altbeacon/beacon/BeaconManager;

    .line 150
    .line 151
    .line 152
    move-result-object v1

    .line 153
    invoke-virtual {p0}, Lorg/altbeacon/beacon/service/RangingData;->getRegion()Lorg/altbeacon/beacon/Region;

    .line 154
    .line 155
    .line 156
    move-result-object v2

    .line 157
    invoke-virtual {v1, v2}, Lorg/altbeacon/beacon/BeaconManager;->isRegionViewModelInitialized(Lorg/altbeacon/beacon/Region;)Z

    .line 158
    .line 159
    .line 160
    move-result v1

    .line 161
    if-eqz v1, :cond_7

    .line 162
    .line 163
    invoke-static {p1}, Lorg/altbeacon/beacon/BeaconManager;->getInstanceForApplication(Landroid/content/Context;)Lorg/altbeacon/beacon/BeaconManager;

    .line 164
    .line 165
    .line 166
    move-result-object v1

    .line 167
    invoke-virtual {p0}, Lorg/altbeacon/beacon/service/RangingData;->getRegion()Lorg/altbeacon/beacon/Region;

    .line 168
    .line 169
    .line 170
    move-result-object v2

    .line 171
    invoke-virtual {v1, v2}, Lorg/altbeacon/beacon/BeaconManager;->getRegionViewModel(Lorg/altbeacon/beacon/Region;)Lorg/altbeacon/beacon/RegionViewModel;

    .line 172
    .line 173
    .line 174
    move-result-object v1

    .line 175
    invoke-virtual {v1}, Lorg/altbeacon/beacon/RegionViewModel;->getRangedBeacons()Landroidx/lifecycle/i0;

    .line 176
    .line 177
    .line 178
    move-result-object v1

    .line 179
    invoke-virtual {p0}, Lorg/altbeacon/beacon/service/RangingData;->getBeacons()Ljava/util/Collection;

    .line 180
    .line 181
    .line 182
    move-result-object p0

    .line 183
    invoke-virtual {v1, p0}, Landroidx/lifecycle/i0;->k(Ljava/lang/Object;)V

    .line 184
    .line 185
    .line 186
    :cond_7
    if-eqz v0, :cond_a

    .line 187
    .line 188
    sget-object p0, Lorg/altbeacon/beacon/IntentHandler;->TAG:Ljava/lang/String;

    .line 189
    .line 190
    const-string v1, "got monitoring data"

    .line 191
    .line 192
    new-array p2, p2, [Ljava/lang/Object;

    .line 193
    .line 194
    invoke-static {p0, v1, p2}, Lorg/altbeacon/beacon/logging/LogManager;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 195
    .line 196
    .line 197
    invoke-static {p1}, Lorg/altbeacon/beacon/BeaconManager;->getInstanceForApplication(Landroid/content/Context;)Lorg/altbeacon/beacon/BeaconManager;

    .line 198
    .line 199
    .line 200
    move-result-object p0

    .line 201
    invoke-virtual {p0}, Lorg/altbeacon/beacon/BeaconManager;->getMonitoringNotifiers()Ljava/util/Set;

    .line 202
    .line 203
    .line 204
    move-result-object p0

    .line 205
    invoke-virtual {v0}, Lorg/altbeacon/beacon/service/MonitoringData;->getRegion()Lorg/altbeacon/beacon/Region;

    .line 206
    .line 207
    .line 208
    move-result-object p2

    .line 209
    invoke-virtual {v0}, Lorg/altbeacon/beacon/service/MonitoringData;->isInside()Z

    .line 210
    .line 211
    .line 212
    move-result v1

    .line 213
    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 214
    .line 215
    .line 216
    move-result-object v2

    .line 217
    if-eqz p0, :cond_9

    .line 218
    .line 219
    invoke-interface {p0}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 220
    .line 221
    .line 222
    move-result-object p0

    .line 223
    :goto_3
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 224
    .line 225
    .line 226
    move-result v3

    .line 227
    if-eqz v3, :cond_9

    .line 228
    .line 229
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 230
    .line 231
    .line 232
    move-result-object v3

    .line 233
    check-cast v3, Lorg/altbeacon/beacon/MonitorNotifier;

    .line 234
    .line 235
    sget-object v4, Lorg/altbeacon/beacon/IntentHandler;->TAG:Ljava/lang/String;

    .line 236
    .line 237
    const-string v5, "Calling monitoring notifier: %s"

    .line 238
    .line 239
    filled-new-array {v3}, [Ljava/lang/Object;

    .line 240
    .line 241
    .line 242
    move-result-object v6

    .line 243
    invoke-static {v4, v5, v6}, Lorg/altbeacon/beacon/logging/LogManager;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 244
    .line 245
    .line 246
    invoke-interface {v3, v1, p2}, Lorg/altbeacon/beacon/MonitorNotifier;->didDetermineStateForRegion(ILorg/altbeacon/beacon/Region;)V

    .line 247
    .line 248
    .line 249
    invoke-static {p1}, Lorg/altbeacon/beacon/service/MonitoringStatus;->getInstanceForApplication(Landroid/content/Context;)Lorg/altbeacon/beacon/service/MonitoringStatus;

    .line 250
    .line 251
    .line 252
    move-result-object v4

    .line 253
    invoke-virtual {v4, p2, v2}, Lorg/altbeacon/beacon/service/MonitoringStatus;->updateLocalState(Lorg/altbeacon/beacon/Region;Ljava/lang/Integer;)V

    .line 254
    .line 255
    .line 256
    invoke-virtual {v0}, Lorg/altbeacon/beacon/service/MonitoringData;->isInside()Z

    .line 257
    .line 258
    .line 259
    move-result v4

    .line 260
    if-eqz v4, :cond_8

    .line 261
    .line 262
    invoke-virtual {v0}, Lorg/altbeacon/beacon/service/MonitoringData;->getRegion()Lorg/altbeacon/beacon/Region;

    .line 263
    .line 264
    .line 265
    move-result-object v4

    .line 266
    invoke-interface {v3, v4}, Lorg/altbeacon/beacon/MonitorNotifier;->didEnterRegion(Lorg/altbeacon/beacon/Region;)V

    .line 267
    .line 268
    .line 269
    goto :goto_3

    .line 270
    :cond_8
    invoke-virtual {v0}, Lorg/altbeacon/beacon/service/MonitoringData;->getRegion()Lorg/altbeacon/beacon/Region;

    .line 271
    .line 272
    .line 273
    move-result-object v4

    .line 274
    invoke-interface {v3, v4}, Lorg/altbeacon/beacon/MonitorNotifier;->didExitRegion(Lorg/altbeacon/beacon/Region;)V

    .line 275
    .line 276
    .line 277
    goto :goto_3

    .line 278
    :cond_9
    invoke-static {p1}, Lorg/altbeacon/beacon/BeaconManager;->getInstanceForApplication(Landroid/content/Context;)Lorg/altbeacon/beacon/BeaconManager;

    .line 279
    .line 280
    .line 281
    move-result-object p0

    .line 282
    invoke-virtual {v0}, Lorg/altbeacon/beacon/service/MonitoringData;->getRegion()Lorg/altbeacon/beacon/Region;

    .line 283
    .line 284
    .line 285
    move-result-object p2

    .line 286
    invoke-virtual {p0, p2}, Lorg/altbeacon/beacon/BeaconManager;->isRegionViewModelInitialized(Lorg/altbeacon/beacon/Region;)Z

    .line 287
    .line 288
    .line 289
    move-result p0

    .line 290
    if-eqz p0, :cond_a

    .line 291
    .line 292
    invoke-static {p1}, Lorg/altbeacon/beacon/BeaconManager;->getInstanceForApplication(Landroid/content/Context;)Lorg/altbeacon/beacon/BeaconManager;

    .line 293
    .line 294
    .line 295
    move-result-object p0

    .line 296
    invoke-virtual {v0}, Lorg/altbeacon/beacon/service/MonitoringData;->getRegion()Lorg/altbeacon/beacon/Region;

    .line 297
    .line 298
    .line 299
    move-result-object p1

    .line 300
    invoke-virtual {p0, p1}, Lorg/altbeacon/beacon/BeaconManager;->getRegionViewModel(Lorg/altbeacon/beacon/Region;)Lorg/altbeacon/beacon/RegionViewModel;

    .line 301
    .line 302
    .line 303
    move-result-object p0

    .line 304
    invoke-virtual {p0}, Lorg/altbeacon/beacon/RegionViewModel;->getRegionState()Landroidx/lifecycle/i0;

    .line 305
    .line 306
    .line 307
    move-result-object p0

    .line 308
    invoke-virtual {p0, v2}, Landroidx/lifecycle/i0;->k(Ljava/lang/Object;)V

    .line 309
    .line 310
    .line 311
    :cond_a
    return-void
.end method
