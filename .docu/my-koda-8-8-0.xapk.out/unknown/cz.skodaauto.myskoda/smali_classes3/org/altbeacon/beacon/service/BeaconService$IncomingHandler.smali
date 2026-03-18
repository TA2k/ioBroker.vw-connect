.class Lorg/altbeacon/beacon/service/BeaconService$IncomingHandler;
.super Landroid/os/Handler;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lorg/altbeacon/beacon/service/BeaconService;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x9
    name = "IncomingHandler"
.end annotation


# instance fields
.field private final mService:Ljava/lang/ref/WeakReference;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/lang/ref/WeakReference<",
            "Lorg/altbeacon/beacon/service/BeaconService;",
            ">;"
        }
    .end annotation
.end field


# direct methods
.method public constructor <init>(Lorg/altbeacon/beacon/service/BeaconService;)V
    .locals 1

    .line 1
    invoke-static {}, Landroid/os/Looper;->getMainLooper()Landroid/os/Looper;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    invoke-direct {p0, v0}, Landroid/os/Handler;-><init>(Landroid/os/Looper;)V

    .line 6
    .line 7
    .line 8
    new-instance v0, Ljava/lang/ref/WeakReference;

    .line 9
    .line 10
    invoke-direct {v0, p1}, Ljava/lang/ref/WeakReference;-><init>(Ljava/lang/Object;)V

    .line 11
    .line 12
    .line 13
    iput-object v0, p0, Lorg/altbeacon/beacon/service/BeaconService$IncomingHandler;->mService:Ljava/lang/ref/WeakReference;

    .line 14
    .line 15
    return-void
.end method


# virtual methods
.method public handleMessage(Landroid/os/Message;)V
    .locals 7

    .line 1
    iget-object v0, p0, Lorg/altbeacon/beacon/service/BeaconService$IncomingHandler;->mService:Ljava/lang/ref/WeakReference;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/ref/Reference;->get()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    move-object v1, v0

    .line 8
    check-cast v1, Lorg/altbeacon/beacon/service/BeaconService;

    .line 9
    .line 10
    if-eqz v1, :cond_8

    .line 11
    .line 12
    invoke-virtual {p1}, Landroid/os/Message;->getData()Landroid/os/Bundle;

    .line 13
    .line 14
    .line 15
    move-result-object v0

    .line 16
    invoke-static {v0}, Lorg/altbeacon/beacon/service/StartRMData;->fromBundle(Landroid/os/Bundle;)Lorg/altbeacon/beacon/service/StartRMData;

    .line 17
    .line 18
    .line 19
    move-result-object v0

    .line 20
    const/4 v2, 0x0

    .line 21
    const-string v3, "BeaconService"

    .line 22
    .line 23
    if-eqz v0, :cond_5

    .line 24
    .line 25
    iget v4, p1, Landroid/os/Message;->what:I

    .line 26
    .line 27
    const/4 v5, 0x2

    .line 28
    if-eq v4, v5, :cond_4

    .line 29
    .line 30
    const/4 v5, 0x3

    .line 31
    if-eq v4, v5, :cond_3

    .line 32
    .line 33
    const/4 v5, 0x4

    .line 34
    if-eq v4, v5, :cond_2

    .line 35
    .line 36
    const/4 v5, 0x5

    .line 37
    if-eq v4, v5, :cond_1

    .line 38
    .line 39
    const/4 v5, 0x6

    .line 40
    if-eq v4, v5, :cond_0

    .line 41
    .line 42
    invoke-super {p0, p1}, Landroid/os/Handler;->handleMessage(Landroid/os/Message;)V

    .line 43
    .line 44
    .line 45
    return-void

    .line 46
    :cond_0
    const-string p0, "set scan intervals received"

    .line 47
    .line 48
    new-array p1, v2, [Ljava/lang/Object;

    .line 49
    .line 50
    invoke-static {v3, p0, p1}, Lorg/altbeacon/beacon/logging/LogManager;->i(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 51
    .line 52
    .line 53
    invoke-virtual {v0}, Lorg/altbeacon/beacon/service/StartRMData;->getScanPeriod()J

    .line 54
    .line 55
    .line 56
    move-result-wide v2

    .line 57
    invoke-virtual {v0}, Lorg/altbeacon/beacon/service/StartRMData;->getBetweenScanPeriod()J

    .line 58
    .line 59
    .line 60
    move-result-wide v4

    .line 61
    invoke-virtual {v0}, Lorg/altbeacon/beacon/service/StartRMData;->getBackgroundFlag()Z

    .line 62
    .line 63
    .line 64
    move-result v6

    .line 65
    invoke-virtual/range {v1 .. v6}, Lorg/altbeacon/beacon/service/BeaconService;->setScanPeriods(JJZ)V

    .line 66
    .line 67
    .line 68
    return-void

    .line 69
    :cond_1
    const-string p0, "stop monitoring received"

    .line 70
    .line 71
    new-array p1, v2, [Ljava/lang/Object;

    .line 72
    .line 73
    invoke-static {v3, p0, p1}, Lorg/altbeacon/beacon/logging/LogManager;->i(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 74
    .line 75
    .line 76
    invoke-virtual {v0}, Lorg/altbeacon/beacon/service/StartRMData;->getRegionData()Lorg/altbeacon/beacon/Region;

    .line 77
    .line 78
    .line 79
    move-result-object p0

    .line 80
    invoke-virtual {v1, p0}, Lorg/altbeacon/beacon/service/BeaconService;->stopMonitoringBeaconsInRegion(Lorg/altbeacon/beacon/Region;)V

    .line 81
    .line 82
    .line 83
    invoke-virtual {v0}, Lorg/altbeacon/beacon/service/StartRMData;->getScanPeriod()J

    .line 84
    .line 85
    .line 86
    move-result-wide v2

    .line 87
    invoke-virtual {v0}, Lorg/altbeacon/beacon/service/StartRMData;->getBetweenScanPeriod()J

    .line 88
    .line 89
    .line 90
    move-result-wide v4

    .line 91
    invoke-virtual {v0}, Lorg/altbeacon/beacon/service/StartRMData;->getBackgroundFlag()Z

    .line 92
    .line 93
    .line 94
    move-result v6

    .line 95
    invoke-virtual/range {v1 .. v6}, Lorg/altbeacon/beacon/service/BeaconService;->setScanPeriods(JJZ)V

    .line 96
    .line 97
    .line 98
    return-void

    .line 99
    :cond_2
    const-string p0, "start monitoring received"

    .line 100
    .line 101
    new-array p1, v2, [Ljava/lang/Object;

    .line 102
    .line 103
    invoke-static {v3, p0, p1}, Lorg/altbeacon/beacon/logging/LogManager;->i(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 104
    .line 105
    .line 106
    invoke-virtual {v0}, Lorg/altbeacon/beacon/service/StartRMData;->getRegionData()Lorg/altbeacon/beacon/Region;

    .line 107
    .line 108
    .line 109
    move-result-object p0

    .line 110
    new-instance p1, Lorg/altbeacon/beacon/service/Callback;

    .line 111
    .line 112
    invoke-virtual {v0}, Lorg/altbeacon/beacon/service/StartRMData;->getCallbackPackageName()Ljava/lang/String;

    .line 113
    .line 114
    .line 115
    move-result-object v2

    .line 116
    invoke-direct {p1, v2}, Lorg/altbeacon/beacon/service/Callback;-><init>(Ljava/lang/String;)V

    .line 117
    .line 118
    .line 119
    invoke-virtual {v1, p0, p1}, Lorg/altbeacon/beacon/service/BeaconService;->startMonitoringBeaconsInRegion(Lorg/altbeacon/beacon/Region;Lorg/altbeacon/beacon/service/Callback;)V

    .line 120
    .line 121
    .line 122
    invoke-virtual {v0}, Lorg/altbeacon/beacon/service/StartRMData;->getScanPeriod()J

    .line 123
    .line 124
    .line 125
    move-result-wide v2

    .line 126
    invoke-virtual {v0}, Lorg/altbeacon/beacon/service/StartRMData;->getBetweenScanPeriod()J

    .line 127
    .line 128
    .line 129
    move-result-wide v4

    .line 130
    invoke-virtual {v0}, Lorg/altbeacon/beacon/service/StartRMData;->getBackgroundFlag()Z

    .line 131
    .line 132
    .line 133
    move-result v6

    .line 134
    invoke-virtual/range {v1 .. v6}, Lorg/altbeacon/beacon/service/BeaconService;->setScanPeriods(JJZ)V

    .line 135
    .line 136
    .line 137
    return-void

    .line 138
    :cond_3
    const-string p0, "stop ranging received"

    .line 139
    .line 140
    new-array p1, v2, [Ljava/lang/Object;

    .line 141
    .line 142
    invoke-static {v3, p0, p1}, Lorg/altbeacon/beacon/logging/LogManager;->i(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 143
    .line 144
    .line 145
    invoke-virtual {v0}, Lorg/altbeacon/beacon/service/StartRMData;->getRegionData()Lorg/altbeacon/beacon/Region;

    .line 146
    .line 147
    .line 148
    move-result-object p0

    .line 149
    invoke-virtual {v1, p0}, Lorg/altbeacon/beacon/service/BeaconService;->stopRangingBeaconsInRegion(Lorg/altbeacon/beacon/Region;)V

    .line 150
    .line 151
    .line 152
    invoke-virtual {v0}, Lorg/altbeacon/beacon/service/StartRMData;->getScanPeriod()J

    .line 153
    .line 154
    .line 155
    move-result-wide v2

    .line 156
    invoke-virtual {v0}, Lorg/altbeacon/beacon/service/StartRMData;->getBetweenScanPeriod()J

    .line 157
    .line 158
    .line 159
    move-result-wide v4

    .line 160
    invoke-virtual {v0}, Lorg/altbeacon/beacon/service/StartRMData;->getBackgroundFlag()Z

    .line 161
    .line 162
    .line 163
    move-result v6

    .line 164
    invoke-virtual/range {v1 .. v6}, Lorg/altbeacon/beacon/service/BeaconService;->setScanPeriods(JJZ)V

    .line 165
    .line 166
    .line 167
    return-void

    .line 168
    :cond_4
    const-string p0, "start ranging received"

    .line 169
    .line 170
    new-array p1, v2, [Ljava/lang/Object;

    .line 171
    .line 172
    invoke-static {v3, p0, p1}, Lorg/altbeacon/beacon/logging/LogManager;->i(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 173
    .line 174
    .line 175
    invoke-virtual {v0}, Lorg/altbeacon/beacon/service/StartRMData;->getRegionData()Lorg/altbeacon/beacon/Region;

    .line 176
    .line 177
    .line 178
    move-result-object p0

    .line 179
    new-instance p1, Lorg/altbeacon/beacon/service/Callback;

    .line 180
    .line 181
    invoke-virtual {v0}, Lorg/altbeacon/beacon/service/StartRMData;->getCallbackPackageName()Ljava/lang/String;

    .line 182
    .line 183
    .line 184
    move-result-object v2

    .line 185
    invoke-direct {p1, v2}, Lorg/altbeacon/beacon/service/Callback;-><init>(Ljava/lang/String;)V

    .line 186
    .line 187
    .line 188
    invoke-virtual {v1, p0, p1}, Lorg/altbeacon/beacon/service/BeaconService;->startRangingBeaconsInRegion(Lorg/altbeacon/beacon/Region;Lorg/altbeacon/beacon/service/Callback;)V

    .line 189
    .line 190
    .line 191
    invoke-virtual {v0}, Lorg/altbeacon/beacon/service/StartRMData;->getScanPeriod()J

    .line 192
    .line 193
    .line 194
    move-result-wide v2

    .line 195
    invoke-virtual {v0}, Lorg/altbeacon/beacon/service/StartRMData;->getBetweenScanPeriod()J

    .line 196
    .line 197
    .line 198
    move-result-wide v4

    .line 199
    invoke-virtual {v0}, Lorg/altbeacon/beacon/service/StartRMData;->getBackgroundFlag()Z

    .line 200
    .line 201
    .line 202
    move-result v6

    .line 203
    invoke-virtual/range {v1 .. v6}, Lorg/altbeacon/beacon/service/BeaconService;->setScanPeriods(JJZ)V

    .line 204
    .line 205
    .line 206
    return-void

    .line 207
    :cond_5
    iget p0, p1, Landroid/os/Message;->what:I

    .line 208
    .line 209
    const/4 v0, 0x7

    .line 210
    if-ne p0, v0, :cond_7

    .line 211
    .line 212
    const-string p0, "Received settings update"

    .line 213
    .line 214
    new-array v0, v2, [Ljava/lang/Object;

    .line 215
    .line 216
    invoke-static {v3, p0, v0}, Lorg/altbeacon/beacon/logging/LogManager;->i(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 217
    .line 218
    .line 219
    invoke-virtual {p1}, Landroid/os/Message;->getData()Landroid/os/Bundle;

    .line 220
    .line 221
    .line 222
    move-result-object p0

    .line 223
    invoke-static {p0}, Lorg/altbeacon/beacon/service/SettingsData;->fromBundle(Landroid/os/Bundle;)Lorg/altbeacon/beacon/service/SettingsData;

    .line 224
    .line 225
    .line 226
    move-result-object p0

    .line 227
    if-eqz p0, :cond_6

    .line 228
    .line 229
    invoke-virtual {p0, v1}, Lorg/altbeacon/beacon/service/SettingsData;->apply(Lorg/altbeacon/beacon/service/BeaconService;)V

    .line 230
    .line 231
    .line 232
    return-void

    .line 233
    :cond_6
    const-string p0, "Settings data missing"

    .line 234
    .line 235
    new-array p1, v2, [Ljava/lang/Object;

    .line 236
    .line 237
    invoke-static {v3, p0, p1}, Lorg/altbeacon/beacon/logging/LogManager;->w(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 238
    .line 239
    .line 240
    return-void

    .line 241
    :cond_7
    new-instance p0, Ljava/lang/StringBuilder;

    .line 242
    .line 243
    const-string v0, "Received unknown message from other process : "

    .line 244
    .line 245
    invoke-direct {p0, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 246
    .line 247
    .line 248
    iget p1, p1, Landroid/os/Message;->what:I

    .line 249
    .line 250
    invoke-virtual {p0, p1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 251
    .line 252
    .line 253
    invoke-virtual {p0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 254
    .line 255
    .line 256
    move-result-object p0

    .line 257
    new-array p1, v2, [Ljava/lang/Object;

    .line 258
    .line 259
    invoke-static {v3, p0, p1}, Lorg/altbeacon/beacon/logging/LogManager;->i(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 260
    .line 261
    .line 262
    :cond_8
    return-void
.end method
