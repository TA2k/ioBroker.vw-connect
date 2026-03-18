.class public final Lh/v;
.super Lh/w;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lh/z;

.field public final f:Ljava/lang/Object;


# direct methods
.method public constructor <init>(Lh/z;Landroid/content/Context;)V
    .locals 1

    const/4 v0, 0x0

    iput v0, p0, Lh/v;->d:I

    .line 3
    iput-object p1, p0, Lh/v;->e:Lh/z;

    invoke-direct {p0, p1}, Lh/w;-><init>(Lh/z;)V

    .line 4
    invoke-virtual {p2}, Landroid/content/Context;->getApplicationContext()Landroid/content/Context;

    move-result-object p1

    const-string p2, "power"

    .line 5
    invoke-virtual {p1, p2}, Landroid/content/Context;->getSystemService(Ljava/lang/String;)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Landroid/os/PowerManager;

    iput-object p1, p0, Lh/v;->f:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Lh/z;Lgw0/c;)V
    .locals 1

    const/4 v0, 0x1

    iput v0, p0, Lh/v;->d:I

    .line 1
    iput-object p1, p0, Lh/v;->e:Lh/z;

    invoke-direct {p0, p1}, Lh/w;-><init>(Lh/z;)V

    .line 2
    iput-object p2, p0, Lh/v;->f:Ljava/lang/Object;

    return-void
.end method


# virtual methods
.method public final d()Landroid/content/IntentFilter;
    .locals 1

    .line 1
    iget p0, p0, Lh/v;->d:I

    .line 2
    .line 3
    packed-switch p0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance p0, Landroid/content/IntentFilter;

    .line 7
    .line 8
    invoke-direct {p0}, Landroid/content/IntentFilter;-><init>()V

    .line 9
    .line 10
    .line 11
    const-string v0, "android.intent.action.TIME_SET"

    .line 12
    .line 13
    invoke-virtual {p0, v0}, Landroid/content/IntentFilter;->addAction(Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    const-string v0, "android.intent.action.TIMEZONE_CHANGED"

    .line 17
    .line 18
    invoke-virtual {p0, v0}, Landroid/content/IntentFilter;->addAction(Ljava/lang/String;)V

    .line 19
    .line 20
    .line 21
    const-string v0, "android.intent.action.TIME_TICK"

    .line 22
    .line 23
    invoke-virtual {p0, v0}, Landroid/content/IntentFilter;->addAction(Ljava/lang/String;)V

    .line 24
    .line 25
    .line 26
    return-object p0

    .line 27
    :pswitch_0
    new-instance p0, Landroid/content/IntentFilter;

    .line 28
    .line 29
    invoke-direct {p0}, Landroid/content/IntentFilter;-><init>()V

    .line 30
    .line 31
    .line 32
    const-string v0, "android.os.action.POWER_SAVE_MODE_CHANGED"

    .line 33
    .line 34
    invoke-virtual {p0, v0}, Landroid/content/IntentFilter;->addAction(Ljava/lang/String;)V

    .line 35
    .line 36
    .line 37
    return-object p0

    .line 38
    nop

    .line 39
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final f()I
    .locals 21

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Lh/v;->d:I

    .line 4
    .line 5
    packed-switch v1, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    iget-object v0, v0, Lh/v;->f:Ljava/lang/Object;

    .line 9
    .line 10
    check-cast v0, Lgw0/c;

    .line 11
    .line 12
    iget-object v1, v0, Lgw0/c;->g:Ljava/lang/Object;

    .line 13
    .line 14
    check-cast v1, Lh/f0;

    .line 15
    .line 16
    iget-object v2, v0, Lgw0/c;->f:Ljava/lang/Object;

    .line 17
    .line 18
    check-cast v2, Landroid/location/LocationManager;

    .line 19
    .line 20
    iget-wide v3, v1, Lh/f0;->b:J

    .line 21
    .line 22
    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J

    .line 23
    .line 24
    .line 25
    move-result-wide v5

    .line 26
    cmp-long v3, v3, v5

    .line 27
    .line 28
    const/4 v4, 0x1

    .line 29
    if-lez v3, :cond_0

    .line 30
    .line 31
    iget-boolean v0, v1, Lh/f0;->a:Z

    .line 32
    .line 33
    goto/16 :goto_8

    .line 34
    .line 35
    :cond_0
    iget-object v0, v0, Lgw0/c;->e:Ljava/lang/Object;

    .line 36
    .line 37
    move-object v3, v0

    .line 38
    check-cast v3, Landroid/content/Context;

    .line 39
    .line 40
    const-string v0, "android.permission.ACCESS_COARSE_LOCATION"

    .line 41
    .line 42
    invoke-static {v3, v0}, Ln5/a;->b(Landroid/content/Context;Ljava/lang/String;)I

    .line 43
    .line 44
    .line 45
    move-result v0

    .line 46
    const-string v5, "Failed to get last known location"

    .line 47
    .line 48
    const-string v6, "TwilightManager"

    .line 49
    .line 50
    const/4 v7, 0x0

    .line 51
    if-nez v0, :cond_2

    .line 52
    .line 53
    const-string v0, "network"

    .line 54
    .line 55
    :try_start_0
    invoke-virtual {v2, v0}, Landroid/location/LocationManager;->isProviderEnabled(Ljava/lang/String;)Z

    .line 56
    .line 57
    .line 58
    move-result v8

    .line 59
    if-eqz v8, :cond_1

    .line 60
    .line 61
    invoke-virtual {v2, v0}, Landroid/location/LocationManager;->getLastKnownLocation(Ljava/lang/String;)Landroid/location/Location;

    .line 62
    .line 63
    .line 64
    move-result-object v0
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    .line 65
    goto :goto_0

    .line 66
    :catch_0
    move-exception v0

    .line 67
    invoke-static {v6, v5, v0}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    .line 68
    .line 69
    .line 70
    :cond_1
    move-object v0, v7

    .line 71
    :goto_0
    move-object v8, v0

    .line 72
    goto :goto_1

    .line 73
    :cond_2
    move-object v8, v7

    .line 74
    :goto_1
    const-string v0, "android.permission.ACCESS_FINE_LOCATION"

    .line 75
    .line 76
    invoke-static {v3, v0}, Ln5/a;->b(Landroid/content/Context;Ljava/lang/String;)I

    .line 77
    .line 78
    .line 79
    move-result v0

    .line 80
    if-nez v0, :cond_3

    .line 81
    .line 82
    const-string v0, "gps"

    .line 83
    .line 84
    :try_start_1
    invoke-virtual {v2, v0}, Landroid/location/LocationManager;->isProviderEnabled(Ljava/lang/String;)Z

    .line 85
    .line 86
    .line 87
    move-result v3

    .line 88
    if-eqz v3, :cond_3

    .line 89
    .line 90
    invoke-virtual {v2, v0}, Landroid/location/LocationManager;->getLastKnownLocation(Ljava/lang/String;)Landroid/location/Location;

    .line 91
    .line 92
    .line 93
    move-result-object v7
    :try_end_1
    .catch Ljava/lang/Exception; {:try_start_1 .. :try_end_1} :catch_1

    .line 94
    goto :goto_2

    .line 95
    :catch_1
    move-exception v0

    .line 96
    invoke-static {v6, v5, v0}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    .line 97
    .line 98
    .line 99
    :cond_3
    :goto_2
    if-eqz v7, :cond_4

    .line 100
    .line 101
    if-eqz v8, :cond_4

    .line 102
    .line 103
    invoke-virtual {v7}, Landroid/location/Location;->getTime()J

    .line 104
    .line 105
    .line 106
    move-result-wide v2

    .line 107
    invoke-virtual {v8}, Landroid/location/Location;->getTime()J

    .line 108
    .line 109
    .line 110
    move-result-wide v9

    .line 111
    cmp-long v0, v2, v9

    .line 112
    .line 113
    if-lez v0, :cond_5

    .line 114
    .line 115
    :goto_3
    move-object v8, v7

    .line 116
    goto :goto_4

    .line 117
    :cond_4
    if-eqz v7, :cond_5

    .line 118
    .line 119
    goto :goto_3

    .line 120
    :cond_5
    :goto_4
    const/4 v0, 0x0

    .line 121
    if-eqz v8, :cond_c

    .line 122
    .line 123
    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J

    .line 124
    .line 125
    .line 126
    move-result-wide v10

    .line 127
    sget-object v2, Lh/e0;->e:Lh/e0;

    .line 128
    .line 129
    if-nez v2, :cond_6

    .line 130
    .line 131
    new-instance v2, Lh/e0;

    .line 132
    .line 133
    invoke-direct {v2}, Lh/e0;-><init>()V

    .line 134
    .line 135
    .line 136
    sput-object v2, Lh/e0;->e:Lh/e0;

    .line 137
    .line 138
    :cond_6
    sget-object v12, Lh/e0;->e:Lh/e0;

    .line 139
    .line 140
    const-wide/32 v2, 0x5265c00

    .line 141
    .line 142
    .line 143
    sub-long v13, v10, v2

    .line 144
    .line 145
    invoke-virtual {v8}, Landroid/location/Location;->getLatitude()D

    .line 146
    .line 147
    .line 148
    move-result-wide v15

    .line 149
    invoke-virtual {v8}, Landroid/location/Location;->getLongitude()D

    .line 150
    .line 151
    .line 152
    move-result-wide v17

    .line 153
    invoke-virtual/range {v12 .. v18}, Lh/e0;->a(JDD)V

    .line 154
    .line 155
    .line 156
    invoke-virtual {v8}, Landroid/location/Location;->getLatitude()D

    .line 157
    .line 158
    .line 159
    move-result-wide v5

    .line 160
    invoke-virtual {v8}, Landroid/location/Location;->getLongitude()D

    .line 161
    .line 162
    .line 163
    move-result-wide v14

    .line 164
    move-object v9, v12

    .line 165
    move-wide v12, v5

    .line 166
    invoke-virtual/range {v9 .. v15}, Lh/e0;->a(JDD)V

    .line 167
    .line 168
    .line 169
    move-object v12, v9

    .line 170
    iget v5, v12, Lh/e0;->b:I

    .line 171
    .line 172
    if-ne v5, v4, :cond_7

    .line 173
    .line 174
    move v0, v4

    .line 175
    :cond_7
    iget-wide v5, v12, Lh/e0;->d:J

    .line 176
    .line 177
    iget-wide v13, v12, Lh/e0;->c:J

    .line 178
    .line 179
    add-long/2addr v2, v10

    .line 180
    invoke-virtual {v8}, Landroid/location/Location;->getLatitude()D

    .line 181
    .line 182
    .line 183
    move-result-wide v15

    .line 184
    invoke-virtual {v8}, Landroid/location/Location;->getLongitude()D

    .line 185
    .line 186
    .line 187
    move-result-wide v17

    .line 188
    move-wide/from16 v19, v13

    .line 189
    .line 190
    move-wide v13, v2

    .line 191
    move-wide/from16 v2, v19

    .line 192
    .line 193
    invoke-virtual/range {v12 .. v18}, Lh/e0;->a(JDD)V

    .line 194
    .line 195
    .line 196
    iget-wide v7, v12, Lh/e0;->d:J

    .line 197
    .line 198
    const-wide/16 v12, -0x1

    .line 199
    .line 200
    cmp-long v9, v5, v12

    .line 201
    .line 202
    if-eqz v9, :cond_b

    .line 203
    .line 204
    cmp-long v9, v2, v12

    .line 205
    .line 206
    if-nez v9, :cond_8

    .line 207
    .line 208
    goto :goto_6

    .line 209
    :cond_8
    cmp-long v9, v10, v2

    .line 210
    .line 211
    if-lez v9, :cond_9

    .line 212
    .line 213
    move-wide v5, v7

    .line 214
    goto :goto_5

    .line 215
    :cond_9
    cmp-long v7, v10, v5

    .line 216
    .line 217
    if-lez v7, :cond_a

    .line 218
    .line 219
    move-wide v5, v2

    .line 220
    :cond_a
    :goto_5
    const-wide/32 v2, 0xea60

    .line 221
    .line 222
    .line 223
    add-long/2addr v5, v2

    .line 224
    goto :goto_7

    .line 225
    :cond_b
    :goto_6
    const-wide/32 v2, 0x2932e00

    .line 226
    .line 227
    .line 228
    add-long v5, v10, v2

    .line 229
    .line 230
    :goto_7
    iput-boolean v0, v1, Lh/f0;->a:Z

    .line 231
    .line 232
    iput-wide v5, v1, Lh/f0;->b:J

    .line 233
    .line 234
    goto :goto_8

    .line 235
    :cond_c
    const-string v1, "Could not get last known location. This is probably because the app does not have any location permissions. Falling back to hardcoded sunrise/sunset values."

    .line 236
    .line 237
    invoke-static {v6, v1}, Landroid/util/Log;->i(Ljava/lang/String;Ljava/lang/String;)I

    .line 238
    .line 239
    .line 240
    invoke-static {}, Ljava/util/Calendar;->getInstance()Ljava/util/Calendar;

    .line 241
    .line 242
    .line 243
    move-result-object v1

    .line 244
    const/16 v2, 0xb

    .line 245
    .line 246
    invoke-virtual {v1, v2}, Ljava/util/Calendar;->get(I)I

    .line 247
    .line 248
    .line 249
    move-result v1

    .line 250
    const/4 v2, 0x6

    .line 251
    if-lt v1, v2, :cond_d

    .line 252
    .line 253
    const/16 v2, 0x16

    .line 254
    .line 255
    if-lt v1, v2, :cond_e

    .line 256
    .line 257
    :cond_d
    move v0, v4

    .line 258
    :cond_e
    :goto_8
    if-eqz v0, :cond_f

    .line 259
    .line 260
    const/4 v4, 0x2

    .line 261
    :cond_f
    return v4

    .line 262
    :pswitch_0
    iget-object v0, v0, Lh/v;->f:Ljava/lang/Object;

    .line 263
    .line 264
    check-cast v0, Landroid/os/PowerManager;

    .line 265
    .line 266
    invoke-static {v0}, Lh/r;->a(Landroid/os/PowerManager;)Z

    .line 267
    .line 268
    .line 269
    move-result v0

    .line 270
    if-eqz v0, :cond_10

    .line 271
    .line 272
    const/4 v0, 0x2

    .line 273
    goto :goto_9

    .line 274
    :cond_10
    const/4 v0, 0x1

    .line 275
    :goto_9
    return v0

    .line 276
    nop

    .line 277
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final k()V
    .locals 1

    .line 1
    iget v0, p0, Lh/v;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lh/v;->e:Lh/z;

    .line 7
    .line 8
    const/4 v0, 0x1

    .line 9
    invoke-virtual {p0, v0, v0}, Lh/z;->r(ZZ)Z

    .line 10
    .line 11
    .line 12
    return-void

    .line 13
    :pswitch_0
    iget-object p0, p0, Lh/v;->e:Lh/z;

    .line 14
    .line 15
    const/4 v0, 0x1

    .line 16
    invoke-virtual {p0, v0, v0}, Lh/z;->r(ZZ)Z

    .line 17
    .line 18
    .line 19
    return-void

    .line 20
    nop

    .line 21
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
