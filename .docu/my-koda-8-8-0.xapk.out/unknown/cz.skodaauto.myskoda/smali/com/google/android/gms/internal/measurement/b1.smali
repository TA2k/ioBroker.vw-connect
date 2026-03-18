.class public final Lcom/google/android/gms/internal/measurement/b1;
.super Lcom/google/android/gms/internal/measurement/g1;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final synthetic h:I

.field public final synthetic i:Ljava/lang/Object;

.field public final synthetic j:Ljava/lang/Object;

.field public final synthetic k:Ljava/lang/Object;


# direct methods
.method public constructor <init>(Lcom/google/android/gms/internal/measurement/j1;Landroid/app/Activity;Lcom/google/android/gms/internal/measurement/h0;)V
    .locals 1

    const/4 v0, 0x3

    iput v0, p0, Lcom/google/android/gms/internal/measurement/b1;->h:I

    .line 1
    iput-object p2, p0, Lcom/google/android/gms/internal/measurement/b1;->j:Ljava/lang/Object;

    iput-object p3, p0, Lcom/google/android/gms/internal/measurement/b1;->k:Ljava/lang/Object;

    iput-object p1, p0, Lcom/google/android/gms/internal/measurement/b1;->i:Ljava/lang/Object;

    iget-object p1, p1, Lcom/google/android/gms/internal/measurement/j1;->d:Lcom/google/android/gms/internal/measurement/k1;

    const/4 p2, 0x1

    .line 2
    invoke-direct {p0, p1, p2}, Lcom/google/android/gms/internal/measurement/g1;-><init>(Lcom/google/android/gms/internal/measurement/k1;Z)V

    return-void
.end method

.method public constructor <init>(Lcom/google/android/gms/internal/measurement/j1;Landroid/os/Bundle;Landroid/app/Activity;)V
    .locals 1

    const/4 v0, 0x2

    iput v0, p0, Lcom/google/android/gms/internal/measurement/b1;->h:I

    .line 3
    iput-object p2, p0, Lcom/google/android/gms/internal/measurement/b1;->k:Ljava/lang/Object;

    iput-object p3, p0, Lcom/google/android/gms/internal/measurement/b1;->j:Ljava/lang/Object;

    iput-object p1, p0, Lcom/google/android/gms/internal/measurement/b1;->i:Ljava/lang/Object;

    iget-object p1, p1, Lcom/google/android/gms/internal/measurement/j1;->d:Lcom/google/android/gms/internal/measurement/k1;

    const/4 p2, 0x1

    .line 4
    invoke-direct {p0, p1, p2}, Lcom/google/android/gms/internal/measurement/g1;-><init>(Lcom/google/android/gms/internal/measurement/k1;Z)V

    return-void
.end method

.method public constructor <init>(Lcom/google/android/gms/internal/measurement/k1;Landroid/content/Context;Landroid/os/Bundle;)V
    .locals 1

    const/4 v0, 0x0

    iput v0, p0, Lcom/google/android/gms/internal/measurement/b1;->h:I

    .line 5
    iput-object p2, p0, Lcom/google/android/gms/internal/measurement/b1;->j:Ljava/lang/Object;

    iput-object p3, p0, Lcom/google/android/gms/internal/measurement/b1;->k:Ljava/lang/Object;

    iput-object p1, p0, Lcom/google/android/gms/internal/measurement/b1;->i:Ljava/lang/Object;

    const/4 p2, 0x1

    .line 6
    invoke-direct {p0, p1, p2}, Lcom/google/android/gms/internal/measurement/g1;-><init>(Lcom/google/android/gms/internal/measurement/k1;Z)V

    return-void
.end method

.method public constructor <init>(Lcom/google/android/gms/internal/measurement/k1;Ljava/lang/String;Lcom/google/android/gms/internal/measurement/h0;)V
    .locals 1

    const/4 v0, 0x1

    iput v0, p0, Lcom/google/android/gms/internal/measurement/b1;->h:I

    .line 7
    iput-object p2, p0, Lcom/google/android/gms/internal/measurement/b1;->j:Ljava/lang/Object;

    iput-object p3, p0, Lcom/google/android/gms/internal/measurement/b1;->k:Ljava/lang/Object;

    invoke-static {p1}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;)Ljava/lang/Object;

    iput-object p1, p0, Lcom/google/android/gms/internal/measurement/b1;->i:Ljava/lang/Object;

    const/4 p2, 0x1

    .line 8
    invoke-direct {p0, p1, p2}, Lcom/google/android/gms/internal/measurement/g1;-><init>(Lcom/google/android/gms/internal/measurement/k1;Z)V

    return-void
.end method


# virtual methods
.method public final a()V
    .locals 17

    .line 1
    move-object/from16 v1, p0

    .line 2
    .line 3
    iget v0, v1, Lcom/google/android/gms/internal/measurement/b1;->h:I

    .line 4
    .line 5
    packed-switch v0, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    iget-object v0, v1, Lcom/google/android/gms/internal/measurement/b1;->i:Ljava/lang/Object;

    .line 9
    .line 10
    check-cast v0, Lcom/google/android/gms/internal/measurement/j1;

    .line 11
    .line 12
    iget-object v0, v0, Lcom/google/android/gms/internal/measurement/j1;->d:Lcom/google/android/gms/internal/measurement/k1;

    .line 13
    .line 14
    iget-object v0, v0, Lcom/google/android/gms/internal/measurement/k1;->f:Lcom/google/android/gms/internal/measurement/k0;

    .line 15
    .line 16
    invoke-static {v0}, Lno/c0;->h(Ljava/lang/Object;)V

    .line 17
    .line 18
    .line 19
    iget-object v2, v1, Lcom/google/android/gms/internal/measurement/b1;->j:Ljava/lang/Object;

    .line 20
    .line 21
    check-cast v2, Landroid/app/Activity;

    .line 22
    .line 23
    invoke-static {v2}, Lcom/google/android/gms/internal/measurement/w0;->x0(Landroid/app/Activity;)Lcom/google/android/gms/internal/measurement/w0;

    .line 24
    .line 25
    .line 26
    move-result-object v2

    .line 27
    iget-object v3, v1, Lcom/google/android/gms/internal/measurement/b1;->k:Ljava/lang/Object;

    .line 28
    .line 29
    check-cast v3, Lcom/google/android/gms/internal/measurement/h0;

    .line 30
    .line 31
    iget-wide v4, v1, Lcom/google/android/gms/internal/measurement/g1;->e:J

    .line 32
    .line 33
    invoke-interface {v0, v2, v3, v4, v5}, Lcom/google/android/gms/internal/measurement/k0;->onActivitySaveInstanceStateByScionActivityInfo(Lcom/google/android/gms/internal/measurement/w0;Lcom/google/android/gms/internal/measurement/m0;J)V

    .line 34
    .line 35
    .line 36
    return-void

    .line 37
    :pswitch_0
    iget-object v0, v1, Lcom/google/android/gms/internal/measurement/b1;->k:Ljava/lang/Object;

    .line 38
    .line 39
    check-cast v0, Landroid/os/Bundle;

    .line 40
    .line 41
    if-eqz v0, :cond_0

    .line 42
    .line 43
    new-instance v2, Landroid/os/Bundle;

    .line 44
    .line 45
    invoke-direct {v2}, Landroid/os/Bundle;-><init>()V

    .line 46
    .line 47
    .line 48
    const-string v3, "com.google.app_measurement.screen_service"

    .line 49
    .line 50
    invoke-virtual {v0, v3}, Landroid/os/BaseBundle;->containsKey(Ljava/lang/String;)Z

    .line 51
    .line 52
    .line 53
    move-result v4

    .line 54
    if-eqz v4, :cond_1

    .line 55
    .line 56
    invoke-virtual {v0, v3}, Landroid/os/BaseBundle;->get(Ljava/lang/String;)Ljava/lang/Object;

    .line 57
    .line 58
    .line 59
    move-result-object v0

    .line 60
    instance-of v4, v0, Landroid/os/Bundle;

    .line 61
    .line 62
    if-eqz v4, :cond_1

    .line 63
    .line 64
    check-cast v0, Landroid/os/Bundle;

    .line 65
    .line 66
    invoke-virtual {v2, v3, v0}, Landroid/os/Bundle;->putBundle(Ljava/lang/String;Landroid/os/Bundle;)V

    .line 67
    .line 68
    .line 69
    goto :goto_0

    .line 70
    :cond_0
    const/4 v2, 0x0

    .line 71
    :cond_1
    :goto_0
    iget-object v0, v1, Lcom/google/android/gms/internal/measurement/b1;->i:Ljava/lang/Object;

    .line 72
    .line 73
    check-cast v0, Lcom/google/android/gms/internal/measurement/j1;

    .line 74
    .line 75
    iget-object v0, v0, Lcom/google/android/gms/internal/measurement/j1;->d:Lcom/google/android/gms/internal/measurement/k1;

    .line 76
    .line 77
    iget-object v0, v0, Lcom/google/android/gms/internal/measurement/k1;->f:Lcom/google/android/gms/internal/measurement/k0;

    .line 78
    .line 79
    invoke-static {v0}, Lno/c0;->h(Ljava/lang/Object;)V

    .line 80
    .line 81
    .line 82
    iget-object v3, v1, Lcom/google/android/gms/internal/measurement/b1;->j:Ljava/lang/Object;

    .line 83
    .line 84
    check-cast v3, Landroid/app/Activity;

    .line 85
    .line 86
    iget-wide v4, v1, Lcom/google/android/gms/internal/measurement/g1;->e:J

    .line 87
    .line 88
    invoke-static {v3}, Lcom/google/android/gms/internal/measurement/w0;->x0(Landroid/app/Activity;)Lcom/google/android/gms/internal/measurement/w0;

    .line 89
    .line 90
    .line 91
    move-result-object v1

    .line 92
    invoke-interface {v0, v1, v2, v4, v5}, Lcom/google/android/gms/internal/measurement/k0;->onActivityCreatedByScionActivityInfo(Lcom/google/android/gms/internal/measurement/w0;Landroid/os/Bundle;J)V

    .line 93
    .line 94
    .line 95
    return-void

    .line 96
    :pswitch_1
    iget-object v0, v1, Lcom/google/android/gms/internal/measurement/b1;->i:Ljava/lang/Object;

    .line 97
    .line 98
    check-cast v0, Lcom/google/android/gms/internal/measurement/k1;

    .line 99
    .line 100
    iget-object v0, v0, Lcom/google/android/gms/internal/measurement/k1;->f:Lcom/google/android/gms/internal/measurement/k0;

    .line 101
    .line 102
    invoke-static {v0}, Lno/c0;->h(Ljava/lang/Object;)V

    .line 103
    .line 104
    .line 105
    iget-object v2, v1, Lcom/google/android/gms/internal/measurement/b1;->j:Ljava/lang/Object;

    .line 106
    .line 107
    check-cast v2, Ljava/lang/String;

    .line 108
    .line 109
    iget-object v1, v1, Lcom/google/android/gms/internal/measurement/b1;->k:Ljava/lang/Object;

    .line 110
    .line 111
    check-cast v1, Lcom/google/android/gms/internal/measurement/h0;

    .line 112
    .line 113
    invoke-interface {v0, v2, v1}, Lcom/google/android/gms/internal/measurement/k0;->getMaxUserProperties(Ljava/lang/String;Lcom/google/android/gms/internal/measurement/m0;)V

    .line 114
    .line 115
    .line 116
    return-void

    .line 117
    :pswitch_2
    const/4 v2, 0x0

    .line 118
    const/4 v3, 0x1

    .line 119
    :try_start_0
    iget-object v0, v1, Lcom/google/android/gms/internal/measurement/b1;->j:Ljava/lang/Object;

    .line 120
    .line 121
    move-object v4, v0

    .line 122
    check-cast v4, Landroid/content/Context;

    .line 123
    .line 124
    invoke-static {v4}, Lno/c0;->h(Ljava/lang/Object;)V

    .line 125
    .line 126
    .line 127
    invoke-static {v4}, Lvp/t1;->a(Landroid/content/Context;)Ljava/lang/String;

    .line 128
    .line 129
    .line 130
    move-result-object v0

    .line 131
    invoke-virtual {v4}, Landroid/content/Context;->getResources()Landroid/content/res/Resources;

    .line 132
    .line 133
    .line 134
    move-result-object v5

    .line 135
    invoke-static {v0}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    .line 136
    .line 137
    .line 138
    move-result v6

    .line 139
    if-eqz v6, :cond_2

    .line 140
    .line 141
    invoke-static {v4}, Lvp/t1;->a(Landroid/content/Context;)Ljava/lang/String;

    .line 142
    .line 143
    .line 144
    move-result-object v0

    .line 145
    goto :goto_1

    .line 146
    :catch_0
    move-exception v0

    .line 147
    goto/16 :goto_8

    .line 148
    .line 149
    :cond_2
    :goto_1
    const-string v6, "google_analytics_force_disable_updates"

    .line 150
    .line 151
    const-string v7, "bool"

    .line 152
    .line 153
    invoke-virtual {v5, v6, v7, v0}, Landroid/content/res/Resources;->getIdentifier(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)I

    .line 154
    .line 155
    .line 156
    move-result v0
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    .line 157
    const/4 v6, 0x0

    .line 158
    if-nez v0, :cond_3

    .line 159
    .line 160
    :catch_1
    move-object v5, v6

    .line 161
    goto :goto_2

    .line 162
    :cond_3
    :try_start_1
    invoke-virtual {v5, v0}, Landroid/content/res/Resources;->getBoolean(I)Z

    .line 163
    .line 164
    .line 165
    move-result v0

    .line 166
    invoke-static {v0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 167
    .line 168
    .line 169
    move-result-object v0
    :try_end_1
    .catch Landroid/content/res/Resources$NotFoundException; {:try_start_1 .. :try_end_1} :catch_1
    .catch Ljava/lang/Exception; {:try_start_1 .. :try_end_1} :catch_0

    .line 170
    move-object v5, v0

    .line 171
    :goto_2
    :try_start_2
    iget-object v0, v1, Lcom/google/android/gms/internal/measurement/b1;->i:Ljava/lang/Object;

    .line 172
    .line 173
    move-object v7, v0

    .line 174
    check-cast v7, Lcom/google/android/gms/internal/measurement/k1;

    .line 175
    .line 176
    if-eqz v5, :cond_4

    .line 177
    .line 178
    invoke-virtual {v5}, Ljava/lang/Boolean;->booleanValue()Z

    .line 179
    .line 180
    .line 181
    move-result v0

    .line 182
    if-nez v0, :cond_5

    .line 183
    .line 184
    :cond_4
    move v0, v3

    .line 185
    goto :goto_3

    .line 186
    :cond_5
    move v0, v2

    .line 187
    :goto_3
    invoke-virtual {v7}, Ljava/lang/Object;->getClass()Ljava/lang/Class;
    :try_end_2
    .catch Ljava/lang/Exception; {:try_start_2 .. :try_end_2} :catch_0

    .line 188
    .line 189
    .line 190
    const-string v8, "com.google.android.gms.measurement.dynamite"

    .line 191
    .line 192
    if-eqz v0, :cond_6

    .line 193
    .line 194
    :try_start_3
    sget-object v0, Lzo/d;->d:Lwe0/b;

    .line 195
    .line 196
    goto :goto_4

    .line 197
    :catch_2
    move-exception v0

    .line 198
    goto :goto_5

    .line 199
    :cond_6
    sget-object v0, Lzo/d;->c:Lst/b;

    .line 200
    .line 201
    :goto_4
    invoke-static {v4, v0, v8}, Lzo/d;->c(Landroid/content/Context;Lzo/c;Ljava/lang/String;)Lzo/d;

    .line 202
    .line 203
    .line 204
    move-result-object v0

    .line 205
    const-string v9, "com.google.android.gms.measurement.internal.AppMeasurementDynamiteService"

    .line 206
    .line 207
    invoke-virtual {v0, v9}, Lzo/d;->b(Ljava/lang/String;)Landroid/os/IBinder;

    .line 208
    .line 209
    .line 210
    move-result-object v0

    .line 211
    invoke-static {v0}, Lcom/google/android/gms/internal/measurement/j0;->asInterface(Landroid/os/IBinder;)Lcom/google/android/gms/internal/measurement/k0;

    .line 212
    .line 213
    .line 214
    move-result-object v6
    :try_end_3
    .catch Lzo/a; {:try_start_3 .. :try_end_3} :catch_2
    .catch Ljava/lang/Exception; {:try_start_3 .. :try_end_3} :catch_0

    .line 215
    goto :goto_6

    .line 216
    :goto_5
    :try_start_4
    invoke-virtual {v7, v0, v3, v2}, Lcom/google/android/gms/internal/measurement/k1;->d(Ljava/lang/Exception;ZZ)V

    .line 217
    .line 218
    .line 219
    :goto_6
    iput-object v6, v7, Lcom/google/android/gms/internal/measurement/k1;->f:Lcom/google/android/gms/internal/measurement/k0;

    .line 220
    .line 221
    iget-object v0, v7, Lcom/google/android/gms/internal/measurement/k1;->f:Lcom/google/android/gms/internal/measurement/k0;

    .line 222
    .line 223
    if-nez v0, :cond_7

    .line 224
    .line 225
    const-string v0, "FA"

    .line 226
    .line 227
    const-string v4, "Failed to connect to measurement client."

    .line 228
    .line 229
    invoke-static {v0, v4}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;)I

    .line 230
    .line 231
    .line 232
    goto :goto_9

    .line 233
    :cond_7
    invoke-static {v4, v8}, Lzo/d;->a(Landroid/content/Context;Ljava/lang/String;)I

    .line 234
    .line 235
    .line 236
    move-result v0

    .line 237
    invoke-static {v4, v8, v2}, Lzo/d;->d(Landroid/content/Context;Ljava/lang/String;Z)I

    .line 238
    .line 239
    .line 240
    move-result v6

    .line 241
    invoke-static {v0, v6}, Ljava/lang/Math;->max(II)I

    .line 242
    .line 243
    .line 244
    move-result v8

    .line 245
    sget-object v9, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 246
    .line 247
    invoke-virtual {v9, v5}, Ljava/lang/Boolean;->equals(Ljava/lang/Object;)Z

    .line 248
    .line 249
    .line 250
    move-result v5

    .line 251
    if-nez v5, :cond_8

    .line 252
    .line 253
    if-ge v6, v0, :cond_9

    .line 254
    .line 255
    :cond_8
    move v14, v3

    .line 256
    goto :goto_7

    .line 257
    :cond_9
    move v14, v2

    .line 258
    :goto_7
    new-instance v9, Lcom/google/android/gms/internal/measurement/u0;

    .line 259
    .line 260
    int-to-long v12, v8

    .line 261
    iget-object v0, v1, Lcom/google/android/gms/internal/measurement/b1;->k:Ljava/lang/Object;

    .line 262
    .line 263
    move-object v15, v0

    .line 264
    check-cast v15, Landroid/os/Bundle;

    .line 265
    .line 266
    invoke-static {v4}, Lvp/t1;->a(Landroid/content/Context;)Ljava/lang/String;

    .line 267
    .line 268
    .line 269
    move-result-object v16

    .line 270
    const-wide/32 v10, 0x2078d

    .line 271
    .line 272
    .line 273
    invoke-direct/range {v9 .. v16}, Lcom/google/android/gms/internal/measurement/u0;-><init>(JJZLandroid/os/Bundle;Ljava/lang/String;)V

    .line 274
    .line 275
    .line 276
    iget-object v0, v7, Lcom/google/android/gms/internal/measurement/k1;->f:Lcom/google/android/gms/internal/measurement/k0;

    .line 277
    .line 278
    invoke-static {v0}, Lno/c0;->h(Ljava/lang/Object;)V

    .line 279
    .line 280
    .line 281
    new-instance v5, Lyo/b;

    .line 282
    .line 283
    invoke-direct {v5, v4}, Lyo/b;-><init>(Ljava/lang/Object;)V

    .line 284
    .line 285
    .line 286
    iget-wide v6, v1, Lcom/google/android/gms/internal/measurement/g1;->d:J

    .line 287
    .line 288
    invoke-interface {v0, v5, v9, v6, v7}, Lcom/google/android/gms/internal/measurement/k0;->initialize(Lyo/a;Lcom/google/android/gms/internal/measurement/u0;J)V
    :try_end_4
    .catch Ljava/lang/Exception; {:try_start_4 .. :try_end_4} :catch_0

    .line 289
    .line 290
    .line 291
    goto :goto_9

    .line 292
    :goto_8
    iget-object v1, v1, Lcom/google/android/gms/internal/measurement/b1;->i:Ljava/lang/Object;

    .line 293
    .line 294
    check-cast v1, Lcom/google/android/gms/internal/measurement/k1;

    .line 295
    .line 296
    invoke-virtual {v1, v0, v3, v2}, Lcom/google/android/gms/internal/measurement/k1;->d(Ljava/lang/Exception;ZZ)V

    .line 297
    .line 298
    .line 299
    :goto_9
    return-void

    .line 300
    nop

    .line 301
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public b()V
    .locals 1

    .line 1
    iget v0, p0, Lcom/google/android/gms/internal/measurement/b1;->h:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    return-void

    .line 7
    :pswitch_0
    iget-object p0, p0, Lcom/google/android/gms/internal/measurement/b1;->k:Ljava/lang/Object;

    .line 8
    .line 9
    check-cast p0, Lcom/google/android/gms/internal/measurement/h0;

    .line 10
    .line 11
    const/4 v0, 0x0

    .line 12
    invoke-virtual {p0, v0}, Lcom/google/android/gms/internal/measurement/h0;->I(Landroid/os/Bundle;)V

    .line 13
    .line 14
    .line 15
    return-void

    .line 16
    nop

    .line 17
    :pswitch_data_0
    .packed-switch 0x1
        :pswitch_0
    .end packed-switch
.end method
