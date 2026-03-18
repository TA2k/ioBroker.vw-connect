.class public final synthetic Lc91/u;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/a;


# instance fields
.field public final synthetic d:I


# direct methods
.method public synthetic constructor <init>(I)V
    .locals 0

    .line 1
    iput p1, p0, Lc91/u;->d:I

    .line 2
    .line 3
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 7

    .line 1
    iget p0, p0, Lc91/u;->d:I

    .line 2
    .line 3
    packed-switch p0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 7
    .line 8
    const-string v0, "No InfoViewManager provided!"

    .line 9
    .line 10
    invoke-direct {p0, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 11
    .line 12
    .line 13
    throw p0

    .line 14
    :pswitch_0
    invoke-static {}, Lcz/myskoda/api/bff_test_drive/v2/infrastructure/Serializer;->a()Lcom/squareup/moshi/Moshi;

    .line 15
    .line 16
    .line 17
    move-result-object p0

    .line 18
    return-object p0

    .line 19
    :pswitch_1
    invoke-static {}, Lcz/myskoda/api/bff_test_drive/v2/infrastructure/ApiClient;->a()Ljava/lang/String;

    .line 20
    .line 21
    .line 22
    move-result-object p0

    .line 23
    return-object p0

    .line 24
    :pswitch_2
    new-instance p0, Lqz0/d;

    .line 25
    .line 26
    const-class v0, Lqy0/c;

    .line 27
    .line 28
    sget-object v1, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 29
    .line 30
    invoke-virtual {v1, v0}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 31
    .line 32
    .line 33
    move-result-object v0

    .line 34
    const/4 v1, 0x0

    .line 35
    new-array v1, v1, [Ljava/lang/annotation/Annotation;

    .line 36
    .line 37
    invoke-direct {p0, v0, v1}, Lqz0/d;-><init>(Lhy0/d;[Ljava/lang/annotation/Annotation;)V

    .line 38
    .line 39
    .line 40
    return-object p0

    .line 41
    :pswitch_3
    new-instance p0, Lqz0/d;

    .line 42
    .line 43
    const-class v0, Lqy0/c;

    .line 44
    .line 45
    sget-object v1, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 46
    .line 47
    invoke-virtual {v1, v0}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 48
    .line 49
    .line 50
    move-result-object v0

    .line 51
    const/4 v1, 0x0

    .line 52
    new-array v1, v1, [Ljava/lang/annotation/Annotation;

    .line 53
    .line 54
    invoke-direct {p0, v0, v1}, Lqz0/d;-><init>(Lhy0/d;[Ljava/lang/annotation/Annotation;)V

    .line 55
    .line 56
    .line 57
    return-object p0

    .line 58
    :pswitch_4
    new-instance p0, Lqz0/d;

    .line 59
    .line 60
    const-class v0, Lqy0/b;

    .line 61
    .line 62
    sget-object v1, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 63
    .line 64
    invoke-virtual {v1, v0}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 65
    .line 66
    .line 67
    move-result-object v0

    .line 68
    const/4 v1, 0x0

    .line 69
    new-array v1, v1, [Ljava/lang/annotation/Annotation;

    .line 70
    .line 71
    invoke-direct {p0, v0, v1}, Lqz0/d;-><init>(Lhy0/d;[Ljava/lang/annotation/Annotation;)V

    .line 72
    .line 73
    .line 74
    return-object p0

    .line 75
    :pswitch_5
    const-string p0, "Failed to update user preferences"

    .line 76
    .line 77
    return-object p0

    .line 78
    :pswitch_6
    sget-object p0, Lu01/k;->d:Lu01/u;

    .line 79
    .line 80
    sget-object v0, Lu01/k;->e:Lu01/y;

    .line 81
    .line 82
    const-string v1, "coil3_disk_cache"

    .line 83
    .line 84
    invoke-virtual {v0, v1}, Lu01/y;->e(Ljava/lang/String;)Lu01/y;

    .line 85
    .line 86
    .line 87
    move-result-object v0

    .line 88
    const-wide/32 v3, 0xa00000

    .line 89
    .line 90
    .line 91
    :try_start_0
    invoke-virtual {v0}, Lu01/y;->toFile()Ljava/io/File;

    .line 92
    .line 93
    .line 94
    move-result-object v1

    .line 95
    invoke-virtual {v1}, Ljava/io/File;->mkdir()Z

    .line 96
    .line 97
    .line 98
    invoke-virtual {v1}, Ljava/io/File;->getAbsolutePath()Ljava/lang/String;

    .line 99
    .line 100
    .line 101
    move-result-object v1

    .line 102
    new-instance v2, Landroid/os/StatFs;

    .line 103
    .line 104
    invoke-direct {v2, v1}, Landroid/os/StatFs;-><init>(Ljava/lang/String;)V

    .line 105
    .line 106
    .line 107
    invoke-virtual {v2}, Landroid/os/StatFs;->getBlockCountLong()J

    .line 108
    .line 109
    .line 110
    move-result-wide v5

    .line 111
    invoke-virtual {v2}, Landroid/os/StatFs;->getBlockSizeLong()J

    .line 112
    .line 113
    .line 114
    move-result-wide v1

    .line 115
    mul-long/2addr v1, v5

    .line 116
    long-to-double v1, v1

    .line 117
    const-wide v5, 0x3f947ae147ae147bL    # 0.02

    .line 118
    .line 119
    .line 120
    .line 121
    .line 122
    mul-double/2addr v5, v1

    .line 123
    double-to-long v1, v5

    .line 124
    const-wide/32 v5, 0xfa00000

    .line 125
    .line 126
    .line 127
    invoke-static/range {v1 .. v6}, Lkp/r9;->g(JJJ)J

    .line 128
    .line 129
    .line 130
    move-result-wide v3
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    .line 131
    :catch_0
    new-instance v1, Lcm/g;

    .line 132
    .line 133
    invoke-direct {v1, v3, v4, p0, v0}, Lcm/g;-><init>(JLu01/k;Lu01/y;)V

    .line 134
    .line 135
    .line 136
    return-object v1

    .line 137
    :pswitch_7
    new-instance p0, Luz0/d;

    .line 138
    .line 139
    sget-object v0, Lch/g;->a:Lch/g;

    .line 140
    .line 141
    const/4 v1, 0x0

    .line 142
    invoke-direct {p0, v0, v1}, Luz0/d;-><init>(Lqz0/a;I)V

    .line 143
    .line 144
    .line 145
    return-object p0

    .line 146
    :pswitch_8
    new-instance p0, Luz0/d;

    .line 147
    .line 148
    sget-object v0, Lcd/d;->a:Lcd/d;

    .line 149
    .line 150
    const/4 v1, 0x0

    .line 151
    invoke-direct {p0, v0, v1}, Luz0/d;-><init>(Lqz0/a;I)V

    .line 152
    .line 153
    .line 154
    return-object p0

    .line 155
    :pswitch_9
    new-instance p0, Luz0/d;

    .line 156
    .line 157
    sget-object v0, Lcd/z;->Companion:Lcd/v;

    .line 158
    .line 159
    invoke-virtual {v0}, Lcd/v;->serializer()Lqz0/a;

    .line 160
    .line 161
    .line 162
    move-result-object v0

    .line 163
    const/4 v1, 0x0

    .line 164
    invoke-direct {p0, v0, v1}, Luz0/d;-><init>(Lqz0/a;I)V

    .line 165
    .line 166
    .line 167
    return-object p0

    .line 168
    :pswitch_a
    new-instance p0, Luz0/d;

    .line 169
    .line 170
    sget-object v0, Luz0/q1;->a:Luz0/q1;

    .line 171
    .line 172
    const/4 v1, 0x0

    .line 173
    invoke-direct {p0, v0, v1}, Luz0/d;-><init>(Lqz0/a;I)V

    .line 174
    .line 175
    .line 176
    return-object p0

    .line 177
    :pswitch_b
    new-instance p0, Luz0/d;

    .line 178
    .line 179
    sget-object v0, Luz0/q1;->a:Luz0/q1;

    .line 180
    .line 181
    const/4 v1, 0x0

    .line 182
    invoke-direct {p0, v0, v1}, Luz0/d;-><init>(Lqz0/a;I)V

    .line 183
    .line 184
    .line 185
    return-object p0

    .line 186
    :pswitch_c
    invoke-static {}, Lcd/g;->values()[Lcd/g;

    .line 187
    .line 188
    .line 189
    move-result-object p0

    .line 190
    const-string v0, "APP"

    .line 191
    .line 192
    const-string v1, "DATE"

    .line 193
    .line 194
    const-string v2, "RFIDCARD"

    .line 195
    .line 196
    const-string v3, "WALLBOX"

    .line 197
    .line 198
    filled-new-array {v2, v3, v0, v1}, [Ljava/lang/String;

    .line 199
    .line 200
    .line 201
    move-result-object v0

    .line 202
    const/4 v1, 0x0

    .line 203
    filled-new-array {v1, v1, v1, v1}, [[Ljava/lang/annotation/Annotation;

    .line 204
    .line 205
    .line 206
    move-result-object v1

    .line 207
    const-string v2, "cariad.charging.multicharge.kitten.charginghistory.models.home.HomeChargingHistoryFilter.Type"

    .line 208
    .line 209
    invoke-static {v2, p0, v0, v1}, Luz0/b1;->e(Ljava/lang/String;[Ljava/lang/Enum;[Ljava/lang/String;[[Ljava/lang/annotation/Annotation;)Luz0/y;

    .line 210
    .line 211
    .line 212
    move-result-object p0

    .line 213
    return-object p0

    .line 214
    :pswitch_d
    sget-object p0, Lcd/g;->Companion:Lcd/f;

    .line 215
    .line 216
    invoke-virtual {p0}, Lcd/f;->serializer()Lqz0/a;

    .line 217
    .line 218
    .line 219
    move-result-object p0

    .line 220
    return-object p0

    .line 221
    :pswitch_e
    const-string p0, "Automatically reconnecting to async messages topics."

    .line 222
    .line 223
    return-object p0

    .line 224
    :pswitch_f
    new-instance p0, Lfb/k;

    .line 225
    .line 226
    const/4 v0, 0x4

    .line 227
    invoke-direct {p0, v0}, Lfb/k;-><init>(I)V

    .line 228
    .line 229
    .line 230
    new-instance v0, Lc1/c2;

    .line 231
    .line 232
    const/16 v1, 0x13

    .line 233
    .line 234
    invoke-direct {v0, v1}, Lc1/c2;-><init>(I)V

    .line 235
    .line 236
    .line 237
    const-class v1, Lca/b;

    .line 238
    .line 239
    sget-object v2, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 240
    .line 241
    invoke-virtual {v2, v1}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 242
    .line 243
    .line 244
    move-result-object v1

    .line 245
    invoke-virtual {p0, v1, v0}, Lfb/k;->b(Lhy0/d;Lay0/k;)V

    .line 246
    .line 247
    .line 248
    invoke-virtual {p0}, Lfb/k;->d()Lp7/d;

    .line 249
    .line 250
    .line 251
    move-result-object p0

    .line 252
    return-object p0

    .line 253
    :pswitch_10
    new-instance p0, Landroidx/lifecycle/y0;

    .line 254
    .line 255
    invoke-direct {p0}, Landroidx/lifecycle/y0;-><init>()V

    .line 256
    .line 257
    .line 258
    return-object p0

    .line 259
    :pswitch_11
    new-instance p0, Lc91/e;

    .line 260
    .line 261
    const/4 v0, 0x0

    .line 262
    invoke-direct {p0, v0}, Lc91/e;-><init>(I)V

    .line 263
    .line 264
    .line 265
    return-object p0

    .line 266
    :pswitch_12
    new-instance p0, Lc91/e;

    .line 267
    .line 268
    const/4 v0, 0x0

    .line 269
    invoke-direct {p0, v0}, Lc91/e;-><init>(I)V

    .line 270
    .line 271
    .line 272
    return-object p0

    .line 273
    :pswitch_13
    new-instance p0, Luz0/d;

    .line 274
    .line 275
    new-instance v0, Lc91/e;

    .line 276
    .line 277
    const/4 v1, 0x2

    .line 278
    invoke-direct {v0, v1}, Lc91/e;-><init>(I)V

    .line 279
    .line 280
    .line 281
    const/4 v1, 0x0

    .line 282
    invoke-direct {p0, v0, v1}, Luz0/d;-><init>(Lqz0/a;I)V

    .line 283
    .line 284
    .line 285
    return-object p0

    .line 286
    :pswitch_14
    new-instance p0, Luz0/d;

    .line 287
    .line 288
    new-instance v0, Lc91/e;

    .line 289
    .line 290
    const/4 v1, 0x1

    .line 291
    invoke-direct {v0, v1}, Lc91/e;-><init>(I)V

    .line 292
    .line 293
    .line 294
    const/4 v1, 0x0

    .line 295
    invoke-direct {p0, v0, v1}, Luz0/d;-><init>(Lqz0/a;I)V

    .line 296
    .line 297
    .line 298
    return-object p0

    .line 299
    :pswitch_15
    new-instance p0, Lc91/e;

    .line 300
    .line 301
    const/4 v0, 0x0

    .line 302
    invoke-direct {p0, v0}, Lc91/e;-><init>(I)V

    .line 303
    .line 304
    .line 305
    return-object p0

    .line 306
    :pswitch_16
    const-string p0, "io.opentelemetry.api.trace.StatusCode"

    .line 307
    .line 308
    invoke-static {}, Lio/opentelemetry/api/trace/StatusCode;->values()[Lio/opentelemetry/api/trace/StatusCode;

    .line 309
    .line 310
    .line 311
    move-result-object v0

    .line 312
    invoke-static {p0, v0}, Luz0/b1;->f(Ljava/lang/String;[Ljava/lang/Enum;)Luz0/y;

    .line 313
    .line 314
    .line 315
    move-result-object p0

    .line 316
    return-object p0

    .line 317
    :pswitch_17
    new-instance p0, Lc91/e;

    .line 318
    .line 319
    const/4 v0, 0x4

    .line 320
    invoke-direct {p0, v0}, Lc91/e;-><init>(I)V

    .line 321
    .line 322
    .line 323
    return-object p0

    .line 324
    :pswitch_18
    new-instance p0, Lc91/e;

    .line 325
    .line 326
    const/4 v0, 0x4

    .line 327
    invoke-direct {p0, v0}, Lc91/e;-><init>(I)V

    .line 328
    .line 329
    .line 330
    return-object p0

    .line 331
    :pswitch_19
    const-string p0, "io.opentelemetry.api.trace.SpanKind"

    .line 332
    .line 333
    invoke-static {}, Lio/opentelemetry/api/trace/SpanKind;->values()[Lio/opentelemetry/api/trace/SpanKind;

    .line 334
    .line 335
    .line 336
    move-result-object v0

    .line 337
    invoke-static {p0, v0}, Luz0/b1;->f(Ljava/lang/String;[Ljava/lang/Enum;)Luz0/y;

    .line 338
    .line 339
    .line 340
    move-result-object p0

    .line 341
    return-object p0

    .line 342
    :pswitch_1a
    new-instance p0, Luz0/e0;

    .line 343
    .line 344
    sget-object v0, Luz0/q1;->a:Luz0/q1;

    .line 345
    .line 346
    const/4 v1, 0x1

    .line 347
    invoke-direct {p0, v0, v0, v1}, Luz0/e0;-><init>(Lqz0/a;Lqz0/a;I)V

    .line 348
    .line 349
    .line 350
    return-object p0

    .line 351
    :pswitch_1b
    new-instance p0, Luz0/d;

    .line 352
    .line 353
    new-instance v0, Lc91/e;

    .line 354
    .line 355
    const/4 v1, 0x5

    .line 356
    invoke-direct {v0, v1}, Lc91/e;-><init>(I)V

    .line 357
    .line 358
    .line 359
    const/4 v1, 0x0

    .line 360
    invoke-direct {p0, v0, v1}, Luz0/d;-><init>(Lqz0/a;I)V

    .line 361
    .line 362
    .line 363
    return-object p0

    .line 364
    :pswitch_1c
    new-instance p0, Luz0/d;

    .line 365
    .line 366
    new-instance v0, Lc91/e;

    .line 367
    .line 368
    const/4 v1, 0x3

    .line 369
    invoke-direct {v0, v1}, Lc91/e;-><init>(I)V

    .line 370
    .line 371
    .line 372
    const/4 v1, 0x0

    .line 373
    invoke-direct {p0, v0, v1}, Luz0/d;-><init>(Lqz0/a;I)V

    .line 374
    .line 375
    .line 376
    return-object p0

    .line 377
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1c
        :pswitch_1b
        :pswitch_1a
        :pswitch_19
        :pswitch_18
        :pswitch_17
        :pswitch_16
        :pswitch_15
        :pswitch_14
        :pswitch_13
        :pswitch_12
        :pswitch_11
        :pswitch_10
        :pswitch_f
        :pswitch_e
        :pswitch_d
        :pswitch_c
        :pswitch_b
        :pswitch_a
        :pswitch_9
        :pswitch_8
        :pswitch_7
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
