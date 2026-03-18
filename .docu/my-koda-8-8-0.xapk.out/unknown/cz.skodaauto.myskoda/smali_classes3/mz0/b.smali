.class public final synthetic Lmz0/b;
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
    iput p1, p0, Lmz0/b;->d:I

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
    .locals 8

    .line 1
    iget p0, p0, Lmz0/b;->d:I

    .line 2
    .line 3
    const/4 v0, 0x0

    .line 4
    const-string v1, "Blank serial names are prohibited"

    .line 5
    .line 6
    const/4 v2, 0x0

    .line 7
    packed-switch p0, :pswitch_data_0

    .line 8
    .line 9
    .line 10
    sget p0, Lcz/skodaauto/myskoda/app/main/system/MainApplication;->k:I

    .line 11
    .line 12
    const-string p0, "Application created"

    .line 13
    .line 14
    return-object p0

    .line 15
    :pswitch_0
    sget p0, Lcz/skodaauto/myskoda/app/main/system/MainApplication;->k:I

    .line 16
    .line 17
    const-string p0, "No base context provided for Phrase"

    .line 18
    .line 19
    return-object p0

    .line 20
    :pswitch_1
    invoke-static {}, Lcz/myskoda/api/bff_air_conditioning/v2/infrastructure/Serializer;->a()Lcom/squareup/moshi/Moshi;

    .line 21
    .line 22
    .line 23
    move-result-object p0

    .line 24
    return-object p0

    .line 25
    :pswitch_2
    invoke-static {}, Lcz/myskoda/api/bff_air_conditioning/v2/infrastructure/ApiClient;->e()Ljava/lang/String;

    .line 26
    .line 27
    .line 28
    move-result-object p0

    .line 29
    return-object p0

    .line 30
    :pswitch_3
    invoke-static {}, Lnj/d;->values()[Lnj/d;

    .line 31
    .line 32
    .line 33
    move-result-object p0

    .line 34
    const-string v1, "ACTIVE"

    .line 35
    .line 36
    const-string v2, "EXPIRED"

    .line 37
    .line 38
    filled-new-array {v1, v2}, [Ljava/lang/String;

    .line 39
    .line 40
    .line 41
    move-result-object v1

    .line 42
    filled-new-array {v0, v0}, [[Ljava/lang/annotation/Annotation;

    .line 43
    .line 44
    .line 45
    move-result-object v0

    .line 46
    const-string v2, "cariad.charging.multicharge.sdk.headless.subscription.internal.models.HeadlessSubscription.Status"

    .line 47
    .line 48
    invoke-static {v2, p0, v1, v0}, Luz0/b1;->e(Ljava/lang/String;[Ljava/lang/Enum;[Ljava/lang/String;[[Ljava/lang/annotation/Annotation;)Luz0/y;

    .line 49
    .line 50
    .line 51
    move-result-object p0

    .line 52
    return-object p0

    .line 53
    :pswitch_4
    sget-object p0, Lnj/d;->Companion:Lnj/c;

    .line 54
    .line 55
    invoke-virtual {p0}, Lnj/c;->serializer()Lqz0/a;

    .line 56
    .line 57
    .line 58
    move-result-object p0

    .line 59
    return-object p0

    .line 60
    :pswitch_5
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 61
    .line 62
    return-object p0

    .line 63
    :pswitch_6
    const-string p0, "Access token has been successfully refreshed during interception."

    .line 64
    .line 65
    return-object p0

    .line 66
    :pswitch_7
    const-string p0, "SHA-256 is not supported on this device! Using plain challenge"

    .line 67
    .line 68
    return-object p0

    .line 69
    :pswitch_8
    new-instance p0, Luz0/d;

    .line 70
    .line 71
    sget-object v0, Lnc/u;->a:Lnc/u;

    .line 72
    .line 73
    invoke-direct {p0, v0, v2}, Luz0/d;-><init>(Lqz0/a;I)V

    .line 74
    .line 75
    .line 76
    return-object p0

    .line 77
    :pswitch_9
    invoke-static {}, Lnc/d;->values()[Lnc/d;

    .line 78
    .line 79
    .line 80
    move-result-object p0

    .line 81
    const-string v1, "TEST"

    .line 82
    .line 83
    const-string v2, "LIVE"

    .line 84
    .line 85
    filled-new-array {v1, v2}, [Ljava/lang/String;

    .line 86
    .line 87
    .line 88
    move-result-object v1

    .line 89
    filled-new-array {v0, v0}, [[Ljava/lang/annotation/Annotation;

    .line 90
    .line 91
    .line 92
    move-result-object v0

    .line 93
    const-string v2, "cariad.charging.multicharge.common.presentation.payment.models.ContoWorksSettings.ProviderMode"

    .line 94
    .line 95
    invoke-static {v2, p0, v1, v0}, Luz0/b1;->e(Ljava/lang/String;[Ljava/lang/Enum;[Ljava/lang/String;[[Ljava/lang/annotation/Annotation;)Luz0/y;

    .line 96
    .line 97
    .line 98
    move-result-object p0

    .line 99
    return-object p0

    .line 100
    :pswitch_a
    sget-object p0, Lnc/d;->Companion:Lnc/c;

    .line 101
    .line 102
    invoke-virtual {p0}, Lnc/c;->serializer()Lqz0/a;

    .line 103
    .line 104
    .line 105
    move-result-object p0

    .line 106
    return-object p0

    .line 107
    :pswitch_b
    new-instance p0, Luz0/d;

    .line 108
    .line 109
    sget-object v0, Luz0/q1;->a:Luz0/q1;

    .line 110
    .line 111
    invoke-direct {p0, v0, v2}, Luz0/d;-><init>(Lqz0/a;I)V

    .line 112
    .line 113
    .line 114
    return-object p0

    .line 115
    :pswitch_c
    const-string p0, "Error while get selected vehicle - null was returned"

    .line 116
    .line 117
    return-object p0

    .line 118
    :pswitch_d
    const-string p0, "No VIN provided for copy"

    .line 119
    .line 120
    return-object p0

    .line 121
    :pswitch_e
    new-instance p0, Lkj0/h;

    .line 122
    .line 123
    const-string v0, "How to Videos"

    .line 124
    .line 125
    invoke-direct {p0, v0}, Lkj0/h;-><init>(Ljava/lang/String;)V

    .line 126
    .line 127
    .line 128
    return-object p0

    .line 129
    :pswitch_f
    const/16 p0, 0x64

    .line 130
    .line 131
    invoke-static {p0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 132
    .line 133
    .line 134
    move-result-object p0

    .line 135
    return-object p0

    .line 136
    :pswitch_10
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 137
    .line 138
    const-string v0, "CompositionLocal LocalLifecycleOwner not present"

    .line 139
    .line 140
    invoke-direct {p0, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 141
    .line 142
    .line 143
    throw p0

    .line 144
    :pswitch_11
    invoke-static {}, Ltechnology/cariad/cat/genx/protocol/data/SmartphoneInformationResponseKt;->e()Ljava/lang/String;

    .line 145
    .line 146
    .line 147
    move-result-object p0

    .line 148
    return-object p0

    .line 149
    :pswitch_12
    invoke-static {}, Ltechnology/cariad/cat/genx/protocol/data/SmartphoneInformationResponseKt;->h()Ljava/lang/String;

    .line 150
    .line 151
    .line 152
    move-result-object p0

    .line 153
    return-object p0

    .line 154
    :pswitch_13
    invoke-static {}, Ltechnology/cariad/cat/genx/protocol/data/SmartphoneInformationResponseKt;->g()Ljava/lang/String;

    .line 155
    .line 156
    .line 157
    move-result-object p0

    .line 158
    return-object p0

    .line 159
    :pswitch_14
    invoke-static {}, Ltechnology/cariad/cat/genx/protocol/data/SmartphoneInformationResponseKt;->b()Ljava/lang/String;

    .line 160
    .line 161
    .line 162
    move-result-object p0

    .line 163
    return-object p0

    .line 164
    :pswitch_15
    invoke-static {}, Ltechnology/cariad/cat/genx/protocol/data/SmartphoneInformationResponseKt;->f()Ljava/lang/String;

    .line 165
    .line 166
    .line 167
    move-result-object p0

    .line 168
    return-object p0

    .line 169
    :pswitch_16
    invoke-static {}, Ltechnology/cariad/cat/genx/protocol/data/SmartphoneInformationResponseKt;->c()Ljava/lang/String;

    .line 170
    .line 171
    .line 172
    move-result-object p0

    .line 173
    return-object p0

    .line 174
    :pswitch_17
    invoke-static {}, Ltechnology/cariad/cat/genx/protocol/data/LinkParameters;->a()Lqz0/a;

    .line 175
    .line 176
    .line 177
    move-result-object p0

    .line 178
    return-object p0

    .line 179
    :pswitch_18
    new-instance p0, Llj0/a;

    .line 180
    .line 181
    const-string v0, "connectivity_sunset_banner_close"

    .line 182
    .line 183
    invoke-direct {p0, v0}, Llj0/a;-><init>(Ljava/lang/String;)V

    .line 184
    .line 185
    .line 186
    return-object p0

    .line 187
    :pswitch_19
    new-array p0, v2, [Lsz0/g;

    .line 188
    .line 189
    const-string v3, "kotlinx.datetime.TimeBased"

    .line 190
    .line 191
    invoke-static {v3}, Lly0/p;->M(Ljava/lang/CharSequence;)Z

    .line 192
    .line 193
    .line 194
    move-result v0

    .line 195
    if-nez v0, :cond_0

    .line 196
    .line 197
    new-instance v7, Lsz0/a;

    .line 198
    .line 199
    invoke-direct {v7, v3}, Lsz0/a;-><init>(Ljava/lang/String;)V

    .line 200
    .line 201
    .line 202
    sget-object v0, Luz0/q0;->a:Luz0/q0;

    .line 203
    .line 204
    sget-object v0, Luz0/q0;->b:Luz0/h1;

    .line 205
    .line 206
    const-string v1, "nanoseconds"

    .line 207
    .line 208
    invoke-virtual {v7, v1, v0}, Lsz0/a;->a(Ljava/lang/String;Lsz0/g;)V

    .line 209
    .line 210
    .line 211
    new-instance v2, Lsz0/h;

    .line 212
    .line 213
    sget-object v4, Lsz0/k;->b:Lsz0/k;

    .line 214
    .line 215
    iget-object v0, v7, Lsz0/a;->c:Ljava/util/ArrayList;

    .line 216
    .line 217
    invoke-virtual {v0}, Ljava/util/ArrayList;->size()I

    .line 218
    .line 219
    .line 220
    move-result v5

    .line 221
    invoke-static {p0}, Lmx0/n;->b0([Ljava/lang/Object;)Ljava/util/List;

    .line 222
    .line 223
    .line 224
    move-result-object v6

    .line 225
    invoke-direct/range {v2 .. v7}, Lsz0/h;-><init>(Ljava/lang/String;Lkp/y8;ILjava/util/List;Lsz0/a;)V

    .line 226
    .line 227
    .line 228
    return-object v2

    .line 229
    :cond_0
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 230
    .line 231
    invoke-direct {p0, v1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 232
    .line 233
    .line 234
    throw p0

    .line 235
    :pswitch_1a
    new-array p0, v2, [Lsz0/g;

    .line 236
    .line 237
    const-string v3, "kotlinx.datetime.MonthBased"

    .line 238
    .line 239
    invoke-static {v3}, Lly0/p;->M(Ljava/lang/CharSequence;)Z

    .line 240
    .line 241
    .line 242
    move-result v0

    .line 243
    if-nez v0, :cond_1

    .line 244
    .line 245
    new-instance v7, Lsz0/a;

    .line 246
    .line 247
    invoke-direct {v7, v3}, Lsz0/a;-><init>(Ljava/lang/String;)V

    .line 248
    .line 249
    .line 250
    sget-object v0, Luz0/k0;->a:Luz0/k0;

    .line 251
    .line 252
    sget-object v0, Luz0/k0;->b:Luz0/h1;

    .line 253
    .line 254
    const-string v1, "months"

    .line 255
    .line 256
    invoke-virtual {v7, v1, v0}, Lsz0/a;->a(Ljava/lang/String;Lsz0/g;)V

    .line 257
    .line 258
    .line 259
    new-instance v2, Lsz0/h;

    .line 260
    .line 261
    sget-object v4, Lsz0/k;->b:Lsz0/k;

    .line 262
    .line 263
    iget-object v0, v7, Lsz0/a;->c:Ljava/util/ArrayList;

    .line 264
    .line 265
    invoke-virtual {v0}, Ljava/util/ArrayList;->size()I

    .line 266
    .line 267
    .line 268
    move-result v5

    .line 269
    invoke-static {p0}, Lmx0/n;->b0([Ljava/lang/Object;)Ljava/util/List;

    .line 270
    .line 271
    .line 272
    move-result-object v6

    .line 273
    invoke-direct/range {v2 .. v7}, Lsz0/h;-><init>(Ljava/lang/String;Lkp/y8;ILjava/util/List;Lsz0/a;)V

    .line 274
    .line 275
    .line 276
    return-object v2

    .line 277
    :cond_1
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 278
    .line 279
    invoke-direct {p0, v1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 280
    .line 281
    .line 282
    throw p0

    .line 283
    :pswitch_1b
    new-array p0, v2, [Lsz0/g;

    .line 284
    .line 285
    const-string v3, "kotlinx.datetime.DayBased"

    .line 286
    .line 287
    invoke-static {v3}, Lly0/p;->M(Ljava/lang/CharSequence;)Z

    .line 288
    .line 289
    .line 290
    move-result v0

    .line 291
    if-nez v0, :cond_2

    .line 292
    .line 293
    new-instance v7, Lsz0/a;

    .line 294
    .line 295
    invoke-direct {v7, v3}, Lsz0/a;-><init>(Ljava/lang/String;)V

    .line 296
    .line 297
    .line 298
    sget-object v0, Luz0/k0;->a:Luz0/k0;

    .line 299
    .line 300
    sget-object v0, Luz0/k0;->b:Luz0/h1;

    .line 301
    .line 302
    const-string v1, "days"

    .line 303
    .line 304
    invoke-virtual {v7, v1, v0}, Lsz0/a;->a(Ljava/lang/String;Lsz0/g;)V

    .line 305
    .line 306
    .line 307
    new-instance v2, Lsz0/h;

    .line 308
    .line 309
    sget-object v4, Lsz0/k;->b:Lsz0/k;

    .line 310
    .line 311
    iget-object v0, v7, Lsz0/a;->c:Ljava/util/ArrayList;

    .line 312
    .line 313
    invoke-virtual {v0}, Ljava/util/ArrayList;->size()I

    .line 314
    .line 315
    .line 316
    move-result v5

    .line 317
    invoke-static {p0}, Lmx0/n;->b0([Ljava/lang/Object;)Ljava/util/List;

    .line 318
    .line 319
    .line 320
    move-result-object v6

    .line 321
    invoke-direct/range {v2 .. v7}, Lsz0/h;-><init>(Ljava/lang/String;Lkp/y8;ILjava/util/List;Lsz0/a;)V

    .line 322
    .line 323
    .line 324
    return-object v2

    .line 325
    :cond_2
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 326
    .line 327
    invoke-direct {p0, v1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 328
    .line 329
    .line 330
    throw p0

    .line 331
    :pswitch_1c
    new-instance p0, Lqz0/f;

    .line 332
    .line 333
    sget-object v0, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 334
    .line 335
    const-class v1, Lgz0/k;

    .line 336
    .line 337
    invoke-virtual {v0, v1}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 338
    .line 339
    .line 340
    move-result-object v1

    .line 341
    const-class v3, Lgz0/f;

    .line 342
    .line 343
    invoke-virtual {v0, v3}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 344
    .line 345
    .line 346
    move-result-object v3

    .line 347
    const-class v4, Lgz0/h;

    .line 348
    .line 349
    invoke-virtual {v0, v4}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 350
    .line 351
    .line 352
    move-result-object v4

    .line 353
    const-class v5, Lgz0/j;

    .line 354
    .line 355
    invoke-virtual {v0, v5}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 356
    .line 357
    .line 358
    move-result-object v0

    .line 359
    const/4 v5, 0x3

    .line 360
    new-array v6, v5, [Lhy0/d;

    .line 361
    .line 362
    aput-object v3, v6, v2

    .line 363
    .line 364
    const/4 v3, 0x1

    .line 365
    aput-object v4, v6, v3

    .line 366
    .line 367
    const/4 v4, 0x2

    .line 368
    aput-object v0, v6, v4

    .line 369
    .line 370
    new-array v0, v5, [Lqz0/a;

    .line 371
    .line 372
    sget-object v5, Lmz0/d;->a:Lmz0/d;

    .line 373
    .line 374
    aput-object v5, v0, v2

    .line 375
    .line 376
    sget-object v2, Lmz0/j;->a:Lmz0/j;

    .line 377
    .line 378
    aput-object v2, v0, v3

    .line 379
    .line 380
    sget-object v2, Lmz0/k;->a:Lmz0/k;

    .line 381
    .line 382
    aput-object v2, v0, v4

    .line 383
    .line 384
    const-string v2, "kotlinx.datetime.DateTimeUnit"

    .line 385
    .line 386
    invoke-direct {p0, v2, v1, v6, v0}, Lqz0/f;-><init>(Ljava/lang/String;Lhy0/d;[Lhy0/d;[Lqz0/a;)V

    .line 387
    .line 388
    .line 389
    return-object p0

    .line 390
    nop

    .line 391
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
