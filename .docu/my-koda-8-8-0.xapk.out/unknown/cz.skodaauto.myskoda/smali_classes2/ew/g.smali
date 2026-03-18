.class public final synthetic Lew/g;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I


# direct methods
.method public synthetic constructor <init>(I)V
    .locals 0

    .line 1
    iput p1, p0, Lew/g;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(II)V
    .locals 0

    .line 2
    iput p2, p0, Lew/g;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(Lfw0/h0;)V
    .locals 0

    .line 3
    const/16 p1, 0x19

    iput p1, p0, Lew/g;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 10

    .line 1
    iget p0, p0, Lew/g;->d:I

    .line 2
    .line 3
    packed-switch p0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Lu2/b;

    .line 7
    .line 8
    check-cast p2, Lr4/q;

    .line 9
    .line 10
    iget-wide v0, p2, Lr4/q;->a:J

    .line 11
    .line 12
    new-instance p0, Lt4/o;

    .line 13
    .line 14
    invoke-direct {p0, v0, v1}, Lt4/o;-><init>(J)V

    .line 15
    .line 16
    .line 17
    sget-object v0, Lg4/e0;->s:Lg4/d0;

    .line 18
    .line 19
    invoke-static {p0, v0, p1}, Lg4/e0;->a(Ljava/lang/Object;Lu2/k;Lu2/b;)Ljava/lang/Object;

    .line 20
    .line 21
    .line 22
    move-result-object p0

    .line 23
    iget-wide v1, p2, Lr4/q;->b:J

    .line 24
    .line 25
    new-instance p2, Lt4/o;

    .line 26
    .line 27
    invoke-direct {p2, v1, v2}, Lt4/o;-><init>(J)V

    .line 28
    .line 29
    .line 30
    invoke-static {p2, v0, p1}, Lg4/e0;->a(Ljava/lang/Object;Lu2/k;Lu2/b;)Ljava/lang/Object;

    .line 31
    .line 32
    .line 33
    move-result-object p1

    .line 34
    filled-new-array {p0, p1}, [Ljava/lang/Object;

    .line 35
    .line 36
    .line 37
    move-result-object p0

    .line 38
    invoke-static {p0}, Ljp/k1;->b([Ljava/lang/Object;)Ljava/util/ArrayList;

    .line 39
    .line 40
    .line 41
    move-result-object p0

    .line 42
    return-object p0

    .line 43
    :pswitch_0
    check-cast p1, Lu2/b;

    .line 44
    .line 45
    check-cast p2, Lr4/p;

    .line 46
    .line 47
    iget p0, p2, Lr4/p;->a:F

    .line 48
    .line 49
    invoke-static {p0}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 50
    .line 51
    .line 52
    move-result-object p0

    .line 53
    iget p1, p2, Lr4/p;->b:F

    .line 54
    .line 55
    invoke-static {p1}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 56
    .line 57
    .line 58
    move-result-object p1

    .line 59
    filled-new-array {p0, p1}, [Ljava/lang/Float;

    .line 60
    .line 61
    .line 62
    move-result-object p0

    .line 63
    invoke-static {p0}, Ljp/k1;->b([Ljava/lang/Object;)Ljava/util/ArrayList;

    .line 64
    .line 65
    .line 66
    move-result-object p0

    .line 67
    return-object p0

    .line 68
    :pswitch_1
    check-cast p1, Lu2/b;

    .line 69
    .line 70
    check-cast p2, Lr4/l;

    .line 71
    .line 72
    iget p0, p2, Lr4/l;->a:I

    .line 73
    .line 74
    invoke-static {p0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 75
    .line 76
    .line 77
    move-result-object p0

    .line 78
    return-object p0

    .line 79
    :pswitch_2
    check-cast p1, Lu2/b;

    .line 80
    .line 81
    check-cast p2, Lg4/g;

    .line 82
    .line 83
    iget-object p0, p2, Lg4/g;->e:Ljava/lang/String;

    .line 84
    .line 85
    iget-object p2, p2, Lg4/g;->d:Ljava/util/List;

    .line 86
    .line 87
    sget-object v0, Lg4/e0;->b:Lu2/l;

    .line 88
    .line 89
    invoke-static {p2, v0, p1}, Lg4/e0;->a(Ljava/lang/Object;Lu2/k;Lu2/b;)Ljava/lang/Object;

    .line 90
    .line 91
    .line 92
    move-result-object p1

    .line 93
    filled-new-array {p0, p1}, [Ljava/lang/Object;

    .line 94
    .line 95
    .line 96
    move-result-object p0

    .line 97
    invoke-static {p0}, Ljp/k1;->b([Ljava/lang/Object;)Ljava/util/ArrayList;

    .line 98
    .line 99
    .line 100
    move-result-object p0

    .line 101
    return-object p0

    .line 102
    :pswitch_3
    check-cast p1, Lfw0/p0;

    .line 103
    .line 104
    check-cast p2, Ljava/lang/Integer;

    .line 105
    .line 106
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 107
    .line 108
    .line 109
    move-result p0

    .line 110
    const-string p2, "$this$delayMillis"

    .line 111
    .line 112
    invoke-static {p1, p2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 113
    .line 114
    .line 115
    add-int/lit8 p0, p0, -0x1

    .line 116
    .line 117
    int-to-double p0, p0

    .line 118
    const-wide/high16 v0, 0x4000000000000000L    # 2.0

    .line 119
    .line 120
    invoke-static {v0, v1, p0, p1}, Ljava/lang/Math;->pow(DD)D

    .line 121
    .line 122
    .line 123
    move-result-wide p0

    .line 124
    const-wide/16 v0, 0x3e8

    .line 125
    .line 126
    long-to-double v0, v0

    .line 127
    mul-double/2addr p0, v0

    .line 128
    double-to-long p0, p0

    .line 129
    const-wide/32 v0, 0xea60

    .line 130
    .line 131
    .line 132
    invoke-static {p0, p1, v0, v1}, Ljava/lang/Math;->min(JJ)J

    .line 133
    .line 134
    .line 135
    move-result-wide p0

    .line 136
    sget-object p2, Ley0/e;->e:Ley0/a;

    .line 137
    .line 138
    invoke-virtual {p2}, Ley0/e;->e()J

    .line 139
    .line 140
    .line 141
    move-result-wide v0

    .line 142
    add-long/2addr v0, p0

    .line 143
    invoke-static {v0, v1}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 144
    .line 145
    .line 146
    move-result-object p0

    .line 147
    return-object p0

    .line 148
    :pswitch_4
    check-cast p1, Lfw0/q0;

    .line 149
    .line 150
    check-cast p2, Lkw0/c;

    .line 151
    .line 152
    const-string p0, "<this>"

    .line 153
    .line 154
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 155
    .line 156
    .line 157
    const-string p0, "it"

    .line 158
    .line 159
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 160
    .line 161
    .line 162
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 163
    .line 164
    return-object p0

    .line 165
    :pswitch_5
    check-cast p1, Lk21/a;

    .line 166
    .line 167
    check-cast p2, Lg21/a;

    .line 168
    .line 169
    const-string p0, "$this$single"

    .line 170
    .line 171
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 172
    .line 173
    .line 174
    const-string p0, "it"

    .line 175
    .line 176
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 177
    .line 178
    .line 179
    new-instance p0, Let0/a;

    .line 180
    .line 181
    sget-object p2, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 182
    .line 183
    const-class v0, Lxl0/f;

    .line 184
    .line 185
    invoke-virtual {p2, v0}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 186
    .line 187
    .line 188
    move-result-object v0

    .line 189
    const/4 v1, 0x0

    .line 190
    invoke-virtual {p1, v0, v1, v1}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 191
    .line 192
    .line 193
    move-result-object v0

    .line 194
    check-cast v0, Lxl0/f;

    .line 195
    .line 196
    const-class v2, Lcz/myskoda/api/bff_car_configurator/v3/CarConfiguratorApi;

    .line 197
    .line 198
    const-string v3, "null"

    .line 199
    .line 200
    invoke-static {p2, v2, v3}, Lia/b;->f(Lkotlin/jvm/internal/h0;Ljava/lang/Class;Ljava/lang/String;)Lh21/b;

    .line 201
    .line 202
    .line 203
    move-result-object v2

    .line 204
    const-class v3, Lti0/a;

    .line 205
    .line 206
    invoke-virtual {p2, v3}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 207
    .line 208
    .line 209
    move-result-object p2

    .line 210
    invoke-virtual {p1, p2, v2, v1}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 211
    .line 212
    .line 213
    move-result-object p1

    .line 214
    check-cast p1, Lti0/a;

    .line 215
    .line 216
    invoke-direct {p0, v0, p1}, Let0/a;-><init>(Lxl0/f;Lti0/a;)V

    .line 217
    .line 218
    .line 219
    return-object p0

    .line 220
    :pswitch_6
    check-cast p1, Lk21/a;

    .line 221
    .line 222
    check-cast p2, Lg21/a;

    .line 223
    .line 224
    const-string p0, "$this$single"

    .line 225
    .line 226
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 227
    .line 228
    .line 229
    const-string p0, "it"

    .line 230
    .line 231
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 232
    .line 233
    .line 234
    new-instance p0, Len0/k;

    .line 235
    .line 236
    sget-object p2, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 237
    .line 238
    const-class v0, Lxl0/f;

    .line 239
    .line 240
    invoke-virtual {p2, v0}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 241
    .line 242
    .line 243
    move-result-object v0

    .line 244
    const/4 v1, 0x0

    .line 245
    invoke-virtual {p1, v0, v1, v1}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 246
    .line 247
    .line 248
    move-result-object v0

    .line 249
    check-cast v0, Lxl0/f;

    .line 250
    .line 251
    const-class v2, Lcz/myskoda/api/bff_garage/v2/GarageApi;

    .line 252
    .line 253
    const-string v3, "null"

    .line 254
    .line 255
    invoke-static {p2, v2, v3}, Lia/b;->f(Lkotlin/jvm/internal/h0;Ljava/lang/Class;Ljava/lang/String;)Lh21/b;

    .line 256
    .line 257
    .line 258
    move-result-object v2

    .line 259
    const-class v3, Lti0/a;

    .line 260
    .line 261
    invoke-virtual {p2, v3}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 262
    .line 263
    .line 264
    move-result-object p2

    .line 265
    invoke-virtual {p1, p2, v2, v1}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 266
    .line 267
    .line 268
    move-result-object p1

    .line 269
    check-cast p1, Lti0/a;

    .line 270
    .line 271
    invoke-direct {p0, v0, p1}, Len0/k;-><init>(Lxl0/f;Lti0/a;)V

    .line 272
    .line 273
    .line 274
    return-object p0

    .line 275
    :pswitch_7
    check-cast p1, Lk21/a;

    .line 276
    .line 277
    check-cast p2, Lg21/a;

    .line 278
    .line 279
    const-string p0, "$this$single"

    .line 280
    .line 281
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 282
    .line 283
    .line 284
    const-string p0, "it"

    .line 285
    .line 286
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 287
    .line 288
    .line 289
    new-instance v0, Len0/s;

    .line 290
    .line 291
    sget-object p0, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 292
    .line 293
    const-class p2, Len0/g;

    .line 294
    .line 295
    const-string v1, "null"

    .line 296
    .line 297
    invoke-static {p0, p2, v1}, Lia/b;->f(Lkotlin/jvm/internal/h0;Ljava/lang/Class;Ljava/lang/String;)Lh21/b;

    .line 298
    .line 299
    .line 300
    move-result-object p2

    .line 301
    const-class v2, Lti0/a;

    .line 302
    .line 303
    invoke-virtual {p0, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 304
    .line 305
    .line 306
    move-result-object v3

    .line 307
    const/4 v4, 0x0

    .line 308
    invoke-virtual {p1, v3, p2, v4}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 309
    .line 310
    .line 311
    move-result-object p2

    .line 312
    check-cast p2, Lti0/a;

    .line 313
    .line 314
    const-class v3, Lgp0/a;

    .line 315
    .line 316
    invoke-static {p0, v3, v1}, Lia/b;->f(Lkotlin/jvm/internal/h0;Ljava/lang/Class;Ljava/lang/String;)Lh21/b;

    .line 317
    .line 318
    .line 319
    move-result-object v3

    .line 320
    invoke-virtual {p0, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 321
    .line 322
    .line 323
    move-result-object v5

    .line 324
    invoke-virtual {p1, v5, v3, v4}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 325
    .line 326
    .line 327
    move-result-object v3

    .line 328
    check-cast v3, Lti0/a;

    .line 329
    .line 330
    const-class v5, Lgp0/c;

    .line 331
    .line 332
    invoke-static {p0, v5, v1}, Lia/b;->f(Lkotlin/jvm/internal/h0;Ljava/lang/Class;Ljava/lang/String;)Lh21/b;

    .line 333
    .line 334
    .line 335
    move-result-object v5

    .line 336
    invoke-virtual {p0, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 337
    .line 338
    .line 339
    move-result-object v6

    .line 340
    invoke-virtual {p1, v6, v5, v4}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 341
    .line 342
    .line 343
    move-result-object v5

    .line 344
    check-cast v5, Lti0/a;

    .line 345
    .line 346
    const-class v6, Len0/c;

    .line 347
    .line 348
    invoke-static {p0, v6, v1}, Lia/b;->f(Lkotlin/jvm/internal/h0;Ljava/lang/Class;Ljava/lang/String;)Lh21/b;

    .line 349
    .line 350
    .line 351
    move-result-object v1

    .line 352
    invoke-virtual {p0, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 353
    .line 354
    .line 355
    move-result-object v2

    .line 356
    invoke-virtual {p1, v2, v1, v4}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 357
    .line 358
    .line 359
    move-result-object v1

    .line 360
    check-cast v1, Lti0/a;

    .line 361
    .line 362
    const-class v2, Lwe0/a;

    .line 363
    .line 364
    invoke-virtual {p0, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 365
    .line 366
    .line 367
    move-result-object v6

    .line 368
    invoke-virtual {p1, v6, v4, v4}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 369
    .line 370
    .line 371
    move-result-object v6

    .line 372
    check-cast v6, Lwe0/a;

    .line 373
    .line 374
    invoke-virtual {p0, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 375
    .line 376
    .line 377
    move-result-object v2

    .line 378
    invoke-virtual {p1, v2, v4, v4}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 379
    .line 380
    .line 381
    move-result-object v2

    .line 382
    check-cast v2, Lwe0/a;

    .line 383
    .line 384
    const-class v7, Lny/d;

    .line 385
    .line 386
    invoke-virtual {p0, v7}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 387
    .line 388
    .line 389
    move-result-object p0

    .line 390
    invoke-virtual {p1, p0, v4, v4}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 391
    .line 392
    .line 393
    move-result-object p0

    .line 394
    move-object v7, p0

    .line 395
    check-cast v7, Lny/d;

    .line 396
    .line 397
    move-object v4, v6

    .line 398
    move-object v6, v2

    .line 399
    move-object v2, v3

    .line 400
    move-object v3, v5

    .line 401
    move-object v5, v4

    .line 402
    move-object v4, v1

    .line 403
    move-object v1, p2

    .line 404
    invoke-direct/range {v0 .. v7}, Len0/s;-><init>(Lti0/a;Lti0/a;Lti0/a;Lti0/a;Lwe0/a;Lwe0/a;Lny/d;)V

    .line 405
    .line 406
    .line 407
    return-object v0

    .line 408
    :pswitch_8
    check-cast p1, Lk21/a;

    .line 409
    .line 410
    check-cast p2, Lg21/a;

    .line 411
    .line 412
    const-string p0, "$this$factory"

    .line 413
    .line 414
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 415
    .line 416
    .line 417
    const-string p0, "it"

    .line 418
    .line 419
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 420
    .line 421
    .line 422
    new-instance v0, Lgn0/m;

    .line 423
    .line 424
    sget-object p0, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 425
    .line 426
    const-class p2, Lgn0/f;

    .line 427
    .line 428
    invoke-virtual {p0, p2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 429
    .line 430
    .line 431
    move-result-object p2

    .line 432
    const/4 v1, 0x0

    .line 433
    invoke-virtual {p1, p2, v1, v1}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 434
    .line 435
    .line 436
    move-result-object p2

    .line 437
    check-cast p2, Lgn0/f;

    .line 438
    .line 439
    const-class v2, Lrs0/f;

    .line 440
    .line 441
    invoke-virtual {p0, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 442
    .line 443
    .line 444
    move-result-object v2

    .line 445
    invoke-virtual {p1, v2, v1, v1}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 446
    .line 447
    .line 448
    move-result-object v2

    .line 449
    check-cast v2, Lrs0/f;

    .line 450
    .line 451
    const-class v3, Len0/s;

    .line 452
    .line 453
    invoke-virtual {p0, v3}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 454
    .line 455
    .line 456
    move-result-object v3

    .line 457
    invoke-virtual {p1, v3, v1, v1}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 458
    .line 459
    .line 460
    move-result-object v3

    .line 461
    check-cast v3, Len0/s;

    .line 462
    .line 463
    const-class v4, Lgn0/j;

    .line 464
    .line 465
    invoke-virtual {p0, v4}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 466
    .line 467
    .line 468
    move-result-object v4

    .line 469
    invoke-virtual {p1, v4, v1, v1}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 470
    .line 471
    .line 472
    move-result-object v1

    .line 473
    move-object v4, v1

    .line 474
    check-cast v4, Lgn0/j;

    .line 475
    .line 476
    const-class v1, Lme0/b;

    .line 477
    .line 478
    invoke-virtual {p0, v1}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 479
    .line 480
    .line 481
    move-result-object p0

    .line 482
    invoke-virtual {p1, p0}, Lk21/a;->b(Lhy0/d;)Ljava/util/ArrayList;

    .line 483
    .line 484
    .line 485
    move-result-object v5

    .line 486
    move-object v1, p2

    .line 487
    invoke-direct/range {v0 .. v5}, Lgn0/m;-><init>(Lgn0/f;Lrs0/f;Len0/s;Lgn0/j;Ljava/util/ArrayList;)V

    .line 488
    .line 489
    .line 490
    return-object v0

    .line 491
    :pswitch_9
    check-cast p1, Lk21/a;

    .line 492
    .line 493
    check-cast p2, Lg21/a;

    .line 494
    .line 495
    const-string p0, "$this$single"

    .line 496
    .line 497
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 498
    .line 499
    .line 500
    const-string p0, "it"

    .line 501
    .line 502
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 503
    .line 504
    .line 505
    new-instance p0, Len0/k;

    .line 506
    .line 507
    sget-object p2, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 508
    .line 509
    const-class v0, Lxl0/f;

    .line 510
    .line 511
    invoke-virtual {p2, v0}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 512
    .line 513
    .line 514
    move-result-object v0

    .line 515
    const/4 v1, 0x0

    .line 516
    invoke-virtual {p1, v0, v1, v1}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 517
    .line 518
    .line 519
    move-result-object v0

    .line 520
    check-cast v0, Lxl0/f;

    .line 521
    .line 522
    const-class v2, Lcz/myskoda/api/bff_garage/v2/GarageApi;

    .line 523
    .line 524
    const-string v3, "null"

    .line 525
    .line 526
    invoke-static {p2, v2, v3}, Lia/b;->f(Lkotlin/jvm/internal/h0;Ljava/lang/Class;Ljava/lang/String;)Lh21/b;

    .line 527
    .line 528
    .line 529
    move-result-object v2

    .line 530
    const-class v3, Lti0/a;

    .line 531
    .line 532
    invoke-virtual {p2, v3}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 533
    .line 534
    .line 535
    move-result-object p2

    .line 536
    invoke-virtual {p1, p2, v2, v1}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 537
    .line 538
    .line 539
    move-result-object p1

    .line 540
    check-cast p1, Lti0/a;

    .line 541
    .line 542
    invoke-direct {p0, v0, p1}, Len0/k;-><init>(Lxl0/f;Lti0/a;)V

    .line 543
    .line 544
    .line 545
    return-object p0

    .line 546
    :pswitch_a
    check-cast p1, Lk21/a;

    .line 547
    .line 548
    check-cast p2, Lg21/a;

    .line 549
    .line 550
    const-string p0, "$this$single"

    .line 551
    .line 552
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 553
    .line 554
    .line 555
    const-string p0, "it"

    .line 556
    .line 557
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 558
    .line 559
    .line 560
    new-instance p0, Lim0/c;

    .line 561
    .line 562
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 563
    .line 564
    .line 565
    return-object p0

    .line 566
    :pswitch_b
    check-cast p1, Lk21/a;

    .line 567
    .line 568
    check-cast p2, Lg21/a;

    .line 569
    .line 570
    const-string p0, "$this$single"

    .line 571
    .line 572
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 573
    .line 574
    .line 575
    const-string p0, "it"

    .line 576
    .line 577
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 578
    .line 579
    .line 580
    new-instance p0, Lem0/m;

    .line 581
    .line 582
    sget-object p2, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 583
    .line 584
    const-string v0, "null"

    .line 585
    .line 586
    const-class v1, Lem0/f;

    .line 587
    .line 588
    invoke-static {p2, v1, v0}, Lia/b;->f(Lkotlin/jvm/internal/h0;Ljava/lang/Class;Ljava/lang/String;)Lh21/b;

    .line 589
    .line 590
    .line 591
    move-result-object v0

    .line 592
    const-class v1, Lti0/a;

    .line 593
    .line 594
    invoke-virtual {p2, v1}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 595
    .line 596
    .line 597
    move-result-object v1

    .line 598
    const/4 v2, 0x0

    .line 599
    invoke-virtual {p1, v1, v0, v2}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 600
    .line 601
    .line 602
    move-result-object v0

    .line 603
    check-cast v0, Lti0/a;

    .line 604
    .line 605
    const-class v1, Lem0/a;

    .line 606
    .line 607
    invoke-virtual {p2, v1}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 608
    .line 609
    .line 610
    move-result-object p2

    .line 611
    invoke-virtual {p1, p2, v2, v2}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 612
    .line 613
    .line 614
    move-result-object p1

    .line 615
    check-cast p1, Lem0/a;

    .line 616
    .line 617
    invoke-direct {p0, v0, p1}, Lem0/m;-><init>(Lti0/a;Lem0/a;)V

    .line 618
    .line 619
    .line 620
    return-object p0

    .line 621
    :pswitch_c
    check-cast p1, Lk21/a;

    .line 622
    .line 623
    check-cast p2, Lg21/a;

    .line 624
    .line 625
    const-string p0, "$this$viewModel"

    .line 626
    .line 627
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 628
    .line 629
    .line 630
    const-string p0, "it"

    .line 631
    .line 632
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 633
    .line 634
    .line 635
    new-instance p0, Lhk0/c;

    .line 636
    .line 637
    sget-object p2, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 638
    .line 639
    const-class v0, Lgk0/a;

    .line 640
    .line 641
    invoke-virtual {p2, v0}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 642
    .line 643
    .line 644
    move-result-object v0

    .line 645
    const/4 v1, 0x0

    .line 646
    invoke-virtual {p1, v0, v1, v1}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 647
    .line 648
    .line 649
    move-result-object v0

    .line 650
    check-cast v0, Lgk0/a;

    .line 651
    .line 652
    const-class v2, Lwj0/k;

    .line 653
    .line 654
    invoke-virtual {p2, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 655
    .line 656
    .line 657
    move-result-object v2

    .line 658
    invoke-virtual {p1, v2, v1, v1}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 659
    .line 660
    .line 661
    move-result-object v2

    .line 662
    check-cast v2, Lwj0/k;

    .line 663
    .line 664
    sget-object v3, Lfk0/a;->a:Leo0/b;

    .line 665
    .line 666
    iget-object v3, v3, Leo0/b;->b:Ljava/lang/String;

    .line 667
    .line 668
    invoke-static {v3}, Lkp/fa;->c(Ljava/lang/String;)Lh21/b;

    .line 669
    .line 670
    .line 671
    move-result-object v3

    .line 672
    const-class v4, Lal0/s0;

    .line 673
    .line 674
    invoke-virtual {p2, v4}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 675
    .line 676
    .line 677
    move-result-object p2

    .line 678
    invoke-virtual {p1, p2, v3, v1}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 679
    .line 680
    .line 681
    move-result-object p1

    .line 682
    check-cast p1, Lal0/s0;

    .line 683
    .line 684
    invoke-direct {p0, v0, v2, p1}, Lhk0/c;-><init>(Lgk0/a;Lwj0/k;Lal0/s0;)V

    .line 685
    .line 686
    .line 687
    return-object p0

    .line 688
    :pswitch_d
    check-cast p1, Lk21/a;

    .line 689
    .line 690
    check-cast p2, Lg21/a;

    .line 691
    .line 692
    const-string p0, "$this$single"

    .line 693
    .line 694
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 695
    .line 696
    .line 697
    const-string p0, "it"

    .line 698
    .line 699
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 700
    .line 701
    .line 702
    sget-object p0, Lds/a;->a:Lds/a;

    .line 703
    .line 704
    return-object p0

    .line 705
    :pswitch_e
    check-cast p1, Lk21/a;

    .line 706
    .line 707
    check-cast p2, Lg21/a;

    .line 708
    .line 709
    const-string p0, "$this$factory"

    .line 710
    .line 711
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 712
    .line 713
    .line 714
    const-string p0, "it"

    .line 715
    .line 716
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 717
    .line 718
    .line 719
    new-instance p0, Leb0/b;

    .line 720
    .line 721
    sget-object p2, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 722
    .line 723
    const-class v0, Lxl0/f;

    .line 724
    .line 725
    invoke-virtual {p2, v0}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 726
    .line 727
    .line 728
    move-result-object v0

    .line 729
    const/4 v1, 0x0

    .line 730
    invoke-virtual {p1, v0, v1, v1}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 731
    .line 732
    .line 733
    move-result-object v0

    .line 734
    check-cast v0, Lxl0/f;

    .line 735
    .line 736
    const-class v2, Lcz/myskoda/api/bff_garage/v2/GarageApi;

    .line 737
    .line 738
    const-string v3, "null"

    .line 739
    .line 740
    invoke-static {p2, v2, v3}, Lia/b;->f(Lkotlin/jvm/internal/h0;Ljava/lang/Class;Ljava/lang/String;)Lh21/b;

    .line 741
    .line 742
    .line 743
    move-result-object v2

    .line 744
    const-class v3, Lti0/a;

    .line 745
    .line 746
    invoke-virtual {p2, v3}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 747
    .line 748
    .line 749
    move-result-object p2

    .line 750
    invoke-virtual {p1, p2, v2, v1}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 751
    .line 752
    .line 753
    move-result-object p1

    .line 754
    check-cast p1, Lti0/a;

    .line 755
    .line 756
    invoke-direct {p0, v0, p1}, Leb0/b;-><init>(Lxl0/f;Lti0/a;)V

    .line 757
    .line 758
    .line 759
    return-object p0

    .line 760
    :pswitch_f
    check-cast p1, Lk21/a;

    .line 761
    .line 762
    check-cast p2, Lg21/a;

    .line 763
    .line 764
    const-string p0, "$this$factory"

    .line 765
    .line 766
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 767
    .line 768
    .line 769
    const-string p0, "it"

    .line 770
    .line 771
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 772
    .line 773
    .line 774
    new-instance p0, Lgb0/c0;

    .line 775
    .line 776
    sget-object p2, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 777
    .line 778
    const-class v0, Lrs0/f;

    .line 779
    .line 780
    invoke-virtual {p2, v0}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 781
    .line 782
    .line 783
    move-result-object v0

    .line 784
    const/4 v1, 0x0

    .line 785
    invoke-virtual {p1, v0, v1, v1}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 786
    .line 787
    .line 788
    move-result-object v0

    .line 789
    check-cast v0, Lrs0/f;

    .line 790
    .line 791
    const-class v2, Lif0/f0;

    .line 792
    .line 793
    invoke-virtual {p2, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 794
    .line 795
    .line 796
    move-result-object v2

    .line 797
    invoke-virtual {p1, v2, v1, v1}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 798
    .line 799
    .line 800
    move-result-object v2

    .line 801
    check-cast v2, Lif0/f0;

    .line 802
    .line 803
    const-class v3, Len0/s;

    .line 804
    .line 805
    invoke-virtual {p2, v3}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 806
    .line 807
    .line 808
    move-result-object v3

    .line 809
    invoke-virtual {p1, v3, v1, v1}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 810
    .line 811
    .line 812
    move-result-object v1

    .line 813
    check-cast v1, Len0/s;

    .line 814
    .line 815
    const-class v3, Lme0/b;

    .line 816
    .line 817
    invoke-virtual {p2, v3}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 818
    .line 819
    .line 820
    move-result-object p2

    .line 821
    invoke-virtual {p1, p2}, Lk21/a;->b(Lhy0/d;)Ljava/util/ArrayList;

    .line 822
    .line 823
    .line 824
    move-result-object p1

    .line 825
    invoke-direct {p0, v0, v2, v1, p1}, Lgb0/c0;-><init>(Lrs0/f;Lif0/f0;Len0/s;Ljava/util/ArrayList;)V

    .line 826
    .line 827
    .line 828
    return-object p0

    .line 829
    :pswitch_10
    check-cast p1, Ll2/o;

    .line 830
    .line 831
    check-cast p2, Ljava/lang/Integer;

    .line 832
    .line 833
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 834
    .line 835
    .line 836
    const/4 p0, 0x1

    .line 837
    invoke-static {p0}, Ll2/b;->x(I)I

    .line 838
    .line 839
    .line 840
    move-result p0

    .line 841
    invoke-static {p1, p0}, Lf30/a;->n(Ll2/o;I)V

    .line 842
    .line 843
    .line 844
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 845
    .line 846
    return-object p0

    .line 847
    :pswitch_11
    check-cast p1, Ll2/o;

    .line 848
    .line 849
    check-cast p2, Ljava/lang/Integer;

    .line 850
    .line 851
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 852
    .line 853
    .line 854
    const/4 p0, 0x1

    .line 855
    invoke-static {p0}, Ll2/b;->x(I)I

    .line 856
    .line 857
    .line 858
    move-result p0

    .line 859
    invoke-static {p1, p0}, Lf30/a;->l(Ll2/o;I)V

    .line 860
    .line 861
    .line 862
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 863
    .line 864
    return-object p0

    .line 865
    :pswitch_12
    check-cast p1, Ll2/o;

    .line 866
    .line 867
    check-cast p2, Ljava/lang/Integer;

    .line 868
    .line 869
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 870
    .line 871
    .line 872
    const/4 p0, 0x1

    .line 873
    invoke-static {p0}, Ll2/b;->x(I)I

    .line 874
    .line 875
    .line 876
    move-result p0

    .line 877
    invoke-static {p1, p0}, Lf30/a;->j(Ll2/o;I)V

    .line 878
    .line 879
    .line 880
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 881
    .line 882
    return-object p0

    .line 883
    :pswitch_13
    check-cast p1, Ll2/o;

    .line 884
    .line 885
    check-cast p2, Ljava/lang/Integer;

    .line 886
    .line 887
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 888
    .line 889
    .line 890
    const/4 p0, 0x1

    .line 891
    invoke-static {p0}, Ll2/b;->x(I)I

    .line 892
    .line 893
    .line 894
    move-result p0

    .line 895
    invoke-static {p1, p0}, Lf30/a;->q(Ll2/o;I)V

    .line 896
    .line 897
    .line 898
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 899
    .line 900
    return-object p0

    .line 901
    :pswitch_14
    check-cast p1, Ll2/o;

    .line 902
    .line 903
    check-cast p2, Ljava/lang/Integer;

    .line 904
    .line 905
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 906
    .line 907
    .line 908
    const/4 p0, 0x1

    .line 909
    invoke-static {p0}, Ll2/b;->x(I)I

    .line 910
    .line 911
    .line 912
    move-result p0

    .line 913
    invoke-static {p1, p0}, Lf30/a;->c(Ll2/o;I)V

    .line 914
    .line 915
    .line 916
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 917
    .line 918
    return-object p0

    .line 919
    :pswitch_15
    check-cast p1, Ll2/o;

    .line 920
    .line 921
    check-cast p2, Ljava/lang/Integer;

    .line 922
    .line 923
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 924
    .line 925
    .line 926
    move-result p0

    .line 927
    and-int/lit8 p2, p0, 0x3

    .line 928
    .line 929
    const/4 v0, 0x2

    .line 930
    const/4 v1, 0x1

    .line 931
    if-eq p2, v0, :cond_0

    .line 932
    .line 933
    move p2, v1

    .line 934
    goto :goto_0

    .line 935
    :cond_0
    const/4 p2, 0x0

    .line 936
    :goto_0
    and-int/2addr p0, v1

    .line 937
    move-object v7, p1

    .line 938
    check-cast v7, Ll2/t;

    .line 939
    .line 940
    invoke-virtual {v7, p0, p2}, Ll2/t;->O(IZ)Z

    .line 941
    .line 942
    .line 943
    move-result p0

    .line 944
    if-eqz p0, :cond_1

    .line 945
    .line 946
    new-instance v2, Le30/h;

    .line 947
    .line 948
    sget-object p0, Le30/g;->d:Le30/g;

    .line 949
    .line 950
    const-string p1, "3 guests"

    .line 951
    .line 952
    invoke-direct {v2, v1, p0, p1}, Le30/h;-><init>(ZLe30/g;Ljava/lang/String;)V

    .line 953
    .line 954
    .line 955
    const/4 v8, 0x0

    .line 956
    const/16 v9, 0x1e

    .line 957
    .line 958
    const/4 v3, 0x0

    .line 959
    const/4 v4, 0x0

    .line 960
    const/4 v5, 0x0

    .line 961
    const/4 v6, 0x0

    .line 962
    invoke-static/range {v2 .. v9}, Lf30/a;->h(Le30/h;Lx2/s;ZLay0/a;Lay0/a;Ll2/o;II)V

    .line 963
    .line 964
    .line 965
    goto :goto_1

    .line 966
    :cond_1
    invoke-virtual {v7}, Ll2/t;->R()V

    .line 967
    .line 968
    .line 969
    :goto_1
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 970
    .line 971
    return-object p0

    .line 972
    :pswitch_16
    check-cast p1, Ll2/o;

    .line 973
    .line 974
    check-cast p2, Ljava/lang/Integer;

    .line 975
    .line 976
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 977
    .line 978
    .line 979
    const/4 p0, 0x1

    .line 980
    invoke-static {p0}, Ll2/b;->x(I)I

    .line 981
    .line 982
    .line 983
    move-result p0

    .line 984
    invoke-static {p1, p0}, Lf20/a;->e(Ll2/o;I)V

    .line 985
    .line 986
    .line 987
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 988
    .line 989
    return-object p0

    .line 990
    :pswitch_17
    check-cast p1, Ll2/o;

    .line 991
    .line 992
    check-cast p2, Ljava/lang/Integer;

    .line 993
    .line 994
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 995
    .line 996
    .line 997
    const/4 p0, 0x1

    .line 998
    invoke-static {p0}, Ll2/b;->x(I)I

    .line 999
    .line 1000
    .line 1001
    move-result p0

    .line 1002
    invoke-static {p1, p0}, Lf20/j;->f(Ll2/o;I)V

    .line 1003
    .line 1004
    .line 1005
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 1006
    .line 1007
    return-object p0

    .line 1008
    :pswitch_18
    check-cast p1, Ll2/o;

    .line 1009
    .line 1010
    check-cast p2, Ljava/lang/Integer;

    .line 1011
    .line 1012
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1013
    .line 1014
    .line 1015
    const/4 p0, 0x1

    .line 1016
    invoke-static {p0}, Ll2/b;->x(I)I

    .line 1017
    .line 1018
    .line 1019
    move-result p0

    .line 1020
    invoke-static {p1, p0}, Lf20/j;->a(Ll2/o;I)V

    .line 1021
    .line 1022
    .line 1023
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 1024
    .line 1025
    return-object p0

    .line 1026
    :pswitch_19
    check-cast p1, Ll2/o;

    .line 1027
    .line 1028
    check-cast p2, Ljava/lang/Integer;

    .line 1029
    .line 1030
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1031
    .line 1032
    .line 1033
    const/4 p0, 0x1

    .line 1034
    invoke-static {p0}, Ll2/b;->x(I)I

    .line 1035
    .line 1036
    .line 1037
    move-result p0

    .line 1038
    invoke-static {p1, p0}, Lf20/a;->c(Ll2/o;I)V

    .line 1039
    .line 1040
    .line 1041
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 1042
    .line 1043
    return-object p0

    .line 1044
    :pswitch_1a
    check-cast p1, Ll2/o;

    .line 1045
    .line 1046
    check-cast p2, Ljava/lang/Integer;

    .line 1047
    .line 1048
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 1049
    .line 1050
    .line 1051
    move-result p0

    .line 1052
    and-int/lit8 p2, p0, 0x3

    .line 1053
    .line 1054
    const/4 v0, 0x2

    .line 1055
    const/4 v1, 0x0

    .line 1056
    const/4 v2, 0x1

    .line 1057
    if-eq p2, v0, :cond_2

    .line 1058
    .line 1059
    move p2, v2

    .line 1060
    goto :goto_2

    .line 1061
    :cond_2
    move p2, v1

    .line 1062
    :goto_2
    and-int/2addr p0, v2

    .line 1063
    check-cast p1, Ll2/t;

    .line 1064
    .line 1065
    invoke-virtual {p1, p0, p2}, Ll2/t;->O(IZ)Z

    .line 1066
    .line 1067
    .line 1068
    move-result p0

    .line 1069
    if-eqz p0, :cond_3

    .line 1070
    .line 1071
    const/4 p0, 0x0

    .line 1072
    const/4 p2, 0x3

    .line 1073
    invoke-static {p0, p0, p1, v1, p2}, Lf20/a;->b(Lx2/s;Lay0/a;Ll2/o;II)V

    .line 1074
    .line 1075
    .line 1076
    goto :goto_3

    .line 1077
    :cond_3
    invoke-virtual {p1}, Ll2/t;->R()V

    .line 1078
    .line 1079
    .line 1080
    :goto_3
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 1081
    .line 1082
    return-object p0

    .line 1083
    :pswitch_1b
    check-cast p1, Lu2/b;

    .line 1084
    .line 1085
    check-cast p2, Lew/j;

    .line 1086
    .line 1087
    const-string p0, "$this$Saver"

    .line 1088
    .line 1089
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1090
    .line 1091
    .line 1092
    const-string p0, "it"

    .line 1093
    .line 1094
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1095
    .line 1096
    .line 1097
    iget-object p0, p2, Lew/j;->e:Ll2/f1;

    .line 1098
    .line 1099
    invoke-virtual {p0}, Ll2/f1;->o()F

    .line 1100
    .line 1101
    .line 1102
    move-result p0

    .line 1103
    invoke-static {p0}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 1104
    .line 1105
    .line 1106
    move-result-object p0

    .line 1107
    iget-boolean p1, p2, Lew/j;->d:Z

    .line 1108
    .line 1109
    invoke-static {p1}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 1110
    .line 1111
    .line 1112
    move-result-object p1

    .line 1113
    new-instance p2, Llx0/l;

    .line 1114
    .line 1115
    invoke-direct {p2, p0, p1}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 1116
    .line 1117
    .line 1118
    return-object p2

    .line 1119
    :pswitch_1c
    check-cast p1, Lu2/b;

    .line 1120
    .line 1121
    check-cast p2, Lew/i;

    .line 1122
    .line 1123
    const-string p0, "$this$Saver"

    .line 1124
    .line 1125
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1126
    .line 1127
    .line 1128
    const-string p0, "it"

    .line 1129
    .line 1130
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1131
    .line 1132
    .line 1133
    iget-object p0, p2, Lew/i;->e:Ll2/f1;

    .line 1134
    .line 1135
    invoke-virtual {p0}, Ll2/f1;->o()F

    .line 1136
    .line 1137
    .line 1138
    move-result p0

    .line 1139
    invoke-static {p0}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 1140
    .line 1141
    .line 1142
    move-result-object p0

    .line 1143
    iget-boolean p1, p2, Lew/i;->g:Z

    .line 1144
    .line 1145
    invoke-static {p1}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 1146
    .line 1147
    .line 1148
    move-result-object p1

    .line 1149
    new-instance p2, Llx0/l;

    .line 1150
    .line 1151
    invoke-direct {p2, p0, p1}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 1152
    .line 1153
    .line 1154
    return-object p2

    .line 1155
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
