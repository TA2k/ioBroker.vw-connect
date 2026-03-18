.class public final Lsc0/e;
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
    iput p1, p0, Lsc0/e;->d:I

    .line 2
    .line 3
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 10

    .line 1
    iget p0, p0, Lsc0/e;->d:I

    .line 2
    .line 3
    packed-switch p0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Lk21/a;

    .line 7
    .line 8
    check-cast p2, Lg21/a;

    .line 9
    .line 10
    const-string p0, "$this$factory"

    .line 11
    .line 12
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 13
    .line 14
    .line 15
    const-string p0, "it"

    .line 16
    .line 17
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 18
    .line 19
    .line 20
    sget-object p0, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 21
    .line 22
    const-class p2, Lkf0/m;

    .line 23
    .line 24
    invoke-virtual {p0, p2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 25
    .line 26
    .line 27
    move-result-object p2

    .line 28
    const/4 v0, 0x0

    .line 29
    invoke-virtual {p1, p2, v0, v0}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 30
    .line 31
    .line 32
    move-result-object p2

    .line 33
    const-class v1, Lsf0/a;

    .line 34
    .line 35
    invoke-virtual {p0, v1}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 36
    .line 37
    .line 38
    move-result-object v1

    .line 39
    invoke-virtual {p1, v1, v0, v0}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 40
    .line 41
    .line 42
    move-result-object v1

    .line 43
    const-class v2, Lkf0/j0;

    .line 44
    .line 45
    invoke-virtual {p0, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 46
    .line 47
    .line 48
    move-result-object v2

    .line 49
    invoke-virtual {p1, v2, v0, v0}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 50
    .line 51
    .line 52
    move-result-object v2

    .line 53
    const-class v3, Lko0/f;

    .line 54
    .line 55
    invoke-virtual {p0, v3}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 56
    .line 57
    .line 58
    move-result-object v3

    .line 59
    invoke-virtual {p1, v3, v0, v0}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 60
    .line 61
    .line 62
    move-result-object v3

    .line 63
    const-class v4, Lry/k;

    .line 64
    .line 65
    invoke-virtual {p0, v4}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 66
    .line 67
    .line 68
    move-result-object p0

    .line 69
    invoke-virtual {p1, p0, v0, v0}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 70
    .line 71
    .line 72
    move-result-object p0

    .line 73
    move-object v8, p0

    .line 74
    check-cast v8, Lry/k;

    .line 75
    .line 76
    move-object v7, v3

    .line 77
    check-cast v7, Lko0/f;

    .line 78
    .line 79
    move-object v6, v2

    .line 80
    check-cast v6, Lkf0/j0;

    .line 81
    .line 82
    move-object v9, v1

    .line 83
    check-cast v9, Lsf0/a;

    .line 84
    .line 85
    move-object v5, p2

    .line 86
    check-cast v5, Lkf0/m;

    .line 87
    .line 88
    new-instance v4, Lty/k;

    .line 89
    .line 90
    invoke-direct/range {v4 .. v9}, Lty/k;-><init>(Lkf0/m;Lkf0/j0;Lko0/f;Lry/k;Lsf0/a;)V

    .line 91
    .line 92
    .line 93
    return-object v4

    .line 94
    :pswitch_0
    check-cast p1, Lk21/a;

    .line 95
    .line 96
    check-cast p2, Lg21/a;

    .line 97
    .line 98
    const-string p0, "$this$factory"

    .line 99
    .line 100
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 101
    .line 102
    .line 103
    const-string p0, "it"

    .line 104
    .line 105
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 106
    .line 107
    .line 108
    sget-object p0, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 109
    .line 110
    const-class p2, Lkf0/m;

    .line 111
    .line 112
    invoke-virtual {p0, p2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 113
    .line 114
    .line 115
    move-result-object p2

    .line 116
    const/4 v0, 0x0

    .line 117
    invoke-virtual {p1, p2, v0, v0}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 118
    .line 119
    .line 120
    move-result-object p2

    .line 121
    const-class v1, Lsf0/a;

    .line 122
    .line 123
    invoke-virtual {p0, v1}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 124
    .line 125
    .line 126
    move-result-object v1

    .line 127
    invoke-virtual {p1, v1, v0, v0}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 128
    .line 129
    .line 130
    move-result-object v1

    .line 131
    const-class v2, Ljn0/c;

    .line 132
    .line 133
    invoke-virtual {p0, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 134
    .line 135
    .line 136
    move-result-object v2

    .line 137
    invoke-virtual {p1, v2, v0, v0}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 138
    .line 139
    .line 140
    move-result-object v2

    .line 141
    const-class v3, Lkf0/j0;

    .line 142
    .line 143
    invoke-virtual {p0, v3}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 144
    .line 145
    .line 146
    move-result-object v3

    .line 147
    invoke-virtual {p1, v3, v0, v0}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 148
    .line 149
    .line 150
    move-result-object v3

    .line 151
    const-class v4, Lry/k;

    .line 152
    .line 153
    invoke-virtual {p0, v4}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 154
    .line 155
    .line 156
    move-result-object p0

    .line 157
    invoke-virtual {p1, p0, v0, v0}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 158
    .line 159
    .line 160
    move-result-object p0

    .line 161
    move-object v9, p0

    .line 162
    check-cast v9, Lry/k;

    .line 163
    .line 164
    move-object v8, v3

    .line 165
    check-cast v8, Lkf0/j0;

    .line 166
    .line 167
    move-object v7, v2

    .line 168
    check-cast v7, Ljn0/c;

    .line 169
    .line 170
    move-object v6, v1

    .line 171
    check-cast v6, Lsf0/a;

    .line 172
    .line 173
    move-object v5, p2

    .line 174
    check-cast v5, Lkf0/m;

    .line 175
    .line 176
    new-instance v4, Lty/m;

    .line 177
    .line 178
    invoke-direct/range {v4 .. v9}, Lty/m;-><init>(Lkf0/m;Lsf0/a;Ljn0/c;Lkf0/j0;Lry/k;)V

    .line 179
    .line 180
    .line 181
    return-object v4

    .line 182
    :pswitch_1
    check-cast p1, Lk21/a;

    .line 183
    .line 184
    check-cast p2, Lg21/a;

    .line 185
    .line 186
    const-string p0, "$this$factory"

    .line 187
    .line 188
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 189
    .line 190
    .line 191
    const-string p0, "it"

    .line 192
    .line 193
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 194
    .line 195
    .line 196
    const-class p0, Lty/a;

    .line 197
    .line 198
    sget-object p2, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 199
    .line 200
    invoke-virtual {p2, p0}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 201
    .line 202
    .line 203
    move-result-object p0

    .line 204
    const/4 p2, 0x0

    .line 205
    invoke-virtual {p1, p0, p2, p2}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 206
    .line 207
    .line 208
    move-result-object p0

    .line 209
    check-cast p0, Lty/a;

    .line 210
    .line 211
    new-instance p1, Lty/i;

    .line 212
    .line 213
    invoke-direct {p1, p0}, Lty/i;-><init>(Lty/a;)V

    .line 214
    .line 215
    .line 216
    return-object p1

    .line 217
    :pswitch_2
    check-cast p1, Lk21/a;

    .line 218
    .line 219
    check-cast p2, Lg21/a;

    .line 220
    .line 221
    const-string p0, "$this$factory"

    .line 222
    .line 223
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 224
    .line 225
    .line 226
    const-string p0, "it"

    .line 227
    .line 228
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 229
    .line 230
    .line 231
    const-class p0, Ltr0/a;

    .line 232
    .line 233
    sget-object p2, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 234
    .line 235
    invoke-virtual {p2, p0}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 236
    .line 237
    .line 238
    move-result-object p0

    .line 239
    const/4 p2, 0x0

    .line 240
    invoke-virtual {p1, p0, p2, p2}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 241
    .line 242
    .line 243
    move-result-object p0

    .line 244
    check-cast p0, Ltr0/a;

    .line 245
    .line 246
    new-instance p1, Ltr0/b;

    .line 247
    .line 248
    invoke-direct {p1, p0}, Ltr0/b;-><init>(Ltr0/a;)V

    .line 249
    .line 250
    .line 251
    return-object p1

    .line 252
    :pswitch_3
    check-cast p1, Lk21/a;

    .line 253
    .line 254
    check-cast p2, Lg21/a;

    .line 255
    .line 256
    const-string p0, "$this$single"

    .line 257
    .line 258
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 259
    .line 260
    .line 261
    const-string p0, "it"

    .line 262
    .line 263
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 264
    .line 265
    .line 266
    new-instance p0, Lrn0/i;

    .line 267
    .line 268
    invoke-direct {p0}, Lrn0/i;-><init>()V

    .line 269
    .line 270
    .line 271
    return-object p0

    .line 272
    :pswitch_4
    check-cast p1, Lk21/a;

    .line 273
    .line 274
    check-cast p2, Lg21/a;

    .line 275
    .line 276
    const-string p0, "$this$factory"

    .line 277
    .line 278
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 279
    .line 280
    .line 281
    const-string p0, "it"

    .line 282
    .line 283
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 284
    .line 285
    .line 286
    const-class p0, Lrn0/i;

    .line 287
    .line 288
    sget-object p2, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 289
    .line 290
    invoke-virtual {p2, p0}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 291
    .line 292
    .line 293
    move-result-object p0

    .line 294
    const/4 p2, 0x0

    .line 295
    invoke-virtual {p1, p0, p2, p2}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 296
    .line 297
    .line 298
    move-result-object p0

    .line 299
    check-cast p0, Lrn0/i;

    .line 300
    .line 301
    new-instance p1, Lvn0/a;

    .line 302
    .line 303
    invoke-direct {p1, p0}, Lvn0/a;-><init>(Lrn0/i;)V

    .line 304
    .line 305
    .line 306
    return-object p1

    .line 307
    :pswitch_5
    check-cast p1, Lk21/a;

    .line 308
    .line 309
    check-cast p2, Lg21/a;

    .line 310
    .line 311
    const-string p0, "$this$factory"

    .line 312
    .line 313
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 314
    .line 315
    .line 316
    const-string p0, "it"

    .line 317
    .line 318
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 319
    .line 320
    .line 321
    const-class p0, Ltn0/f;

    .line 322
    .line 323
    sget-object p2, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 324
    .line 325
    invoke-virtual {p2, p0}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 326
    .line 327
    .line 328
    move-result-object p0

    .line 329
    const/4 p2, 0x0

    .line 330
    invoke-virtual {p1, p0, p2, p2}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 331
    .line 332
    .line 333
    move-result-object p0

    .line 334
    check-cast p0, Ltn0/f;

    .line 335
    .line 336
    new-instance p1, Ltn0/e;

    .line 337
    .line 338
    invoke-direct {p1, p0}, Ltn0/e;-><init>(Ltn0/f;)V

    .line 339
    .line 340
    .line 341
    return-object p1

    .line 342
    :pswitch_6
    check-cast p1, Lk21/a;

    .line 343
    .line 344
    check-cast p2, Lg21/a;

    .line 345
    .line 346
    const-string p0, "$this$factory"

    .line 347
    .line 348
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 349
    .line 350
    .line 351
    const-string p0, "it"

    .line 352
    .line 353
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 354
    .line 355
    .line 356
    const-class p0, Ltn0/f;

    .line 357
    .line 358
    sget-object p2, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 359
    .line 360
    invoke-virtual {p2, p0}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 361
    .line 362
    .line 363
    move-result-object p0

    .line 364
    const/4 p2, 0x0

    .line 365
    invoke-virtual {p1, p0, p2, p2}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 366
    .line 367
    .line 368
    move-result-object p0

    .line 369
    check-cast p0, Ltn0/f;

    .line 370
    .line 371
    new-instance p1, Ltn0/d;

    .line 372
    .line 373
    invoke-direct {p1, p0}, Ltn0/d;-><init>(Ltn0/f;)V

    .line 374
    .line 375
    .line 376
    return-object p1

    .line 377
    :pswitch_7
    check-cast p1, Lk21/a;

    .line 378
    .line 379
    check-cast p2, Lg21/a;

    .line 380
    .line 381
    const-string p0, "$this$factory"

    .line 382
    .line 383
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 384
    .line 385
    .line 386
    const-string p0, "it"

    .line 387
    .line 388
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 389
    .line 390
    .line 391
    const-class p0, Ltn0/f;

    .line 392
    .line 393
    sget-object p2, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 394
    .line 395
    invoke-virtual {p2, p0}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 396
    .line 397
    .line 398
    move-result-object p0

    .line 399
    const/4 p2, 0x0

    .line 400
    invoke-virtual {p1, p0, p2, p2}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 401
    .line 402
    .line 403
    move-result-object p0

    .line 404
    check-cast p0, Ltn0/f;

    .line 405
    .line 406
    new-instance p1, Ltn0/b;

    .line 407
    .line 408
    invoke-direct {p1, p0}, Ltn0/b;-><init>(Ltn0/f;)V

    .line 409
    .line 410
    .line 411
    return-object p1

    .line 412
    :pswitch_8
    check-cast p1, Lk21/a;

    .line 413
    .line 414
    check-cast p2, Lg21/a;

    .line 415
    .line 416
    const-string p0, "$this$factory"

    .line 417
    .line 418
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 419
    .line 420
    .line 421
    const-string p0, "it"

    .line 422
    .line 423
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 424
    .line 425
    .line 426
    const-class p0, Ltn0/f;

    .line 427
    .line 428
    sget-object p2, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 429
    .line 430
    invoke-virtual {p2, p0}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 431
    .line 432
    .line 433
    move-result-object p0

    .line 434
    const/4 p2, 0x0

    .line 435
    invoke-virtual {p1, p0, p2, p2}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 436
    .line 437
    .line 438
    move-result-object p0

    .line 439
    check-cast p0, Ltn0/f;

    .line 440
    .line 441
    new-instance p1, Ltn0/a;

    .line 442
    .line 443
    invoke-direct {p1, p0}, Ltn0/a;-><init>(Ltn0/f;)V

    .line 444
    .line 445
    .line 446
    return-object p1

    .line 447
    :pswitch_9
    check-cast p1, Lk21/a;

    .line 448
    .line 449
    check-cast p2, Lg21/a;

    .line 450
    .line 451
    const-string p0, "$this$factory"

    .line 452
    .line 453
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 454
    .line 455
    .line 456
    const-string p0, "it"

    .line 457
    .line 458
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 459
    .line 460
    .line 461
    sget-object p0, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 462
    .line 463
    const-class p2, Lbd0/c;

    .line 464
    .line 465
    invoke-virtual {p0, p2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 466
    .line 467
    .line 468
    move-result-object p2

    .line 469
    const/4 v0, 0x0

    .line 470
    invoke-virtual {p1, p2, v0, v0}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 471
    .line 472
    .line 473
    move-result-object p2

    .line 474
    const-class v1, Lkf0/o;

    .line 475
    .line 476
    invoke-virtual {p0, v1}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 477
    .line 478
    .line 479
    move-result-object v1

    .line 480
    invoke-virtual {p1, v1, v0, v0}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 481
    .line 482
    .line 483
    move-result-object v1

    .line 484
    const-class v2, Lrj0/a;

    .line 485
    .line 486
    invoke-virtual {p0, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 487
    .line 488
    .line 489
    move-result-object v2

    .line 490
    invoke-virtual {p1, v2, v0, v0}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 491
    .line 492
    .line 493
    move-result-object v2

    .line 494
    const-class v3, Lsf0/a;

    .line 495
    .line 496
    invoke-virtual {p0, v3}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 497
    .line 498
    .line 499
    move-result-object p0

    .line 500
    invoke-virtual {p1, p0, v0, v0}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 501
    .line 502
    .line 503
    move-result-object p0

    .line 504
    check-cast p0, Lsf0/a;

    .line 505
    .line 506
    check-cast v2, Lrj0/a;

    .line 507
    .line 508
    check-cast v1, Lkf0/o;

    .line 509
    .line 510
    check-cast p2, Lbd0/c;

    .line 511
    .line 512
    new-instance p1, Ltj0/a;

    .line 513
    .line 514
    invoke-direct {p1, p2, v1, v2, p0}, Ltj0/a;-><init>(Lbd0/c;Lkf0/o;Lrj0/a;Lsf0/a;)V

    .line 515
    .line 516
    .line 517
    return-object p1

    .line 518
    :pswitch_a
    check-cast p1, Lk21/a;

    .line 519
    .line 520
    check-cast p2, Lg21/a;

    .line 521
    .line 522
    const-string p0, "$this$single"

    .line 523
    .line 524
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 525
    .line 526
    .line 527
    const-string p0, "it"

    .line 528
    .line 529
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 530
    .line 531
    .line 532
    const-class p0, Lve0/u;

    .line 533
    .line 534
    sget-object p2, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 535
    .line 536
    invoke-virtual {p2, p0}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 537
    .line 538
    .line 539
    move-result-object p0

    .line 540
    const/4 p2, 0x0

    .line 541
    invoke-virtual {p1, p0, p2, p2}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 542
    .line 543
    .line 544
    move-result-object p0

    .line 545
    check-cast p0, Lve0/u;

    .line 546
    .line 547
    new-instance p1, Lre0/d;

    .line 548
    .line 549
    invoke-direct {p1, p0}, Lre0/d;-><init>(Lve0/u;)V

    .line 550
    .line 551
    .line 552
    return-object p1

    .line 553
    :pswitch_b
    check-cast p1, Lk21/a;

    .line 554
    .line 555
    check-cast p2, Lg21/a;

    .line 556
    .line 557
    const-string p0, "$this$single"

    .line 558
    .line 559
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 560
    .line 561
    .line 562
    const-string p0, "it"

    .line 563
    .line 564
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 565
    .line 566
    .line 567
    sget-object p0, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 568
    .line 569
    const-class p2, Lve0/v;

    .line 570
    .line 571
    invoke-virtual {p0, p2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 572
    .line 573
    .line 574
    move-result-object p2

    .line 575
    const/4 v0, 0x0

    .line 576
    invoke-virtual {p1, p2, v0, v0}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 577
    .line 578
    .line 579
    move-result-object p2

    .line 580
    const-class v1, Lve0/a;

    .line 581
    .line 582
    invoke-virtual {p0, v1}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 583
    .line 584
    .line 585
    move-result-object p0

    .line 586
    invoke-virtual {p1, p0, v0, v0}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 587
    .line 588
    .line 589
    move-result-object p0

    .line 590
    check-cast p0, Lve0/a;

    .line 591
    .line 592
    check-cast p2, Lve0/v;

    .line 593
    .line 594
    new-instance p1, Lre0/c;

    .line 595
    .line 596
    invoke-direct {p1, p2, p0}, Lre0/c;-><init>(Lve0/v;Lve0/a;)V

    .line 597
    .line 598
    .line 599
    return-object p1

    .line 600
    :pswitch_c
    check-cast p1, Lk21/a;

    .line 601
    .line 602
    check-cast p2, Lg21/a;

    .line 603
    .line 604
    const-string p0, "$this$factory"

    .line 605
    .line 606
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 607
    .line 608
    .line 609
    const-string p0, "it"

    .line 610
    .line 611
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 612
    .line 613
    .line 614
    const-class p0, Lte0/a;

    .line 615
    .line 616
    sget-object p2, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 617
    .line 618
    invoke-virtual {p2, p0}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 619
    .line 620
    .line 621
    move-result-object p0

    .line 622
    const/4 p2, 0x0

    .line 623
    invoke-virtual {p1, p0, p2, p2}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 624
    .line 625
    .line 626
    move-result-object p0

    .line 627
    check-cast p0, Lte0/a;

    .line 628
    .line 629
    new-instance p1, Lve0/d;

    .line 630
    .line 631
    invoke-direct {p1, p0}, Lve0/d;-><init>(Lte0/a;)V

    .line 632
    .line 633
    .line 634
    return-object p1

    .line 635
    :pswitch_d
    check-cast p1, Lk21/a;

    .line 636
    .line 637
    check-cast p2, Lg21/a;

    .line 638
    .line 639
    const-string p0, "$this$factory"

    .line 640
    .line 641
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 642
    .line 643
    .line 644
    const-string p0, "it"

    .line 645
    .line 646
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 647
    .line 648
    .line 649
    new-instance p0, Lve0/v;

    .line 650
    .line 651
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 652
    .line 653
    .line 654
    return-object p0

    .line 655
    :pswitch_e
    check-cast p1, Lk21/a;

    .line 656
    .line 657
    check-cast p2, Lg21/a;

    .line 658
    .line 659
    const-string p0, "$this$factory"

    .line 660
    .line 661
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 662
    .line 663
    .line 664
    const-string p0, "it"

    .line 665
    .line 666
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 667
    .line 668
    .line 669
    const-class p0, Lte0/d;

    .line 670
    .line 671
    sget-object p2, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 672
    .line 673
    invoke-virtual {p2, p0}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 674
    .line 675
    .line 676
    move-result-object p0

    .line 677
    const/4 p2, 0x0

    .line 678
    invoke-virtual {p1, p0, p2, p2}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 679
    .line 680
    .line 681
    move-result-object p0

    .line 682
    check-cast p0, Lte0/d;

    .line 683
    .line 684
    new-instance p1, Lte0/f;

    .line 685
    .line 686
    invoke-direct {p1, p0}, Lte0/f;-><init>(Lte0/d;)V

    .line 687
    .line 688
    .line 689
    return-object p1

    .line 690
    :pswitch_f
    check-cast p1, Lk21/a;

    .line 691
    .line 692
    check-cast p2, Lg21/a;

    .line 693
    .line 694
    const-string p0, "$this$factory"

    .line 695
    .line 696
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 697
    .line 698
    .line 699
    const-string p0, "it"

    .line 700
    .line 701
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 702
    .line 703
    .line 704
    const-class p0, Lte0/c;

    .line 705
    .line 706
    sget-object p2, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 707
    .line 708
    invoke-virtual {p2, p0}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 709
    .line 710
    .line 711
    move-result-object p0

    .line 712
    const/4 p2, 0x0

    .line 713
    invoke-virtual {p1, p0, p2, p2}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 714
    .line 715
    .line 716
    move-result-object p0

    .line 717
    check-cast p0, Lte0/c;

    .line 718
    .line 719
    new-instance p1, Lte0/a;

    .line 720
    .line 721
    invoke-direct {p1, p0}, Lte0/a;-><init>(Lte0/c;)V

    .line 722
    .line 723
    .line 724
    return-object p1

    .line 725
    :pswitch_10
    check-cast p1, Lk21/a;

    .line 726
    .line 727
    check-cast p2, Lg21/a;

    .line 728
    .line 729
    const-string p0, "$this$factory"

    .line 730
    .line 731
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 732
    .line 733
    .line 734
    const-string p0, "it"

    .line 735
    .line 736
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 737
    .line 738
    .line 739
    const-class p0, Lte0/c;

    .line 740
    .line 741
    sget-object p2, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 742
    .line 743
    invoke-virtual {p2, p0}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 744
    .line 745
    .line 746
    move-result-object p0

    .line 747
    const/4 p2, 0x0

    .line 748
    invoke-virtual {p1, p0, p2, p2}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 749
    .line 750
    .line 751
    move-result-object p0

    .line 752
    check-cast p0, Lte0/c;

    .line 753
    .line 754
    new-instance p1, Lte0/b;

    .line 755
    .line 756
    invoke-direct {p1, p0}, Lte0/b;-><init>(Lte0/c;)V

    .line 757
    .line 758
    .line 759
    return-object p1

    .line 760
    :pswitch_11
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
    new-instance p0, Lve0/a;

    .line 775
    .line 776
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 777
    .line 778
    .line 779
    return-object p0

    .line 780
    :pswitch_12
    check-cast p1, Lk21/a;

    .line 781
    .line 782
    check-cast p2, Lg21/a;

    .line 783
    .line 784
    const-string p0, "$this$single"

    .line 785
    .line 786
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 787
    .line 788
    .line 789
    const-string p0, "it"

    .line 790
    .line 791
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 792
    .line 793
    .line 794
    new-instance p0, Lsc0/c;

    .line 795
    .line 796
    const/16 p2, 0x17

    .line 797
    .line 798
    invoke-direct {p0, p1, p2}, Lsc0/c;-><init>(Lk21/a;I)V

    .line 799
    .line 800
    .line 801
    return-object p0

    .line 802
    :pswitch_13
    check-cast p1, Lk21/a;

    .line 803
    .line 804
    check-cast p2, Lg21/a;

    .line 805
    .line 806
    const-string p0, "$this$single"

    .line 807
    .line 808
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 809
    .line 810
    .line 811
    const-string p0, "it"

    .line 812
    .line 813
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 814
    .line 815
    .line 816
    new-instance p0, Lsc0/c;

    .line 817
    .line 818
    const/16 p2, 0x16

    .line 819
    .line 820
    invoke-direct {p0, p1, p2}, Lsc0/c;-><init>(Lk21/a;I)V

    .line 821
    .line 822
    .line 823
    return-object p0

    .line 824
    :pswitch_14
    check-cast p1, Lk21/a;

    .line 825
    .line 826
    check-cast p2, Lg21/a;

    .line 827
    .line 828
    const-string p0, "$this$single"

    .line 829
    .line 830
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 831
    .line 832
    .line 833
    const-string p0, "it"

    .line 834
    .line 835
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 836
    .line 837
    .line 838
    new-instance p0, Lsc0/c;

    .line 839
    .line 840
    const/16 p2, 0x15

    .line 841
    .line 842
    invoke-direct {p0, p1, p2}, Lsc0/c;-><init>(Lk21/a;I)V

    .line 843
    .line 844
    .line 845
    return-object p0

    .line 846
    :pswitch_15
    check-cast p1, Lk21/a;

    .line 847
    .line 848
    check-cast p2, Lg21/a;

    .line 849
    .line 850
    const-string p0, "$this$single"

    .line 851
    .line 852
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 853
    .line 854
    .line 855
    const-string p0, "it"

    .line 856
    .line 857
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 858
    .line 859
    .line 860
    new-instance p0, Lsc0/c;

    .line 861
    .line 862
    const/16 p2, 0x14

    .line 863
    .line 864
    invoke-direct {p0, p1, p2}, Lsc0/c;-><init>(Lk21/a;I)V

    .line 865
    .line 866
    .line 867
    return-object p0

    .line 868
    :pswitch_16
    check-cast p1, Lk21/a;

    .line 869
    .line 870
    check-cast p2, Lg21/a;

    .line 871
    .line 872
    const-string p0, "$this$single"

    .line 873
    .line 874
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 875
    .line 876
    .line 877
    const-string p0, "it"

    .line 878
    .line 879
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 880
    .line 881
    .line 882
    new-instance p0, Lsc0/c;

    .line 883
    .line 884
    const/16 p2, 0x13

    .line 885
    .line 886
    invoke-direct {p0, p1, p2}, Lsc0/c;-><init>(Lk21/a;I)V

    .line 887
    .line 888
    .line 889
    return-object p0

    .line 890
    :pswitch_17
    check-cast p1, Lk21/a;

    .line 891
    .line 892
    check-cast p2, Lg21/a;

    .line 893
    .line 894
    const-string p0, "$this$single"

    .line 895
    .line 896
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 897
    .line 898
    .line 899
    const-string p0, "it"

    .line 900
    .line 901
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 902
    .line 903
    .line 904
    new-instance p0, Lsc0/c;

    .line 905
    .line 906
    const/16 p2, 0x12

    .line 907
    .line 908
    invoke-direct {p0, p1, p2}, Lsc0/c;-><init>(Lk21/a;I)V

    .line 909
    .line 910
    .line 911
    return-object p0

    .line 912
    :pswitch_18
    check-cast p1, Lk21/a;

    .line 913
    .line 914
    check-cast p2, Lg21/a;

    .line 915
    .line 916
    const-string p0, "$this$factory"

    .line 917
    .line 918
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 919
    .line 920
    .line 921
    const-string p0, "it"

    .line 922
    .line 923
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 924
    .line 925
    .line 926
    new-instance p0, Lsc0/c;

    .line 927
    .line 928
    const/16 p2, 0x11

    .line 929
    .line 930
    invoke-direct {p0, p1, p2}, Lsc0/c;-><init>(Lk21/a;I)V

    .line 931
    .line 932
    .line 933
    return-object p0

    .line 934
    :pswitch_19
    check-cast p1, Lk21/a;

    .line 935
    .line 936
    check-cast p2, Lg21/a;

    .line 937
    .line 938
    const-string p0, "$this$factory"

    .line 939
    .line 940
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 941
    .line 942
    .line 943
    const-string p0, "it"

    .line 944
    .line 945
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 946
    .line 947
    .line 948
    new-instance p0, Lsc0/c;

    .line 949
    .line 950
    const/16 p2, 0x10

    .line 951
    .line 952
    invoke-direct {p0, p1, p2}, Lsc0/c;-><init>(Lk21/a;I)V

    .line 953
    .line 954
    .line 955
    return-object p0

    .line 956
    :pswitch_1a
    check-cast p1, Lk21/a;

    .line 957
    .line 958
    check-cast p2, Lg21/a;

    .line 959
    .line 960
    const-string p0, "$this$factory"

    .line 961
    .line 962
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 963
    .line 964
    .line 965
    const-string p0, "it"

    .line 966
    .line 967
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 968
    .line 969
    .line 970
    new-instance p0, Lsc0/c;

    .line 971
    .line 972
    const/16 p2, 0xf

    .line 973
    .line 974
    invoke-direct {p0, p1, p2}, Lsc0/c;-><init>(Lk21/a;I)V

    .line 975
    .line 976
    .line 977
    return-object p0

    .line 978
    :pswitch_1b
    check-cast p1, Lk21/a;

    .line 979
    .line 980
    check-cast p2, Lg21/a;

    .line 981
    .line 982
    const-string p0, "$this$factory"

    .line 983
    .line 984
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 985
    .line 986
    .line 987
    const-string p0, "it"

    .line 988
    .line 989
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 990
    .line 991
    .line 992
    new-instance p0, Lsc0/c;

    .line 993
    .line 994
    const/16 p2, 0xe

    .line 995
    .line 996
    invoke-direct {p0, p1, p2}, Lsc0/c;-><init>(Lk21/a;I)V

    .line 997
    .line 998
    .line 999
    return-object p0

    .line 1000
    :pswitch_1c
    check-cast p1, Lk21/a;

    .line 1001
    .line 1002
    check-cast p2, Lg21/a;

    .line 1003
    .line 1004
    const-string p0, "$this$factory"

    .line 1005
    .line 1006
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1007
    .line 1008
    .line 1009
    const-string p0, "it"

    .line 1010
    .line 1011
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1012
    .line 1013
    .line 1014
    new-instance p0, Lsc0/c;

    .line 1015
    .line 1016
    const/16 p2, 0xd

    .line 1017
    .line 1018
    invoke-direct {p0, p1, p2}, Lsc0/c;-><init>(Lk21/a;I)V

    .line 1019
    .line 1020
    .line 1021
    return-object p0

    .line 1022
    nop

    .line 1023
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
