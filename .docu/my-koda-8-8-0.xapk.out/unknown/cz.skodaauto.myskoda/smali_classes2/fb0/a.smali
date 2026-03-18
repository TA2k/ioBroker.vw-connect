.class public final Lfb0/a;
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
    iput p1, p0, Lfb0/a;->d:I

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
    iget p0, p0, Lfb0/a;->d:I

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
    const-string p0, "$this$viewModel"

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
    const-class p2, Lgk0/a;

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
    const-class v1, Lwj0/k;

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
    const-class v2, Lal0/s0;

    .line 44
    .line 45
    invoke-virtual {p0, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 46
    .line 47
    .line 48
    move-result-object p0

    .line 49
    invoke-virtual {p1, p0, v0, v0}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 50
    .line 51
    .line 52
    move-result-object p0

    .line 53
    check-cast p0, Lal0/s0;

    .line 54
    .line 55
    check-cast v1, Lwj0/k;

    .line 56
    .line 57
    check-cast p2, Lgk0/a;

    .line 58
    .line 59
    new-instance p1, Lhk0/c;

    .line 60
    .line 61
    invoke-direct {p1, p2, v1, p0}, Lhk0/c;-><init>(Lgk0/a;Lwj0/k;Lal0/s0;)V

    .line 62
    .line 63
    .line 64
    return-object p1

    .line 65
    :pswitch_0
    check-cast p1, Lk21/a;

    .line 66
    .line 67
    check-cast p2, Lg21/a;

    .line 68
    .line 69
    const-string p0, "$this$single"

    .line 70
    .line 71
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 72
    .line 73
    .line 74
    const-string p0, "it"

    .line 75
    .line 76
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 77
    .line 78
    .line 79
    const-class p0, Lve0/u;

    .line 80
    .line 81
    sget-object p2, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 82
    .line 83
    invoke-virtual {p2, p0}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 84
    .line 85
    .line 86
    move-result-object p0

    .line 87
    const/4 p2, 0x0

    .line 88
    invoke-virtual {p1, p0, p2, p2}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 89
    .line 90
    .line 91
    move-result-object p0

    .line 92
    check-cast p0, Lve0/u;

    .line 93
    .line 94
    new-instance p1, Lek0/a;

    .line 95
    .line 96
    invoke-direct {p1, p0}, Lek0/a;-><init>(Lve0/u;)V

    .line 97
    .line 98
    .line 99
    return-object p1

    .line 100
    :pswitch_1
    check-cast p1, Lk21/a;

    .line 101
    .line 102
    check-cast p2, Lg21/a;

    .line 103
    .line 104
    const-string p0, "$this$factory"

    .line 105
    .line 106
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 107
    .line 108
    .line 109
    const-string p0, "it"

    .line 110
    .line 111
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 112
    .line 113
    .line 114
    const-class p0, Lgk0/b;

    .line 115
    .line 116
    sget-object p2, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 117
    .line 118
    invoke-virtual {p2, p0}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 119
    .line 120
    .line 121
    move-result-object p0

    .line 122
    const/4 p2, 0x0

    .line 123
    invoke-virtual {p1, p0, p2, p2}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 124
    .line 125
    .line 126
    move-result-object p0

    .line 127
    check-cast p0, Lgk0/b;

    .line 128
    .line 129
    new-instance p1, Lgk0/d;

    .line 130
    .line 131
    invoke-direct {p1, p0}, Lgk0/d;-><init>(Lgk0/b;)V

    .line 132
    .line 133
    .line 134
    return-object p1

    .line 135
    :pswitch_2
    check-cast p1, Lk21/a;

    .line 136
    .line 137
    check-cast p2, Lg21/a;

    .line 138
    .line 139
    const-string p0, "$this$factory"

    .line 140
    .line 141
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 142
    .line 143
    .line 144
    const-string p0, "it"

    .line 145
    .line 146
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 147
    .line 148
    .line 149
    const-class p0, Lgk0/b;

    .line 150
    .line 151
    sget-object p2, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 152
    .line 153
    invoke-virtual {p2, p0}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 154
    .line 155
    .line 156
    move-result-object p0

    .line 157
    const/4 p2, 0x0

    .line 158
    invoke-virtual {p1, p0, p2, p2}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 159
    .line 160
    .line 161
    move-result-object p0

    .line 162
    check-cast p0, Lgk0/b;

    .line 163
    .line 164
    new-instance p1, Lgk0/a;

    .line 165
    .line 166
    invoke-direct {p1, p0}, Lgk0/a;-><init>(Lgk0/b;)V

    .line 167
    .line 168
    .line 169
    return-object p1

    .line 170
    :pswitch_3
    check-cast p1, Lk21/a;

    .line 171
    .line 172
    check-cast p2, Lg21/a;

    .line 173
    .line 174
    const-string p0, "$this$single"

    .line 175
    .line 176
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 177
    .line 178
    .line 179
    const-string p0, "it"

    .line 180
    .line 181
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 182
    .line 183
    .line 184
    sget-object p0, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 185
    .line 186
    const-class p2, Landroid/content/Context;

    .line 187
    .line 188
    invoke-virtual {p0, p2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 189
    .line 190
    .line 191
    move-result-object p2

    .line 192
    const/4 v0, 0x0

    .line 193
    invoke-virtual {p1, p2, v0, v0}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 194
    .line 195
    .line 196
    move-result-object p2

    .line 197
    const-class v1, Lei0/a;

    .line 198
    .line 199
    invoke-virtual {p0, v1}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 200
    .line 201
    .line 202
    move-result-object p0

    .line 203
    invoke-virtual {p1, p0, v0, v0}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 204
    .line 205
    .line 206
    move-result-object p0

    .line 207
    check-cast p0, Lei0/a;

    .line 208
    .line 209
    check-cast p2, Landroid/content/Context;

    .line 210
    .line 211
    new-instance p1, Lhi0/a;

    .line 212
    .line 213
    invoke-direct {p1, p2, p0}, Lhi0/a;-><init>(Landroid/content/Context;Lei0/a;)V

    .line 214
    .line 215
    .line 216
    return-object p1

    .line 217
    :pswitch_4
    check-cast p1, Lk21/a;

    .line 218
    .line 219
    check-cast p2, Lg21/a;

    .line 220
    .line 221
    const-string p0, "$this$single"

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
    new-instance p0, Lei0/a;

    .line 232
    .line 233
    invoke-direct {p0}, Lei0/a;-><init>()V

    .line 234
    .line 235
    .line 236
    return-object p0

    .line 237
    :pswitch_5
    check-cast p1, Lk21/a;

    .line 238
    .line 239
    check-cast p2, Lg21/a;

    .line 240
    .line 241
    const-string p0, "$this$factory"

    .line 242
    .line 243
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 244
    .line 245
    .line 246
    const-string p0, "it"

    .line 247
    .line 248
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 249
    .line 250
    .line 251
    const-class p0, Lgi0/b;

    .line 252
    .line 253
    sget-object p2, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 254
    .line 255
    invoke-virtual {p2, p0}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 256
    .line 257
    .line 258
    move-result-object p0

    .line 259
    const/4 p2, 0x0

    .line 260
    invoke-virtual {p1, p0, p2, p2}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 261
    .line 262
    .line 263
    move-result-object p0

    .line 264
    check-cast p0, Lgi0/b;

    .line 265
    .line 266
    new-instance p1, Lgi0/a;

    .line 267
    .line 268
    invoke-direct {p1, p0}, Lgi0/a;-><init>(Lgi0/b;)V

    .line 269
    .line 270
    .line 271
    return-object p1

    .line 272
    :pswitch_6
    check-cast p1, Lk21/a;

    .line 273
    .line 274
    check-cast p2, Lg21/a;

    .line 275
    .line 276
    const-string p0, "$this$single"

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
    new-instance p0, Ldf0/a;

    .line 287
    .line 288
    invoke-direct {p0}, Ldf0/a;-><init>()V

    .line 289
    .line 290
    .line 291
    return-object p0

    .line 292
    :pswitch_7
    check-cast p1, Lk21/a;

    .line 293
    .line 294
    check-cast p2, Lg21/a;

    .line 295
    .line 296
    const-string p0, "$this$single"

    .line 297
    .line 298
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 299
    .line 300
    .line 301
    const-string p0, "it"

    .line 302
    .line 303
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 304
    .line 305
    .line 306
    new-instance p0, Ldf0/b;

    .line 307
    .line 308
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 309
    .line 310
    .line 311
    return-object p0

    .line 312
    :pswitch_8
    check-cast p1, Lk21/a;

    .line 313
    .line 314
    check-cast p2, Lg21/a;

    .line 315
    .line 316
    const-string p0, "$this$single"

    .line 317
    .line 318
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 319
    .line 320
    .line 321
    const-string p0, "it"

    .line 322
    .line 323
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 324
    .line 325
    .line 326
    new-instance p0, Lef0/a;

    .line 327
    .line 328
    invoke-direct {p0}, Lef0/a;-><init>()V

    .line 329
    .line 330
    .line 331
    return-object p0

    .line 332
    :pswitch_9
    check-cast p1, Lk21/a;

    .line 333
    .line 334
    check-cast p2, Lg21/a;

    .line 335
    .line 336
    const-string p0, "$this$factory"

    .line 337
    .line 338
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 339
    .line 340
    .line 341
    const-string p0, "it"

    .line 342
    .line 343
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 344
    .line 345
    .line 346
    const-class p0, Lgf0/b;

    .line 347
    .line 348
    sget-object p2, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 349
    .line 350
    invoke-virtual {p2, p0}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 351
    .line 352
    .line 353
    move-result-object p0

    .line 354
    const/4 p2, 0x0

    .line 355
    invoke-virtual {p1, p0, p2, p2}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 356
    .line 357
    .line 358
    move-result-object p0

    .line 359
    check-cast p0, Lgf0/b;

    .line 360
    .line 361
    new-instance p1, Lgf0/f;

    .line 362
    .line 363
    invoke-direct {p1, p0}, Lgf0/f;-><init>(Lgf0/b;)V

    .line 364
    .line 365
    .line 366
    return-object p1

    .line 367
    :pswitch_a
    check-cast p1, Lk21/a;

    .line 368
    .line 369
    check-cast p2, Lg21/a;

    .line 370
    .line 371
    const-string p0, "$this$factory"

    .line 372
    .line 373
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 374
    .line 375
    .line 376
    const-string p0, "it"

    .line 377
    .line 378
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 379
    .line 380
    .line 381
    const-class p0, Lgf0/b;

    .line 382
    .line 383
    sget-object p2, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 384
    .line 385
    invoke-virtual {p2, p0}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 386
    .line 387
    .line 388
    move-result-object p0

    .line 389
    const/4 p2, 0x0

    .line 390
    invoke-virtual {p1, p0, p2, p2}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 391
    .line 392
    .line 393
    move-result-object p0

    .line 394
    check-cast p0, Lgf0/b;

    .line 395
    .line 396
    new-instance p1, Lgf0/c;

    .line 397
    .line 398
    invoke-direct {p1, p0}, Lgf0/c;-><init>(Lgf0/b;)V

    .line 399
    .line 400
    .line 401
    return-object p1

    .line 402
    :pswitch_b
    check-cast p1, Lk21/a;

    .line 403
    .line 404
    check-cast p2, Lg21/a;

    .line 405
    .line 406
    const-string p0, "$this$factory"

    .line 407
    .line 408
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 409
    .line 410
    .line 411
    const-string p0, "it"

    .line 412
    .line 413
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 414
    .line 415
    .line 416
    const-class p0, Lgf0/h;

    .line 417
    .line 418
    sget-object p2, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 419
    .line 420
    invoke-virtual {p2, p0}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 421
    .line 422
    .line 423
    move-result-object p0

    .line 424
    const/4 p2, 0x0

    .line 425
    invoke-virtual {p1, p0, p2, p2}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 426
    .line 427
    .line 428
    move-result-object p0

    .line 429
    check-cast p0, Lgf0/h;

    .line 430
    .line 431
    new-instance p1, Lgf0/d;

    .line 432
    .line 433
    invoke-direct {p1, p0}, Lgf0/d;-><init>(Lgf0/h;)V

    .line 434
    .line 435
    .line 436
    return-object p1

    .line 437
    :pswitch_c
    check-cast p1, Lk21/a;

    .line 438
    .line 439
    check-cast p2, Lg21/a;

    .line 440
    .line 441
    const-string p0, "$this$factory"

    .line 442
    .line 443
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 444
    .line 445
    .line 446
    const-string p0, "it"

    .line 447
    .line 448
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 449
    .line 450
    .line 451
    const-class p0, Lgf0/h;

    .line 452
    .line 453
    sget-object p2, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 454
    .line 455
    invoke-virtual {p2, p0}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 456
    .line 457
    .line 458
    move-result-object p0

    .line 459
    const/4 p2, 0x0

    .line 460
    invoke-virtual {p1, p0, p2, p2}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 461
    .line 462
    .line 463
    move-result-object p0

    .line 464
    check-cast p0, Lgf0/h;

    .line 465
    .line 466
    new-instance p1, Lgf0/g;

    .line 467
    .line 468
    invoke-direct {p1, p0}, Lgf0/g;-><init>(Lgf0/h;)V

    .line 469
    .line 470
    .line 471
    return-object p1

    .line 472
    :pswitch_d
    check-cast p1, Lk21/a;

    .line 473
    .line 474
    check-cast p2, Lg21/a;

    .line 475
    .line 476
    const-string p0, "$this$factory"

    .line 477
    .line 478
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 479
    .line 480
    .line 481
    const-string p0, "it"

    .line 482
    .line 483
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 484
    .line 485
    .line 486
    const-class p0, Lgf0/a;

    .line 487
    .line 488
    sget-object p2, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 489
    .line 490
    invoke-virtual {p2, p0}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 491
    .line 492
    .line 493
    move-result-object p0

    .line 494
    const/4 p2, 0x0

    .line 495
    invoke-virtual {p1, p0, p2, p2}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 496
    .line 497
    .line 498
    move-result-object p0

    .line 499
    check-cast p0, Lgf0/a;

    .line 500
    .line 501
    new-instance p1, Lgf0/e;

    .line 502
    .line 503
    invoke-direct {p1, p0}, Lgf0/e;-><init>(Lgf0/a;)V

    .line 504
    .line 505
    .line 506
    return-object p1

    .line 507
    :pswitch_e
    check-cast p1, Lk21/a;

    .line 508
    .line 509
    check-cast p2, Lg21/a;

    .line 510
    .line 511
    const-string p0, "$this$single"

    .line 512
    .line 513
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 514
    .line 515
    .line 516
    const-string p0, "it"

    .line 517
    .line 518
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 519
    .line 520
    .line 521
    new-instance p0, Lhc0/c;

    .line 522
    .line 523
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 524
    .line 525
    .line 526
    return-object p0

    .line 527
    :pswitch_f
    check-cast p1, Lk21/a;

    .line 528
    .line 529
    check-cast p2, Lg21/a;

    .line 530
    .line 531
    const-string p0, "$this$factory"

    .line 532
    .line 533
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 534
    .line 535
    .line 536
    const-string p0, "it"

    .line 537
    .line 538
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 539
    .line 540
    .line 541
    const-class p0, Lgc0/c;

    .line 542
    .line 543
    sget-object p2, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 544
    .line 545
    invoke-virtual {p2, p0}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 546
    .line 547
    .line 548
    move-result-object p0

    .line 549
    const/4 p2, 0x0

    .line 550
    invoke-virtual {p1, p0, p2, p2}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 551
    .line 552
    .line 553
    move-result-object p0

    .line 554
    check-cast p0, Lgc0/c;

    .line 555
    .line 556
    new-instance p1, Lhc0/a;

    .line 557
    .line 558
    invoke-direct {p1, p0}, Lhc0/a;-><init>(Lgc0/c;)V

    .line 559
    .line 560
    .line 561
    return-object p1

    .line 562
    :pswitch_10
    check-cast p1, Lk21/a;

    .line 563
    .line 564
    check-cast p2, Lg21/a;

    .line 565
    .line 566
    const-string p0, "$this$factory"

    .line 567
    .line 568
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 569
    .line 570
    .line 571
    const-string p0, "it"

    .line 572
    .line 573
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 574
    .line 575
    .line 576
    const-class p0, Lzr/a;

    .line 577
    .line 578
    sget-object p2, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 579
    .line 580
    invoke-virtual {p2, p0}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 581
    .line 582
    .line 583
    move-result-object p0

    .line 584
    const/4 p2, 0x0

    .line 585
    invoke-virtual {p1, p0, p2, p2}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 586
    .line 587
    .line 588
    move-result-object p0

    .line 589
    check-cast p0, Lzr/a;

    .line 590
    .line 591
    new-instance p0, Lhc0/d;

    .line 592
    .line 593
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 594
    .line 595
    .line 596
    return-object p0

    .line 597
    :pswitch_11
    check-cast p1, Lk21/a;

    .line 598
    .line 599
    check-cast p2, Lg21/a;

    .line 600
    .line 601
    const-string p0, "$this$factory"

    .line 602
    .line 603
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 604
    .line 605
    .line 606
    const-string p0, "it"

    .line 607
    .line 608
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 609
    .line 610
    .line 611
    const-class p0, Lgc0/a;

    .line 612
    .line 613
    sget-object p2, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 614
    .line 615
    invoke-virtual {p2, p0}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 616
    .line 617
    .line 618
    move-result-object p0

    .line 619
    const/4 p2, 0x0

    .line 620
    invoke-virtual {p1, p0, p2, p2}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 621
    .line 622
    .line 623
    move-result-object p0

    .line 624
    check-cast p0, Lgc0/a;

    .line 625
    .line 626
    new-instance p1, Lgc0/c;

    .line 627
    .line 628
    invoke-direct {p1, p0}, Lgc0/c;-><init>(Lgc0/a;)V

    .line 629
    .line 630
    .line 631
    return-object p1

    .line 632
    :pswitch_12
    check-cast p1, Lk21/a;

    .line 633
    .line 634
    check-cast p2, Lg21/a;

    .line 635
    .line 636
    const-string p0, "$this$single"

    .line 637
    .line 638
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 639
    .line 640
    .line 641
    const-string p0, "it"

    .line 642
    .line 643
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 644
    .line 645
    .line 646
    sget-object p0, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 647
    .line 648
    const-class p2, Lcu0/d;

    .line 649
    .line 650
    invoke-virtual {p0, p2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 651
    .line 652
    .line 653
    move-result-object p2

    .line 654
    const/4 v0, 0x0

    .line 655
    invoke-virtual {p1, p2, v0, v0}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 656
    .line 657
    .line 658
    move-result-object p2

    .line 659
    const-class v1, Lrs0/b;

    .line 660
    .line 661
    invoke-virtual {p0, v1}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 662
    .line 663
    .line 664
    move-result-object v1

    .line 665
    invoke-virtual {p1, v1, v0, v0}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 666
    .line 667
    .line 668
    move-result-object v1

    .line 669
    const-class v2, Lgb0/c0;

    .line 670
    .line 671
    invoke-virtual {p0, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 672
    .line 673
    .line 674
    move-result-object p0

    .line 675
    invoke-virtual {p1, p0, v0, v0}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 676
    .line 677
    .line 678
    move-result-object p0

    .line 679
    check-cast p0, Lgb0/c0;

    .line 680
    .line 681
    check-cast v1, Lrs0/b;

    .line 682
    .line 683
    check-cast p2, Lcu0/d;

    .line 684
    .line 685
    new-instance p1, Lgb0/u;

    .line 686
    .line 687
    invoke-direct {p1, p2, v1, p0}, Lgb0/u;-><init>(Lcu0/d;Lrs0/b;Lgb0/c0;)V

    .line 688
    .line 689
    .line 690
    return-object p1

    .line 691
    :pswitch_13
    check-cast p1, Lk21/a;

    .line 692
    .line 693
    check-cast p2, Lg21/a;

    .line 694
    .line 695
    const-string p0, "$this$single"

    .line 696
    .line 697
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 698
    .line 699
    .line 700
    const-string p0, "it"

    .line 701
    .line 702
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 703
    .line 704
    .line 705
    const-class p0, Lgb0/x;

    .line 706
    .line 707
    sget-object p2, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 708
    .line 709
    invoke-virtual {p2, p0}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 710
    .line 711
    .line 712
    move-result-object p0

    .line 713
    const/4 p2, 0x0

    .line 714
    invoke-virtual {p1, p0, p2, p2}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 715
    .line 716
    .line 717
    move-result-object p0

    .line 718
    check-cast p0, Lgb0/x;

    .line 719
    .line 720
    new-instance p1, Lib0/a;

    .line 721
    .line 722
    invoke-direct {p1, p0}, Lib0/a;-><init>(Lgb0/x;)V

    .line 723
    .line 724
    .line 725
    return-object p1

    .line 726
    :pswitch_14
    check-cast p1, Lk21/a;

    .line 727
    .line 728
    check-cast p2, Lg21/a;

    .line 729
    .line 730
    const-string p0, "$this$factory"

    .line 731
    .line 732
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 733
    .line 734
    .line 735
    const-string p0, "it"

    .line 736
    .line 737
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 738
    .line 739
    .line 740
    sget-object p0, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 741
    .line 742
    const-class p2, Leb0/b;

    .line 743
    .line 744
    invoke-virtual {p0, p2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 745
    .line 746
    .line 747
    move-result-object p2

    .line 748
    const/4 v0, 0x0

    .line 749
    invoke-virtual {p1, p2, v0, v0}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 750
    .line 751
    .line 752
    move-result-object p2

    .line 753
    const-class v1, Lgb0/c0;

    .line 754
    .line 755
    invoke-virtual {p0, v1}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 756
    .line 757
    .line 758
    move-result-object v1

    .line 759
    invoke-virtual {p1, v1, v0, v0}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 760
    .line 761
    .line 762
    move-result-object v1

    .line 763
    const-class v2, Lif0/f0;

    .line 764
    .line 765
    invoke-virtual {p0, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 766
    .line 767
    .line 768
    move-result-object v2

    .line 769
    invoke-virtual {p1, v2, v0, v0}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 770
    .line 771
    .line 772
    move-result-object v2

    .line 773
    const-class v3, Len0/s;

    .line 774
    .line 775
    invoke-virtual {p0, v3}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 776
    .line 777
    .line 778
    move-result-object v3

    .line 779
    invoke-virtual {p1, v3, v0, v0}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 780
    .line 781
    .line 782
    move-result-object v3

    .line 783
    const-class v4, Lrs0/b;

    .line 784
    .line 785
    invoke-virtual {p0, v4}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 786
    .line 787
    .line 788
    move-result-object p0

    .line 789
    invoke-virtual {p1, p0, v0, v0}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 790
    .line 791
    .line 792
    move-result-object p0

    .line 793
    move-object v9, p0

    .line 794
    check-cast v9, Lrs0/b;

    .line 795
    .line 796
    move-object v8, v3

    .line 797
    check-cast v8, Len0/s;

    .line 798
    .line 799
    move-object v7, v2

    .line 800
    check-cast v7, Lif0/f0;

    .line 801
    .line 802
    move-object v6, v1

    .line 803
    check-cast v6, Lgb0/c0;

    .line 804
    .line 805
    move-object v5, p2

    .line 806
    check-cast v5, Leb0/b;

    .line 807
    .line 808
    new-instance v4, Lgb0/l;

    .line 809
    .line 810
    invoke-direct/range {v4 .. v9}, Lgb0/l;-><init>(Leb0/b;Lgb0/c0;Lif0/f0;Len0/s;Lrs0/b;)V

    .line 811
    .line 812
    .line 813
    return-object v4

    .line 814
    :pswitch_15
    check-cast p1, Lk21/a;

    .line 815
    .line 816
    check-cast p2, Lg21/a;

    .line 817
    .line 818
    const-string p0, "$this$factory"

    .line 819
    .line 820
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 821
    .line 822
    .line 823
    const-string p0, "it"

    .line 824
    .line 825
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 826
    .line 827
    .line 828
    const-class p0, Lrs0/f;

    .line 829
    .line 830
    sget-object p2, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 831
    .line 832
    invoke-virtual {p2, p0}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 833
    .line 834
    .line 835
    move-result-object p0

    .line 836
    const/4 p2, 0x0

    .line 837
    invoke-virtual {p1, p0, p2, p2}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 838
    .line 839
    .line 840
    move-result-object p0

    .line 841
    check-cast p0, Lrs0/f;

    .line 842
    .line 843
    new-instance p1, Lgb0/h;

    .line 844
    .line 845
    invoke-direct {p1, p0}, Lgb0/h;-><init>(Lrs0/f;)V

    .line 846
    .line 847
    .line 848
    return-object p1

    .line 849
    :pswitch_16
    check-cast p1, Lk21/a;

    .line 850
    .line 851
    check-cast p2, Lg21/a;

    .line 852
    .line 853
    const-string p0, "$this$factory"

    .line 854
    .line 855
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 856
    .line 857
    .line 858
    const-string p0, "it"

    .line 859
    .line 860
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 861
    .line 862
    .line 863
    sget-object p0, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 864
    .line 865
    const-class p2, Lif0/f0;

    .line 866
    .line 867
    invoke-virtual {p0, p2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 868
    .line 869
    .line 870
    move-result-object p2

    .line 871
    const/4 v0, 0x0

    .line 872
    invoke-virtual {p1, p2, v0, v0}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 873
    .line 874
    .line 875
    move-result-object p2

    .line 876
    const-class v1, Len0/s;

    .line 877
    .line 878
    invoke-virtual {p0, v1}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 879
    .line 880
    .line 881
    move-result-object p0

    .line 882
    invoke-virtual {p1, p0, v0, v0}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 883
    .line 884
    .line 885
    move-result-object p0

    .line 886
    check-cast p0, Len0/s;

    .line 887
    .line 888
    check-cast p2, Lif0/f0;

    .line 889
    .line 890
    new-instance p1, Lgb0/m;

    .line 891
    .line 892
    invoke-direct {p1, p2, p0}, Lgb0/m;-><init>(Lif0/f0;Len0/s;)V

    .line 893
    .line 894
    .line 895
    return-object p1

    .line 896
    :pswitch_17
    check-cast p1, Lk21/a;

    .line 897
    .line 898
    check-cast p2, Lg21/a;

    .line 899
    .line 900
    const-string p0, "$this$factory"

    .line 901
    .line 902
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 903
    .line 904
    .line 905
    const-string p0, "it"

    .line 906
    .line 907
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 908
    .line 909
    .line 910
    sget-object p0, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 911
    .line 912
    const-class p2, Lif0/f0;

    .line 913
    .line 914
    invoke-virtual {p0, p2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 915
    .line 916
    .line 917
    move-result-object p2

    .line 918
    const/4 v0, 0x0

    .line 919
    invoke-virtual {p1, p2, v0, v0}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 920
    .line 921
    .line 922
    move-result-object p2

    .line 923
    const-class v1, Len0/s;

    .line 924
    .line 925
    invoke-virtual {p0, v1}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 926
    .line 927
    .line 928
    move-result-object p0

    .line 929
    invoke-virtual {p1, p0, v0, v0}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 930
    .line 931
    .line 932
    move-result-object p0

    .line 933
    check-cast p0, Len0/s;

    .line 934
    .line 935
    check-cast p2, Lif0/f0;

    .line 936
    .line 937
    new-instance p1, Lgb0/p;

    .line 938
    .line 939
    invoke-direct {p1, p2, p0}, Lgb0/p;-><init>(Lif0/f0;Len0/s;)V

    .line 940
    .line 941
    .line 942
    return-object p1

    .line 943
    :pswitch_18
    check-cast p1, Lk21/a;

    .line 944
    .line 945
    check-cast p2, Lg21/a;

    .line 946
    .line 947
    const-string p0, "$this$factory"

    .line 948
    .line 949
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 950
    .line 951
    .line 952
    const-string p0, "it"

    .line 953
    .line 954
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 955
    .line 956
    .line 957
    const-class p0, Lgb0/j;

    .line 958
    .line 959
    sget-object p2, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 960
    .line 961
    invoke-virtual {p2, p0}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 962
    .line 963
    .line 964
    move-result-object p0

    .line 965
    const/4 p2, 0x0

    .line 966
    invoke-virtual {p1, p0, p2, p2}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 967
    .line 968
    .line 969
    move-result-object p0

    .line 970
    check-cast p0, Lgb0/j;

    .line 971
    .line 972
    new-instance p1, Lgb0/f;

    .line 973
    .line 974
    invoke-direct {p1, p0}, Lgb0/f;-><init>(Lgb0/j;)V

    .line 975
    .line 976
    .line 977
    return-object p1

    .line 978
    :pswitch_19
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
    sget-object p0, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 993
    .line 994
    const-class p2, Lkf0/z;

    .line 995
    .line 996
    invoke-virtual {p0, p2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 997
    .line 998
    .line 999
    move-result-object p2

    .line 1000
    const/4 v0, 0x0

    .line 1001
    invoke-virtual {p1, p2, v0, v0}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 1002
    .line 1003
    .line 1004
    move-result-object p2

    .line 1005
    const-class v1, Lgn0/i;

    .line 1006
    .line 1007
    invoke-virtual {p0, v1}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1008
    .line 1009
    .line 1010
    move-result-object v1

    .line 1011
    invoke-virtual {p1, v1, v0, v0}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 1012
    .line 1013
    .line 1014
    move-result-object v1

    .line 1015
    const-class v2, Lrs0/f;

    .line 1016
    .line 1017
    invoke-virtual {p0, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1018
    .line 1019
    .line 1020
    move-result-object p0

    .line 1021
    invoke-virtual {p1, p0, v0, v0}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 1022
    .line 1023
    .line 1024
    move-result-object p0

    .line 1025
    check-cast p0, Lrs0/f;

    .line 1026
    .line 1027
    check-cast v1, Lgn0/i;

    .line 1028
    .line 1029
    check-cast p2, Lkf0/z;

    .line 1030
    .line 1031
    new-instance p1, Lgb0/a0;

    .line 1032
    .line 1033
    invoke-direct {p1, p2, v1, p0}, Lgb0/a0;-><init>(Lkf0/z;Lgn0/i;Lrs0/f;)V

    .line 1034
    .line 1035
    .line 1036
    return-object p1

    .line 1037
    :pswitch_1a
    check-cast p1, Lk21/a;

    .line 1038
    .line 1039
    check-cast p2, Lg21/a;

    .line 1040
    .line 1041
    const-string p0, "$this$factory"

    .line 1042
    .line 1043
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1044
    .line 1045
    .line 1046
    const-string p0, "it"

    .line 1047
    .line 1048
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1049
    .line 1050
    .line 1051
    const-class p0, Lgb0/a0;

    .line 1052
    .line 1053
    sget-object p2, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 1054
    .line 1055
    invoke-virtual {p2, p0}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1056
    .line 1057
    .line 1058
    move-result-object p0

    .line 1059
    const/4 p2, 0x0

    .line 1060
    invoke-virtual {p1, p0, p2, p2}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 1061
    .line 1062
    .line 1063
    move-result-object p0

    .line 1064
    check-cast p0, Lgb0/a0;

    .line 1065
    .line 1066
    new-instance p1, Lgb0/y;

    .line 1067
    .line 1068
    invoke-direct {p1, p0}, Lgb0/y;-><init>(Lgb0/a0;)V

    .line 1069
    .line 1070
    .line 1071
    return-object p1

    .line 1072
    :pswitch_1b
    check-cast p1, Lk21/a;

    .line 1073
    .line 1074
    check-cast p2, Lg21/a;

    .line 1075
    .line 1076
    const-string p0, "$this$factory"

    .line 1077
    .line 1078
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1079
    .line 1080
    .line 1081
    const-string p0, "it"

    .line 1082
    .line 1083
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1084
    .line 1085
    .line 1086
    sget-object p0, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 1087
    .line 1088
    const-class p2, Lif0/f0;

    .line 1089
    .line 1090
    invoke-virtual {p0, p2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1091
    .line 1092
    .line 1093
    move-result-object p2

    .line 1094
    const/4 v0, 0x0

    .line 1095
    invoke-virtual {p1, p2, v0, v0}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 1096
    .line 1097
    .line 1098
    move-result-object p2

    .line 1099
    const-class v1, Len0/s;

    .line 1100
    .line 1101
    invoke-virtual {p0, v1}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1102
    .line 1103
    .line 1104
    move-result-object v1

    .line 1105
    invoke-virtual {p1, v1, v0, v0}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 1106
    .line 1107
    .line 1108
    move-result-object v1

    .line 1109
    const-class v2, Lrs0/f;

    .line 1110
    .line 1111
    invoke-virtual {p0, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1112
    .line 1113
    .line 1114
    move-result-object p0

    .line 1115
    invoke-virtual {p1, p0, v0, v0}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 1116
    .line 1117
    .line 1118
    move-result-object p0

    .line 1119
    check-cast p0, Lrs0/f;

    .line 1120
    .line 1121
    check-cast v1, Len0/s;

    .line 1122
    .line 1123
    check-cast p2, Lif0/f0;

    .line 1124
    .line 1125
    new-instance p1, Lgb0/j;

    .line 1126
    .line 1127
    invoke-direct {p1, p2, v1, p0}, Lgb0/j;-><init>(Lif0/f0;Len0/s;Lrs0/f;)V

    .line 1128
    .line 1129
    .line 1130
    return-object p1

    .line 1131
    :pswitch_1c
    check-cast p1, Lk21/a;

    .line 1132
    .line 1133
    check-cast p2, Lg21/a;

    .line 1134
    .line 1135
    const-string p0, "$this$factory"

    .line 1136
    .line 1137
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1138
    .line 1139
    .line 1140
    const-string p0, "it"

    .line 1141
    .line 1142
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1143
    .line 1144
    .line 1145
    const-class p0, Lrs0/f;

    .line 1146
    .line 1147
    sget-object p2, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 1148
    .line 1149
    invoke-virtual {p2, p0}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1150
    .line 1151
    .line 1152
    move-result-object p0

    .line 1153
    const/4 p2, 0x0

    .line 1154
    invoke-virtual {p1, p0, p2, p2}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 1155
    .line 1156
    .line 1157
    move-result-object p0

    .line 1158
    check-cast p0, Lrs0/f;

    .line 1159
    .line 1160
    new-instance p1, Lgb0/b;

    .line 1161
    .line 1162
    invoke-direct {p1, p0}, Lgb0/b;-><init>(Lrs0/f;)V

    .line 1163
    .line 1164
    .line 1165
    return-object p1

    .line 1166
    nop

    .line 1167
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
