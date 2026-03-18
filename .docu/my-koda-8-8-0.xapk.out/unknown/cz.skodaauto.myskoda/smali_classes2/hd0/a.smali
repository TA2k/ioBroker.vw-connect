.class public final Lhd0/a;
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
    iput p1, p0, Lhd0/a;->d:I

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
    iget p0, p0, Lhd0/a;->d:I

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
    const-class p0, Lk70/v;

    .line 21
    .line 22
    sget-object p2, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 23
    .line 24
    invoke-virtual {p2, p0}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 25
    .line 26
    .line 27
    move-result-object p0

    .line 28
    const/4 p2, 0x0

    .line 29
    invoke-virtual {p1, p0, p2, p2}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 30
    .line 31
    .line 32
    move-result-object p0

    .line 33
    check-cast p0, Lk70/v;

    .line 34
    .line 35
    new-instance p1, Lk70/p;

    .line 36
    .line 37
    invoke-direct {p1, p0}, Lk70/p;-><init>(Lk70/v;)V

    .line 38
    .line 39
    .line 40
    return-object p1

    .line 41
    :pswitch_0
    check-cast p1, Lk21/a;

    .line 42
    .line 43
    check-cast p2, Lg21/a;

    .line 44
    .line 45
    const-string p0, "$this$factory"

    .line 46
    .line 47
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 48
    .line 49
    .line 50
    const-string p0, "it"

    .line 51
    .line 52
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 53
    .line 54
    .line 55
    sget-object p0, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 56
    .line 57
    const-class p2, Lkf0/o;

    .line 58
    .line 59
    invoke-virtual {p0, p2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 60
    .line 61
    .line 62
    move-result-object p2

    .line 63
    const/4 v0, 0x0

    .line 64
    invoke-virtual {p1, p2, v0, v0}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 65
    .line 66
    .line 67
    move-result-object p2

    .line 68
    const-class v1, Li70/v;

    .line 69
    .line 70
    invoke-virtual {p0, v1}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 71
    .line 72
    .line 73
    move-result-object v1

    .line 74
    invoke-virtual {p1, v1, v0, v0}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 75
    .line 76
    .line 77
    move-result-object v1

    .line 78
    const-class v2, Lk70/y;

    .line 79
    .line 80
    invoke-virtual {p0, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 81
    .line 82
    .line 83
    move-result-object p0

    .line 84
    invoke-virtual {p1, p0, v0, v0}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 85
    .line 86
    .line 87
    move-result-object p0

    .line 88
    check-cast p0, Lk70/y;

    .line 89
    .line 90
    check-cast v1, Li70/v;

    .line 91
    .line 92
    check-cast p2, Lkf0/o;

    .line 93
    .line 94
    new-instance p1, Lk70/m;

    .line 95
    .line 96
    invoke-direct {p1, p2, v1, p0}, Lk70/m;-><init>(Lkf0/o;Li70/v;Lk70/y;)V

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
    sget-object p0, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 115
    .line 116
    const-class p2, Lk70/y;

    .line 117
    .line 118
    invoke-virtual {p0, p2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 119
    .line 120
    .line 121
    move-result-object p2

    .line 122
    const/4 v0, 0x0

    .line 123
    invoke-virtual {p1, p2, v0, v0}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 124
    .line 125
    .line 126
    move-result-object p2

    .line 127
    const-class v1, Lk70/v;

    .line 128
    .line 129
    invoke-virtual {p0, v1}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 130
    .line 131
    .line 132
    move-result-object v1

    .line 133
    invoke-virtual {p1, v1, v0, v0}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 134
    .line 135
    .line 136
    move-result-object v1

    .line 137
    const-class v2, Lk70/g;

    .line 138
    .line 139
    invoke-virtual {p0, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 140
    .line 141
    .line 142
    move-result-object p0

    .line 143
    invoke-virtual {p1, p0, v0, v0}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 144
    .line 145
    .line 146
    move-result-object p0

    .line 147
    check-cast p0, Lk70/g;

    .line 148
    .line 149
    check-cast v1, Lk70/v;

    .line 150
    .line 151
    check-cast p2, Lk70/y;

    .line 152
    .line 153
    new-instance p1, Lk70/g0;

    .line 154
    .line 155
    invoke-direct {p1, p2, v1, p0}, Lk70/g0;-><init>(Lk70/y;Lk70/v;Lk70/g;)V

    .line 156
    .line 157
    .line 158
    return-object p1

    .line 159
    :pswitch_2
    check-cast p1, Lk21/a;

    .line 160
    .line 161
    check-cast p2, Lg21/a;

    .line 162
    .line 163
    const-string p0, "$this$factory"

    .line 164
    .line 165
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 166
    .line 167
    .line 168
    const-string p0, "it"

    .line 169
    .line 170
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 171
    .line 172
    .line 173
    sget-object p0, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 174
    .line 175
    const-class p2, Li70/r;

    .line 176
    .line 177
    invoke-virtual {p0, p2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 178
    .line 179
    .line 180
    move-result-object p2

    .line 181
    const/4 v0, 0x0

    .line 182
    invoke-virtual {p1, p2, v0, v0}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 183
    .line 184
    .line 185
    move-result-object p2

    .line 186
    const-class v1, Lk70/v;

    .line 187
    .line 188
    invoke-virtual {p0, v1}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 189
    .line 190
    .line 191
    move-result-object v1

    .line 192
    invoke-virtual {p1, v1, v0, v0}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 193
    .line 194
    .line 195
    move-result-object v1

    .line 196
    const-class v2, Lk70/y;

    .line 197
    .line 198
    invoke-virtual {p0, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 199
    .line 200
    .line 201
    move-result-object v2

    .line 202
    invoke-virtual {p1, v2, v0, v0}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 203
    .line 204
    .line 205
    move-result-object v2

    .line 206
    const-class v3, Lk70/x;

    .line 207
    .line 208
    invoke-virtual {p0, v3}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 209
    .line 210
    .line 211
    move-result-object v3

    .line 212
    invoke-virtual {p1, v3, v0, v0}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 213
    .line 214
    .line 215
    move-result-object v3

    .line 216
    const-class v4, Lkf0/o;

    .line 217
    .line 218
    invoke-virtual {p0, v4}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 219
    .line 220
    .line 221
    move-result-object p0

    .line 222
    invoke-virtual {p1, p0, v0, v0}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 223
    .line 224
    .line 225
    move-result-object p0

    .line 226
    move-object v9, p0

    .line 227
    check-cast v9, Lkf0/o;

    .line 228
    .line 229
    move-object v8, v3

    .line 230
    check-cast v8, Lk70/x;

    .line 231
    .line 232
    move-object v7, v2

    .line 233
    check-cast v7, Lk70/y;

    .line 234
    .line 235
    move-object v6, v1

    .line 236
    check-cast v6, Lk70/v;

    .line 237
    .line 238
    move-object v5, p2

    .line 239
    check-cast v5, Li70/r;

    .line 240
    .line 241
    new-instance v4, Lk70/b;

    .line 242
    .line 243
    invoke-direct/range {v4 .. v9}, Lk70/b;-><init>(Li70/r;Lk70/v;Lk70/y;Lk70/x;Lkf0/o;)V

    .line 244
    .line 245
    .line 246
    return-object v4

    .line 247
    :pswitch_3
    check-cast p1, Lk21/a;

    .line 248
    .line 249
    check-cast p2, Lg21/a;

    .line 250
    .line 251
    const-string p0, "$this$factory"

    .line 252
    .line 253
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 254
    .line 255
    .line 256
    const-string p0, "it"

    .line 257
    .line 258
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 259
    .line 260
    .line 261
    sget-object p0, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 262
    .line 263
    const-class p2, Lk70/v;

    .line 264
    .line 265
    invoke-virtual {p0, p2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 266
    .line 267
    .line 268
    move-result-object p2

    .line 269
    const/4 v0, 0x0

    .line 270
    invoke-virtual {p1, p2, v0, v0}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 271
    .line 272
    .line 273
    move-result-object p2

    .line 274
    const-class v1, Lk70/e;

    .line 275
    .line 276
    invoke-virtual {p0, v1}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 277
    .line 278
    .line 279
    move-result-object p0

    .line 280
    invoke-virtual {p1, p0, v0, v0}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 281
    .line 282
    .line 283
    move-result-object p0

    .line 284
    check-cast p0, Lk70/e;

    .line 285
    .line 286
    check-cast p2, Lk70/v;

    .line 287
    .line 288
    new-instance p1, Lk70/b0;

    .line 289
    .line 290
    invoke-direct {p1, p2, p0}, Lk70/b0;-><init>(Lk70/v;Lk70/e;)V

    .line 291
    .line 292
    .line 293
    return-object p1

    .line 294
    :pswitch_4
    check-cast p1, Lk21/a;

    .line 295
    .line 296
    check-cast p2, Lg21/a;

    .line 297
    .line 298
    const-string p0, "$this$factory"

    .line 299
    .line 300
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 301
    .line 302
    .line 303
    const-string p0, "it"

    .line 304
    .line 305
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 306
    .line 307
    .line 308
    sget-object p0, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 309
    .line 310
    const-class p2, Li70/r;

    .line 311
    .line 312
    invoke-virtual {p0, p2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 313
    .line 314
    .line 315
    move-result-object p2

    .line 316
    const/4 v0, 0x0

    .line 317
    invoke-virtual {p1, p2, v0, v0}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 318
    .line 319
    .line 320
    move-result-object p2

    .line 321
    const-class v1, Lk70/v;

    .line 322
    .line 323
    invoke-virtual {p0, v1}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 324
    .line 325
    .line 326
    move-result-object v1

    .line 327
    invoke-virtual {p1, v1, v0, v0}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 328
    .line 329
    .line 330
    move-result-object v1

    .line 331
    const-class v2, Lkf0/o;

    .line 332
    .line 333
    invoke-virtual {p0, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 334
    .line 335
    .line 336
    move-result-object p0

    .line 337
    invoke-virtual {p1, p0, v0, v0}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 338
    .line 339
    .line 340
    move-result-object p0

    .line 341
    check-cast p0, Lkf0/o;

    .line 342
    .line 343
    check-cast v1, Lk70/v;

    .line 344
    .line 345
    check-cast p2, Li70/r;

    .line 346
    .line 347
    new-instance p1, Lk70/e;

    .line 348
    .line 349
    invoke-direct {p1, p2, v1, p0}, Lk70/e;-><init>(Li70/r;Lk70/v;Lkf0/o;)V

    .line 350
    .line 351
    .line 352
    return-object p1

    .line 353
    :pswitch_5
    check-cast p1, Lk21/a;

    .line 354
    .line 355
    check-cast p2, Lg21/a;

    .line 356
    .line 357
    const-string p0, "$this$factory"

    .line 358
    .line 359
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 360
    .line 361
    .line 362
    const-string p0, "it"

    .line 363
    .line 364
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 365
    .line 366
    .line 367
    const-class p0, Lk70/v;

    .line 368
    .line 369
    sget-object p2, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 370
    .line 371
    invoke-virtual {p2, p0}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 372
    .line 373
    .line 374
    move-result-object p0

    .line 375
    const/4 p2, 0x0

    .line 376
    invoke-virtual {p1, p0, p2, p2}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 377
    .line 378
    .line 379
    move-result-object p0

    .line 380
    check-cast p0, Lk70/v;

    .line 381
    .line 382
    new-instance p1, Lk70/u;

    .line 383
    .line 384
    invoke-direct {p1, p0}, Lk70/u;-><init>(Lk70/v;)V

    .line 385
    .line 386
    .line 387
    return-object p1

    .line 388
    :pswitch_6
    check-cast p1, Lk21/a;

    .line 389
    .line 390
    check-cast p2, Lg21/a;

    .line 391
    .line 392
    const-string p0, "$this$factory"

    .line 393
    .line 394
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 395
    .line 396
    .line 397
    const-string p0, "it"

    .line 398
    .line 399
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 400
    .line 401
    .line 402
    const-class p0, Lk70/y;

    .line 403
    .line 404
    sget-object p2, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 405
    .line 406
    invoke-virtual {p2, p0}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 407
    .line 408
    .line 409
    move-result-object p0

    .line 410
    const/4 p2, 0x0

    .line 411
    invoke-virtual {p1, p0, p2, p2}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 412
    .line 413
    .line 414
    move-result-object p0

    .line 415
    check-cast p0, Lk70/y;

    .line 416
    .line 417
    new-instance p1, Lk70/e1;

    .line 418
    .line 419
    invoke-direct {p1, p0}, Lk70/e1;-><init>(Lk70/y;)V

    .line 420
    .line 421
    .line 422
    return-object p1

    .line 423
    :pswitch_7
    check-cast p1, Lk21/a;

    .line 424
    .line 425
    check-cast p2, Lg21/a;

    .line 426
    .line 427
    const-string p0, "$this$factory"

    .line 428
    .line 429
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 430
    .line 431
    .line 432
    const-string p0, "it"

    .line 433
    .line 434
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 435
    .line 436
    .line 437
    const-class p0, Lk70/y;

    .line 438
    .line 439
    sget-object p2, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 440
    .line 441
    invoke-virtual {p2, p0}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 442
    .line 443
    .line 444
    move-result-object p0

    .line 445
    const/4 p2, 0x0

    .line 446
    invoke-virtual {p1, p0, p2, p2}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 447
    .line 448
    .line 449
    move-result-object p0

    .line 450
    check-cast p0, Lk70/y;

    .line 451
    .line 452
    new-instance p1, Lk70/c1;

    .line 453
    .line 454
    invoke-direct {p1, p0}, Lk70/c1;-><init>(Lk70/y;)V

    .line 455
    .line 456
    .line 457
    return-object p1

    .line 458
    :pswitch_8
    check-cast p1, Lk21/a;

    .line 459
    .line 460
    check-cast p2, Lg21/a;

    .line 461
    .line 462
    const-string p0, "$this$factory"

    .line 463
    .line 464
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 465
    .line 466
    .line 467
    const-string p0, "it"

    .line 468
    .line 469
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 470
    .line 471
    .line 472
    const-class p0, Lk70/y;

    .line 473
    .line 474
    sget-object p2, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 475
    .line 476
    invoke-virtual {p2, p0}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 477
    .line 478
    .line 479
    move-result-object p0

    .line 480
    const/4 p2, 0x0

    .line 481
    invoke-virtual {p1, p0, p2, p2}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 482
    .line 483
    .line 484
    move-result-object p0

    .line 485
    check-cast p0, Lk70/y;

    .line 486
    .line 487
    new-instance p1, Lk70/m0;

    .line 488
    .line 489
    invoke-direct {p1, p0}, Lk70/m0;-><init>(Lk70/y;)V

    .line 490
    .line 491
    .line 492
    return-object p1

    .line 493
    :pswitch_9
    check-cast p1, Lk21/a;

    .line 494
    .line 495
    check-cast p2, Lg21/a;

    .line 496
    .line 497
    const-string p0, "$this$factory"

    .line 498
    .line 499
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 500
    .line 501
    .line 502
    const-string p0, "it"

    .line 503
    .line 504
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 505
    .line 506
    .line 507
    const-class p0, Lk70/y;

    .line 508
    .line 509
    sget-object p2, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 510
    .line 511
    invoke-virtual {p2, p0}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 512
    .line 513
    .line 514
    move-result-object p0

    .line 515
    const/4 p2, 0x0

    .line 516
    invoke-virtual {p1, p0, p2, p2}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 517
    .line 518
    .line 519
    move-result-object p0

    .line 520
    check-cast p0, Lk70/y;

    .line 521
    .line 522
    new-instance p1, Lk70/l0;

    .line 523
    .line 524
    invoke-direct {p1, p0}, Lk70/l0;-><init>(Lk70/y;)V

    .line 525
    .line 526
    .line 527
    return-object p1

    .line 528
    :pswitch_a
    check-cast p1, Lk21/a;

    .line 529
    .line 530
    check-cast p2, Lg21/a;

    .line 531
    .line 532
    const-string p0, "$this$factory"

    .line 533
    .line 534
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 535
    .line 536
    .line 537
    const-string p0, "it"

    .line 538
    .line 539
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 540
    .line 541
    .line 542
    const-class p0, Lk70/a1;

    .line 543
    .line 544
    sget-object p2, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 545
    .line 546
    invoke-virtual {p2, p0}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 547
    .line 548
    .line 549
    move-result-object p0

    .line 550
    const/4 p2, 0x0

    .line 551
    invoke-virtual {p1, p0, p2, p2}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 552
    .line 553
    .line 554
    move-result-object p0

    .line 555
    check-cast p0, Lk70/a1;

    .line 556
    .line 557
    new-instance p1, Lk70/u0;

    .line 558
    .line 559
    invoke-direct {p1, p0}, Lk70/u0;-><init>(Lk70/a1;)V

    .line 560
    .line 561
    .line 562
    return-object p1

    .line 563
    :pswitch_b
    check-cast p1, Lk21/a;

    .line 564
    .line 565
    check-cast p2, Lg21/a;

    .line 566
    .line 567
    const-string p0, "$this$factory"

    .line 568
    .line 569
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 570
    .line 571
    .line 572
    const-string p0, "it"

    .line 573
    .line 574
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 575
    .line 576
    .line 577
    sget-object p0, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 578
    .line 579
    const-class p2, Lzo0/d;

    .line 580
    .line 581
    invoke-virtual {p0, p2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 582
    .line 583
    .line 584
    move-result-object p2

    .line 585
    const/4 v0, 0x0

    .line 586
    invoke-virtual {p1, p2, v0, v0}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 587
    .line 588
    .line 589
    move-result-object p2

    .line 590
    const-class v1, Lzo0/l;

    .line 591
    .line 592
    invoke-virtual {p0, v1}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 593
    .line 594
    .line 595
    move-result-object p0

    .line 596
    invoke-virtual {p1, p0, v0, v0}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 597
    .line 598
    .line 599
    move-result-object p0

    .line 600
    check-cast p0, Lzo0/l;

    .line 601
    .line 602
    check-cast p2, Lzo0/d;

    .line 603
    .line 604
    new-instance p1, Lk60/a;

    .line 605
    .line 606
    invoke-direct {p1, p2, p0}, Lk60/a;-><init>(Lzo0/d;Lzo0/l;)V

    .line 607
    .line 608
    .line 609
    return-object p1

    .line 610
    :pswitch_c
    check-cast p1, Lk21/a;

    .line 611
    .line 612
    check-cast p2, Lg21/a;

    .line 613
    .line 614
    const-string p0, "$this$viewModel"

    .line 615
    .line 616
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 617
    .line 618
    .line 619
    const-string p0, "it"

    .line 620
    .line 621
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 622
    .line 623
    .line 624
    sget-object p0, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 625
    .line 626
    const-class p2, Ltj0/a;

    .line 627
    .line 628
    invoke-virtual {p0, p2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 629
    .line 630
    .line 631
    move-result-object p2

    .line 632
    const/4 v0, 0x0

    .line 633
    invoke-virtual {p1, p2, v0, v0}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 634
    .line 635
    .line 636
    move-result-object p2

    .line 637
    const-class v1, Ljn0/c;

    .line 638
    .line 639
    invoke-virtual {p0, v1}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 640
    .line 641
    .line 642
    move-result-object p0

    .line 643
    invoke-virtual {p1, p0, v0, v0}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 644
    .line 645
    .line 646
    move-result-object p0

    .line 647
    check-cast p0, Ljn0/c;

    .line 648
    .line 649
    check-cast p2, Ltj0/a;

    .line 650
    .line 651
    new-instance p1, Lk40/b;

    .line 652
    .line 653
    invoke-direct {p1, p2, p0}, Lk40/b;-><init>(Ltj0/a;Ljn0/c;)V

    .line 654
    .line 655
    .line 656
    return-object p1

    .line 657
    :pswitch_d
    check-cast p1, Lk21/a;

    .line 658
    .line 659
    check-cast p2, Lg21/a;

    .line 660
    .line 661
    const-string p0, "$this$single"

    .line 662
    .line 663
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 664
    .line 665
    .line 666
    const-string p0, "it"

    .line 667
    .line 668
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 669
    .line 670
    .line 671
    const-class p0, Landroid/content/Context;

    .line 672
    .line 673
    sget-object p2, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 674
    .line 675
    invoke-virtual {p2, p0}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 676
    .line 677
    .line 678
    move-result-object p0

    .line 679
    const/4 p2, 0x0

    .line 680
    invoke-virtual {p1, p0, p2, p2}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 681
    .line 682
    .line 683
    move-result-object p0

    .line 684
    check-cast p0, Landroid/content/Context;

    .line 685
    .line 686
    new-instance p1, Llr0/a;

    .line 687
    .line 688
    invoke-direct {p1, p0}, Llr0/a;-><init>(Landroid/content/Context;)V

    .line 689
    .line 690
    .line 691
    return-object p1

    .line 692
    :pswitch_e
    check-cast p1, Lk21/a;

    .line 693
    .line 694
    check-cast p2, Lg21/a;

    .line 695
    .line 696
    const-string p0, "$this$single"

    .line 697
    .line 698
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 699
    .line 700
    .line 701
    const-string p0, "it"

    .line 702
    .line 703
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 704
    .line 705
    .line 706
    const-class p0, Ljr0/d;

    .line 707
    .line 708
    sget-object p2, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 709
    .line 710
    invoke-virtual {p2, p0}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 711
    .line 712
    .line 713
    move-result-object p0

    .line 714
    const/4 p2, 0x0

    .line 715
    invoke-virtual {p1, p0, p2, p2}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 716
    .line 717
    .line 718
    move-result-object p0

    .line 719
    check-cast p0, Ljr0/d;

    .line 720
    .line 721
    new-instance p1, Ljr0/f;

    .line 722
    .line 723
    invoke-direct {p1, p0}, Ljr0/f;-><init>(Ljr0/d;)V

    .line 724
    .line 725
    .line 726
    return-object p1

    .line 727
    :pswitch_f
    check-cast p1, Lk21/a;

    .line 728
    .line 729
    check-cast p2, Lg21/a;

    .line 730
    .line 731
    const-string p0, "$this$single"

    .line 732
    .line 733
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 734
    .line 735
    .line 736
    const-string p0, "it"

    .line 737
    .line 738
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 739
    .line 740
    .line 741
    sget-object p0, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 742
    .line 743
    const-class p2, Ljr0/e;

    .line 744
    .line 745
    invoke-virtual {p0, p2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 746
    .line 747
    .line 748
    move-result-object p2

    .line 749
    const/4 v0, 0x0

    .line 750
    invoke-virtual {p1, p2, v0, v0}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 751
    .line 752
    .line 753
    move-result-object p2

    .line 754
    const-class v1, Ljr0/d;

    .line 755
    .line 756
    invoke-virtual {p0, v1}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 757
    .line 758
    .line 759
    move-result-object v1

    .line 760
    invoke-virtual {p1, v1, v0, v0}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 761
    .line 762
    .line 763
    move-result-object v1

    .line 764
    const-class v2, Ljr0/a;

    .line 765
    .line 766
    invoke-virtual {p0, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 767
    .line 768
    .line 769
    move-result-object v2

    .line 770
    invoke-virtual {p1, v2, v0, v0}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 771
    .line 772
    .line 773
    move-result-object v2

    .line 774
    const-class v3, Lkf0/m;

    .line 775
    .line 776
    invoke-virtual {p0, v3}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 777
    .line 778
    .line 779
    move-result-object p0

    .line 780
    invoke-virtual {p1, p0, v0, v0}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 781
    .line 782
    .line 783
    move-result-object p0

    .line 784
    check-cast p0, Lkf0/m;

    .line 785
    .line 786
    check-cast v2, Ljr0/a;

    .line 787
    .line 788
    check-cast v1, Ljr0/d;

    .line 789
    .line 790
    check-cast p2, Ljr0/e;

    .line 791
    .line 792
    new-instance p1, Ljr0/c;

    .line 793
    .line 794
    invoke-direct {p1, p2, v1, v2, p0}, Ljr0/c;-><init>(Ljr0/e;Ljr0/d;Ljr0/a;Lkf0/m;)V

    .line 795
    .line 796
    .line 797
    return-object p1

    .line 798
    :pswitch_10
    check-cast p1, Lk21/a;

    .line 799
    .line 800
    check-cast p2, Lg21/a;

    .line 801
    .line 802
    const-string p0, "$this$single"

    .line 803
    .line 804
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 805
    .line 806
    .line 807
    const-string p0, "it"

    .line 808
    .line 809
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 810
    .line 811
    .line 812
    new-instance p0, Lhr0/a;

    .line 813
    .line 814
    invoke-direct {p0}, Lhr0/a;-><init>()V

    .line 815
    .line 816
    .line 817
    return-object p0

    .line 818
    :pswitch_11
    check-cast p1, Lk21/a;

    .line 819
    .line 820
    check-cast p2, Lg21/a;

    .line 821
    .line 822
    const-string p0, "$this$single"

    .line 823
    .line 824
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 825
    .line 826
    .line 827
    const-string p0, "it"

    .line 828
    .line 829
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 830
    .line 831
    .line 832
    const-class p0, Lz51/b;

    .line 833
    .line 834
    sget-object p2, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 835
    .line 836
    invoke-virtual {p2, p0}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 837
    .line 838
    .line 839
    move-result-object p0

    .line 840
    const/4 p2, 0x0

    .line 841
    invoke-virtual {p1, p0, p2, p2}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 842
    .line 843
    .line 844
    move-result-object p0

    .line 845
    check-cast p0, Lz51/b;

    .line 846
    .line 847
    new-instance p1, Lhr0/c;

    .line 848
    .line 849
    invoke-direct {p1, p0}, Lhr0/c;-><init>(Lz51/b;)V

    .line 850
    .line 851
    .line 852
    return-object p1

    .line 853
    :pswitch_12
    check-cast p1, Lk21/a;

    .line 854
    .line 855
    check-cast p2, Lg21/a;

    .line 856
    .line 857
    const-string p0, "$this$single"

    .line 858
    .line 859
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 860
    .line 861
    .line 862
    const-string p0, "it"

    .line 863
    .line 864
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 865
    .line 866
    .line 867
    new-instance p0, Lhn0/b;

    .line 868
    .line 869
    invoke-direct {p0}, Lhn0/b;-><init>()V

    .line 870
    .line 871
    .line 872
    return-object p0

    .line 873
    :pswitch_13
    check-cast p1, Lk21/a;

    .line 874
    .line 875
    check-cast p2, Lg21/a;

    .line 876
    .line 877
    const-string p0, "$this$factory"

    .line 878
    .line 879
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 880
    .line 881
    .line 882
    const-string p0, "it"

    .line 883
    .line 884
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 885
    .line 886
    .line 887
    const-class p0, Lhn0/b;

    .line 888
    .line 889
    sget-object p2, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 890
    .line 891
    invoke-virtual {p2, p0}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 892
    .line 893
    .line 894
    move-result-object p0

    .line 895
    const/4 p2, 0x0

    .line 896
    invoke-virtual {p1, p0, p2, p2}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 897
    .line 898
    .line 899
    move-result-object p0

    .line 900
    check-cast p0, Lhn0/b;

    .line 901
    .line 902
    new-instance p1, Ljn0/c;

    .line 903
    .line 904
    invoke-direct {p1, p0}, Ljn0/c;-><init>(Lhn0/b;)V

    .line 905
    .line 906
    .line 907
    return-object p1

    .line 908
    :pswitch_14
    check-cast p1, Lk21/a;

    .line 909
    .line 910
    check-cast p2, Lg21/a;

    .line 911
    .line 912
    const-string p0, "$this$factory"

    .line 913
    .line 914
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 915
    .line 916
    .line 917
    const-string p0, "it"

    .line 918
    .line 919
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 920
    .line 921
    .line 922
    const-class p0, Lhn0/b;

    .line 923
    .line 924
    sget-object p2, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 925
    .line 926
    invoke-virtual {p2, p0}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 927
    .line 928
    .line 929
    move-result-object p0

    .line 930
    const/4 p2, 0x0

    .line 931
    invoke-virtual {p1, p0, p2, p2}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 932
    .line 933
    .line 934
    move-result-object p0

    .line 935
    check-cast p0, Lhn0/b;

    .line 936
    .line 937
    new-instance p1, Ljn0/a;

    .line 938
    .line 939
    invoke-direct {p1, p0}, Ljn0/a;-><init>(Lhn0/b;)V

    .line 940
    .line 941
    .line 942
    return-object p1

    .line 943
    :pswitch_15
    check-cast p1, Lk21/a;

    .line 944
    .line 945
    check-cast p2, Lg21/a;

    .line 946
    .line 947
    const-string p0, "$this$viewModel"

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
    sget-object p0, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 958
    .line 959
    const-class p2, Lwj0/s;

    .line 960
    .line 961
    invoke-virtual {p0, p2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 962
    .line 963
    .line 964
    move-result-object p2

    .line 965
    const/4 v0, 0x0

    .line 966
    invoke-virtual {p1, p2, v0, v0}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 967
    .line 968
    .line 969
    move-result-object p2

    .line 970
    const-class v1, Lwj0/h0;

    .line 971
    .line 972
    invoke-virtual {p0, v1}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 973
    .line 974
    .line 975
    move-result-object p0

    .line 976
    invoke-virtual {p1, p0, v0, v0}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 977
    .line 978
    .line 979
    move-result-object p0

    .line 980
    check-cast p0, Lwj0/h0;

    .line 981
    .line 982
    check-cast p2, Lwj0/s;

    .line 983
    .line 984
    new-instance p1, Ljl0/b;

    .line 985
    .line 986
    invoke-direct {p1, p2, p0}, Ljl0/b;-><init>(Lwj0/s;Lwj0/h0;)V

    .line 987
    .line 988
    .line 989
    return-object p1

    .line 990
    :pswitch_16
    check-cast p1, Lk21/a;

    .line 991
    .line 992
    check-cast p2, Lg21/a;

    .line 993
    .line 994
    const-string p0, "$this$factory"

    .line 995
    .line 996
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 997
    .line 998
    .line 999
    const-string p0, "it"

    .line 1000
    .line 1001
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1002
    .line 1003
    .line 1004
    const-class p0, Lam0/c;

    .line 1005
    .line 1006
    sget-object p2, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 1007
    .line 1008
    invoke-virtual {p2, p0}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1009
    .line 1010
    .line 1011
    move-result-object p0

    .line 1012
    const/4 p2, 0x0

    .line 1013
    invoke-virtual {p1, p0, p2, p2}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 1014
    .line 1015
    .line 1016
    move-result-object p0

    .line 1017
    check-cast p0, Lam0/c;

    .line 1018
    .line 1019
    new-instance p1, Lji0/b;

    .line 1020
    .line 1021
    invoke-direct {p1, p0}, Lji0/b;-><init>(Lam0/c;)V

    .line 1022
    .line 1023
    .line 1024
    return-object p1

    .line 1025
    :pswitch_17
    check-cast p1, Lk21/a;

    .line 1026
    .line 1027
    check-cast p2, Lg21/a;

    .line 1028
    .line 1029
    const-string p0, "$this$factory"

    .line 1030
    .line 1031
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1032
    .line 1033
    .line 1034
    const-string p0, "it"

    .line 1035
    .line 1036
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1037
    .line 1038
    .line 1039
    const-class p0, Lje0/d;

    .line 1040
    .line 1041
    sget-object p2, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 1042
    .line 1043
    invoke-virtual {p2, p0}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1044
    .line 1045
    .line 1046
    move-result-object p0

    .line 1047
    const/4 p2, 0x0

    .line 1048
    invoke-virtual {p1, p0, p2, p2}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 1049
    .line 1050
    .line 1051
    move-result-object p0

    .line 1052
    check-cast p0, Lje0/d;

    .line 1053
    .line 1054
    new-instance p1, Lke0/a;

    .line 1055
    .line 1056
    invoke-direct {p1, p0}, Lke0/a;-><init>(Lje0/d;)V

    .line 1057
    .line 1058
    .line 1059
    return-object p1

    .line 1060
    :pswitch_18
    check-cast p1, Lk21/a;

    .line 1061
    .line 1062
    check-cast p2, Lg21/a;

    .line 1063
    .line 1064
    const-string p0, "$this$factory"

    .line 1065
    .line 1066
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1067
    .line 1068
    .line 1069
    const-string p0, "it"

    .line 1070
    .line 1071
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1072
    .line 1073
    .line 1074
    const-class p0, Lve0/u;

    .line 1075
    .line 1076
    sget-object p2, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 1077
    .line 1078
    invoke-virtual {p2, p0}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1079
    .line 1080
    .line 1081
    move-result-object p0

    .line 1082
    const/4 p2, 0x0

    .line 1083
    invoke-virtual {p1, p0, p2, p2}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 1084
    .line 1085
    .line 1086
    move-result-object p0

    .line 1087
    check-cast p0, Lve0/u;

    .line 1088
    .line 1089
    new-instance p1, Lhe0/b;

    .line 1090
    .line 1091
    invoke-direct {p1, p0}, Lhe0/b;-><init>(Lve0/u;)V

    .line 1092
    .line 1093
    .line 1094
    return-object p1

    .line 1095
    :pswitch_19
    check-cast p1, Lk21/a;

    .line 1096
    .line 1097
    check-cast p2, Lg21/a;

    .line 1098
    .line 1099
    const-string p0, "$this$factory"

    .line 1100
    .line 1101
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1102
    .line 1103
    .line 1104
    const-string p0, "it"

    .line 1105
    .line 1106
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1107
    .line 1108
    .line 1109
    const-class p0, Lje0/b;

    .line 1110
    .line 1111
    sget-object p2, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 1112
    .line 1113
    invoke-virtual {p2, p0}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1114
    .line 1115
    .line 1116
    move-result-object p0

    .line 1117
    const/4 p2, 0x0

    .line 1118
    invoke-virtual {p1, p0, p2, p2}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 1119
    .line 1120
    .line 1121
    move-result-object p0

    .line 1122
    check-cast p0, Lje0/b;

    .line 1123
    .line 1124
    new-instance p1, Lje0/d;

    .line 1125
    .line 1126
    invoke-direct {p1, p0}, Lje0/d;-><init>(Lje0/b;)V

    .line 1127
    .line 1128
    .line 1129
    return-object p1

    .line 1130
    :pswitch_1a
    check-cast p1, Lk21/a;

    .line 1131
    .line 1132
    check-cast p2, Lg21/a;

    .line 1133
    .line 1134
    const-string p0, "$this$factory"

    .line 1135
    .line 1136
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1137
    .line 1138
    .line 1139
    const-string p0, "it"

    .line 1140
    .line 1141
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1142
    .line 1143
    .line 1144
    const-class p0, Lje0/b;

    .line 1145
    .line 1146
    sget-object p2, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 1147
    .line 1148
    invoke-virtual {p2, p0}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1149
    .line 1150
    .line 1151
    move-result-object p0

    .line 1152
    const/4 p2, 0x0

    .line 1153
    invoke-virtual {p1, p0, p2, p2}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 1154
    .line 1155
    .line 1156
    move-result-object p0

    .line 1157
    check-cast p0, Lje0/b;

    .line 1158
    .line 1159
    new-instance p1, Lje0/a;

    .line 1160
    .line 1161
    invoke-direct {p1, p0}, Lje0/a;-><init>(Lje0/b;)V

    .line 1162
    .line 1163
    .line 1164
    return-object p1

    .line 1165
    :pswitch_1b
    check-cast p1, Lk21/a;

    .line 1166
    .line 1167
    check-cast p2, Lg21/a;

    .line 1168
    .line 1169
    const-string p0, "$this$single"

    .line 1170
    .line 1171
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1172
    .line 1173
    .line 1174
    const-string p0, "it"

    .line 1175
    .line 1176
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1177
    .line 1178
    .line 1179
    new-instance p0, Lk10/a;

    .line 1180
    .line 1181
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 1182
    .line 1183
    .line 1184
    return-object p0

    .line 1185
    :pswitch_1c
    check-cast p1, Lk21/a;

    .line 1186
    .line 1187
    check-cast p2, Lg21/a;

    .line 1188
    .line 1189
    const-string p0, "$this$single"

    .line 1190
    .line 1191
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1192
    .line 1193
    .line 1194
    const-string p0, "it"

    .line 1195
    .line 1196
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1197
    .line 1198
    .line 1199
    const-class p0, Lrh0/f;

    .line 1200
    .line 1201
    sget-object p2, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 1202
    .line 1203
    invoke-virtual {p2, p0}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1204
    .line 1205
    .line 1206
    move-result-object p0

    .line 1207
    const/4 p2, 0x0

    .line 1208
    invoke-virtual {p1, p0, p2, p2}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 1209
    .line 1210
    .line 1211
    move-result-object p0

    .line 1212
    check-cast p0, Lrh0/f;

    .line 1213
    .line 1214
    new-instance p1, Lgd0/d;

    .line 1215
    .line 1216
    invoke-direct {p1, p0}, Lgd0/d;-><init>(Lrh0/f;)V

    .line 1217
    .line 1218
    .line 1219
    return-object p1

    .line 1220
    nop

    .line 1221
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
