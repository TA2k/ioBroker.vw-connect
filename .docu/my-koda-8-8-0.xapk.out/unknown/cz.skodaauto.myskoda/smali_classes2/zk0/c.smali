.class public final synthetic Lzk0/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Leo0/b;


# direct methods
.method public synthetic constructor <init>(Leo0/b;I)V
    .locals 0

    .line 1
    iput p2, p0, Lzk0/c;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lzk0/c;->e:Leo0/b;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 5

    .line 1
    iget v0, p0, Lzk0/c;->d:I

    .line 2
    .line 3
    check-cast p1, Lk21/a;

    .line 4
    .line 5
    check-cast p2, Lg21/a;

    .line 6
    .line 7
    packed-switch v0, :pswitch_data_0

    .line 8
    .line 9
    .line 10
    const-string v0, "$this$scopedFactory"

    .line 11
    .line 12
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 13
    .line 14
    .line 15
    const-string v0, "it"

    .line 16
    .line 17
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 18
    .line 19
    .line 20
    new-instance p2, Lal0/o1;

    .line 21
    .line 22
    iget-object p0, p0, Lzk0/c;->e:Leo0/b;

    .line 23
    .line 24
    iget-object p0, p0, Leo0/b;->b:Ljava/lang/String;

    .line 25
    .line 26
    invoke-static {p0}, Lkp/fa;->c(Ljava/lang/String;)Lh21/b;

    .line 27
    .line 28
    .line 29
    move-result-object v0

    .line 30
    sget-object v1, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 31
    .line 32
    const-class v2, Lal0/e0;

    .line 33
    .line 34
    invoke-virtual {v1, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 35
    .line 36
    .line 37
    move-result-object v2

    .line 38
    const/4 v3, 0x0

    .line 39
    invoke-virtual {p1, v2, v0, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 40
    .line 41
    .line 42
    move-result-object v0

    .line 43
    check-cast v0, Lal0/e0;

    .line 44
    .line 45
    const-class v2, Lwj0/g;

    .line 46
    .line 47
    invoke-virtual {v1, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 48
    .line 49
    .line 50
    move-result-object v2

    .line 51
    invoke-virtual {p1, v2, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 52
    .line 53
    .line 54
    move-result-object v2

    .line 55
    check-cast v2, Lwj0/g;

    .line 56
    .line 57
    invoke-static {p0}, Lkp/fa;->c(Ljava/lang/String;)Lh21/b;

    .line 58
    .line 59
    .line 60
    move-result-object p0

    .line 61
    const-class v4, Lwj0/x;

    .line 62
    .line 63
    invoke-virtual {v1, v4}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 64
    .line 65
    .line 66
    move-result-object v1

    .line 67
    invoke-virtual {p1, v1, p0, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 68
    .line 69
    .line 70
    move-result-object p0

    .line 71
    check-cast p0, Lwj0/x;

    .line 72
    .line 73
    invoke-direct {p2, v0, v2, p0}, Lal0/o1;-><init>(Lal0/e0;Lwj0/g;Lwj0/x;)V

    .line 74
    .line 75
    .line 76
    return-object p2

    .line 77
    :pswitch_0
    const-string v0, "$this$scopedFactory"

    .line 78
    .line 79
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 80
    .line 81
    .line 82
    const-string v0, "it"

    .line 83
    .line 84
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 85
    .line 86
    .line 87
    new-instance p2, Lal0/x0;

    .line 88
    .line 89
    iget-object p0, p0, Lzk0/c;->e:Leo0/b;

    .line 90
    .line 91
    iget-object p0, p0, Leo0/b;->b:Ljava/lang/String;

    .line 92
    .line 93
    invoke-static {p0}, Lkp/fa;->c(Ljava/lang/String;)Lh21/b;

    .line 94
    .line 95
    .line 96
    move-result-object p0

    .line 97
    const-class v0, Lal0/e0;

    .line 98
    .line 99
    sget-object v1, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 100
    .line 101
    invoke-virtual {v1, v0}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 102
    .line 103
    .line 104
    move-result-object v0

    .line 105
    const/4 v1, 0x0

    .line 106
    invoke-virtual {p1, v0, p0, v1}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 107
    .line 108
    .line 109
    move-result-object p0

    .line 110
    check-cast p0, Lal0/e0;

    .line 111
    .line 112
    invoke-direct {p2, p0}, Lal0/x0;-><init>(Lal0/e0;)V

    .line 113
    .line 114
    .line 115
    return-object p2

    .line 116
    :pswitch_1
    const-string v0, "$this$scopedFactory"

    .line 117
    .line 118
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 119
    .line 120
    .line 121
    const-string v0, "it"

    .line 122
    .line 123
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 124
    .line 125
    .line 126
    new-instance p2, Lal0/r0;

    .line 127
    .line 128
    iget-object p0, p0, Lzk0/c;->e:Leo0/b;

    .line 129
    .line 130
    iget-object p0, p0, Leo0/b;->b:Ljava/lang/String;

    .line 131
    .line 132
    invoke-static {p0}, Lkp/fa;->c(Ljava/lang/String;)Lh21/b;

    .line 133
    .line 134
    .line 135
    move-result-object p0

    .line 136
    const-class v0, Lal0/e0;

    .line 137
    .line 138
    sget-object v1, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 139
    .line 140
    invoke-virtual {v1, v0}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 141
    .line 142
    .line 143
    move-result-object v0

    .line 144
    const/4 v1, 0x0

    .line 145
    invoke-virtual {p1, v0, p0, v1}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 146
    .line 147
    .line 148
    move-result-object p0

    .line 149
    check-cast p0, Lal0/e0;

    .line 150
    .line 151
    invoke-direct {p2, p0}, Lal0/r0;-><init>(Lal0/e0;)V

    .line 152
    .line 153
    .line 154
    return-object p2

    .line 155
    :pswitch_2
    const-string v0, "$this$scopedFactory"

    .line 156
    .line 157
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 158
    .line 159
    .line 160
    const-string v0, "it"

    .line 161
    .line 162
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 163
    .line 164
    .line 165
    new-instance p2, Lal0/s0;

    .line 166
    .line 167
    iget-object p0, p0, Lzk0/c;->e:Leo0/b;

    .line 168
    .line 169
    iget-object p0, p0, Leo0/b;->b:Ljava/lang/String;

    .line 170
    .line 171
    invoke-static {p0}, Lkp/fa;->c(Ljava/lang/String;)Lh21/b;

    .line 172
    .line 173
    .line 174
    move-result-object p0

    .line 175
    const-class v0, Lal0/e0;

    .line 176
    .line 177
    sget-object v1, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 178
    .line 179
    invoke-virtual {v1, v0}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 180
    .line 181
    .line 182
    move-result-object v0

    .line 183
    const/4 v1, 0x0

    .line 184
    invoke-virtual {p1, v0, p0, v1}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 185
    .line 186
    .line 187
    move-result-object p0

    .line 188
    check-cast p0, Lal0/e0;

    .line 189
    .line 190
    invoke-direct {p2, p0}, Lal0/s0;-><init>(Lal0/e0;)V

    .line 191
    .line 192
    .line 193
    return-object p2

    .line 194
    :pswitch_3
    const-string v0, "$this$scopedFactory"

    .line 195
    .line 196
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 197
    .line 198
    .line 199
    const-string v0, "it"

    .line 200
    .line 201
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 202
    .line 203
    .line 204
    new-instance p2, Lal0/c;

    .line 205
    .line 206
    iget-object p0, p0, Lzk0/c;->e:Leo0/b;

    .line 207
    .line 208
    iget-object p0, p0, Leo0/b;->b:Ljava/lang/String;

    .line 209
    .line 210
    invoke-static {p0}, Lkp/fa;->c(Ljava/lang/String;)Lh21/b;

    .line 211
    .line 212
    .line 213
    move-result-object p0

    .line 214
    const-class v0, Lal0/e0;

    .line 215
    .line 216
    sget-object v1, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 217
    .line 218
    invoke-virtual {v1, v0}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 219
    .line 220
    .line 221
    move-result-object v0

    .line 222
    const/4 v1, 0x0

    .line 223
    invoke-virtual {p1, v0, p0, v1}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 224
    .line 225
    .line 226
    move-result-object p0

    .line 227
    check-cast p0, Lal0/e0;

    .line 228
    .line 229
    invoke-direct {p2, p0}, Lal0/c;-><init>(Lal0/e0;)V

    .line 230
    .line 231
    .line 232
    return-object p2

    .line 233
    :pswitch_4
    const-string v0, "$this$scopedFactory"

    .line 234
    .line 235
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 236
    .line 237
    .line 238
    const-string v0, "it"

    .line 239
    .line 240
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 241
    .line 242
    .line 243
    new-instance p2, Lal0/j;

    .line 244
    .line 245
    sget-object v0, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 246
    .line 247
    const-class v1, Lml0/a;

    .line 248
    .line 249
    invoke-virtual {v0, v1}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 250
    .line 251
    .line 252
    move-result-object v1

    .line 253
    const/4 v2, 0x0

    .line 254
    invoke-virtual {p1, v1, v2, v2}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 255
    .line 256
    .line 257
    move-result-object v1

    .line 258
    check-cast v1, Lml0/a;

    .line 259
    .line 260
    const-class v3, Lml0/e;

    .line 261
    .line 262
    invoke-virtual {v0, v3}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 263
    .line 264
    .line 265
    move-result-object v3

    .line 266
    invoke-virtual {p1, v3, v2, v2}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 267
    .line 268
    .line 269
    move-result-object v3

    .line 270
    check-cast v3, Lml0/e;

    .line 271
    .line 272
    iget-object p0, p0, Lzk0/c;->e:Leo0/b;

    .line 273
    .line 274
    iget-object p0, p0, Leo0/b;->b:Ljava/lang/String;

    .line 275
    .line 276
    invoke-static {p0}, Lkp/fa;->c(Ljava/lang/String;)Lh21/b;

    .line 277
    .line 278
    .line 279
    move-result-object p0

    .line 280
    const-class v4, Lal0/e0;

    .line 281
    .line 282
    invoke-virtual {v0, v4}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 283
    .line 284
    .line 285
    move-result-object v4

    .line 286
    invoke-virtual {p1, v4, p0, v2}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 287
    .line 288
    .line 289
    move-result-object p0

    .line 290
    check-cast p0, Lal0/e0;

    .line 291
    .line 292
    const-class v4, Lyk0/q;

    .line 293
    .line 294
    invoke-virtual {v0, v4}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 295
    .line 296
    .line 297
    move-result-object v0

    .line 298
    invoke-virtual {p1, v0, v2, v2}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 299
    .line 300
    .line 301
    move-result-object p1

    .line 302
    check-cast p1, Lyk0/q;

    .line 303
    .line 304
    invoke-direct {p2, v1, v3, p0, p1}, Lal0/j;-><init>(Lml0/a;Lml0/e;Lal0/e0;Lyk0/q;)V

    .line 305
    .line 306
    .line 307
    return-object p2

    .line 308
    :pswitch_5
    const-string v0, "$this$scopedViewModel"

    .line 309
    .line 310
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 311
    .line 312
    .line 313
    const-string v0, "it"

    .line 314
    .line 315
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 316
    .line 317
    .line 318
    new-instance p2, Lcl0/l;

    .line 319
    .line 320
    iget-object p0, p0, Lzk0/c;->e:Leo0/b;

    .line 321
    .line 322
    iget-object p0, p0, Leo0/b;->b:Ljava/lang/String;

    .line 323
    .line 324
    invoke-static {p0}, Lkp/fa;->c(Ljava/lang/String;)Lh21/b;

    .line 325
    .line 326
    .line 327
    move-result-object v0

    .line 328
    sget-object v1, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 329
    .line 330
    const-class v2, Lal0/x0;

    .line 331
    .line 332
    invoke-virtual {v1, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 333
    .line 334
    .line 335
    move-result-object v2

    .line 336
    const/4 v3, 0x0

    .line 337
    invoke-virtual {p1, v2, v0, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 338
    .line 339
    .line 340
    move-result-object v0

    .line 341
    check-cast v0, Lal0/x0;

    .line 342
    .line 343
    invoke-static {p0}, Lkp/fa;->c(Ljava/lang/String;)Lh21/b;

    .line 344
    .line 345
    .line 346
    move-result-object p0

    .line 347
    const-class v2, Lal0/o1;

    .line 348
    .line 349
    invoke-virtual {v1, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 350
    .line 351
    .line 352
    move-result-object v1

    .line 353
    invoke-virtual {p1, v1, p0, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 354
    .line 355
    .line 356
    move-result-object p0

    .line 357
    check-cast p0, Lal0/o1;

    .line 358
    .line 359
    invoke-direct {p2, v0, p0}, Lcl0/l;-><init>(Lal0/x0;Lal0/o1;)V

    .line 360
    .line 361
    .line 362
    return-object p2

    .line 363
    :pswitch_6
    const-string v0, "$this$scopedViewModel"

    .line 364
    .line 365
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 366
    .line 367
    .line 368
    const-string v0, "it"

    .line 369
    .line 370
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 371
    .line 372
    .line 373
    new-instance p2, Lcl0/n;

    .line 374
    .line 375
    iget-object p0, p0, Lzk0/c;->e:Leo0/b;

    .line 376
    .line 377
    iget-object p0, p0, Leo0/b;->b:Ljava/lang/String;

    .line 378
    .line 379
    invoke-static {p0}, Lkp/fa;->c(Ljava/lang/String;)Lh21/b;

    .line 380
    .line 381
    .line 382
    move-result-object v0

    .line 383
    sget-object v1, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 384
    .line 385
    const-class v2, Lal0/x0;

    .line 386
    .line 387
    invoke-virtual {v1, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 388
    .line 389
    .line 390
    move-result-object v2

    .line 391
    const/4 v3, 0x0

    .line 392
    invoke-virtual {p1, v2, v0, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 393
    .line 394
    .line 395
    move-result-object v0

    .line 396
    check-cast v0, Lal0/x0;

    .line 397
    .line 398
    invoke-static {p0}, Lkp/fa;->c(Ljava/lang/String;)Lh21/b;

    .line 399
    .line 400
    .line 401
    move-result-object p0

    .line 402
    const-class v2, Lal0/o1;

    .line 403
    .line 404
    invoke-virtual {v1, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 405
    .line 406
    .line 407
    move-result-object v1

    .line 408
    invoke-virtual {p1, v1, p0, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 409
    .line 410
    .line 411
    move-result-object p0

    .line 412
    check-cast p0, Lal0/o1;

    .line 413
    .line 414
    invoke-direct {p2, v0, p0}, Lcl0/n;-><init>(Lal0/x0;Lal0/o1;)V

    .line 415
    .line 416
    .line 417
    return-object p2

    .line 418
    :pswitch_7
    const-string v0, "$this$scopedViewModel"

    .line 419
    .line 420
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 421
    .line 422
    .line 423
    const-string v0, "it"

    .line 424
    .line 425
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 426
    .line 427
    .line 428
    new-instance p2, Lcl0/s;

    .line 429
    .line 430
    iget-object p0, p0, Lzk0/c;->e:Leo0/b;

    .line 431
    .line 432
    iget-object p0, p0, Leo0/b;->b:Ljava/lang/String;

    .line 433
    .line 434
    invoke-static {p0}, Lkp/fa;->c(Ljava/lang/String;)Lh21/b;

    .line 435
    .line 436
    .line 437
    move-result-object p0

    .line 438
    sget-object v0, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 439
    .line 440
    const-class v1, Lal0/x0;

    .line 441
    .line 442
    invoke-virtual {v0, v1}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 443
    .line 444
    .line 445
    move-result-object v1

    .line 446
    const/4 v2, 0x0

    .line 447
    invoke-virtual {p1, v1, p0, v2}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 448
    .line 449
    .line 450
    move-result-object p0

    .line 451
    check-cast p0, Lal0/x0;

    .line 452
    .line 453
    const-class v1, Lal0/q0;

    .line 454
    .line 455
    invoke-virtual {v0, v1}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 456
    .line 457
    .line 458
    move-result-object v1

    .line 459
    invoke-virtual {p1, v1, v2, v2}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 460
    .line 461
    .line 462
    move-result-object v1

    .line 463
    check-cast v1, Lal0/q0;

    .line 464
    .line 465
    const-class v3, Lal0/i1;

    .line 466
    .line 467
    invoke-virtual {v0, v3}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 468
    .line 469
    .line 470
    move-result-object v3

    .line 471
    invoke-virtual {p1, v3, v2, v2}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 472
    .line 473
    .line 474
    move-result-object v3

    .line 475
    check-cast v3, Lal0/i1;

    .line 476
    .line 477
    const-class v4, Lij0/a;

    .line 478
    .line 479
    invoke-virtual {v0, v4}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 480
    .line 481
    .line 482
    move-result-object v0

    .line 483
    invoke-virtual {p1, v0, v2, v2}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 484
    .line 485
    .line 486
    move-result-object p1

    .line 487
    check-cast p1, Lij0/a;

    .line 488
    .line 489
    invoke-direct {p2, p0, v1, v3, p1}, Lcl0/s;-><init>(Lal0/x0;Lal0/q0;Lal0/i1;Lij0/a;)V

    .line 490
    .line 491
    .line 492
    return-object p2

    :pswitch_data_0
    .packed-switch 0x0
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
