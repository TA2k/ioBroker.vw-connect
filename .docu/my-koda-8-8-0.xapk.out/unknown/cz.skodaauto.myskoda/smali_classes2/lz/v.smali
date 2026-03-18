.class public final Llz/v;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/c;


# instance fields
.field public final a:Lkf0/m;

.field public final b:Lsf0/a;

.field public final c:Ljn0/c;

.field public final d:Lwq0/e0;

.field public final e:Lkf0/j0;

.field public final f:Ljz/m;

.field public final g:Lko0/f;


# direct methods
.method public constructor <init>(Lkf0/m;Lsf0/a;Ljn0/c;Lwq0/e0;Lkf0/j0;Ljz/m;Lko0/f;Llz/n;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Llz/v;->a:Lkf0/m;

    .line 5
    .line 6
    iput-object p2, p0, Llz/v;->b:Lsf0/a;

    .line 7
    .line 8
    iput-object p3, p0, Llz/v;->c:Ljn0/c;

    .line 9
    .line 10
    iput-object p4, p0, Llz/v;->d:Lwq0/e0;

    .line 11
    .line 12
    iput-object p5, p0, Llz/v;->e:Lkf0/j0;

    .line 13
    .line 14
    iput-object p6, p0, Llz/v;->f:Ljz/m;

    .line 15
    .line 16
    iput-object p7, p0, Llz/v;->g:Lko0/f;

    .line 17
    .line 18
    return-void
.end method


# virtual methods
.method public final bridge synthetic a(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Ljava/util/List;

    .line 2
    .line 3
    invoke-virtual {p0, p1, p2}, Llz/v;->b(Ljava/util/List;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public final b(Ljava/util/List;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 19

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p2

    .line 4
    .line 5
    instance-of v2, v1, Llz/t;

    .line 6
    .line 7
    if-eqz v2, :cond_0

    .line 8
    .line 9
    move-object v2, v1

    .line 10
    check-cast v2, Llz/t;

    .line 11
    .line 12
    iget v3, v2, Llz/t;->i:I

    .line 13
    .line 14
    const/high16 v4, -0x80000000

    .line 15
    .line 16
    and-int v5, v3, v4

    .line 17
    .line 18
    if-eqz v5, :cond_0

    .line 19
    .line 20
    sub-int/2addr v3, v4

    .line 21
    iput v3, v2, Llz/t;->i:I

    .line 22
    .line 23
    goto :goto_0

    .line 24
    :cond_0
    new-instance v2, Llz/t;

    .line 25
    .line 26
    invoke-direct {v2, v0, v1}, Llz/t;-><init>(Llz/v;Lkotlin/coroutines/Continuation;)V

    .line 27
    .line 28
    .line 29
    :goto_0
    iget-object v1, v2, Llz/t;->g:Ljava/lang/Object;

    .line 30
    .line 31
    sget-object v3, Lqx0/a;->d:Lqx0/a;

    .line 32
    .line 33
    iget v4, v2, Llz/t;->i:I

    .line 34
    .line 35
    const/4 v5, 0x5

    .line 36
    const/4 v6, 0x4

    .line 37
    const/4 v7, 0x3

    .line 38
    const/4 v8, 0x1

    .line 39
    const/4 v9, 0x2

    .line 40
    const/4 v10, 0x0

    .line 41
    if-eqz v4, :cond_6

    .line 42
    .line 43
    if-eq v4, v8, :cond_5

    .line 44
    .line 45
    if-eq v4, v9, :cond_4

    .line 46
    .line 47
    if-eq v4, v7, :cond_3

    .line 48
    .line 49
    if-eq v4, v6, :cond_2

    .line 50
    .line 51
    if-ne v4, v5, :cond_1

    .line 52
    .line 53
    iget-object v0, v2, Llz/t;->f:Lne0/t;

    .line 54
    .line 55
    iget-object v2, v2, Llz/t;->d:Ljava/util/List;

    .line 56
    .line 57
    check-cast v2, Ljava/util/List;

    .line 58
    .line 59
    invoke-static {v1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 60
    .line 61
    .line 62
    return-object v0

    .line 63
    :cond_1
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 64
    .line 65
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 66
    .line 67
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 68
    .line 69
    .line 70
    throw v0

    .line 71
    :cond_2
    iget-object v4, v2, Llz/t;->d:Ljava/util/List;

    .line 72
    .line 73
    check-cast v4, Ljava/util/List;

    .line 74
    .line 75
    invoke-static {v1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 76
    .line 77
    .line 78
    goto/16 :goto_4

    .line 79
    .line 80
    :cond_3
    iget-object v4, v2, Llz/t;->e:Lss0/k;

    .line 81
    .line 82
    iget-object v7, v2, Llz/t;->d:Ljava/util/List;

    .line 83
    .line 84
    check-cast v7, Ljava/util/List;

    .line 85
    .line 86
    invoke-static {v1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 87
    .line 88
    .line 89
    goto/16 :goto_3

    .line 90
    .line 91
    :cond_4
    iget-object v4, v2, Llz/t;->d:Ljava/util/List;

    .line 92
    .line 93
    check-cast v4, Ljava/util/List;

    .line 94
    .line 95
    invoke-static {v1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 96
    .line 97
    .line 98
    goto :goto_2

    .line 99
    :cond_5
    iget-object v4, v2, Llz/t;->d:Ljava/util/List;

    .line 100
    .line 101
    check-cast v4, Ljava/util/List;

    .line 102
    .line 103
    invoke-static {v1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 104
    .line 105
    .line 106
    goto :goto_1

    .line 107
    :cond_6
    invoke-static {v1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 108
    .line 109
    .line 110
    move-object/from16 v1, p1

    .line 111
    .line 112
    check-cast v1, Ljava/util/List;

    .line 113
    .line 114
    iput-object v1, v2, Llz/t;->d:Ljava/util/List;

    .line 115
    .line 116
    iput v8, v2, Llz/t;->i:I

    .line 117
    .line 118
    iget-object v1, v0, Llz/v;->a:Lkf0/m;

    .line 119
    .line 120
    invoke-virtual {v1, v2}, Lkf0/m;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 121
    .line 122
    .line 123
    move-result-object v1

    .line 124
    if-ne v1, v3, :cond_7

    .line 125
    .line 126
    goto/16 :goto_5

    .line 127
    .line 128
    :cond_7
    move-object/from16 v4, p1

    .line 129
    .line 130
    :goto_1
    check-cast v1, Lne0/t;

    .line 131
    .line 132
    new-instance v8, Llz/u;

    .line 133
    .line 134
    const/4 v11, 0x1

    .line 135
    invoke-direct {v8, v0, v10, v11}, Llz/u;-><init>(Llz/v;Lkotlin/coroutines/Continuation;I)V

    .line 136
    .line 137
    .line 138
    move-object v11, v4

    .line 139
    check-cast v11, Ljava/util/List;

    .line 140
    .line 141
    iput-object v11, v2, Llz/t;->d:Ljava/util/List;

    .line 142
    .line 143
    iput v9, v2, Llz/t;->i:I

    .line 144
    .line 145
    invoke-static {v1, v8, v2}, Llp/sf;->b(Lne0/t;Lay0/n;Lrx0/c;)Ljava/lang/Object;

    .line 146
    .line 147
    .line 148
    move-result-object v1

    .line 149
    if-ne v1, v3, :cond_8

    .line 150
    .line 151
    goto/16 :goto_5

    .line 152
    .line 153
    :cond_8
    :goto_2
    check-cast v1, Lne0/t;

    .line 154
    .line 155
    instance-of v8, v1, Lne0/c;

    .line 156
    .line 157
    if-eqz v8, :cond_9

    .line 158
    .line 159
    check-cast v1, Lne0/c;

    .line 160
    .line 161
    return-object v1

    .line 162
    :cond_9
    instance-of v8, v1, Lne0/e;

    .line 163
    .line 164
    if-eqz v8, :cond_11

    .line 165
    .line 166
    check-cast v1, Lne0/e;

    .line 167
    .line 168
    iget-object v1, v1, Lne0/e;->a:Ljava/lang/Object;

    .line 169
    .line 170
    check-cast v1, Lss0/k;

    .line 171
    .line 172
    sget-object v8, Lyq0/n;->i:Lyq0/n;

    .line 173
    .line 174
    move-object v9, v4

    .line 175
    check-cast v9, Ljava/util/List;

    .line 176
    .line 177
    iput-object v9, v2, Llz/t;->d:Ljava/util/List;

    .line 178
    .line 179
    iput-object v1, v2, Llz/t;->e:Lss0/k;

    .line 180
    .line 181
    iput v7, v2, Llz/t;->i:I

    .line 182
    .line 183
    iget-object v7, v0, Llz/v;->d:Lwq0/e0;

    .line 184
    .line 185
    invoke-virtual {v7, v8, v2}, Lwq0/e0;->b(Lyq0/n;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 186
    .line 187
    .line 188
    move-result-object v7

    .line 189
    if-ne v7, v3, :cond_a

    .line 190
    .line 191
    goto/16 :goto_5

    .line 192
    .line 193
    :cond_a
    move-object/from16 v18, v4

    .line 194
    .line 195
    move-object v4, v1

    .line 196
    move-object v1, v7

    .line 197
    move-object/from16 v7, v18

    .line 198
    .line 199
    :goto_3
    check-cast v1, Lne0/t;

    .line 200
    .line 201
    instance-of v8, v1, Lne0/c;

    .line 202
    .line 203
    if-eqz v8, :cond_b

    .line 204
    .line 205
    check-cast v1, Lne0/c;

    .line 206
    .line 207
    return-object v1

    .line 208
    :cond_b
    instance-of v8, v1, Lne0/e;

    .line 209
    .line 210
    if-eqz v8, :cond_10

    .line 211
    .line 212
    check-cast v1, Lne0/e;

    .line 213
    .line 214
    iget-object v1, v1, Lne0/e;->a:Ljava/lang/Object;

    .line 215
    .line 216
    check-cast v1, Lyq0/k;

    .line 217
    .line 218
    iget-object v15, v1, Lyq0/k;->a:Ljava/lang/String;

    .line 219
    .line 220
    sget-object v1, Lss0/e;->q:Lss0/e;

    .line 221
    .line 222
    invoke-static {v4, v1}, Llp/sf;->a(Lss0/k;Lss0/e;)Z

    .line 223
    .line 224
    .line 225
    move-result v1

    .line 226
    if-eqz v1, :cond_c

    .line 227
    .line 228
    new-instance v1, Llz/m;

    .line 229
    .line 230
    invoke-static {}, Ljava/time/ZoneId;->systemDefault()Ljava/time/ZoneId;

    .line 231
    .line 232
    .line 233
    move-result-object v8

    .line 234
    const-string v9, "systemDefault(...)"

    .line 235
    .line 236
    invoke-static {v8, v9}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 237
    .line 238
    .line 239
    sget-object v9, Ljava/time/ZoneOffset;->UTC:Ljava/time/ZoneOffset;

    .line 240
    .line 241
    invoke-virtual {v9}, Ljava/time/ZoneId;->normalized()Ljava/time/ZoneId;

    .line 242
    .line 243
    .line 244
    move-result-object v9

    .line 245
    const-string v11, "normalized(...)"

    .line 246
    .line 247
    invoke-static {v9, v11}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 248
    .line 249
    .line 250
    invoke-direct {v1, v8, v9, v7}, Llz/m;-><init>(Ljava/time/ZoneId;Ljava/time/ZoneId;Ljava/util/List;)V

    .line 251
    .line 252
    .line 253
    invoke-static {v1}, Llz/n;->a(Llz/m;)Ljava/util/ArrayList;

    .line 254
    .line 255
    .line 256
    move-result-object v7

    .line 257
    :cond_c
    move-object v14, v7

    .line 258
    iget-object v13, v4, Lss0/k;->a:Ljava/lang/String;

    .line 259
    .line 260
    iget-object v12, v0, Llz/v;->f:Ljz/m;

    .line 261
    .line 262
    const-string v1, "$v$c$cz-skodaauto-myskoda-library-vehicle-model-Vin$-vin$0"

    .line 263
    .line 264
    invoke-static {v13, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 265
    .line 266
    .line 267
    const-string v1, "timers"

    .line 268
    .line 269
    invoke-static {v14, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 270
    .line 271
    .line 272
    const-string v1, "$v$c$cz-skodaauto-myskoda-library-spin-model-Spin$-spin$0"

    .line 273
    .line 274
    invoke-static {v15, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 275
    .line 276
    .line 277
    iget-object v1, v12, Ljz/m;->a:Lxl0/f;

    .line 278
    .line 279
    new-instance v11, Ld40/k;

    .line 280
    .line 281
    const/16 v16, 0x0

    .line 282
    .line 283
    const/16 v17, 0x5

    .line 284
    .line 285
    invoke-direct/range {v11 .. v17}, Ld40/k;-><init>(Ljava/lang/Object;Ljava/lang/String;Ljava/lang/Object;Ljava/lang/String;Lkotlin/coroutines/Continuation;I)V

    .line 286
    .line 287
    .line 288
    invoke-virtual {v1, v11}, Lxl0/f;->c(Lay0/k;)Lyy0/m1;

    .line 289
    .line 290
    .line 291
    move-result-object v1

    .line 292
    new-instance v4, Llb0/q0;

    .line 293
    .line 294
    const/16 v7, 0x8

    .line 295
    .line 296
    invoke-direct {v4, v0, v10, v7}, Llb0/q0;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 297
    .line 298
    .line 299
    invoke-static {v4, v1}, Lbb/j0;->e(Lay0/n;Lyy0/i;)Lne0/n;

    .line 300
    .line 301
    .line 302
    move-result-object v1

    .line 303
    iget-object v4, v0, Llz/v;->b:Lsf0/a;

    .line 304
    .line 305
    invoke-static {v1, v4, v10}, Llp/o1;->d(Lyy0/i;Lsf0/a;Ljava/lang/String;)Lam0/i;

    .line 306
    .line 307
    .line 308
    move-result-object v1

    .line 309
    new-instance v4, Llz/u;

    .line 310
    .line 311
    const/4 v7, 0x0

    .line 312
    invoke-direct {v4, v0, v10, v7}, Llz/u;-><init>(Llz/v;Lkotlin/coroutines/Continuation;I)V

    .line 313
    .line 314
    .line 315
    invoke-static {v4, v1}, Llp/ae;->c(Lay0/n;Lyy0/i;)Lyy0/m1;

    .line 316
    .line 317
    .line 318
    move-result-object v1

    .line 319
    iput-object v10, v2, Llz/t;->d:Ljava/util/List;

    .line 320
    .line 321
    iput-object v10, v2, Llz/t;->e:Lss0/k;

    .line 322
    .line 323
    iput v6, v2, Llz/t;->i:I

    .line 324
    .line 325
    invoke-static {v1, v2}, Lyy0/u;->w(Lyy0/i;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 326
    .line 327
    .line 328
    move-result-object v1

    .line 329
    if-ne v1, v3, :cond_d

    .line 330
    .line 331
    goto :goto_5

    .line 332
    :cond_d
    :goto_4
    check-cast v1, Lne0/t;

    .line 333
    .line 334
    if-eqz v1, :cond_f

    .line 335
    .line 336
    instance-of v4, v1, Lne0/c;

    .line 337
    .line 338
    if-eqz v4, :cond_e

    .line 339
    .line 340
    move-object v4, v1

    .line 341
    check-cast v4, Lne0/c;

    .line 342
    .line 343
    iput-object v10, v2, Llz/t;->d:Ljava/util/List;

    .line 344
    .line 345
    iput-object v10, v2, Llz/t;->e:Lss0/k;

    .line 346
    .line 347
    iput-object v1, v2, Llz/t;->f:Lne0/t;

    .line 348
    .line 349
    iput v5, v2, Llz/t;->i:I

    .line 350
    .line 351
    iget-object v0, v0, Llz/v;->c:Ljn0/c;

    .line 352
    .line 353
    invoke-virtual {v0, v4, v2}, Ljn0/c;->c(Lne0/c;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 354
    .line 355
    .line 356
    move-result-object v0

    .line 357
    if-ne v0, v3, :cond_e

    .line 358
    .line 359
    :goto_5
    return-object v3

    .line 360
    :cond_e
    return-object v1

    .line 361
    :cond_f
    return-object v10

    .line 362
    :cond_10
    new-instance v0, La8/r0;

    .line 363
    .line 364
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 365
    .line 366
    .line 367
    throw v0

    .line 368
    :cond_11
    new-instance v0, La8/r0;

    .line 369
    .line 370
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 371
    .line 372
    .line 373
    throw v0
.end method
