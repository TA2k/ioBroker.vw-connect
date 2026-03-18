.class public final Lnl/l;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lnl/g;


# static fields
.field public static final f:Ld01/h;

.field public static final g:Ld01/h;


# instance fields
.field public final a:Ljava/lang/String;

.field public final b:Ltl/l;

.field public final c:Llx0/q;

.field public final d:Llx0/q;

.field public final e:Z


# direct methods
.method static constructor <clinit>()V
    .locals 15

    .line 1
    new-instance v0, Ld01/h;

    .line 2
    .line 3
    const/4 v12, 0x0

    .line 4
    const/4 v13, 0x0

    .line 5
    const/4 v1, 0x1

    .line 6
    const/4 v2, 0x1

    .line 7
    const/4 v3, -0x1

    .line 8
    const/4 v4, -0x1

    .line 9
    const/4 v5, 0x0

    .line 10
    const/4 v6, 0x0

    .line 11
    const/4 v7, 0x0

    .line 12
    const/4 v8, -0x1

    .line 13
    const/4 v9, -0x1

    .line 14
    const/4 v10, 0x0

    .line 15
    const/4 v11, 0x0

    .line 16
    invoke-direct/range {v0 .. v13}, Ld01/h;-><init>(ZZIIZZZIIZZZLjava/lang/String;)V

    .line 17
    .line 18
    .line 19
    sput-object v0, Lnl/l;->f:Ld01/h;

    .line 20
    .line 21
    new-instance v1, Ld01/h;

    .line 22
    .line 23
    const/4 v13, 0x0

    .line 24
    const/4 v14, 0x0

    .line 25
    const/4 v3, 0x0

    .line 26
    const/4 v5, -0x1

    .line 27
    const/4 v8, 0x0

    .line 28
    const/4 v10, -0x1

    .line 29
    const/4 v11, 0x1

    .line 30
    invoke-direct/range {v1 .. v14}, Ld01/h;-><init>(ZZIIZZZIIZZZLjava/lang/String;)V

    .line 31
    .line 32
    .line 33
    sput-object v1, Lnl/l;->g:Ld01/h;

    .line 34
    .line 35
    return-void
.end method

.method public constructor <init>(Ljava/lang/String;Ltl/l;Llx0/q;Llx0/q;Z)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lnl/l;->a:Ljava/lang/String;

    .line 5
    .line 6
    iput-object p2, p0, Lnl/l;->b:Ltl/l;

    .line 7
    .line 8
    iput-object p3, p0, Lnl/l;->c:Llx0/q;

    .line 9
    .line 10
    iput-object p4, p0, Lnl/l;->d:Llx0/q;

    .line 11
    .line 12
    iput-boolean p5, p0, Lnl/l;->e:Z

    .line 13
    .line 14
    return-void
.end method

.method public static d(Ljava/lang/String;Ld01/d0;)Ljava/lang/String;
    .locals 3

    .line 1
    const/4 v0, 0x0

    .line 2
    if-eqz p1, :cond_0

    .line 3
    .line 4
    iget-object p1, p1, Ld01/d0;->a:Ljava/lang/String;

    .line 5
    .line 6
    goto :goto_0

    .line 7
    :cond_0
    move-object p1, v0

    .line 8
    :goto_0
    if-eqz p1, :cond_1

    .line 9
    .line 10
    const-string v1, "text/plain"

    .line 11
    .line 12
    const/4 v2, 0x0

    .line 13
    invoke-static {p1, v1, v2}, Lly0/w;->x(Ljava/lang/String;Ljava/lang/String;Z)Z

    .line 14
    .line 15
    .line 16
    move-result v1

    .line 17
    if-eqz v1, :cond_2

    .line 18
    .line 19
    :cond_1
    invoke-static {}, Landroid/webkit/MimeTypeMap;->getSingleton()Landroid/webkit/MimeTypeMap;

    .line 20
    .line 21
    .line 22
    move-result-object v1

    .line 23
    invoke-static {v1, p0}, Lxl/c;->b(Landroid/webkit/MimeTypeMap;Ljava/lang/String;)Ljava/lang/String;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    if-eqz p0, :cond_2

    .line 28
    .line 29
    return-object p0

    .line 30
    :cond_2
    if-eqz p1, :cond_3

    .line 31
    .line 32
    const/16 p0, 0x3b

    .line 33
    .line 34
    invoke-static {p1, p0}, Lly0/p;->f0(Ljava/lang/String;C)Ljava/lang/String;

    .line 35
    .line 36
    .line 37
    move-result-object p0

    .line 38
    return-object p0

    .line 39
    :cond_3
    return-object v0
.end method


# virtual methods
.method public final a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 14

    .line 1
    instance-of v0, p1, Lnl/k;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p1

    .line 6
    check-cast v0, Lnl/k;

    .line 7
    .line 8
    iget v1, v0, Lnl/k;->i:I

    .line 9
    .line 10
    const/high16 v2, -0x80000000

    .line 11
    .line 12
    and-int v3, v1, v2

    .line 13
    .line 14
    if-eqz v3, :cond_0

    .line 15
    .line 16
    sub-int/2addr v1, v2

    .line 17
    iput v1, v0, Lnl/k;->i:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lnl/k;

    .line 21
    .line 22
    check-cast p1, Lrx0/c;

    .line 23
    .line 24
    invoke-direct {v0, p0, p1}, Lnl/k;-><init>(Lnl/l;Lrx0/c;)V

    .line 25
    .line 26
    .line 27
    :goto_0
    iget-object p1, v0, Lnl/k;->g:Ljava/lang/Object;

    .line 28
    .line 29
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 30
    .line 31
    iget v2, v0, Lnl/k;->i:I

    .line 32
    .line 33
    const/4 v3, 0x0

    .line 34
    const-string v4, "response body == null"

    .line 35
    .line 36
    const-wide/16 v5, 0x0

    .line 37
    .line 38
    const/4 v7, 0x2

    .line 39
    const/4 v8, 0x1

    .line 40
    const/4 v9, 0x0

    .line 41
    if-eqz v2, :cond_3

    .line 42
    .line 43
    if-eq v2, v8, :cond_2

    .line 44
    .line 45
    if-ne v2, v7, :cond_1

    .line 46
    .line 47
    iget-object p0, v0, Lnl/k;->f:Ljava/lang/Object;

    .line 48
    .line 49
    check-cast p0, Ld01/t0;

    .line 50
    .line 51
    iget-object v1, v0, Lnl/k;->e:Lll/e;

    .line 52
    .line 53
    iget-object v0, v0, Lnl/k;->d:Lnl/l;

    .line 54
    .line 55
    :try_start_0
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    .line 56
    .line 57
    .line 58
    goto/16 :goto_9

    .line 59
    .line 60
    :catch_0
    move-exception p1

    .line 61
    goto/16 :goto_b

    .line 62
    .line 63
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 64
    .line 65
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 66
    .line 67
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 68
    .line 69
    .line 70
    throw p0

    .line 71
    :cond_2
    iget-object p0, v0, Lnl/k;->f:Ljava/lang/Object;

    .line 72
    .line 73
    check-cast p0, Lsl/d;

    .line 74
    .line 75
    iget-object v2, v0, Lnl/k;->e:Lll/e;

    .line 76
    .line 77
    iget-object v8, v0, Lnl/k;->d:Lnl/l;

    .line 78
    .line 79
    :try_start_1
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V
    :try_end_1
    .catch Ljava/lang/Exception; {:try_start_1 .. :try_end_1} :catch_1

    .line 80
    .line 81
    .line 82
    move-object v13, p1

    .line 83
    move-object p1, p0

    .line 84
    move-object p0, v8

    .line 85
    move-object v8, v13

    .line 86
    goto/16 :goto_3

    .line 87
    .line 88
    :catch_1
    move-exception p0

    .line 89
    goto/16 :goto_c

    .line 90
    .line 91
    :cond_3
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 92
    .line 93
    .line 94
    iget-object p1, p0, Lnl/l;->b:Ltl/l;

    .line 95
    .line 96
    iget-object v2, p1, Ltl/l;->n:Ltl/a;

    .line 97
    .line 98
    iget-boolean v2, v2, Ltl/a;->d:Z

    .line 99
    .line 100
    iget-object v10, p0, Lnl/l;->a:Ljava/lang/String;

    .line 101
    .line 102
    if-eqz v2, :cond_5

    .line 103
    .line 104
    iget-object v2, p0, Lnl/l;->d:Llx0/q;

    .line 105
    .line 106
    invoke-virtual {v2}, Llx0/q;->getValue()Ljava/lang/Object;

    .line 107
    .line 108
    .line 109
    move-result-object v2

    .line 110
    check-cast v2, Lll/f;

    .line 111
    .line 112
    if-eqz v2, :cond_5

    .line 113
    .line 114
    iget-object p1, p1, Ltl/l;->i:Ljava/lang/String;

    .line 115
    .line 116
    if-nez p1, :cond_4

    .line 117
    .line 118
    move-object p1, v10

    .line 119
    :cond_4
    iget-object v2, v2, Lll/f;->b:Lll/d;

    .line 120
    .line 121
    sget-object v11, Lu01/i;->g:Lu01/i;

    .line 122
    .line 123
    invoke-static {p1}, Lpy/a;->m(Ljava/lang/String;)Lu01/i;

    .line 124
    .line 125
    .line 126
    move-result-object p1

    .line 127
    const-string v11, "SHA-256"

    .line 128
    .line 129
    invoke-virtual {p1, v11}, Lu01/i;->c(Ljava/lang/String;)Lu01/i;

    .line 130
    .line 131
    .line 132
    move-result-object p1

    .line 133
    invoke-virtual {p1}, Lu01/i;->e()Ljava/lang/String;

    .line 134
    .line 135
    .line 136
    move-result-object p1

    .line 137
    invoke-virtual {v2, p1}, Lll/d;->d(Ljava/lang/String;)Lll/b;

    .line 138
    .line 139
    .line 140
    move-result-object p1

    .line 141
    if-eqz p1, :cond_5

    .line 142
    .line 143
    new-instance v2, Lll/e;

    .line 144
    .line 145
    invoke-direct {v2, p1}, Lll/e;-><init>(Lll/b;)V

    .line 146
    .line 147
    .line 148
    goto :goto_1

    .line 149
    :cond_5
    move-object v2, v9

    .line 150
    :goto_1
    if-eqz v2, :cond_b

    .line 151
    .line 152
    :try_start_2
    invoke-virtual {p0}, Lnl/l;->c()Lu01/k;

    .line 153
    .line 154
    .line 155
    move-result-object p1

    .line 156
    iget-object v11, v2, Lll/e;->e:Ljava/io/Closeable;

    .line 157
    .line 158
    check-cast v11, Lll/b;

    .line 159
    .line 160
    iget-boolean v12, v11, Lll/b;->e:Z

    .line 161
    .line 162
    if-nez v12, :cond_a

    .line 163
    .line 164
    iget-object v11, v11, Lll/b;->d:Lll/a;

    .line 165
    .line 166
    iget-object v11, v11, Lll/a;->c:Ljava/util/ArrayList;

    .line 167
    .line 168
    invoke-virtual {v11, v3}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 169
    .line 170
    .line 171
    move-result-object v11

    .line 172
    check-cast v11, Lu01/y;

    .line 173
    .line 174
    invoke-virtual {p1, v11}, Lu01/k;->l(Lu01/y;)Li5/f;

    .line 175
    .line 176
    .line 177
    move-result-object p1

    .line 178
    iget-object p1, p1, Li5/f;->e:Ljava/lang/Object;

    .line 179
    .line 180
    check-cast p1, Ljava/lang/Long;

    .line 181
    .line 182
    if-nez p1, :cond_6

    .line 183
    .line 184
    goto :goto_2

    .line 185
    :cond_6
    invoke-virtual {p1}, Ljava/lang/Long;->longValue()J

    .line 186
    .line 187
    .line 188
    move-result-wide v11

    .line 189
    cmp-long p1, v11, v5

    .line 190
    .line 191
    if-nez p1, :cond_7

    .line 192
    .line 193
    new-instance p1, Lnl/m;

    .line 194
    .line 195
    invoke-virtual {p0, v2}, Lnl/l;->g(Lll/e;)Lkl/k;

    .line 196
    .line 197
    .line 198
    move-result-object p0

    .line 199
    invoke-static {v10, v9}, Lnl/l;->d(Ljava/lang/String;Ld01/d0;)Ljava/lang/String;

    .line 200
    .line 201
    .line 202
    move-result-object v0

    .line 203
    sget-object v1, Lkl/e;->f:Lkl/e;

    .line 204
    .line 205
    invoke-direct {p1, p0, v0, v1}, Lnl/m;-><init>(Lkl/l;Ljava/lang/String;Lkl/e;)V

    .line 206
    .line 207
    .line 208
    return-object p1

    .line 209
    :cond_7
    :goto_2
    iget-boolean p1, p0, Lnl/l;->e:Z

    .line 210
    .line 211
    if-eqz p1, :cond_8

    .line 212
    .line 213
    new-instance p1, Lsl/c;

    .line 214
    .line 215
    invoke-virtual {p0}, Lnl/l;->e()Ld01/k0;

    .line 216
    .line 217
    .line 218
    move-result-object v11

    .line 219
    invoke-virtual {p0, v2}, Lnl/l;->f(Lll/e;)Lsl/b;

    .line 220
    .line 221
    .line 222
    move-result-object v12

    .line 223
    invoke-direct {p1, v11, v12}, Lsl/c;-><init>(Ld01/k0;Lsl/b;)V

    .line 224
    .line 225
    .line 226
    invoke-virtual {p1}, Lsl/c;->a()Lsl/d;

    .line 227
    .line 228
    .line 229
    move-result-object p1

    .line 230
    iget-object v11, p1, Lsl/d;->b:Lsl/b;

    .line 231
    .line 232
    iget-object v12, p1, Lsl/d;->a:Ld01/k0;

    .line 233
    .line 234
    if-nez v12, :cond_c

    .line 235
    .line 236
    if-eqz v11, :cond_c

    .line 237
    .line 238
    new-instance p1, Lnl/m;

    .line 239
    .line 240
    invoke-virtual {p0, v2}, Lnl/l;->g(Lll/e;)Lkl/k;

    .line 241
    .line 242
    .line 243
    move-result-object p0

    .line 244
    iget-object v0, v11, Lsl/b;->b:Ljava/lang/Object;

    .line 245
    .line 246
    invoke-interface {v0}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 247
    .line 248
    .line 249
    move-result-object v0

    .line 250
    check-cast v0, Ld01/d0;

    .line 251
    .line 252
    invoke-static {v10, v0}, Lnl/l;->d(Ljava/lang/String;Ld01/d0;)Ljava/lang/String;

    .line 253
    .line 254
    .line 255
    move-result-object v0

    .line 256
    sget-object v1, Lkl/e;->f:Lkl/e;

    .line 257
    .line 258
    invoke-direct {p1, p0, v0, v1}, Lnl/m;-><init>(Lkl/l;Ljava/lang/String;Lkl/e;)V

    .line 259
    .line 260
    .line 261
    return-object p1

    .line 262
    :cond_8
    new-instance p1, Lnl/m;

    .line 263
    .line 264
    invoke-virtual {p0, v2}, Lnl/l;->g(Lll/e;)Lkl/k;

    .line 265
    .line 266
    .line 267
    move-result-object v0

    .line 268
    invoke-virtual {p0, v2}, Lnl/l;->f(Lll/e;)Lsl/b;

    .line 269
    .line 270
    .line 271
    move-result-object p0

    .line 272
    if-eqz p0, :cond_9

    .line 273
    .line 274
    iget-object p0, p0, Lsl/b;->b:Ljava/lang/Object;

    .line 275
    .line 276
    invoke-interface {p0}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 277
    .line 278
    .line 279
    move-result-object p0

    .line 280
    move-object v9, p0

    .line 281
    check-cast v9, Ld01/d0;

    .line 282
    .line 283
    :cond_9
    invoke-static {v10, v9}, Lnl/l;->d(Ljava/lang/String;Ld01/d0;)Ljava/lang/String;

    .line 284
    .line 285
    .line 286
    move-result-object p0

    .line 287
    sget-object v1, Lkl/e;->f:Lkl/e;

    .line 288
    .line 289
    invoke-direct {p1, v0, p0, v1}, Lnl/m;-><init>(Lkl/l;Ljava/lang/String;Lkl/e;)V

    .line 290
    .line 291
    .line 292
    return-object p1

    .line 293
    :cond_a
    const-string p0, "snapshot is closed"

    .line 294
    .line 295
    new-instance p1, Ljava/lang/IllegalStateException;

    .line 296
    .line 297
    invoke-direct {p1, p0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 298
    .line 299
    .line 300
    throw p1

    .line 301
    :cond_b
    new-instance p1, Lsl/c;

    .line 302
    .line 303
    invoke-virtual {p0}, Lnl/l;->e()Ld01/k0;

    .line 304
    .line 305
    .line 306
    move-result-object v10

    .line 307
    invoke-direct {p1, v10, v9}, Lsl/c;-><init>(Ld01/k0;Lsl/b;)V

    .line 308
    .line 309
    .line 310
    invoke-virtual {p1}, Lsl/c;->a()Lsl/d;

    .line 311
    .line 312
    .line 313
    move-result-object p1

    .line 314
    :cond_c
    iget-object v10, p1, Lsl/d;->a:Ld01/k0;

    .line 315
    .line 316
    invoke-static {v10}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 317
    .line 318
    .line 319
    iput-object p0, v0, Lnl/k;->d:Lnl/l;

    .line 320
    .line 321
    iput-object v2, v0, Lnl/k;->e:Lll/e;

    .line 322
    .line 323
    iput-object p1, v0, Lnl/k;->f:Ljava/lang/Object;

    .line 324
    .line 325
    iput v8, v0, Lnl/k;->i:I

    .line 326
    .line 327
    invoke-virtual {p0, v10, v0}, Lnl/l;->b(Ld01/k0;Lrx0/c;)Ljava/lang/Object;

    .line 328
    .line 329
    .line 330
    move-result-object v8

    .line 331
    if-ne v8, v1, :cond_d

    .line 332
    .line 333
    goto/16 :goto_8

    .line 334
    .line 335
    :cond_d
    :goto_3
    check-cast v8, Ld01/t0;

    .line 336
    .line 337
    sget-object v10, Lxl/c;->a:[Landroid/graphics/Bitmap$Config;

    .line 338
    .line 339
    iget-object v10, v8, Ld01/t0;->j:Ld01/v0;
    :try_end_2
    .catch Ljava/lang/Exception; {:try_start_2 .. :try_end_2} :catch_1

    .line 340
    .line 341
    if-eqz v10, :cond_15

    .line 342
    .line 343
    :try_start_3
    iget-object v11, p1, Lsl/d;->a:Ld01/k0;

    .line 344
    .line 345
    iget-object p1, p1, Lsl/d;->b:Lsl/b;

    .line 346
    .line 347
    invoke-virtual {p0, v2, v11, v8, p1}, Lnl/l;->h(Lll/e;Ld01/k0;Ld01/t0;Lsl/b;)Lll/e;

    .line 348
    .line 349
    .line 350
    move-result-object p1
    :try_end_3
    .catch Ljava/lang/Exception; {:try_start_3 .. :try_end_3} :catch_4

    .line 351
    iget-object v2, p0, Lnl/l;->a:Ljava/lang/String;

    .line 352
    .line 353
    if-eqz p1, :cond_f

    .line 354
    .line 355
    :try_start_4
    new-instance v0, Lnl/m;

    .line 356
    .line 357
    invoke-virtual {p0, p1}, Lnl/l;->g(Lll/e;)Lkl/k;

    .line 358
    .line 359
    .line 360
    move-result-object v1

    .line 361
    invoke-virtual {p0, p1}, Lnl/l;->f(Lll/e;)Lsl/b;

    .line 362
    .line 363
    .line 364
    move-result-object p0

    .line 365
    if-eqz p0, :cond_e

    .line 366
    .line 367
    iget-object p0, p0, Lsl/b;->b:Ljava/lang/Object;

    .line 368
    .line 369
    invoke-interface {p0}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 370
    .line 371
    .line 372
    move-result-object p0

    .line 373
    move-object v9, p0

    .line 374
    check-cast v9, Ld01/d0;

    .line 375
    .line 376
    goto :goto_6

    .line 377
    :goto_4
    move-object v1, p1

    .line 378
    move-object p1, p0

    .line 379
    :goto_5
    move-object p0, v8

    .line 380
    goto/16 :goto_b

    .line 381
    .line 382
    :cond_e
    :goto_6
    invoke-static {v2, v9}, Lnl/l;->d(Ljava/lang/String;Ld01/d0;)Ljava/lang/String;

    .line 383
    .line 384
    .line 385
    move-result-object p0

    .line 386
    sget-object v2, Lkl/e;->g:Lkl/e;

    .line 387
    .line 388
    invoke-direct {v0, v1, p0, v2}, Lnl/m;-><init>(Lkl/l;Ljava/lang/String;Lkl/e;)V

    .line 389
    .line 390
    .line 391
    return-object v0

    .line 392
    :catch_2
    move-exception p0

    .line 393
    goto :goto_4

    .line 394
    :cond_f
    invoke-virtual {v10}, Ld01/v0;->b()J

    .line 395
    .line 396
    .line 397
    move-result-wide v11

    .line 398
    cmp-long v5, v11, v5

    .line 399
    .line 400
    if-lez v5, :cond_11

    .line 401
    .line 402
    new-instance v0, Lnl/m;

    .line 403
    .line 404
    invoke-virtual {v10}, Ld01/v0;->p0()Lu01/h;

    .line 405
    .line 406
    .line 407
    move-result-object v1

    .line 408
    iget-object p0, p0, Lnl/l;->b:Ltl/l;

    .line 409
    .line 410
    iget-object p0, p0, Ltl/l;->a:Landroid/content/Context;

    .line 411
    .line 412
    new-instance v4, Lkl/o;

    .line 413
    .line 414
    new-instance v5, Lkl/m;

    .line 415
    .line 416
    invoke-direct {v5, p0, v3}, Lkl/m;-><init>(Landroid/content/Context;I)V

    .line 417
    .line 418
    .line 419
    invoke-direct {v4, v1, v5, v9}, Lkl/o;-><init>(Lu01/h;Lay0/a;Llp/qd;)V

    .line 420
    .line 421
    .line 422
    invoke-virtual {v10}, Ld01/v0;->d()Ld01/d0;

    .line 423
    .line 424
    .line 425
    move-result-object p0

    .line 426
    invoke-static {v2, p0}, Lnl/l;->d(Ljava/lang/String;Ld01/d0;)Ljava/lang/String;

    .line 427
    .line 428
    .line 429
    move-result-object p0

    .line 430
    iget-object v1, v8, Ld01/t0;->l:Ld01/t0;

    .line 431
    .line 432
    if-eqz v1, :cond_10

    .line 433
    .line 434
    sget-object v1, Lkl/e;->g:Lkl/e;

    .line 435
    .line 436
    goto :goto_7

    .line 437
    :cond_10
    sget-object v1, Lkl/e;->f:Lkl/e;

    .line 438
    .line 439
    :goto_7
    invoke-direct {v0, v4, p0, v1}, Lnl/m;-><init>(Lkl/l;Ljava/lang/String;Lkl/e;)V

    .line 440
    .line 441
    .line 442
    return-object v0

    .line 443
    :cond_11
    invoke-static {v8}, Lxl/c;->a(Ljava/io/Closeable;)V

    .line 444
    .line 445
    .line 446
    invoke-virtual {p0}, Lnl/l;->e()Ld01/k0;

    .line 447
    .line 448
    .line 449
    move-result-object v2

    .line 450
    iput-object p0, v0, Lnl/k;->d:Lnl/l;

    .line 451
    .line 452
    iput-object p1, v0, Lnl/k;->e:Lll/e;

    .line 453
    .line 454
    iput-object v8, v0, Lnl/k;->f:Ljava/lang/Object;

    .line 455
    .line 456
    iput v7, v0, Lnl/k;->i:I

    .line 457
    .line 458
    invoke-virtual {p0, v2, v0}, Lnl/l;->b(Ld01/k0;Lrx0/c;)Ljava/lang/Object;

    .line 459
    .line 460
    .line 461
    move-result-object v0
    :try_end_4
    .catch Ljava/lang/Exception; {:try_start_4 .. :try_end_4} :catch_2

    .line 462
    if-ne v0, v1, :cond_12

    .line 463
    .line 464
    :goto_8
    return-object v1

    .line 465
    :cond_12
    move-object v1, p1

    .line 466
    move-object p1, v0

    .line 467
    move-object v0, p0

    .line 468
    move-object p0, v8

    .line 469
    :goto_9
    :try_start_5
    check-cast p1, Ld01/t0;
    :try_end_5
    .catch Ljava/lang/Exception; {:try_start_5 .. :try_end_5} :catch_0

    .line 470
    .line 471
    :try_start_6
    sget-object p0, Lxl/c;->a:[Landroid/graphics/Bitmap$Config;

    .line 472
    .line 473
    iget-object p0, p1, Ld01/t0;->j:Ld01/v0;

    .line 474
    .line 475
    if-eqz p0, :cond_14

    .line 476
    .line 477
    new-instance v2, Lnl/m;

    .line 478
    .line 479
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 480
    .line 481
    .line 482
    invoke-virtual {p0}, Ld01/v0;->p0()Lu01/h;

    .line 483
    .line 484
    .line 485
    move-result-object v4

    .line 486
    iget-object v5, v0, Lnl/l;->b:Ltl/l;

    .line 487
    .line 488
    iget-object v5, v5, Ltl/l;->a:Landroid/content/Context;

    .line 489
    .line 490
    new-instance v6, Lkl/o;

    .line 491
    .line 492
    new-instance v7, Lkl/m;

    .line 493
    .line 494
    invoke-direct {v7, v5, v3}, Lkl/m;-><init>(Landroid/content/Context;I)V

    .line 495
    .line 496
    .line 497
    invoke-direct {v6, v4, v7, v9}, Lkl/o;-><init>(Lu01/h;Lay0/a;Llp/qd;)V

    .line 498
    .line 499
    .line 500
    iget-object v0, v0, Lnl/l;->a:Ljava/lang/String;

    .line 501
    .line 502
    invoke-virtual {p0}, Ld01/v0;->d()Ld01/d0;

    .line 503
    .line 504
    .line 505
    move-result-object p0

    .line 506
    invoke-static {v0, p0}, Lnl/l;->d(Ljava/lang/String;Ld01/d0;)Ljava/lang/String;

    .line 507
    .line 508
    .line 509
    move-result-object p0

    .line 510
    iget-object v0, p1, Ld01/t0;->l:Ld01/t0;

    .line 511
    .line 512
    if-eqz v0, :cond_13

    .line 513
    .line 514
    sget-object v0, Lkl/e;->g:Lkl/e;

    .line 515
    .line 516
    goto :goto_a

    .line 517
    :cond_13
    sget-object v0, Lkl/e;->f:Lkl/e;

    .line 518
    .line 519
    :goto_a
    invoke-direct {v2, v6, p0, v0}, Lnl/m;-><init>(Lkl/l;Ljava/lang/String;Lkl/e;)V

    .line 520
    .line 521
    .line 522
    return-object v2

    .line 523
    :catch_3
    move-exception p0

    .line 524
    move-object v13, p1

    .line 525
    move-object p1, p0

    .line 526
    move-object p0, v13

    .line 527
    goto :goto_b

    .line 528
    :cond_14
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 529
    .line 530
    invoke-direct {p0, v4}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 531
    .line 532
    .line 533
    throw p0
    :try_end_6
    .catch Ljava/lang/Exception; {:try_start_6 .. :try_end_6} :catch_3

    .line 534
    :catch_4
    move-exception p1

    .line 535
    move-object v1, v2

    .line 536
    goto/16 :goto_5

    .line 537
    .line 538
    :goto_b
    :try_start_7
    invoke-static {p0}, Lxl/c;->a(Ljava/io/Closeable;)V

    .line 539
    .line 540
    .line 541
    throw p1
    :try_end_7
    .catch Ljava/lang/Exception; {:try_start_7 .. :try_end_7} :catch_5

    .line 542
    :catch_5
    move-exception p0

    .line 543
    move-object v2, v1

    .line 544
    goto :goto_c

    .line 545
    :cond_15
    :try_start_8
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 546
    .line 547
    invoke-direct {p0, v4}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 548
    .line 549
    .line 550
    throw p0
    :try_end_8
    .catch Ljava/lang/Exception; {:try_start_8 .. :try_end_8} :catch_1

    .line 551
    :goto_c
    if-eqz v2, :cond_16

    .line 552
    .line 553
    invoke-static {v2}, Lxl/c;->a(Ljava/io/Closeable;)V

    .line 554
    .line 555
    .line 556
    :cond_16
    throw p0
.end method

.method public final b(Ld01/k0;Lrx0/c;)Ljava/lang/Object;
    .locals 4

    .line 1
    instance-of v0, p2, Lnl/j;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p2

    .line 6
    check-cast v0, Lnl/j;

    .line 7
    .line 8
    iget v1, v0, Lnl/j;->f:I

    .line 9
    .line 10
    const/high16 v2, -0x80000000

    .line 11
    .line 12
    and-int v3, v1, v2

    .line 13
    .line 14
    if-eqz v3, :cond_0

    .line 15
    .line 16
    sub-int/2addr v1, v2

    .line 17
    iput v1, v0, Lnl/j;->f:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lnl/j;

    .line 21
    .line 22
    invoke-direct {v0, p0, p2}, Lnl/j;-><init>(Lnl/l;Lrx0/c;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p2, v0, Lnl/j;->d:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lnl/j;->f:I

    .line 30
    .line 31
    const/4 v3, 0x1

    .line 32
    if-eqz v2, :cond_2

    .line 33
    .line 34
    if-ne v2, v3, :cond_1

    .line 35
    .line 36
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 37
    .line 38
    .line 39
    goto :goto_1

    .line 40
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 41
    .line 42
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 43
    .line 44
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 45
    .line 46
    .line 47
    throw p0

    .line 48
    :cond_2
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 49
    .line 50
    .line 51
    sget-object p2, Lxl/c;->a:[Landroid/graphics/Bitmap$Config;

    .line 52
    .line 53
    invoke-static {}, Landroid/os/Looper;->myLooper()Landroid/os/Looper;

    .line 54
    .line 55
    .line 56
    move-result-object p2

    .line 57
    invoke-static {}, Landroid/os/Looper;->getMainLooper()Landroid/os/Looper;

    .line 58
    .line 59
    .line 60
    move-result-object v2

    .line 61
    invoke-static {p2, v2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 62
    .line 63
    .line 64
    move-result p2

    .line 65
    iget-object v2, p0, Lnl/l;->c:Llx0/q;

    .line 66
    .line 67
    if-eqz p2, :cond_4

    .line 68
    .line 69
    iget-object p0, p0, Lnl/l;->b:Ltl/l;

    .line 70
    .line 71
    iget-object p0, p0, Ltl/l;->o:Ltl/a;

    .line 72
    .line 73
    iget-boolean p0, p0, Ltl/a;->d:Z

    .line 74
    .line 75
    if-nez p0, :cond_3

    .line 76
    .line 77
    invoke-virtual {v2}, Llx0/q;->getValue()Ljava/lang/Object;

    .line 78
    .line 79
    .line 80
    move-result-object p0

    .line 81
    check-cast p0, Ld01/i;

    .line 82
    .line 83
    invoke-interface {p0, p1}, Ld01/i;->newCall(Ld01/k0;)Ld01/j;

    .line 84
    .line 85
    .line 86
    move-result-object p0

    .line 87
    invoke-static {p0}, Lcom/google/firebase/perf/network/FirebasePerfOkHttpClient;->execute(Ld01/j;)Ld01/t0;

    .line 88
    .line 89
    .line 90
    move-result-object p0

    .line 91
    goto :goto_2

    .line 92
    :cond_3
    new-instance p0, Landroid/os/NetworkOnMainThreadException;

    .line 93
    .line 94
    invoke-direct {p0}, Landroid/os/NetworkOnMainThreadException;-><init>()V

    .line 95
    .line 96
    .line 97
    throw p0

    .line 98
    :cond_4
    invoke-virtual {v2}, Llx0/q;->getValue()Ljava/lang/Object;

    .line 99
    .line 100
    .line 101
    move-result-object p0

    .line 102
    check-cast p0, Ld01/i;

    .line 103
    .line 104
    invoke-interface {p0, p1}, Ld01/i;->newCall(Ld01/k0;)Ld01/j;

    .line 105
    .line 106
    .line 107
    move-result-object p0

    .line 108
    iput v3, v0, Lnl/j;->f:I

    .line 109
    .line 110
    new-instance p1, Lvy0/l;

    .line 111
    .line 112
    invoke-static {v0}, Ljp/hg;->b(Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 113
    .line 114
    .line 115
    move-result-object p2

    .line 116
    invoke-direct {p1, v3, p2}, Lvy0/l;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 117
    .line 118
    .line 119
    invoke-virtual {p1}, Lvy0/l;->q()V

    .line 120
    .line 121
    .line 122
    new-instance p2, Llm/c;

    .line 123
    .line 124
    invoke-direct {p2, p0, p1, v3}, Llm/c;-><init>(Ld01/j;Lvy0/l;I)V

    .line 125
    .line 126
    .line 127
    invoke-static {p0, p2}, Lcom/google/firebase/perf/network/FirebasePerfOkHttpClient;->enqueue(Ld01/j;Ld01/k;)V

    .line 128
    .line 129
    .line 130
    invoke-virtual {p1, p2}, Lvy0/l;->s(Lay0/k;)V

    .line 131
    .line 132
    .line 133
    invoke-virtual {p1}, Lvy0/l;->p()Ljava/lang/Object;

    .line 134
    .line 135
    .line 136
    move-result-object p2

    .line 137
    if-ne p2, v1, :cond_5

    .line 138
    .line 139
    return-object v1

    .line 140
    :cond_5
    :goto_1
    move-object p0, p2

    .line 141
    check-cast p0, Ld01/t0;

    .line 142
    .line 143
    :goto_2
    iget-boolean p1, p0, Ld01/t0;->t:Z

    .line 144
    .line 145
    iget p2, p0, Ld01/t0;->g:I

    .line 146
    .line 147
    if-nez p1, :cond_7

    .line 148
    .line 149
    const/16 p1, 0x130

    .line 150
    .line 151
    if-eq p2, p1, :cond_7

    .line 152
    .line 153
    iget-object p1, p0, Ld01/t0;->j:Ld01/v0;

    .line 154
    .line 155
    if-eqz p1, :cond_6

    .line 156
    .line 157
    invoke-static {p1}, Lxl/c;->a(Ljava/io/Closeable;)V

    .line 158
    .line 159
    .line 160
    :cond_6
    new-instance p1, La8/r0;

    .line 161
    .line 162
    const-string v0, "HTTP "

    .line 163
    .line 164
    const-string v1, ": "

    .line 165
    .line 166
    invoke-static {v0, p2, v1}, Lp3/m;->p(Ljava/lang/String;ILjava/lang/String;)Ljava/lang/StringBuilder;

    .line 167
    .line 168
    .line 169
    move-result-object p2

    .line 170
    iget-object p0, p0, Ld01/t0;->f:Ljava/lang/String;

    .line 171
    .line 172
    invoke-virtual {p2, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 173
    .line 174
    .line 175
    invoke-virtual {p2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 176
    .line 177
    .line 178
    move-result-object p0

    .line 179
    invoke-direct {p1, p0}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/String;)V

    .line 180
    .line 181
    .line 182
    throw p1

    .line 183
    :cond_7
    return-object p0
.end method

.method public final c()Lu01/k;
    .locals 0

    .line 1
    iget-object p0, p0, Lnl/l;->d:Llx0/q;

    .line 2
    .line 3
    invoke-virtual {p0}, Llx0/q;->getValue()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    invoke-static {p0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 8
    .line 9
    .line 10
    check-cast p0, Lll/f;

    .line 11
    .line 12
    iget-object p0, p0, Lll/f;->a:Lu01/k;

    .line 13
    .line 14
    return-object p0
.end method

.method public final e()Ld01/k0;
    .locals 5

    .line 1
    new-instance v0, Ld01/j0;

    .line 2
    .line 3
    invoke-direct {v0}, Ld01/j0;-><init>()V

    .line 4
    .line 5
    .line 6
    iget-object v1, p0, Lnl/l;->a:Ljava/lang/String;

    .line 7
    .line 8
    invoke-virtual {v0, v1}, Ld01/j0;->f(Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    iget-object p0, p0, Lnl/l;->b:Ltl/l;

    .line 12
    .line 13
    iget-object v1, p0, Ltl/l;->j:Ld01/y;

    .line 14
    .line 15
    invoke-virtual {v0, v1}, Ld01/j0;->d(Ld01/y;)V

    .line 16
    .line 17
    .line 18
    iget-object v1, p0, Ltl/l;->k:Ltl/o;

    .line 19
    .line 20
    iget-object v1, v1, Ltl/o;->a:Ljava/util/Map;

    .line 21
    .line 22
    invoke-interface {v1}, Ljava/util/Map;->entrySet()Ljava/util/Set;

    .line 23
    .line 24
    .line 25
    move-result-object v1

    .line 26
    invoke-interface {v1}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 27
    .line 28
    .line 29
    move-result-object v1

    .line 30
    :goto_0
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 31
    .line 32
    .line 33
    move-result v2

    .line 34
    if-eqz v2, :cond_0

    .line 35
    .line 36
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 37
    .line 38
    .line 39
    move-result-object v2

    .line 40
    check-cast v2, Ljava/util/Map$Entry;

    .line 41
    .line 42
    invoke-interface {v2}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    .line 43
    .line 44
    .line 45
    move-result-object v3

    .line 46
    const-string v4, "null cannot be cast to non-null type java.lang.Class<kotlin.Any>"

    .line 47
    .line 48
    invoke-static {v3, v4}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 49
    .line 50
    .line 51
    check-cast v3, Ljava/lang/Class;

    .line 52
    .line 53
    invoke-interface {v2}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    .line 54
    .line 55
    .line 56
    move-result-object v2

    .line 57
    invoke-static {v3}, Ljp/p1;->f(Ljava/lang/Class;)Lhy0/d;

    .line 58
    .line 59
    .line 60
    move-result-object v3

    .line 61
    const-string v4, "type"

    .line 62
    .line 63
    invoke-static {v3, v4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 64
    .line 65
    .line 66
    iget-object v4, v0, Ld01/j0;->e:Ljp/ng;

    .line 67
    .line 68
    invoke-virtual {v4, v3, v2}, Ljp/ng;->b(Lhy0/d;Ljava/lang/Object;)Ljp/ng;

    .line 69
    .line 70
    .line 71
    move-result-object v2

    .line 72
    iput-object v2, v0, Ld01/j0;->e:Ljp/ng;

    .line 73
    .line 74
    goto :goto_0

    .line 75
    :cond_0
    iget-object v1, p0, Ltl/l;->n:Ltl/a;

    .line 76
    .line 77
    iget-boolean v2, v1, Ltl/a;->d:Z

    .line 78
    .line 79
    iget-object p0, p0, Ltl/l;->o:Ltl/a;

    .line 80
    .line 81
    iget-boolean p0, p0, Ltl/a;->d:Z

    .line 82
    .line 83
    if-nez p0, :cond_1

    .line 84
    .line 85
    if-eqz v2, :cond_1

    .line 86
    .line 87
    sget-object p0, Ld01/h;->o:Ld01/h;

    .line 88
    .line 89
    invoke-virtual {v0, p0}, Ld01/j0;->b(Ld01/h;)V

    .line 90
    .line 91
    .line 92
    goto :goto_1

    .line 93
    :cond_1
    if-eqz p0, :cond_3

    .line 94
    .line 95
    if-nez v2, :cond_3

    .line 96
    .line 97
    iget-boolean p0, v1, Ltl/a;->e:Z

    .line 98
    .line 99
    if-eqz p0, :cond_2

    .line 100
    .line 101
    sget-object p0, Ld01/h;->n:Ld01/h;

    .line 102
    .line 103
    invoke-virtual {v0, p0}, Ld01/j0;->b(Ld01/h;)V

    .line 104
    .line 105
    .line 106
    goto :goto_1

    .line 107
    :cond_2
    sget-object p0, Lnl/l;->f:Ld01/h;

    .line 108
    .line 109
    invoke-virtual {v0, p0}, Ld01/j0;->b(Ld01/h;)V

    .line 110
    .line 111
    .line 112
    goto :goto_1

    .line 113
    :cond_3
    if-nez p0, :cond_4

    .line 114
    .line 115
    if-nez v2, :cond_4

    .line 116
    .line 117
    sget-object p0, Lnl/l;->g:Ld01/h;

    .line 118
    .line 119
    invoke-virtual {v0, p0}, Ld01/j0;->b(Ld01/h;)V

    .line 120
    .line 121
    .line 122
    :cond_4
    :goto_1
    new-instance p0, Ld01/k0;

    .line 123
    .line 124
    invoke-direct {p0, v0}, Ld01/k0;-><init>(Ld01/j0;)V

    .line 125
    .line 126
    .line 127
    return-object p0
.end method

.method public final f(Lll/e;)Lsl/b;
    .locals 2

    .line 1
    const/4 v0, 0x0

    .line 2
    :try_start_0
    invoke-virtual {p0}, Lnl/l;->c()Lu01/k;

    .line 3
    .line 4
    .line 5
    move-result-object p0

    .line 6
    iget-object p1, p1, Lll/e;->e:Ljava/io/Closeable;

    .line 7
    .line 8
    check-cast p1, Lll/b;

    .line 9
    .line 10
    iget-boolean v1, p1, Lll/b;->e:Z

    .line 11
    .line 12
    if-nez v1, :cond_1

    .line 13
    .line 14
    iget-object p1, p1, Lll/b;->d:Lll/a;

    .line 15
    .line 16
    iget-object p1, p1, Lll/a;->c:Ljava/util/ArrayList;

    .line 17
    .line 18
    const/4 v1, 0x0

    .line 19
    invoke-virtual {p1, v1}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 20
    .line 21
    .line 22
    move-result-object p1

    .line 23
    check-cast p1, Lu01/y;

    .line 24
    .line 25
    invoke-virtual {p0, p1}, Lu01/k;->H(Lu01/y;)Lu01/h0;

    .line 26
    .line 27
    .line 28
    move-result-object p0

    .line 29
    invoke-static {p0}, Lu01/b;->c(Lu01/h0;)Lu01/b0;

    .line 30
    .line 31
    .line 32
    move-result-object p0
    :try_end_0
    .catch Ljava/io/IOException; {:try_start_0 .. :try_end_0} :catch_0

    .line 33
    :try_start_1
    new-instance p1, Lsl/b;

    .line 34
    .line 35
    invoke-direct {p1, p0}, Lsl/b;-><init>(Lu01/b0;)V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 36
    .line 37
    .line 38
    :try_start_2
    invoke-virtual {p0}, Lu01/b0;->close()V
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 39
    .line 40
    .line 41
    move-object p0, v0

    .line 42
    goto :goto_1

    .line 43
    :catchall_0
    move-exception p0

    .line 44
    goto :goto_1

    .line 45
    :catchall_1
    move-exception p1

    .line 46
    :try_start_3
    invoke-virtual {p0}, Lu01/b0;->close()V
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_2

    .line 47
    .line 48
    .line 49
    goto :goto_0

    .line 50
    :catchall_2
    move-exception p0

    .line 51
    :try_start_4
    invoke-static {p1, p0}, Loa0/b;->a(Ljava/lang/Throwable;Ljava/lang/Throwable;)V

    .line 52
    .line 53
    .line 54
    :goto_0
    move-object p0, p1

    .line 55
    move-object p1, v0

    .line 56
    :goto_1
    if-nez p0, :cond_0

    .line 57
    .line 58
    invoke-static {p1}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 59
    .line 60
    .line 61
    return-object p1

    .line 62
    :cond_0
    throw p0

    .line 63
    :cond_1
    const-string p0, "snapshot is closed"

    .line 64
    .line 65
    new-instance p1, Ljava/lang/IllegalStateException;

    .line 66
    .line 67
    invoke-direct {p1, p0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 68
    .line 69
    .line 70
    throw p1
    :try_end_4
    .catch Ljava/io/IOException; {:try_start_4 .. :try_end_4} :catch_0

    .line 71
    :catch_0
    return-object v0
.end method

.method public final g(Lll/e;)Lkl/k;
    .locals 3

    .line 1
    iget-object v0, p1, Lll/e;->e:Ljava/io/Closeable;

    .line 2
    .line 3
    check-cast v0, Lll/b;

    .line 4
    .line 5
    iget-boolean v1, v0, Lll/b;->e:Z

    .line 6
    .line 7
    if-nez v1, :cond_1

    .line 8
    .line 9
    iget-object v0, v0, Lll/b;->d:Lll/a;

    .line 10
    .line 11
    iget-object v0, v0, Lll/a;->c:Ljava/util/ArrayList;

    .line 12
    .line 13
    const/4 v1, 0x1

    .line 14
    invoke-virtual {v0, v1}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 15
    .line 16
    .line 17
    move-result-object v0

    .line 18
    check-cast v0, Lu01/y;

    .line 19
    .line 20
    invoke-virtual {p0}, Lnl/l;->c()Lu01/k;

    .line 21
    .line 22
    .line 23
    move-result-object v1

    .line 24
    iget-object v2, p0, Lnl/l;->b:Ltl/l;

    .line 25
    .line 26
    iget-object v2, v2, Ltl/l;->i:Ljava/lang/String;

    .line 27
    .line 28
    if-nez v2, :cond_0

    .line 29
    .line 30
    iget-object v2, p0, Lnl/l;->a:Ljava/lang/String;

    .line 31
    .line 32
    :cond_0
    new-instance p0, Lkl/k;

    .line 33
    .line 34
    invoke-direct {p0, v0, v1, v2, p1}, Lkl/k;-><init>(Lu01/y;Lu01/k;Ljava/lang/String;Ljava/io/Closeable;)V

    .line 35
    .line 36
    .line 37
    return-object p0

    .line 38
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 39
    .line 40
    const-string p1, "snapshot is closed"

    .line 41
    .line 42
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 43
    .line 44
    .line 45
    throw p0
.end method

.method public final h(Lll/e;Ld01/k0;Ld01/t0;Lsl/b;)Lll/e;
    .locals 5

    .line 1
    iget-object v0, p0, Lnl/l;->b:Ltl/l;

    .line 2
    .line 3
    iget-object v0, v0, Ltl/l;->n:Ltl/a;

    .line 4
    .line 5
    iget-boolean v0, v0, Ltl/a;->e:Z

    .line 6
    .line 7
    const/4 v1, 0x0

    .line 8
    if-eqz v0, :cond_9

    .line 9
    .line 10
    iget-boolean v0, p0, Lnl/l;->e:Z

    .line 11
    .line 12
    if-eqz v0, :cond_0

    .line 13
    .line 14
    invoke-virtual {p2}, Ld01/k0;->a()Ld01/h;

    .line 15
    .line 16
    .line 17
    move-result-object p2

    .line 18
    iget-boolean p2, p2, Ld01/h;->b:Z

    .line 19
    .line 20
    if-nez p2, :cond_9

    .line 21
    .line 22
    invoke-virtual {p3}, Ld01/t0;->a()Ld01/h;

    .line 23
    .line 24
    .line 25
    move-result-object p2

    .line 26
    iget-boolean p2, p2, Ld01/h;->b:Z

    .line 27
    .line 28
    if-nez p2, :cond_9

    .line 29
    .line 30
    iget-object p2, p3, Ld01/t0;->i:Ld01/y;

    .line 31
    .line 32
    const-string v0, "Vary"

    .line 33
    .line 34
    invoke-virtual {p2, v0}, Ld01/y;->c(Ljava/lang/String;)Ljava/lang/String;

    .line 35
    .line 36
    .line 37
    move-result-object p2

    .line 38
    const-string v0, "*"

    .line 39
    .line 40
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 41
    .line 42
    .line 43
    move-result p2

    .line 44
    if-nez p2, :cond_9

    .line 45
    .line 46
    :cond_0
    const/16 p2, 0x11

    .line 47
    .line 48
    if-eqz p1, :cond_1

    .line 49
    .line 50
    iget-object p1, p1, Lll/e;->e:Ljava/io/Closeable;

    .line 51
    .line 52
    check-cast p1, Lll/b;

    .line 53
    .line 54
    iget-object v0, p1, Lll/b;->f:Lll/d;

    .line 55
    .line 56
    monitor-enter v0

    .line 57
    :try_start_0
    invoke-virtual {p1}, Lll/b;->close()V

    .line 58
    .line 59
    .line 60
    iget-object p1, p1, Lll/b;->d:Lll/a;

    .line 61
    .line 62
    iget-object p1, p1, Lll/a;->a:Ljava/lang/String;

    .line 63
    .line 64
    invoke-virtual {v0, p1}, Lll/d;->b(Ljava/lang/String;)La8/b;

    .line 65
    .line 66
    .line 67
    move-result-object p1
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 68
    monitor-exit v0

    .line 69
    if-eqz p1, :cond_3

    .line 70
    .line 71
    new-instance v0, Lh6/e;

    .line 72
    .line 73
    invoke-direct {v0, p1, p2}, Lh6/e;-><init>(Ljava/lang/Object;I)V

    .line 74
    .line 75
    .line 76
    goto :goto_0

    .line 77
    :catchall_0
    move-exception p0

    .line 78
    monitor-exit v0

    .line 79
    throw p0

    .line 80
    :cond_1
    iget-object p1, p0, Lnl/l;->d:Llx0/q;

    .line 81
    .line 82
    invoke-virtual {p1}, Llx0/q;->getValue()Ljava/lang/Object;

    .line 83
    .line 84
    .line 85
    move-result-object p1

    .line 86
    check-cast p1, Lll/f;

    .line 87
    .line 88
    if-eqz p1, :cond_3

    .line 89
    .line 90
    iget-object v0, p0, Lnl/l;->b:Ltl/l;

    .line 91
    .line 92
    iget-object v0, v0, Ltl/l;->i:Ljava/lang/String;

    .line 93
    .line 94
    if-nez v0, :cond_2

    .line 95
    .line 96
    iget-object v0, p0, Lnl/l;->a:Ljava/lang/String;

    .line 97
    .line 98
    :cond_2
    iget-object p1, p1, Lll/f;->b:Lll/d;

    .line 99
    .line 100
    sget-object v2, Lu01/i;->g:Lu01/i;

    .line 101
    .line 102
    invoke-static {v0}, Lpy/a;->m(Ljava/lang/String;)Lu01/i;

    .line 103
    .line 104
    .line 105
    move-result-object v0

    .line 106
    const-string v2, "SHA-256"

    .line 107
    .line 108
    invoke-virtual {v0, v2}, Lu01/i;->c(Ljava/lang/String;)Lu01/i;

    .line 109
    .line 110
    .line 111
    move-result-object v0

    .line 112
    invoke-virtual {v0}, Lu01/i;->e()Ljava/lang/String;

    .line 113
    .line 114
    .line 115
    move-result-object v0

    .line 116
    invoke-virtual {p1, v0}, Lll/d;->b(Ljava/lang/String;)La8/b;

    .line 117
    .line 118
    .line 119
    move-result-object p1

    .line 120
    if-eqz p1, :cond_3

    .line 121
    .line 122
    new-instance v0, Lh6/e;

    .line 123
    .line 124
    invoke-direct {v0, p1, p2}, Lh6/e;-><init>(Ljava/lang/Object;I)V

    .line 125
    .line 126
    .line 127
    goto :goto_0

    .line 128
    :cond_3
    move-object v0, v1

    .line 129
    :goto_0
    if-nez v0, :cond_4

    .line 130
    .line 131
    goto/16 :goto_a

    .line 132
    .line 133
    :cond_4
    const/4 p1, 0x0

    .line 134
    :try_start_1
    iget p2, p3, Ld01/t0;->g:I

    .line 135
    .line 136
    const/16 v2, 0x130

    .line 137
    .line 138
    if-ne p2, v2, :cond_6

    .line 139
    .line 140
    if-eqz p4, :cond_6

    .line 141
    .line 142
    invoke-virtual {p3}, Ld01/t0;->d()Ld01/s0;

    .line 143
    .line 144
    .line 145
    move-result-object p2

    .line 146
    iget-object p4, p4, Lsl/b;->f:Ld01/y;

    .line 147
    .line 148
    iget-object v2, p3, Ld01/t0;->i:Ld01/y;

    .line 149
    .line 150
    invoke-static {p4, v2}, Lkp/f8;->a(Ld01/y;Ld01/y;)Ld01/y;

    .line 151
    .line 152
    .line 153
    move-result-object p4

    .line 154
    invoke-virtual {p2, p4}, Ld01/s0;->c(Ld01/y;)V

    .line 155
    .line 156
    .line 157
    invoke-virtual {p2}, Ld01/s0;->a()Ld01/t0;

    .line 158
    .line 159
    .line 160
    move-result-object p2

    .line 161
    invoke-virtual {p0}, Lnl/l;->c()Lu01/k;

    .line 162
    .line 163
    .line 164
    move-result-object p0

    .line 165
    iget-object p4, v0, Lh6/e;->e:Ljava/lang/Object;

    .line 166
    .line 167
    check-cast p4, La8/b;

    .line 168
    .line 169
    invoke-virtual {p4, p1}, La8/b;->h(I)Lu01/y;

    .line 170
    .line 171
    .line 172
    move-result-object p4

    .line 173
    invoke-virtual {p0, p4, p1}, Lu01/k;->E(Lu01/y;Z)Lu01/f0;

    .line 174
    .line 175
    .line 176
    move-result-object p0

    .line 177
    invoke-static {p0}, Lu01/b;->b(Lu01/f0;)Lu01/a0;

    .line 178
    .line 179
    .line 180
    move-result-object p0
    :try_end_1
    .catch Ljava/lang/Exception; {:try_start_1 .. :try_end_1} :catch_0
    .catchall {:try_start_1 .. :try_end_1} :catchall_4

    .line 181
    :try_start_2
    new-instance p4, Lsl/b;

    .line 182
    .line 183
    invoke-direct {p4, p2}, Lsl/b;-><init>(Ld01/t0;)V

    .line 184
    .line 185
    .line 186
    invoke-virtual {p4, p0}, Lsl/b;->a(Lu01/a0;)V

    .line 187
    .line 188
    .line 189
    sget-object p2, Llx0/b0;->a:Llx0/b0;
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_2

    .line 190
    .line 191
    :try_start_3
    invoke-virtual {p0}, Lu01/a0;->close()V
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_1

    .line 192
    .line 193
    .line 194
    goto :goto_2

    .line 195
    :catchall_1
    move-exception v1

    .line 196
    goto :goto_2

    .line 197
    :catchall_2
    move-exception p2

    .line 198
    :try_start_4
    invoke-virtual {p0}, Lu01/a0;->close()V
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_3

    .line 199
    .line 200
    .line 201
    goto :goto_1

    .line 202
    :catchall_3
    move-exception p0

    .line 203
    :try_start_5
    invoke-static {p2, p0}, Loa0/b;->a(Ljava/lang/Throwable;Ljava/lang/Throwable;)V

    .line 204
    .line 205
    .line 206
    :goto_1
    move-object v4, v1

    .line 207
    move-object v1, p2

    .line 208
    move-object p2, v4

    .line 209
    :goto_2
    if-nez v1, :cond_5

    .line 210
    .line 211
    invoke-static {p2}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 212
    .line 213
    .line 214
    goto/16 :goto_7

    .line 215
    .line 216
    :catchall_4
    move-exception p0

    .line 217
    goto/16 :goto_9

    .line 218
    .line 219
    :catch_0
    move-exception p0

    .line 220
    goto/16 :goto_8

    .line 221
    .line 222
    :cond_5
    throw v1

    .line 223
    :cond_6
    invoke-virtual {p0}, Lnl/l;->c()Lu01/k;

    .line 224
    .line 225
    .line 226
    move-result-object p2

    .line 227
    iget-object p4, v0, Lh6/e;->e:Ljava/lang/Object;

    .line 228
    .line 229
    check-cast p4, La8/b;

    .line 230
    .line 231
    invoke-virtual {p4, p1}, La8/b;->h(I)Lu01/y;

    .line 232
    .line 233
    .line 234
    move-result-object p4

    .line 235
    invoke-virtual {p2, p4, p1}, Lu01/k;->E(Lu01/y;Z)Lu01/f0;

    .line 236
    .line 237
    .line 238
    move-result-object p2

    .line 239
    invoke-static {p2}, Lu01/b;->b(Lu01/f0;)Lu01/a0;

    .line 240
    .line 241
    .line 242
    move-result-object p2
    :try_end_5
    .catch Ljava/lang/Exception; {:try_start_5 .. :try_end_5} :catch_0
    .catchall {:try_start_5 .. :try_end_5} :catchall_4

    .line 243
    :try_start_6
    new-instance p4, Lsl/b;

    .line 244
    .line 245
    invoke-direct {p4, p3}, Lsl/b;-><init>(Ld01/t0;)V

    .line 246
    .line 247
    .line 248
    invoke-virtual {p4, p2}, Lsl/b;->a(Lu01/a0;)V

    .line 249
    .line 250
    .line 251
    sget-object p4, Llx0/b0;->a:Llx0/b0;
    :try_end_6
    .catchall {:try_start_6 .. :try_end_6} :catchall_6

    .line 252
    .line 253
    :try_start_7
    invoke-virtual {p2}, Lu01/a0;->close()V
    :try_end_7
    .catchall {:try_start_7 .. :try_end_7} :catchall_5

    .line 254
    .line 255
    .line 256
    move-object p2, v1

    .line 257
    goto :goto_4

    .line 258
    :catchall_5
    move-exception p2

    .line 259
    goto :goto_4

    .line 260
    :catchall_6
    move-exception p4

    .line 261
    :try_start_8
    invoke-virtual {p2}, Lu01/a0;->close()V
    :try_end_8
    .catchall {:try_start_8 .. :try_end_8} :catchall_7

    .line 262
    .line 263
    .line 264
    goto :goto_3

    .line 265
    :catchall_7
    move-exception p2

    .line 266
    :try_start_9
    invoke-static {p4, p2}, Loa0/b;->a(Ljava/lang/Throwable;Ljava/lang/Throwable;)V

    .line 267
    .line 268
    .line 269
    :goto_3
    move-object p2, p4

    .line 270
    move-object p4, v1

    .line 271
    :goto_4
    if-nez p2, :cond_8

    .line 272
    .line 273
    invoke-static {p4}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 274
    .line 275
    .line 276
    invoke-virtual {p0}, Lnl/l;->c()Lu01/k;

    .line 277
    .line 278
    .line 279
    move-result-object p0

    .line 280
    iget-object p2, v0, Lh6/e;->e:Ljava/lang/Object;

    .line 281
    .line 282
    check-cast p2, La8/b;

    .line 283
    .line 284
    const/4 p4, 0x1

    .line 285
    invoke-virtual {p2, p4}, La8/b;->h(I)Lu01/y;

    .line 286
    .line 287
    .line 288
    move-result-object p2

    .line 289
    invoke-virtual {p0, p2, p1}, Lu01/k;->E(Lu01/y;Z)Lu01/f0;

    .line 290
    .line 291
    .line 292
    move-result-object p0

    .line 293
    invoke-static {p0}, Lu01/b;->b(Lu01/f0;)Lu01/a0;

    .line 294
    .line 295
    .line 296
    move-result-object p0
    :try_end_9
    .catch Ljava/lang/Exception; {:try_start_9 .. :try_end_9} :catch_0
    .catchall {:try_start_9 .. :try_end_9} :catchall_4

    .line 297
    :try_start_a
    iget-object p2, p3, Ld01/t0;->j:Ld01/v0;

    .line 298
    .line 299
    invoke-static {p2}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 300
    .line 301
    .line 302
    invoke-virtual {p2}, Ld01/v0;->p0()Lu01/h;

    .line 303
    .line 304
    .line 305
    move-result-object p2

    .line 306
    invoke-interface {p2, p0}, Lu01/h;->L(Lu01/g;)J

    .line 307
    .line 308
    .line 309
    move-result-wide v2

    .line 310
    invoke-static {v2, v3}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 311
    .line 312
    .line 313
    move-result-object p2
    :try_end_a
    .catchall {:try_start_a .. :try_end_a} :catchall_9

    .line 314
    :try_start_b
    invoke-virtual {p0}, Lu01/a0;->close()V
    :try_end_b
    .catchall {:try_start_b .. :try_end_b} :catchall_8

    .line 315
    .line 316
    .line 317
    goto :goto_6

    .line 318
    :catchall_8
    move-exception v1

    .line 319
    goto :goto_6

    .line 320
    :catchall_9
    move-exception p2

    .line 321
    :try_start_c
    invoke-virtual {p0}, Lu01/a0;->close()V
    :try_end_c
    .catchall {:try_start_c .. :try_end_c} :catchall_a

    .line 322
    .line 323
    .line 324
    goto :goto_5

    .line 325
    :catchall_a
    move-exception p0

    .line 326
    :try_start_d
    invoke-static {p2, p0}, Loa0/b;->a(Ljava/lang/Throwable;Ljava/lang/Throwable;)V

    .line 327
    .line 328
    .line 329
    :goto_5
    move-object v4, v1

    .line 330
    move-object v1, p2

    .line 331
    move-object p2, v4

    .line 332
    :goto_6
    if-nez v1, :cond_7

    .line 333
    .line 334
    invoke-static {p2}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 335
    .line 336
    .line 337
    :goto_7
    invoke-virtual {v0}, Lh6/e;->v()Lll/e;

    .line 338
    .line 339
    .line 340
    move-result-object p0
    :try_end_d
    .catch Ljava/lang/Exception; {:try_start_d .. :try_end_d} :catch_0
    .catchall {:try_start_d .. :try_end_d} :catchall_4

    .line 341
    invoke-static {p3}, Lxl/c;->a(Ljava/io/Closeable;)V

    .line 342
    .line 343
    .line 344
    return-object p0

    .line 345
    :cond_7
    :try_start_e
    throw v1

    .line 346
    :cond_8
    throw p2
    :try_end_e
    .catch Ljava/lang/Exception; {:try_start_e .. :try_end_e} :catch_0
    .catchall {:try_start_e .. :try_end_e} :catchall_4

    .line 347
    :goto_8
    :try_start_f
    sget-object p2, Lxl/c;->a:[Landroid/graphics/Bitmap$Config;
    :try_end_f
    .catchall {:try_start_f .. :try_end_f} :catchall_4

    .line 348
    .line 349
    :try_start_10
    iget-object p2, v0, Lh6/e;->e:Ljava/lang/Object;

    .line 350
    .line 351
    check-cast p2, La8/b;

    .line 352
    .line 353
    invoke-virtual {p2, p1}, La8/b;->e(Z)V
    :try_end_10
    .catch Ljava/lang/Exception; {:try_start_10 .. :try_end_10} :catch_1
    .catchall {:try_start_10 .. :try_end_10} :catchall_4

    .line 354
    .line 355
    .line 356
    :catch_1
    :try_start_11
    throw p0
    :try_end_11
    .catchall {:try_start_11 .. :try_end_11} :catchall_4

    .line 357
    :goto_9
    invoke-static {p3}, Lxl/c;->a(Ljava/io/Closeable;)V

    .line 358
    .line 359
    .line 360
    throw p0

    .line 361
    :cond_9
    if-eqz p1, :cond_a

    .line 362
    .line 363
    invoke-static {p1}, Lxl/c;->a(Ljava/io/Closeable;)V

    .line 364
    .line 365
    .line 366
    :cond_a
    :goto_a
    return-object v1
.end method
