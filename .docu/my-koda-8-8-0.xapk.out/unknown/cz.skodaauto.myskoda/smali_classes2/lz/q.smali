.class public final Llz/q;
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

.field public final h:Ljr0/f;


# direct methods
.method public constructor <init>(Lkf0/m;Lsf0/a;Ljn0/c;Lwq0/e0;Lkf0/j0;Ljz/m;Lko0/f;Ljr0/f;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Llz/q;->a:Lkf0/m;

    .line 5
    .line 6
    iput-object p2, p0, Llz/q;->b:Lsf0/a;

    .line 7
    .line 8
    iput-object p3, p0, Llz/q;->c:Ljn0/c;

    .line 9
    .line 10
    iput-object p4, p0, Llz/q;->d:Lwq0/e0;

    .line 11
    .line 12
    iput-object p5, p0, Llz/q;->e:Lkf0/j0;

    .line 13
    .line 14
    iput-object p6, p0, Llz/q;->f:Ljz/m;

    .line 15
    .line 16
    iput-object p7, p0, Llz/q;->g:Lko0/f;

    .line 17
    .line 18
    iput-object p8, p0, Llz/q;->h:Ljr0/f;

    .line 19
    .line 20
    return-void
.end method


# virtual methods
.method public final bridge synthetic a(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Lmz/b;

    .line 2
    .line 3
    invoke-virtual {p0, p1, p2}, Llz/q;->b(Lmz/b;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public final b(Lmz/b;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 19

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p2

    .line 4
    .line 5
    instance-of v2, v1, Llz/o;

    .line 6
    .line 7
    if-eqz v2, :cond_0

    .line 8
    .line 9
    move-object v2, v1

    .line 10
    check-cast v2, Llz/o;

    .line 11
    .line 12
    iget v3, v2, Llz/o;->i:I

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
    iput v3, v2, Llz/o;->i:I

    .line 22
    .line 23
    goto :goto_0

    .line 24
    :cond_0
    new-instance v2, Llz/o;

    .line 25
    .line 26
    invoke-direct {v2, v0, v1}, Llz/o;-><init>(Llz/q;Lkotlin/coroutines/Continuation;)V

    .line 27
    .line 28
    .line 29
    :goto_0
    iget-object v1, v2, Llz/o;->g:Ljava/lang/Object;

    .line 30
    .line 31
    sget-object v3, Lqx0/a;->d:Lqx0/a;

    .line 32
    .line 33
    iget v4, v2, Llz/o;->i:I

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
    iget-object v0, v2, Llz/o;->f:Lne0/t;

    .line 54
    .line 55
    invoke-static {v1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 56
    .line 57
    .line 58
    return-object v0

    .line 59
    :cond_1
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 60
    .line 61
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 62
    .line 63
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 64
    .line 65
    .line 66
    throw v0

    .line 67
    :cond_2
    invoke-static {v1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 68
    .line 69
    .line 70
    goto/16 :goto_4

    .line 71
    .line 72
    :cond_3
    iget-object v4, v2, Llz/o;->e:Lss0/k;

    .line 73
    .line 74
    iget-object v7, v2, Llz/o;->d:Lmz/b;

    .line 75
    .line 76
    invoke-static {v1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 77
    .line 78
    .line 79
    move-object v14, v7

    .line 80
    goto/16 :goto_3

    .line 81
    .line 82
    :cond_4
    iget-object v4, v2, Llz/o;->d:Lmz/b;

    .line 83
    .line 84
    invoke-static {v1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 85
    .line 86
    .line 87
    goto :goto_2

    .line 88
    :cond_5
    iget-object v4, v2, Llz/o;->d:Lmz/b;

    .line 89
    .line 90
    invoke-static {v1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 91
    .line 92
    .line 93
    move-object/from16 v18, v4

    .line 94
    .line 95
    move-object v4, v1

    .line 96
    move-object/from16 v1, v18

    .line 97
    .line 98
    goto :goto_1

    .line 99
    :cond_6
    invoke-static {v1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 100
    .line 101
    .line 102
    move-object/from16 v1, p1

    .line 103
    .line 104
    iput-object v1, v2, Llz/o;->d:Lmz/b;

    .line 105
    .line 106
    iput v8, v2, Llz/o;->i:I

    .line 107
    .line 108
    iget-object v4, v0, Llz/q;->a:Lkf0/m;

    .line 109
    .line 110
    invoke-virtual {v4, v2}, Lkf0/m;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 111
    .line 112
    .line 113
    move-result-object v4

    .line 114
    if-ne v4, v3, :cond_7

    .line 115
    .line 116
    goto/16 :goto_5

    .line 117
    .line 118
    :cond_7
    :goto_1
    check-cast v4, Lne0/t;

    .line 119
    .line 120
    new-instance v8, Llz/p;

    .line 121
    .line 122
    const/4 v11, 0x1

    .line 123
    invoke-direct {v8, v0, v10, v11}, Llz/p;-><init>(Llz/q;Lkotlin/coroutines/Continuation;I)V

    .line 124
    .line 125
    .line 126
    iput-object v1, v2, Llz/o;->d:Lmz/b;

    .line 127
    .line 128
    iput v9, v2, Llz/o;->i:I

    .line 129
    .line 130
    invoke-static {v4, v8, v2}, Llp/sf;->b(Lne0/t;Lay0/n;Lrx0/c;)Ljava/lang/Object;

    .line 131
    .line 132
    .line 133
    move-result-object v4

    .line 134
    if-ne v4, v3, :cond_8

    .line 135
    .line 136
    goto/16 :goto_5

    .line 137
    .line 138
    :cond_8
    move-object/from16 v18, v4

    .line 139
    .line 140
    move-object v4, v1

    .line 141
    move-object/from16 v1, v18

    .line 142
    .line 143
    :goto_2
    check-cast v1, Lne0/t;

    .line 144
    .line 145
    instance-of v8, v1, Lne0/c;

    .line 146
    .line 147
    if-eqz v8, :cond_9

    .line 148
    .line 149
    check-cast v1, Lne0/c;

    .line 150
    .line 151
    return-object v1

    .line 152
    :cond_9
    instance-of v8, v1, Lne0/e;

    .line 153
    .line 154
    if-eqz v8, :cond_10

    .line 155
    .line 156
    check-cast v1, Lne0/e;

    .line 157
    .line 158
    iget-object v1, v1, Lne0/e;->a:Ljava/lang/Object;

    .line 159
    .line 160
    check-cast v1, Lss0/k;

    .line 161
    .line 162
    sget-object v8, Lyq0/n;->i:Lyq0/n;

    .line 163
    .line 164
    iput-object v4, v2, Llz/o;->d:Lmz/b;

    .line 165
    .line 166
    iput-object v1, v2, Llz/o;->e:Lss0/k;

    .line 167
    .line 168
    iput v7, v2, Llz/o;->i:I

    .line 169
    .line 170
    iget-object v7, v0, Llz/q;->d:Lwq0/e0;

    .line 171
    .line 172
    invoke-virtual {v7, v8, v2}, Lwq0/e0;->b(Lyq0/n;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 173
    .line 174
    .line 175
    move-result-object v7

    .line 176
    if-ne v7, v3, :cond_a

    .line 177
    .line 178
    goto/16 :goto_5

    .line 179
    .line 180
    :cond_a
    move-object v14, v4

    .line 181
    move-object v4, v1

    .line 182
    move-object v1, v7

    .line 183
    :goto_3
    check-cast v1, Lne0/t;

    .line 184
    .line 185
    instance-of v7, v1, Lne0/c;

    .line 186
    .line 187
    if-eqz v7, :cond_b

    .line 188
    .line 189
    check-cast v1, Lne0/c;

    .line 190
    .line 191
    return-object v1

    .line 192
    :cond_b
    instance-of v7, v1, Lne0/e;

    .line 193
    .line 194
    if-eqz v7, :cond_f

    .line 195
    .line 196
    check-cast v1, Lne0/e;

    .line 197
    .line 198
    iget-object v1, v1, Lne0/e;->a:Ljava/lang/Object;

    .line 199
    .line 200
    check-cast v1, Lyq0/k;

    .line 201
    .line 202
    iget-object v15, v1, Lyq0/k;->a:Ljava/lang/String;

    .line 203
    .line 204
    iget-object v13, v4, Lss0/k;->a:Ljava/lang/String;

    .line 205
    .line 206
    iget-object v12, v0, Llz/q;->f:Ljz/m;

    .line 207
    .line 208
    const-string v1, "$v$c$cz-skodaauto-myskoda-library-vehicle-model-Vin$-vin$0"

    .line 209
    .line 210
    invoke-static {v13, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 211
    .line 212
    .line 213
    const-string v1, "auxiliaryHeating"

    .line 214
    .line 215
    invoke-static {v14, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 216
    .line 217
    .line 218
    const-string v1, "$v$c$cz-skodaauto-myskoda-library-spin-model-Spin$-spin$0"

    .line 219
    .line 220
    invoke-static {v15, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 221
    .line 222
    .line 223
    iget-object v1, v12, Ljz/m;->a:Lxl0/f;

    .line 224
    .line 225
    new-instance v11, Ld40/k;

    .line 226
    .line 227
    const/16 v16, 0x0

    .line 228
    .line 229
    const/16 v17, 0x6

    .line 230
    .line 231
    invoke-direct/range {v11 .. v17}, Ld40/k;-><init>(Ljava/lang/Object;Ljava/lang/String;Ljava/lang/Object;Ljava/lang/String;Lkotlin/coroutines/Continuation;I)V

    .line 232
    .line 233
    .line 234
    invoke-virtual {v1, v11}, Lxl0/f;->c(Lay0/k;)Lyy0/m1;

    .line 235
    .line 236
    .line 237
    move-result-object v1

    .line 238
    new-instance v4, La10/a;

    .line 239
    .line 240
    const/16 v7, 0x1b

    .line 241
    .line 242
    invoke-direct {v4, v0, v10, v7}, La10/a;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 243
    .line 244
    .line 245
    new-instance v7, Lne0/n;

    .line 246
    .line 247
    invoke-direct {v7, v4, v1}, Lne0/n;-><init>(Lay0/n;Lyy0/i;)V

    .line 248
    .line 249
    .line 250
    new-instance v1, Llb0/q0;

    .line 251
    .line 252
    const/4 v4, 0x6

    .line 253
    invoke-direct {v1, v0, v10, v4}, Llb0/q0;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 254
    .line 255
    .line 256
    invoke-static {v1, v7}, Lbb/j0;->e(Lay0/n;Lyy0/i;)Lne0/n;

    .line 257
    .line 258
    .line 259
    move-result-object v1

    .line 260
    iget-object v4, v0, Llz/q;->b:Lsf0/a;

    .line 261
    .line 262
    invoke-static {v1, v4, v10}, Llp/o1;->d(Lyy0/i;Lsf0/a;Ljava/lang/String;)Lam0/i;

    .line 263
    .line 264
    .line 265
    move-result-object v1

    .line 266
    new-instance v4, Llz/p;

    .line 267
    .line 268
    const/4 v7, 0x0

    .line 269
    invoke-direct {v4, v0, v10, v7}, Llz/p;-><init>(Llz/q;Lkotlin/coroutines/Continuation;I)V

    .line 270
    .line 271
    .line 272
    invoke-static {v4, v1}, Llp/ae;->c(Lay0/n;Lyy0/i;)Lyy0/m1;

    .line 273
    .line 274
    .line 275
    move-result-object v1

    .line 276
    iput-object v10, v2, Llz/o;->d:Lmz/b;

    .line 277
    .line 278
    iput-object v10, v2, Llz/o;->e:Lss0/k;

    .line 279
    .line 280
    iput v6, v2, Llz/o;->i:I

    .line 281
    .line 282
    invoke-static {v1, v2}, Lyy0/u;->w(Lyy0/i;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 283
    .line 284
    .line 285
    move-result-object v1

    .line 286
    if-ne v1, v3, :cond_c

    .line 287
    .line 288
    goto :goto_5

    .line 289
    :cond_c
    :goto_4
    check-cast v1, Lne0/t;

    .line 290
    .line 291
    if-eqz v1, :cond_e

    .line 292
    .line 293
    instance-of v4, v1, Lne0/c;

    .line 294
    .line 295
    if-eqz v4, :cond_d

    .line 296
    .line 297
    move-object v4, v1

    .line 298
    check-cast v4, Lne0/c;

    .line 299
    .line 300
    iput-object v10, v2, Llz/o;->d:Lmz/b;

    .line 301
    .line 302
    iput-object v10, v2, Llz/o;->e:Lss0/k;

    .line 303
    .line 304
    iput-object v1, v2, Llz/o;->f:Lne0/t;

    .line 305
    .line 306
    iput v5, v2, Llz/o;->i:I

    .line 307
    .line 308
    iget-object v0, v0, Llz/q;->c:Ljn0/c;

    .line 309
    .line 310
    invoke-virtual {v0, v4, v2}, Ljn0/c;->c(Lne0/c;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 311
    .line 312
    .line 313
    move-result-object v0

    .line 314
    if-ne v0, v3, :cond_d

    .line 315
    .line 316
    :goto_5
    return-object v3

    .line 317
    :cond_d
    return-object v1

    .line 318
    :cond_e
    return-object v10

    .line 319
    :cond_f
    new-instance v0, La8/r0;

    .line 320
    .line 321
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 322
    .line 323
    .line 324
    throw v0

    .line 325
    :cond_10
    new-instance v0, La8/r0;

    .line 326
    .line 327
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 328
    .line 329
    .line 330
    throw v0
.end method
