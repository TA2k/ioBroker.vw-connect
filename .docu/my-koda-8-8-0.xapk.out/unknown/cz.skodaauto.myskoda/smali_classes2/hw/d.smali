.class public final Lhw/d;
.super Lrx0/h;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public e:F

.field public f:F

.field public g:I

.field public h:I

.field public synthetic i:Ljava/lang/Object;

.field public final synthetic j:Ld90/m;


# direct methods
.method public constructor <init>(Ld90/m;Lkotlin/coroutines/Continuation;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lhw/d;->j:Ld90/m;

    .line 2
    .line 3
    const/4 p1, 0x2

    .line 4
    invoke-direct {p0, p1, p2}, Lrx0/h;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 5
    .line 6
    .line 7
    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;
    .locals 1

    .line 1
    new-instance v0, Lhw/d;

    .line 2
    .line 3
    iget-object p0, p0, Lhw/d;->j:Ld90/m;

    .line 4
    .line 5
    invoke-direct {v0, p0, p2}, Lhw/d;-><init>(Ld90/m;Lkotlin/coroutines/Continuation;)V

    .line 6
    .line 7
    .line 8
    iput-object p1, v0, Lhw/d;->i:Ljava/lang/Object;

    .line 9
    .line 10
    return-object v0
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Lp3/i0;

    .line 2
    .line 3
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 4
    .line 5
    invoke-virtual {p0, p1, p2}, Lhw/d;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    check-cast p0, Lhw/d;

    .line 10
    .line 11
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 12
    .line 13
    invoke-virtual {p0, p1}, Lhw/d;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 14
    .line 15
    .line 16
    move-result-object p0

    .line 17
    return-object p0
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 17

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 4
    .line 5
    iget v2, v0, Lhw/d;->h:I

    .line 6
    .line 7
    const/4 v3, 0x2

    .line 8
    const/high16 v4, 0x3f800000    # 1.0f

    .line 9
    .line 10
    const/4 v5, 0x0

    .line 11
    const/4 v6, 0x1

    .line 12
    if-eqz v2, :cond_2

    .line 13
    .line 14
    if-eq v2, v6, :cond_1

    .line 15
    .line 16
    if-ne v2, v3, :cond_0

    .line 17
    .line 18
    iget v2, v0, Lhw/d;->f:F

    .line 19
    .line 20
    iget v7, v0, Lhw/d;->g:I

    .line 21
    .line 22
    iget v8, v0, Lhw/d;->e:F

    .line 23
    .line 24
    iget-object v9, v0, Lhw/d;->i:Ljava/lang/Object;

    .line 25
    .line 26
    check-cast v9, Lp3/i0;

    .line 27
    .line 28
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 29
    .line 30
    .line 31
    move-object/from16 v10, p1

    .line 32
    .line 33
    goto :goto_2

    .line 34
    :cond_0
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 35
    .line 36
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 37
    .line 38
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 39
    .line 40
    .line 41
    throw v0

    .line 42
    :cond_1
    iget v2, v0, Lhw/d;->f:F

    .line 43
    .line 44
    iget v7, v0, Lhw/d;->g:I

    .line 45
    .line 46
    iget v8, v0, Lhw/d;->e:F

    .line 47
    .line 48
    iget-object v9, v0, Lhw/d;->i:Ljava/lang/Object;

    .line 49
    .line 50
    check-cast v9, Lp3/i0;

    .line 51
    .line 52
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 53
    .line 54
    .line 55
    goto :goto_0

    .line 56
    :cond_2
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 57
    .line 58
    .line 59
    iget-object v2, v0, Lhw/d;->i:Ljava/lang/Object;

    .line 60
    .line 61
    move-object v9, v2

    .line 62
    check-cast v9, Lp3/i0;

    .line 63
    .line 64
    invoke-virtual {v9}, Lp3/i0;->f()Lw3/h2;

    .line 65
    .line 66
    .line 67
    move-result-object v2

    .line 68
    invoke-interface {v2}, Lw3/h2;->f()F

    .line 69
    .line 70
    .line 71
    move-result v2

    .line 72
    iput-object v9, v0, Lhw/d;->i:Ljava/lang/Object;

    .line 73
    .line 74
    iput v4, v0, Lhw/d;->e:F

    .line 75
    .line 76
    iput v5, v0, Lhw/d;->g:I

    .line 77
    .line 78
    iput v2, v0, Lhw/d;->f:F

    .line 79
    .line 80
    iput v6, v0, Lhw/d;->h:I

    .line 81
    .line 82
    invoke-static {v9, v0, v3}, Lg1/g3;->c(Lp3/i0;Lkotlin/coroutines/Continuation;I)Ljava/lang/Object;

    .line 83
    .line 84
    .line 85
    move-result-object v7

    .line 86
    if-ne v7, v1, :cond_3

    .line 87
    .line 88
    goto :goto_1

    .line 89
    :cond_3
    move v8, v4

    .line 90
    move v7, v5

    .line 91
    :goto_0
    iput-object v9, v0, Lhw/d;->i:Ljava/lang/Object;

    .line 92
    .line 93
    iput v8, v0, Lhw/d;->e:F

    .line 94
    .line 95
    iput v7, v0, Lhw/d;->g:I

    .line 96
    .line 97
    iput v2, v0, Lhw/d;->f:F

    .line 98
    .line 99
    iput v3, v0, Lhw/d;->h:I

    .line 100
    .line 101
    sget-object v10, Lp3/l;->e:Lp3/l;

    .line 102
    .line 103
    invoke-virtual {v9, v10, v0}, Lp3/i0;->b(Lp3/l;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 104
    .line 105
    .line 106
    move-result-object v10

    .line 107
    if-ne v10, v1, :cond_4

    .line 108
    .line 109
    :goto_1
    return-object v1

    .line 110
    :cond_4
    :goto_2
    check-cast v10, Lp3/k;

    .line 111
    .line 112
    iget-object v11, v10, Lp3/k;->a:Ljava/lang/Object;

    .line 113
    .line 114
    move-object v12, v11

    .line 115
    check-cast v12, Ljava/lang/Iterable;

    .line 116
    .line 117
    instance-of v13, v12, Ljava/util/Collection;

    .line 118
    .line 119
    if-eqz v13, :cond_6

    .line 120
    .line 121
    move-object v13, v12

    .line 122
    check-cast v13, Ljava/util/Collection;

    .line 123
    .line 124
    invoke-interface {v13}, Ljava/util/Collection;->isEmpty()Z

    .line 125
    .line 126
    .line 127
    move-result v13

    .line 128
    if-eqz v13, :cond_6

    .line 129
    .line 130
    :cond_5
    move v12, v5

    .line 131
    goto :goto_3

    .line 132
    :cond_6
    invoke-interface {v12}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 133
    .line 134
    .line 135
    move-result-object v12

    .line 136
    :cond_7
    invoke-interface {v12}, Ljava/util/Iterator;->hasNext()Z

    .line 137
    .line 138
    .line 139
    move-result v13

    .line 140
    if-eqz v13, :cond_5

    .line 141
    .line 142
    invoke-interface {v12}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 143
    .line 144
    .line 145
    move-result-object v13

    .line 146
    check-cast v13, Lp3/t;

    .line 147
    .line 148
    invoke-virtual {v13}, Lp3/t;->b()Z

    .line 149
    .line 150
    .line 151
    move-result v13

    .line 152
    if-eqz v13, :cond_7

    .line 153
    .line 154
    move v12, v6

    .line 155
    :goto_3
    if-nez v12, :cond_d

    .line 156
    .line 157
    invoke-static {v10, v6}, Lg1/h3;->e(Lp3/k;Z)F

    .line 158
    .line 159
    .line 160
    move-result v13

    .line 161
    invoke-static {v10, v5}, Lg1/h3;->e(Lp3/k;Z)F

    .line 162
    .line 163
    .line 164
    move-result v14

    .line 165
    const/4 v15, 0x0

    .line 166
    cmpg-float v16, v13, v15

    .line 167
    .line 168
    if-nez v16, :cond_8

    .line 169
    .line 170
    goto :goto_4

    .line 171
    :cond_8
    cmpg-float v15, v14, v15

    .line 172
    .line 173
    if-nez v15, :cond_9

    .line 174
    .line 175
    :goto_4
    move v13, v4

    .line 176
    goto :goto_5

    .line 177
    :cond_9
    div-float/2addr v13, v14

    .line 178
    :goto_5
    if-nez v7, :cond_a

    .line 179
    .line 180
    mul-float/2addr v8, v13

    .line 181
    invoke-static {v10, v5}, Lg1/h3;->e(Lp3/k;Z)F

    .line 182
    .line 183
    .line 184
    move-result v14

    .line 185
    int-to-float v15, v6

    .line 186
    sub-float/2addr v15, v8

    .line 187
    invoke-static {v15}, Ljava/lang/Math;->abs(F)F

    .line 188
    .line 189
    .line 190
    move-result v15

    .line 191
    mul-float/2addr v15, v14

    .line 192
    cmpl-float v14, v15, v2

    .line 193
    .line 194
    if-lez v14, :cond_a

    .line 195
    .line 196
    move v7, v6

    .line 197
    :cond_a
    if-eqz v7, :cond_d

    .line 198
    .line 199
    invoke-static {v10, v5}, Lg1/h3;->d(Lp3/k;Z)J

    .line 200
    .line 201
    .line 202
    move-result-wide v14

    .line 203
    cmpg-float v10, v13, v4

    .line 204
    .line 205
    if-nez v10, :cond_b

    .line 206
    .line 207
    goto :goto_6

    .line 208
    :cond_b
    new-instance v10, Ld3/b;

    .line 209
    .line 210
    invoke-direct {v10, v14, v15}, Ld3/b;-><init>(J)V

    .line 211
    .line 212
    .line 213
    new-instance v14, Ljava/lang/Float;

    .line 214
    .line 215
    invoke-direct {v14, v13}, Ljava/lang/Float;-><init>(F)V

    .line 216
    .line 217
    .line 218
    iget-object v13, v0, Lhw/d;->j:Ld90/m;

    .line 219
    .line 220
    invoke-virtual {v13, v10, v14}, Ld90/m;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 221
    .line 222
    .line 223
    :goto_6
    move-object v10, v11

    .line 224
    check-cast v10, Ljava/lang/Iterable;

    .line 225
    .line 226
    invoke-interface {v10}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 227
    .line 228
    .line 229
    move-result-object v10

    .line 230
    :goto_7
    invoke-interface {v10}, Ljava/util/Iterator;->hasNext()Z

    .line 231
    .line 232
    .line 233
    move-result v13

    .line 234
    if-eqz v13, :cond_d

    .line 235
    .line 236
    invoke-interface {v10}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 237
    .line 238
    .line 239
    move-result-object v13

    .line 240
    check-cast v13, Lp3/t;

    .line 241
    .line 242
    invoke-static {v13, v5}, Lp3/s;->h(Lp3/t;Z)J

    .line 243
    .line 244
    .line 245
    move-result-wide v14

    .line 246
    const-wide/16 v3, 0x0

    .line 247
    .line 248
    invoke-static {v14, v15, v3, v4}, Ld3/b;->c(JJ)Z

    .line 249
    .line 250
    .line 251
    move-result v3

    .line 252
    if-nez v3, :cond_c

    .line 253
    .line 254
    invoke-virtual {v13}, Lp3/t;->a()V

    .line 255
    .line 256
    .line 257
    :cond_c
    const/4 v3, 0x2

    .line 258
    const/high16 v4, 0x3f800000    # 1.0f

    .line 259
    .line 260
    goto :goto_7

    .line 261
    :cond_d
    if-nez v12, :cond_10

    .line 262
    .line 263
    check-cast v11, Ljava/lang/Iterable;

    .line 264
    .line 265
    instance-of v3, v11, Ljava/util/Collection;

    .line 266
    .line 267
    if-eqz v3, :cond_e

    .line 268
    .line 269
    move-object v3, v11

    .line 270
    check-cast v3, Ljava/util/Collection;

    .line 271
    .line 272
    invoke-interface {v3}, Ljava/util/Collection;->isEmpty()Z

    .line 273
    .line 274
    .line 275
    move-result v3

    .line 276
    if-eqz v3, :cond_e

    .line 277
    .line 278
    goto :goto_8

    .line 279
    :cond_e
    invoke-interface {v11}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 280
    .line 281
    .line 282
    move-result-object v3

    .line 283
    :cond_f
    invoke-interface {v3}, Ljava/util/Iterator;->hasNext()Z

    .line 284
    .line 285
    .line 286
    move-result v4

    .line 287
    if-eqz v4, :cond_10

    .line 288
    .line 289
    invoke-interface {v3}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 290
    .line 291
    .line 292
    move-result-object v4

    .line 293
    check-cast v4, Lp3/t;

    .line 294
    .line 295
    iget-boolean v4, v4, Lp3/t;->d:Z

    .line 296
    .line 297
    if-eqz v4, :cond_f

    .line 298
    .line 299
    const/4 v3, 0x2

    .line 300
    const/high16 v4, 0x3f800000    # 1.0f

    .line 301
    .line 302
    goto/16 :goto_0

    .line 303
    .line 304
    :cond_10
    :goto_8
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 305
    .line 306
    return-object v0
.end method
