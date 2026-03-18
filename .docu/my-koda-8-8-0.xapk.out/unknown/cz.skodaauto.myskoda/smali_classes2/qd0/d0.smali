.class public final Lqd0/d0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/c;


# instance fields
.field public final a:Lyb0/l;

.field public final b:Lod0/o0;

.field public final c:Lqd0/z;

.field public final d:Lqd0/h;

.field public final e:Lqd0/n;

.field public final f:Lkf0/o;


# direct methods
.method public constructor <init>(Lyb0/l;Lod0/o0;Lqd0/z;Lqd0/h;Lqd0/n;Lkf0/o;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lqd0/d0;->a:Lyb0/l;

    .line 5
    .line 6
    iput-object p2, p0, Lqd0/d0;->b:Lod0/o0;

    .line 7
    .line 8
    iput-object p3, p0, Lqd0/d0;->c:Lqd0/z;

    .line 9
    .line 10
    iput-object p4, p0, Lqd0/d0;->d:Lqd0/h;

    .line 11
    .line 12
    iput-object p5, p0, Lqd0/d0;->e:Lqd0/n;

    .line 13
    .line 14
    iput-object p6, p0, Lqd0/d0;->f:Lkf0/o;

    .line 15
    .line 16
    return-void
.end method

.method public static final b(Lqd0/d0;Lrd0/l;Ljava/time/OffsetDateTime;Lrx0/c;)Ljava/lang/Object;
    .locals 19

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p3

    .line 4
    .line 5
    iget-object v2, v0, Lqd0/d0;->c:Lqd0/z;

    .line 6
    .line 7
    iget-object v3, v0, Lqd0/d0;->b:Lod0/o0;

    .line 8
    .line 9
    instance-of v4, v1, Lqd0/c0;

    .line 10
    .line 11
    if-eqz v4, :cond_0

    .line 12
    .line 13
    move-object v4, v1

    .line 14
    check-cast v4, Lqd0/c0;

    .line 15
    .line 16
    iget v5, v4, Lqd0/c0;->j:I

    .line 17
    .line 18
    const/high16 v6, -0x80000000

    .line 19
    .line 20
    and-int v7, v5, v6

    .line 21
    .line 22
    if-eqz v7, :cond_0

    .line 23
    .line 24
    sub-int/2addr v5, v6

    .line 25
    iput v5, v4, Lqd0/c0;->j:I

    .line 26
    .line 27
    goto :goto_0

    .line 28
    :cond_0
    new-instance v4, Lqd0/c0;

    .line 29
    .line 30
    invoke-direct {v4, v0, v1}, Lqd0/c0;-><init>(Lqd0/d0;Lrx0/c;)V

    .line 31
    .line 32
    .line 33
    :goto_0
    iget-object v1, v4, Lqd0/c0;->h:Ljava/lang/Object;

    .line 34
    .line 35
    sget-object v5, Lqx0/a;->d:Lqx0/a;

    .line 36
    .line 37
    iget v6, v4, Lqd0/c0;->j:I

    .line 38
    .line 39
    const/4 v7, 0x4

    .line 40
    const/4 v8, 0x3

    .line 41
    const/4 v9, 0x2

    .line 42
    const/4 v10, 0x1

    .line 43
    const/4 v11, 0x0

    .line 44
    if-eqz v6, :cond_5

    .line 45
    .line 46
    if-eq v6, v10, :cond_4

    .line 47
    .line 48
    if-eq v6, v9, :cond_3

    .line 49
    .line 50
    if-eq v6, v8, :cond_2

    .line 51
    .line 52
    if-ne v6, v7, :cond_1

    .line 53
    .line 54
    iget-object v0, v4, Lqd0/c0;->e:Ljava/time/OffsetDateTime;

    .line 55
    .line 56
    invoke-static {v1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 57
    .line 58
    .line 59
    goto/16 :goto_a

    .line 60
    .line 61
    :cond_1
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 62
    .line 63
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 64
    .line 65
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 66
    .line 67
    .line 68
    throw v0

    .line 69
    :cond_2
    iget-object v0, v4, Lqd0/c0;->f:Ljava/lang/String;

    .line 70
    .line 71
    iget-object v6, v4, Lqd0/c0;->e:Ljava/time/OffsetDateTime;

    .line 72
    .line 73
    iget-object v8, v4, Lqd0/c0;->d:Lrd0/l;

    .line 74
    .line 75
    invoke-static {v1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 76
    .line 77
    .line 78
    goto/16 :goto_5

    .line 79
    .line 80
    :cond_3
    iget v0, v4, Lqd0/c0;->g:I

    .line 81
    .line 82
    iget-object v6, v4, Lqd0/c0;->f:Ljava/lang/String;

    .line 83
    .line 84
    iget-object v9, v4, Lqd0/c0;->e:Ljava/time/OffsetDateTime;

    .line 85
    .line 86
    iget-object v10, v4, Lqd0/c0;->d:Lrd0/l;

    .line 87
    .line 88
    invoke-static {v1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 89
    .line 90
    .line 91
    move-object/from16 v18, v10

    .line 92
    .line 93
    move v10, v0

    .line 94
    move-object v0, v6

    .line 95
    move-object v6, v9

    .line 96
    move-object/from16 v9, v18

    .line 97
    .line 98
    goto/16 :goto_4

    .line 99
    .line 100
    :cond_4
    iget-object v0, v4, Lqd0/c0;->e:Ljava/time/OffsetDateTime;

    .line 101
    .line 102
    iget-object v6, v4, Lqd0/c0;->d:Lrd0/l;

    .line 103
    .line 104
    invoke-static {v1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 105
    .line 106
    .line 107
    move-object/from16 v18, v6

    .line 108
    .line 109
    move-object v6, v1

    .line 110
    move-object/from16 v1, v18

    .line 111
    .line 112
    goto :goto_1

    .line 113
    :cond_5
    invoke-static {v1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 114
    .line 115
    .line 116
    iget-object v0, v0, Lqd0/d0;->f:Lkf0/o;

    .line 117
    .line 118
    move-object/from16 v1, p1

    .line 119
    .line 120
    iput-object v1, v4, Lqd0/c0;->d:Lrd0/l;

    .line 121
    .line 122
    move-object/from16 v6, p2

    .line 123
    .line 124
    iput-object v6, v4, Lqd0/c0;->e:Ljava/time/OffsetDateTime;

    .line 125
    .line 126
    iput v10, v4, Lqd0/c0;->j:I

    .line 127
    .line 128
    invoke-virtual {v0, v4}, Lkf0/o;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 129
    .line 130
    .line 131
    move-result-object v0

    .line 132
    if-ne v0, v5, :cond_6

    .line 133
    .line 134
    goto/16 :goto_c

    .line 135
    .line 136
    :cond_6
    move-object/from16 v18, v6

    .line 137
    .line 138
    move-object v6, v0

    .line 139
    move-object/from16 v0, v18

    .line 140
    .line 141
    :goto_1
    instance-of v10, v6, Lne0/e;

    .line 142
    .line 143
    if-eqz v10, :cond_7

    .line 144
    .line 145
    check-cast v6, Lne0/e;

    .line 146
    .line 147
    goto :goto_2

    .line 148
    :cond_7
    move-object v6, v11

    .line 149
    :goto_2
    if-eqz v6, :cond_8

    .line 150
    .line 151
    iget-object v6, v6, Lne0/e;->a:Ljava/lang/Object;

    .line 152
    .line 153
    check-cast v6, Lss0/j0;

    .line 154
    .line 155
    if-eqz v6, :cond_8

    .line 156
    .line 157
    iget-object v6, v6, Lss0/j0;->d:Ljava/lang/String;

    .line 158
    .line 159
    goto :goto_3

    .line 160
    :cond_8
    move-object v6, v11

    .line 161
    :goto_3
    if-eqz v6, :cond_b

    .line 162
    .line 163
    iput-object v1, v4, Lqd0/c0;->d:Lrd0/l;

    .line 164
    .line 165
    iput-object v0, v4, Lqd0/c0;->e:Ljava/time/OffsetDateTime;

    .line 166
    .line 167
    iput-object v6, v4, Lqd0/c0;->f:Ljava/lang/String;

    .line 168
    .line 169
    const/4 v10, 0x0

    .line 170
    iput v10, v4, Lqd0/c0;->g:I

    .line 171
    .line 172
    iput v9, v4, Lqd0/c0;->j:I

    .line 173
    .line 174
    invoke-virtual {v3, v6, v4}, Lod0/o0;->c(Ljava/lang/String;Lrx0/c;)Ljava/lang/Object;

    .line 175
    .line 176
    .line 177
    move-result-object v9

    .line 178
    if-ne v9, v5, :cond_9

    .line 179
    .line 180
    goto/16 :goto_c

    .line 181
    .line 182
    :cond_9
    move-object/from16 v18, v6

    .line 183
    .line 184
    move-object v6, v0

    .line 185
    move-object/from16 v0, v18

    .line 186
    .line 187
    move-object/from16 v18, v9

    .line 188
    .line 189
    move-object v9, v1

    .line 190
    move-object/from16 v1, v18

    .line 191
    .line 192
    :goto_4
    check-cast v1, Lyy0/i;

    .line 193
    .line 194
    iput-object v9, v4, Lqd0/c0;->d:Lrd0/l;

    .line 195
    .line 196
    iput-object v6, v4, Lqd0/c0;->e:Ljava/time/OffsetDateTime;

    .line 197
    .line 198
    iput-object v0, v4, Lqd0/c0;->f:Ljava/lang/String;

    .line 199
    .line 200
    iput v10, v4, Lqd0/c0;->g:I

    .line 201
    .line 202
    iput v8, v4, Lqd0/c0;->j:I

    .line 203
    .line 204
    invoke-static {v1, v4}, Lyy0/u;->u(Lyy0/i;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 205
    .line 206
    .line 207
    move-result-object v1

    .line 208
    if-ne v1, v5, :cond_a

    .line 209
    .line 210
    goto/16 :goto_c

    .line 211
    .line 212
    :cond_a
    move-object v8, v9

    .line 213
    :goto_5
    check-cast v1, Lne0/s;

    .line 214
    .line 215
    move-object v9, v0

    .line 216
    goto :goto_6

    .line 217
    :cond_b
    move-object v8, v1

    .line 218
    move-object v9, v6

    .line 219
    move-object v1, v11

    .line 220
    move-object v6, v0

    .line 221
    :goto_6
    move-object v0, v2

    .line 222
    check-cast v0, Lod0/v;

    .line 223
    .line 224
    iget-object v0, v0, Lod0/v;->f:Ljava/time/OffsetDateTime;

    .line 225
    .line 226
    if-eqz v1, :cond_12

    .line 227
    .line 228
    if-eqz v0, :cond_c

    .line 229
    .line 230
    invoke-virtual {v0, v6}, Ljava/time/OffsetDateTime;->isBefore(Ljava/time/OffsetDateTime;)Z

    .line 231
    .line 232
    .line 233
    move-result v0

    .line 234
    if-eqz v0, :cond_12

    .line 235
    .line 236
    :cond_c
    instance-of v0, v1, Lne0/e;

    .line 237
    .line 238
    if-eqz v0, :cond_e

    .line 239
    .line 240
    :try_start_0
    check-cast v1, Lne0/e;

    .line 241
    .line 242
    iget-object v0, v1, Lne0/e;->a:Ljava/lang/Object;

    .line 243
    .line 244
    check-cast v0, Lrd0/j;

    .line 245
    .line 246
    invoke-static {v0, v8, v6}, Lqd0/d0;->c(Lrd0/j;Lrd0/l;Ljava/time/OffsetDateTime;)Lrd0/j;

    .line 247
    .line 248
    .line 249
    move-result-object v0

    .line 250
    new-instance v1, Lne0/e;

    .line 251
    .line 252
    invoke-direct {v1, v0}, Lne0/e;-><init>(Ljava/lang/Object;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 253
    .line 254
    .line 255
    goto :goto_7

    .line 256
    :catchall_0
    move-exception v0

    .line 257
    invoke-static {v0}, Lps/t1;->a(Ljava/lang/Throwable;)Llx0/n;

    .line 258
    .line 259
    .line 260
    move-result-object v1

    .line 261
    :goto_7
    invoke-static {v1}, Llx0/o;->a(Ljava/lang/Object;)Ljava/lang/Throwable;

    .line 262
    .line 263
    .line 264
    move-result-object v13

    .line 265
    if-nez v13, :cond_d

    .line 266
    .line 267
    goto :goto_8

    .line 268
    :cond_d
    new-instance v12, Lne0/c;

    .line 269
    .line 270
    const/16 v16, 0x0

    .line 271
    .line 272
    const/16 v17, 0x1e

    .line 273
    .line 274
    const/4 v14, 0x0

    .line 275
    const/4 v15, 0x0

    .line 276
    invoke-direct/range {v12 .. v17}, Lne0/c;-><init>(Ljava/lang/Throwable;Lne0/c;Lne0/a;Lne0/b;I)V

    .line 277
    .line 278
    .line 279
    move-object v1, v12

    .line 280
    :goto_8
    check-cast v1, Lne0/s;

    .line 281
    .line 282
    goto :goto_9

    .line 283
    :cond_e
    instance-of v0, v1, Lne0/c;

    .line 284
    .line 285
    if-eqz v0, :cond_f

    .line 286
    .line 287
    goto :goto_9

    .line 288
    :cond_f
    instance-of v0, v1, Lne0/d;

    .line 289
    .line 290
    if-eqz v0, :cond_11

    .line 291
    .line 292
    :goto_9
    iput-object v11, v4, Lqd0/c0;->d:Lrd0/l;

    .line 293
    .line 294
    iput-object v6, v4, Lqd0/c0;->e:Ljava/time/OffsetDateTime;

    .line 295
    .line 296
    iput-object v11, v4, Lqd0/c0;->f:Ljava/lang/String;

    .line 297
    .line 298
    iput v7, v4, Lqd0/c0;->j:I

    .line 299
    .line 300
    invoke-virtual {v3, v9, v1, v4}, Lod0/o0;->d(Ljava/lang/String;Lne0/s;Lrx0/c;)Ljava/lang/Object;

    .line 301
    .line 302
    .line 303
    move-result-object v0

    .line 304
    if-ne v0, v5, :cond_10

    .line 305
    .line 306
    goto :goto_c

    .line 307
    :cond_10
    move-object v0, v6

    .line 308
    :goto_a
    check-cast v2, Lod0/v;

    .line 309
    .line 310
    iput-object v0, v2, Lod0/v;->f:Ljava/time/OffsetDateTime;

    .line 311
    .line 312
    goto :goto_b

    .line 313
    :cond_11
    new-instance v0, La8/r0;

    .line 314
    .line 315
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 316
    .line 317
    .line 318
    throw v0

    .line 319
    :cond_12
    :goto_b
    sget-object v5, Llx0/b0;->a:Llx0/b0;

    .line 320
    .line 321
    :goto_c
    return-object v5
.end method

.method public static c(Lrd0/j;Lrd0/l;Ljava/time/OffsetDateTime;)Lrd0/j;
    .locals 12

    .line 1
    iget-object v0, p0, Lrd0/j;->d:Lrd0/a0;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    if-eqz v0, :cond_0

    .line 5
    .line 6
    iget-object v6, p1, Lrd0/l;->d:Lmy0/c;

    .line 7
    .line 8
    sget-object v3, Lrd0/y;->e:Lrd0/y;

    .line 9
    .line 10
    iget-object v4, v0, Lrd0/a0;->b:Lrd0/z;

    .line 11
    .line 12
    iget-object v5, v0, Lrd0/a0;->c:Lqr0/n;

    .line 13
    .line 14
    iget-object v7, v0, Lrd0/a0;->e:Lqr0/p;

    .line 15
    .line 16
    new-instance v2, Lrd0/a0;

    .line 17
    .line 18
    invoke-direct/range {v2 .. v7}, Lrd0/a0;-><init>(Lrd0/y;Lrd0/z;Lqr0/n;Lmy0/c;Lqr0/p;)V

    .line 19
    .line 20
    .line 21
    move-object v7, v2

    .line 22
    goto :goto_0

    .line 23
    :cond_0
    move-object v7, v1

    .line 24
    :goto_0
    iget-object v0, p0, Lrd0/j;->b:Lrd0/b;

    .line 25
    .line 26
    if-eqz v0, :cond_1

    .line 27
    .line 28
    iget-object v0, p1, Lrd0/l;->b:Lqr0/l;

    .line 29
    .line 30
    iget-object p1, p1, Lrd0/l;->c:Lqr0/d;

    .line 31
    .line 32
    new-instance v1, Lrd0/b;

    .line 33
    .line 34
    invoke-direct {v1, v0, p1}, Lrd0/b;-><init>(Lqr0/l;Lqr0/d;)V

    .line 35
    .line 36
    .line 37
    :cond_1
    move-object v5, v1

    .line 38
    iget-object v4, p0, Lrd0/j;->a:Lrd0/a;

    .line 39
    .line 40
    iget-object v6, p0, Lrd0/j;->c:Lrd0/v;

    .line 41
    .line 42
    iget-object v8, p0, Lrd0/j;->e:Lrd0/i;

    .line 43
    .line 44
    iget-boolean v9, p0, Lrd0/j;->f:Z

    .line 45
    .line 46
    iget-object v10, p0, Lrd0/j;->g:Ljava/util/List;

    .line 47
    .line 48
    new-instance v3, Lrd0/j;

    .line 49
    .line 50
    move-object v11, p2

    .line 51
    invoke-direct/range {v3 .. v11}, Lrd0/j;-><init>(Lrd0/a;Lrd0/b;Lrd0/v;Lrd0/a0;Lrd0/i;ZLjava/util/List;Ljava/time/OffsetDateTime;)V

    .line 52
    .line 53
    .line 54
    return-object v3
.end method


# virtual methods
.method public final a(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 6

    .line 1
    check-cast p1, Llx0/b0;

    .line 2
    .line 3
    new-instance v0, Lyb0/i;

    .line 4
    .line 5
    sget-object v1, Lzb0/d;->e:Lzb0/d;

    .line 6
    .line 7
    const/4 v4, 0x0

    .line 8
    const/16 v5, 0x3c

    .line 9
    .line 10
    const-string v2, "charging"

    .line 11
    .line 12
    const/4 v3, 0x0

    .line 13
    invoke-direct/range {v0 .. v5}, Lyb0/i;-><init>(Lzb0/d;Ljava/lang/String;Ljava/util/Set;Lyb0/h;I)V

    .line 14
    .line 15
    .line 16
    iget-object p1, p0, Lqd0/d0;->a:Lyb0/l;

    .line 17
    .line 18
    invoke-virtual {p1, v0}, Lyb0/l;->a(Lyb0/i;)Lzy0/j;

    .line 19
    .line 20
    .line 21
    move-result-object p1

    .line 22
    new-instance p2, Llb0/y;

    .line 23
    .line 24
    const/16 v0, 0x8

    .line 25
    .line 26
    invoke-direct {p2, v0, p1, p0}, Llb0/y;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 27
    .line 28
    .line 29
    new-instance p1, Lny/f0;

    .line 30
    .line 31
    const/4 v0, 0x0

    .line 32
    const/16 v1, 0x11

    .line 33
    .line 34
    invoke-direct {p1, p0, v0, v1}, Lny/f0;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 35
    .line 36
    .line 37
    new-instance p0, Lne0/n;

    .line 38
    .line 39
    const/4 v0, 0x5

    .line 40
    invoke-direct {p0, p2, p1, v0}, Lne0/n;-><init>(Lyy0/i;Lay0/n;I)V

    .line 41
    .line 42
    .line 43
    return-object p0
.end method
