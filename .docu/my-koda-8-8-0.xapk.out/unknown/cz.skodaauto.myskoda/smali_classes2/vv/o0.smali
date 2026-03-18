.class public abstract Lvv/o0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Ll2/e0;

.field public static final b:J


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    sget-object v0, Lvv/s;->k:Lvv/s;

    .line 2
    .line 3
    new-instance v1, Ll2/e0;

    .line 4
    .line 5
    invoke-direct {v1, v0}, Ll2/e0;-><init>(Lay0/a;)V

    .line 6
    .line 7
    .line 8
    sput-object v1, Lvv/o0;->a:Ll2/e0;

    .line 9
    .line 10
    const/16 v0, 0x8

    .line 11
    .line 12
    invoke-static {v0}, Lgq/b;->c(I)J

    .line 13
    .line 14
    .line 15
    move-result-wide v0

    .line 16
    sput-wide v0, Lvv/o0;->b:J

    .line 17
    .line 18
    return-void
.end method

.method public static final a(Lvv/n0;Lt2/b;Ll2/o;I)V
    .locals 26

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    move/from16 v2, p3

    .line 6
    .line 7
    move-object/from16 v3, p2

    .line 8
    .line 9
    check-cast v3, Ll2/t;

    .line 10
    .line 11
    const v4, -0x6167c1cd

    .line 12
    .line 13
    .line 14
    invoke-virtual {v3, v4}, Ll2/t;->a0(I)Ll2/t;

    .line 15
    .line 16
    .line 17
    sget-object v4, Lvv/m0;->a:Lvv/m0;

    .line 18
    .line 19
    invoke-virtual {v3, v4}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 20
    .line 21
    .line 22
    move-result v5

    .line 23
    if-eqz v5, :cond_0

    .line 24
    .line 25
    const/4 v5, 0x4

    .line 26
    goto :goto_0

    .line 27
    :cond_0
    const/4 v5, 0x2

    .line 28
    :goto_0
    or-int/2addr v5, v2

    .line 29
    invoke-virtual {v3, v0}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 30
    .line 31
    .line 32
    move-result v6

    .line 33
    if-eqz v6, :cond_1

    .line 34
    .line 35
    const/16 v6, 0x20

    .line 36
    .line 37
    goto :goto_1

    .line 38
    :cond_1
    const/16 v6, 0x10

    .line 39
    .line 40
    :goto_1
    or-int/2addr v5, v6

    .line 41
    and-int/lit16 v6, v5, 0x2db

    .line 42
    .line 43
    const/16 v7, 0x92

    .line 44
    .line 45
    if-ne v6, v7, :cond_3

    .line 46
    .line 47
    invoke-virtual {v3}, Ll2/t;->A()Z

    .line 48
    .line 49
    .line 50
    move-result v6

    .line 51
    if-nez v6, :cond_2

    .line 52
    .line 53
    goto :goto_2

    .line 54
    :cond_2
    invoke-virtual {v3}, Ll2/t;->R()V

    .line 55
    .line 56
    .line 57
    goto/16 :goto_4

    .line 58
    .line 59
    :cond_3
    :goto_2
    const/4 v6, 0x0

    .line 60
    if-nez v0, :cond_4

    .line 61
    .line 62
    const v7, 0x7180599d

    .line 63
    .line 64
    .line 65
    invoke-virtual {v3, v7}, Ll2/t;->Z(I)V

    .line 66
    .line 67
    .line 68
    and-int/lit8 v5, v5, 0xe

    .line 69
    .line 70
    or-int/lit8 v5, v5, 0x30

    .line 71
    .line 72
    invoke-static {v5}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 73
    .line 74
    .line 75
    move-result-object v5

    .line 76
    invoke-virtual {v1, v4, v3, v5}, Lt2/b;->invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 77
    .line 78
    .line 79
    invoke-virtual {v3, v6}, Ll2/t;->q(Z)V

    .line 80
    .line 81
    .line 82
    goto/16 :goto_4

    .line 83
    .line 84
    :cond_4
    iget-object v4, v0, Lvv/n0;->h:Lxv/p;

    .line 85
    .line 86
    const v5, 0x718059b7

    .line 87
    .line 88
    .line 89
    invoke-virtual {v3, v5}, Ll2/t;->Z(I)V

    .line 90
    .line 91
    .line 92
    sget-object v5, Lvv/o0;->a:Ll2/e0;

    .line 93
    .line 94
    invoke-virtual {v3, v5}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 95
    .line 96
    .line 97
    move-result-object v7

    .line 98
    check-cast v7, Lvv/n0;

    .line 99
    .line 100
    const-string v8, "<this>"

    .line 101
    .line 102
    invoke-static {v7, v8}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 103
    .line 104
    .line 105
    new-instance v9, Lvv/n0;

    .line 106
    .line 107
    iget-object v8, v0, Lvv/n0;->a:Lt4/o;

    .line 108
    .line 109
    if-nez v8, :cond_5

    .line 110
    .line 111
    iget-object v8, v7, Lvv/n0;->a:Lt4/o;

    .line 112
    .line 113
    :cond_5
    move-object v10, v8

    .line 114
    iget-object v8, v0, Lvv/n0;->b:Lay0/n;

    .line 115
    .line 116
    if-nez v8, :cond_6

    .line 117
    .line 118
    iget-object v8, v7, Lvv/n0;->b:Lay0/n;

    .line 119
    .line 120
    :cond_6
    move-object v11, v8

    .line 121
    iget-object v8, v0, Lvv/n0;->c:Lvv/f0;

    .line 122
    .line 123
    if-nez v8, :cond_7

    .line 124
    .line 125
    iget-object v8, v7, Lvv/n0;->c:Lvv/f0;

    .line 126
    .line 127
    :cond_7
    move-object v12, v8

    .line 128
    iget-object v8, v0, Lvv/n0;->d:Lvv/c;

    .line 129
    .line 130
    if-nez v8, :cond_8

    .line 131
    .line 132
    iget-object v8, v7, Lvv/n0;->d:Lvv/c;

    .line 133
    .line 134
    :cond_8
    move-object v13, v8

    .line 135
    iget-object v8, v0, Lvv/n0;->e:Lvv/k;

    .line 136
    .line 137
    if-nez v8, :cond_9

    .line 138
    .line 139
    iget-object v8, v7, Lvv/n0;->e:Lvv/k;

    .line 140
    .line 141
    :cond_9
    move-object v14, v8

    .line 142
    iget-object v8, v0, Lvv/n0;->f:Lvv/c1;

    .line 143
    .line 144
    if-nez v8, :cond_a

    .line 145
    .line 146
    iget-object v8, v7, Lvv/n0;->f:Lvv/c1;

    .line 147
    .line 148
    :cond_a
    move-object v15, v8

    .line 149
    iget-object v8, v0, Lvv/n0;->g:Lvv/c0;

    .line 150
    .line 151
    if-nez v8, :cond_b

    .line 152
    .line 153
    iget-object v8, v7, Lvv/n0;->g:Lvv/c0;

    .line 154
    .line 155
    :cond_b
    move-object/from16 v16, v8

    .line 156
    .line 157
    iget-object v7, v7, Lvv/n0;->h:Lxv/p;

    .line 158
    .line 159
    if-eqz v7, :cond_15

    .line 160
    .line 161
    if-nez v4, :cond_c

    .line 162
    .line 163
    move-object v4, v7

    .line 164
    goto :goto_3

    .line 165
    :cond_c
    new-instance v17, Lxv/p;

    .line 166
    .line 167
    iget-object v8, v7, Lxv/p;->a:Lg4/g0;

    .line 168
    .line 169
    iget-object v6, v4, Lxv/p;->a:Lg4/g0;

    .line 170
    .line 171
    if-eqz v8, :cond_d

    .line 172
    .line 173
    invoke-virtual {v8, v6}, Lg4/g0;->d(Lg4/g0;)Lg4/g0;

    .line 174
    .line 175
    .line 176
    move-result-object v6

    .line 177
    :cond_d
    move-object/from16 v18, v6

    .line 178
    .line 179
    iget-object v6, v7, Lxv/p;->b:Lg4/g0;

    .line 180
    .line 181
    iget-object v8, v4, Lxv/p;->b:Lg4/g0;

    .line 182
    .line 183
    if-eqz v6, :cond_e

    .line 184
    .line 185
    invoke-virtual {v6, v8}, Lg4/g0;->d(Lg4/g0;)Lg4/g0;

    .line 186
    .line 187
    .line 188
    move-result-object v8

    .line 189
    :cond_e
    move-object/from16 v19, v8

    .line 190
    .line 191
    iget-object v6, v7, Lxv/p;->c:Lg4/g0;

    .line 192
    .line 193
    iget-object v8, v4, Lxv/p;->c:Lg4/g0;

    .line 194
    .line 195
    if-eqz v6, :cond_f

    .line 196
    .line 197
    invoke-virtual {v6, v8}, Lg4/g0;->d(Lg4/g0;)Lg4/g0;

    .line 198
    .line 199
    .line 200
    move-result-object v8

    .line 201
    :cond_f
    move-object/from16 v20, v8

    .line 202
    .line 203
    iget-object v6, v7, Lxv/p;->d:Lg4/g0;

    .line 204
    .line 205
    iget-object v8, v4, Lxv/p;->d:Lg4/g0;

    .line 206
    .line 207
    if-eqz v6, :cond_10

    .line 208
    .line 209
    invoke-virtual {v6, v8}, Lg4/g0;->d(Lg4/g0;)Lg4/g0;

    .line 210
    .line 211
    .line 212
    move-result-object v8

    .line 213
    :cond_10
    move-object/from16 v21, v8

    .line 214
    .line 215
    iget-object v6, v7, Lxv/p;->e:Lg4/g0;

    .line 216
    .line 217
    iget-object v8, v4, Lxv/p;->e:Lg4/g0;

    .line 218
    .line 219
    if-eqz v6, :cond_11

    .line 220
    .line 221
    invoke-virtual {v6, v8}, Lg4/g0;->d(Lg4/g0;)Lg4/g0;

    .line 222
    .line 223
    .line 224
    move-result-object v8

    .line 225
    :cond_11
    move-object/from16 v22, v8

    .line 226
    .line 227
    iget-object v6, v7, Lxv/p;->f:Lg4/g0;

    .line 228
    .line 229
    iget-object v8, v4, Lxv/p;->f:Lg4/g0;

    .line 230
    .line 231
    if-eqz v6, :cond_12

    .line 232
    .line 233
    invoke-virtual {v6, v8}, Lg4/g0;->d(Lg4/g0;)Lg4/g0;

    .line 234
    .line 235
    .line 236
    move-result-object v8

    .line 237
    :cond_12
    move-object/from16 v23, v8

    .line 238
    .line 239
    iget-object v6, v7, Lxv/p;->g:Lg4/g0;

    .line 240
    .line 241
    iget-object v8, v4, Lxv/p;->g:Lg4/g0;

    .line 242
    .line 243
    if-eqz v6, :cond_13

    .line 244
    .line 245
    invoke-virtual {v6, v8}, Lg4/g0;->d(Lg4/g0;)Lg4/g0;

    .line 246
    .line 247
    .line 248
    move-result-object v8

    .line 249
    :cond_13
    move-object/from16 v24, v8

    .line 250
    .line 251
    iget-object v6, v7, Lxv/p;->h:Lg4/g0;

    .line 252
    .line 253
    iget-object v4, v4, Lxv/p;->h:Lg4/g0;

    .line 254
    .line 255
    if-eqz v6, :cond_14

    .line 256
    .line 257
    invoke-virtual {v6, v4}, Lg4/g0;->d(Lg4/g0;)Lg4/g0;

    .line 258
    .line 259
    .line 260
    move-result-object v4

    .line 261
    :cond_14
    move-object/from16 v25, v4

    .line 262
    .line 263
    invoke-direct/range {v17 .. v25}, Lxv/p;-><init>(Lg4/g0;Lg4/g0;Lg4/g0;Lg4/g0;Lg4/g0;Lg4/g0;Lg4/g0;Lg4/g0;)V

    .line 264
    .line 265
    .line 266
    move-object/from16 v4, v17

    .line 267
    .line 268
    :cond_15
    :goto_3
    move-object/from16 v17, v4

    .line 269
    .line 270
    invoke-direct/range {v9 .. v17}, Lvv/n0;-><init>(Lt4/o;Lay0/n;Lvv/f0;Lvv/c;Lvv/k;Lvv/c1;Lvv/c0;Lxv/p;)V

    .line 271
    .line 272
    .line 273
    invoke-virtual {v5, v9}, Ll2/e0;->a(Ljava/lang/Object;)Ll2/t1;

    .line 274
    .line 275
    .line 276
    move-result-object v4

    .line 277
    new-instance v5, Lvv/w;

    .line 278
    .line 279
    const/4 v6, 0x2

    .line 280
    invoke-direct {v5, v1, v6}, Lvv/w;-><init>(Lt2/b;I)V

    .line 281
    .line 282
    .line 283
    const v6, -0x506d8b69

    .line 284
    .line 285
    .line 286
    invoke-static {v6, v3, v5}, Lt2/c;->b(ILl2/o;Llx0/e;)Lt2/b;

    .line 287
    .line 288
    .line 289
    move-result-object v5

    .line 290
    const/16 v6, 0x38

    .line 291
    .line 292
    invoke-static {v4, v5, v3, v6}, Ll2/b;->a(Ll2/t1;Lay0/n;Ll2/o;I)V

    .line 293
    .line 294
    .line 295
    const/4 v4, 0x0

    .line 296
    invoke-virtual {v3, v4}, Ll2/t;->q(Z)V

    .line 297
    .line 298
    .line 299
    :goto_4
    invoke-virtual {v3}, Ll2/t;->s()Ll2/u1;

    .line 300
    .line 301
    .line 302
    move-result-object v3

    .line 303
    if-eqz v3, :cond_16

    .line 304
    .line 305
    new-instance v4, Lkn/i0;

    .line 306
    .line 307
    const/4 v5, 0x4

    .line 308
    invoke-direct {v4, v2, v5, v0, v1}, Lkn/i0;-><init>(IILjava/lang/Object;Ljava/lang/Object;)V

    .line 309
    .line 310
    .line 311
    iput-object v4, v3, Ll2/u1;->d:Lay0/n;

    .line 312
    .line 313
    :cond_16
    return-void
.end method

.method public static final b(Lvv/m0;Ll2/o;)Lvv/n0;
    .locals 1

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    check-cast p1, Ll2/t;

    .line 7
    .line 8
    const p0, 0x4c1fe7b2    # 4.1918152E7f

    .line 9
    .line 10
    .line 11
    invoke-virtual {p1, p0}, Ll2/t;->Z(I)V

    .line 12
    .line 13
    .line 14
    sget-object p0, Lvv/o0;->a:Ll2/e0;

    .line 15
    .line 16
    invoke-virtual {p1, p0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 17
    .line 18
    .line 19
    move-result-object p0

    .line 20
    check-cast p0, Lvv/n0;

    .line 21
    .line 22
    const/4 v0, 0x0

    .line 23
    invoke-virtual {p1, v0}, Ll2/t;->q(Z)V

    .line 24
    .line 25
    .line 26
    return-object p0
.end method

.method public static final c(Lvv/n0;)Lvv/n0;
    .locals 13

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    new-instance v1, Lvv/n0;

    .line 7
    .line 8
    iget-object v0, p0, Lvv/n0;->a:Lt4/o;

    .line 9
    .line 10
    if-eqz v0, :cond_0

    .line 11
    .line 12
    iget-wide v2, v0, Lt4/o;->a:J

    .line 13
    .line 14
    goto :goto_0

    .line 15
    :cond_0
    sget-wide v2, Lvv/o0;->b:J

    .line 16
    .line 17
    :goto_0
    new-instance v0, Lt4/o;

    .line 18
    .line 19
    invoke-direct {v0, v2, v3}, Lt4/o;-><init>(J)V

    .line 20
    .line 21
    .line 22
    iget-object v2, p0, Lvv/n0;->b:Lay0/n;

    .line 23
    .line 24
    if-nez v2, :cond_1

    .line 25
    .line 26
    sget-object v2, Lvv/y;->g:Lvv/y;

    .line 27
    .line 28
    :cond_1
    move-object v3, v2

    .line 29
    iget-object v2, p0, Lvv/n0;->c:Lvv/f0;

    .line 30
    .line 31
    if-nez v2, :cond_2

    .line 32
    .line 33
    sget-object v2, Lvv/f0;->f:Lvv/f0;

    .line 34
    .line 35
    :cond_2
    sget-object v4, Lvv/x;->d:Lvv/b;

    .line 36
    .line 37
    new-instance v4, Lvv/f0;

    .line 38
    .line 39
    iget-object v5, v2, Lvv/f0;->a:Lt4/o;

    .line 40
    .line 41
    if-eqz v5, :cond_3

    .line 42
    .line 43
    iget-wide v5, v5, Lt4/o;->a:J

    .line 44
    .line 45
    goto :goto_1

    .line 46
    :cond_3
    sget-wide v5, Lvv/x;->a:J

    .line 47
    .line 48
    :goto_1
    new-instance v7, Lt4/o;

    .line 49
    .line 50
    invoke-direct {v7, v5, v6}, Lt4/o;-><init>(J)V

    .line 51
    .line 52
    .line 53
    iget-object v5, v2, Lvv/f0;->b:Lt4/o;

    .line 54
    .line 55
    if-eqz v5, :cond_4

    .line 56
    .line 57
    iget-wide v5, v5, Lt4/o;->a:J

    .line 58
    .line 59
    :goto_2
    move-object v8, v7

    .line 60
    goto :goto_3

    .line 61
    :cond_4
    sget-wide v5, Lvv/x;->b:J

    .line 62
    .line 63
    goto :goto_2

    .line 64
    :goto_3
    new-instance v7, Lt4/o;

    .line 65
    .line 66
    invoke-direct {v7, v5, v6}, Lt4/o;-><init>(J)V

    .line 67
    .line 68
    .line 69
    iget-object v5, v2, Lvv/f0;->c:Lt4/o;

    .line 70
    .line 71
    if-eqz v5, :cond_5

    .line 72
    .line 73
    iget-wide v5, v5, Lt4/o;->a:J

    .line 74
    .line 75
    :goto_4
    move-object v9, v8

    .line 76
    goto :goto_5

    .line 77
    :cond_5
    sget-wide v5, Lvv/x;->c:J

    .line 78
    .line 79
    goto :goto_4

    .line 80
    :goto_5
    new-instance v8, Lt4/o;

    .line 81
    .line 82
    invoke-direct {v8, v5, v6}, Lt4/o;-><init>(J)V

    .line 83
    .line 84
    .line 85
    iget-object v5, v2, Lvv/f0;->d:Lay0/k;

    .line 86
    .line 87
    if-nez v5, :cond_6

    .line 88
    .line 89
    sget-object v5, Lvv/x;->d:Lvv/b;

    .line 90
    .line 91
    :cond_6
    iget-object v2, v2, Lvv/f0;->e:Lay0/k;

    .line 92
    .line 93
    if-nez v2, :cond_7

    .line 94
    .line 95
    sget-object v2, Lvv/x;->e:Lvv/b;

    .line 96
    .line 97
    :cond_7
    move-object v10, v2

    .line 98
    move-object v6, v9

    .line 99
    move-object v9, v5

    .line 100
    move-object v5, v4

    .line 101
    invoke-direct/range {v5 .. v10}, Lvv/f0;-><init>(Lt4/o;Lt4/o;Lt4/o;Lay0/k;Lay0/k;)V

    .line 102
    .line 103
    .line 104
    move-object v4, v5

    .line 105
    iget-object v2, p0, Lvv/n0;->d:Lvv/c;

    .line 106
    .line 107
    if-nez v2, :cond_8

    .line 108
    .line 109
    sget-object v2, Lvv/g;->a:Lvv/c;

    .line 110
    .line 111
    :cond_8
    move-object v5, v2

    .line 112
    iget-object v2, p0, Lvv/n0;->e:Lvv/k;

    .line 113
    .line 114
    if-nez v2, :cond_9

    .line 115
    .line 116
    sget-object v2, Lvv/k;->e:Lvv/k;

    .line 117
    .line 118
    :cond_9
    sget-object v6, Lvv/j;->a:Lg4/p0;

    .line 119
    .line 120
    new-instance v6, Lvv/k;

    .line 121
    .line 122
    iget-object v7, v2, Lvv/k;->a:Lg4/p0;

    .line 123
    .line 124
    if-nez v7, :cond_a

    .line 125
    .line 126
    sget-object v7, Lvv/j;->a:Lg4/p0;

    .line 127
    .line 128
    :cond_a
    iget-object v8, v2, Lvv/k;->b:Lx2/s;

    .line 129
    .line 130
    if-nez v8, :cond_b

    .line 131
    .line 132
    sget-object v8, Lvv/j;->c:Lx2/s;

    .line 133
    .line 134
    :cond_b
    iget-object v9, v2, Lvv/k;->c:Lt4/o;

    .line 135
    .line 136
    if-eqz v9, :cond_c

    .line 137
    .line 138
    iget-wide v9, v9, Lt4/o;->a:J

    .line 139
    .line 140
    goto :goto_6

    .line 141
    :cond_c
    sget-wide v9, Lvv/j;->d:J

    .line 142
    .line 143
    :goto_6
    new-instance v11, Lt4/o;

    .line 144
    .line 145
    invoke-direct {v11, v9, v10}, Lt4/o;-><init>(J)V

    .line 146
    .line 147
    .line 148
    iget-object v2, v2, Lvv/k;->d:Ljava/lang/Boolean;

    .line 149
    .line 150
    if-eqz v2, :cond_d

    .line 151
    .line 152
    invoke-virtual {v2}, Ljava/lang/Boolean;->booleanValue()Z

    .line 153
    .line 154
    .line 155
    move-result v2

    .line 156
    goto :goto_7

    .line 157
    :cond_d
    const/4 v2, 0x1

    .line 158
    :goto_7
    invoke-static {v2}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 159
    .line 160
    .line 161
    move-result-object v2

    .line 162
    invoke-direct {v6, v7, v8, v11, v2}, Lvv/k;-><init>(Lg4/p0;Lx2/s;Lt4/o;Ljava/lang/Boolean;)V

    .line 163
    .line 164
    .line 165
    iget-object v2, p0, Lvv/n0;->f:Lvv/c1;

    .line 166
    .line 167
    if-nez v2, :cond_e

    .line 168
    .line 169
    sget-object v2, Lvv/c1;->e:Lvv/c1;

    .line 170
    .line 171
    :cond_e
    sget-object v7, Lvv/z0;->a:Lg4/p0;

    .line 172
    .line 173
    new-instance v7, Lvv/c1;

    .line 174
    .line 175
    iget-object v8, v2, Lvv/c1;->a:Lg4/p0;

    .line 176
    .line 177
    if-nez v8, :cond_f

    .line 178
    .line 179
    sget-object v8, Lvv/z0;->a:Lg4/p0;

    .line 180
    .line 181
    :cond_f
    iget-object v9, v2, Lvv/c1;->b:Lt4/o;

    .line 182
    .line 183
    if-eqz v9, :cond_10

    .line 184
    .line 185
    iget-wide v9, v9, Lt4/o;->a:J

    .line 186
    .line 187
    goto :goto_8

    .line 188
    :cond_10
    sget-wide v9, Lvv/z0;->b:J

    .line 189
    .line 190
    :goto_8
    new-instance v11, Lt4/o;

    .line 191
    .line 192
    invoke-direct {v11, v9, v10}, Lt4/o;-><init>(J)V

    .line 193
    .line 194
    .line 195
    iget-object v9, v2, Lvv/c1;->c:Le3/s;

    .line 196
    .line 197
    if-eqz v9, :cond_11

    .line 198
    .line 199
    iget-wide v9, v9, Le3/s;->a:J

    .line 200
    .line 201
    goto :goto_9

    .line 202
    :cond_11
    sget-wide v9, Lvv/z0;->c:J

    .line 203
    .line 204
    :goto_9
    new-instance v12, Le3/s;

    .line 205
    .line 206
    invoke-direct {v12, v9, v10}, Le3/s;-><init>(J)V

    .line 207
    .line 208
    .line 209
    iget-object v2, v2, Lvv/c1;->d:Ljava/lang/Float;

    .line 210
    .line 211
    if-eqz v2, :cond_12

    .line 212
    .line 213
    invoke-virtual {v2}, Ljava/lang/Float;->floatValue()F

    .line 214
    .line 215
    .line 216
    move-result v2

    .line 217
    goto :goto_a

    .line 218
    :cond_12
    const/high16 v2, 0x3f800000    # 1.0f

    .line 219
    .line 220
    :goto_a
    invoke-static {v2}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 221
    .line 222
    .line 223
    move-result-object v2

    .line 224
    invoke-direct {v7, v8, v11, v12, v2}, Lvv/c1;-><init>(Lg4/p0;Lt4/o;Le3/s;Ljava/lang/Float;)V

    .line 225
    .line 226
    .line 227
    iget-object v2, p0, Lvv/n0;->g:Lvv/c0;

    .line 228
    .line 229
    if-nez v2, :cond_13

    .line 230
    .line 231
    sget-object v2, Lvv/c0;->d:Lvv/c0;

    .line 232
    .line 233
    :cond_13
    sget-object v8, Lvv/b0;->a:Lk1/a1;

    .line 234
    .line 235
    new-instance v8, Lvv/c0;

    .line 236
    .line 237
    iget-object v9, v2, Lvv/c0;->a:Lk1/z0;

    .line 238
    .line 239
    if-nez v9, :cond_14

    .line 240
    .line 241
    sget-object v9, Lvv/b0;->a:Lk1/a1;

    .line 242
    .line 243
    :cond_14
    iget-object v10, v2, Lvv/c0;->b:Lay0/o;

    .line 244
    .line 245
    if-nez v10, :cond_15

    .line 246
    .line 247
    sget-object v10, Lvv/b0;->b:Lvv/a0;

    .line 248
    .line 249
    :cond_15
    iget-object v2, v2, Lvv/c0;->c:Lay0/o;

    .line 250
    .line 251
    if-nez v2, :cond_16

    .line 252
    .line 253
    sget-object v2, Lvv/b0;->c:Lvv/a0;

    .line 254
    .line 255
    :cond_16
    invoke-direct {v8, v9, v10, v2}, Lvv/c0;-><init>(Lk1/z0;Lay0/o;Lay0/o;)V

    .line 256
    .line 257
    .line 258
    iget-object p0, p0, Lvv/n0;->h:Lxv/p;

    .line 259
    .line 260
    if-nez p0, :cond_17

    .line 261
    .line 262
    sget-object p0, Lxv/p;->i:Lxv/p;

    .line 263
    .line 264
    :cond_17
    invoke-virtual {p0}, Lxv/p;->a()Lxv/p;

    .line 265
    .line 266
    .line 267
    move-result-object v9

    .line 268
    move-object v2, v0

    .line 269
    invoke-direct/range {v1 .. v9}, Lvv/n0;-><init>(Lt4/o;Lay0/n;Lvv/f0;Lvv/c;Lvv/k;Lvv/c1;Lvv/c0;Lxv/p;)V

    .line 270
    .line 271
    .line 272
    return-object v1
.end method
