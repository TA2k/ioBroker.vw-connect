.class public final Li91/k2;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# virtual methods
.method public final a(Lx2/s;Lt2/b;Ll2/o;I)V
    .locals 11

    .line 1
    move-object v0, p3

    .line 2
    check-cast v0, Ll2/t;

    .line 3
    .line 4
    const v1, -0x470ee443

    .line 5
    .line 6
    .line 7
    invoke-virtual {v0, v1}, Ll2/t;->a0(I)Ll2/t;

    .line 8
    .line 9
    .line 10
    or-int/lit8 v1, p4, 0x6

    .line 11
    .line 12
    and-int/lit8 v2, p4, 0x30

    .line 13
    .line 14
    if-nez v2, :cond_1

    .line 15
    .line 16
    invoke-virtual {v0, p2}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 17
    .line 18
    .line 19
    move-result v2

    .line 20
    if-eqz v2, :cond_0

    .line 21
    .line 22
    const/16 v2, 0x20

    .line 23
    .line 24
    goto :goto_0

    .line 25
    :cond_0
    const/16 v2, 0x10

    .line 26
    .line 27
    :goto_0
    or-int/2addr v1, v2

    .line 28
    :cond_1
    and-int/lit8 v2, v1, 0x13

    .line 29
    .line 30
    const/16 v3, 0x12

    .line 31
    .line 32
    const/4 v4, 0x0

    .line 33
    const/4 v6, 0x1

    .line 34
    if-eq v2, v3, :cond_2

    .line 35
    .line 36
    move v2, v6

    .line 37
    goto :goto_1

    .line 38
    :cond_2
    move v2, v4

    .line 39
    :goto_1
    and-int/lit8 v3, v1, 0x1

    .line 40
    .line 41
    invoke-virtual {v0, v3, v2}, Ll2/t;->O(IZ)Z

    .line 42
    .line 43
    .line 44
    move-result v2

    .line 45
    if-eqz v2, :cond_6

    .line 46
    .line 47
    sget-object v2, Lj91/a;->a:Ll2/u2;

    .line 48
    .line 49
    invoke-virtual {v0, v2}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 50
    .line 51
    .line 52
    move-result-object v3

    .line 53
    check-cast v3, Lj91/c;

    .line 54
    .line 55
    iget v3, v3, Lj91/c;->m:F

    .line 56
    .line 57
    invoke-virtual {v0, v2}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 58
    .line 59
    .line 60
    move-result-object v2

    .line 61
    check-cast v2, Lj91/c;

    .line 62
    .line 63
    iget v2, v2, Lj91/c;->m:F

    .line 64
    .line 65
    const/4 v7, 0x0

    .line 66
    const/16 v8, 0xc

    .line 67
    .line 68
    sget-object v9, Lx2/p;->b:Lx2/p;

    .line 69
    .line 70
    invoke-static {v9, v3, v2, v7, v8}, Landroidx/compose/foundation/layout/d;->q(Lx2/s;FFFI)Lx2/s;

    .line 71
    .line 72
    .line 73
    move-result-object v2

    .line 74
    sget-object v3, Lx2/c;->i:Lx2/j;

    .line 75
    .line 76
    invoke-static {v3, v4}, Lk1/n;->d(Lx2/e;Z)Lt3/q0;

    .line 77
    .line 78
    .line 79
    move-result-object v3

    .line 80
    iget-wide v7, v0, Ll2/t;->T:J

    .line 81
    .line 82
    invoke-static {v7, v8}, Ljava/lang/Long;->hashCode(J)I

    .line 83
    .line 84
    .line 85
    move-result v4

    .line 86
    invoke-virtual {v0}, Ll2/t;->m()Ll2/p1;

    .line 87
    .line 88
    .line 89
    move-result-object v7

    .line 90
    invoke-static {v0, v2}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 91
    .line 92
    .line 93
    move-result-object v2

    .line 94
    sget-object v8, Lv3/k;->m1:Lv3/j;

    .line 95
    .line 96
    invoke-virtual {v8}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 97
    .line 98
    .line 99
    sget-object v8, Lv3/j;->b:Lv3/i;

    .line 100
    .line 101
    invoke-virtual {v0}, Ll2/t;->c0()V

    .line 102
    .line 103
    .line 104
    iget-boolean v10, v0, Ll2/t;->S:Z

    .line 105
    .line 106
    if-eqz v10, :cond_3

    .line 107
    .line 108
    invoke-virtual {v0, v8}, Ll2/t;->l(Lay0/a;)V

    .line 109
    .line 110
    .line 111
    goto :goto_2

    .line 112
    :cond_3
    invoke-virtual {v0}, Ll2/t;->m0()V

    .line 113
    .line 114
    .line 115
    :goto_2
    sget-object v8, Lv3/j;->g:Lv3/h;

    .line 116
    .line 117
    invoke-static {v8, v3, v0}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 118
    .line 119
    .line 120
    sget-object v3, Lv3/j;->f:Lv3/h;

    .line 121
    .line 122
    invoke-static {v3, v7, v0}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 123
    .line 124
    .line 125
    sget-object v3, Lv3/j;->j:Lv3/h;

    .line 126
    .line 127
    iget-boolean v7, v0, Ll2/t;->S:Z

    .line 128
    .line 129
    if-nez v7, :cond_4

    .line 130
    .line 131
    invoke-virtual {v0}, Ll2/t;->L()Ljava/lang/Object;

    .line 132
    .line 133
    .line 134
    move-result-object v7

    .line 135
    invoke-static {v4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 136
    .line 137
    .line 138
    move-result-object v8

    .line 139
    invoke-static {v7, v8}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 140
    .line 141
    .line 142
    move-result v7

    .line 143
    if-nez v7, :cond_5

    .line 144
    .line 145
    :cond_4
    invoke-static {v4, v0, v4, v3}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 146
    .line 147
    .line 148
    :cond_5
    sget-object v3, Lv3/j;->d:Lv3/h;

    .line 149
    .line 150
    invoke-static {v3, v2, v0}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 151
    .line 152
    .line 153
    shr-int/lit8 v1, v1, 0x3

    .line 154
    .line 155
    and-int/lit8 v1, v1, 0xe

    .line 156
    .line 157
    invoke-static {v1, p2, v0, v6}, Lia/b;->r(ILt2/b;Ll2/t;Z)V

    .line 158
    .line 159
    .line 160
    move-object v4, v9

    .line 161
    goto :goto_3

    .line 162
    :cond_6
    invoke-virtual {v0}, Ll2/t;->R()V

    .line 163
    .line 164
    .line 165
    move-object v4, p1

    .line 166
    :goto_3
    invoke-virtual {v0}, Ll2/t;->s()Ll2/u1;

    .line 167
    .line 168
    .line 169
    move-result-object v6

    .line 170
    if-eqz v6, :cond_7

    .line 171
    .line 172
    new-instance v0, Li50/j0;

    .line 173
    .line 174
    const/4 v2, 0x2

    .line 175
    move-object v3, p0

    .line 176
    move-object v5, p2

    .line 177
    move v1, p4

    .line 178
    invoke-direct/range {v0 .. v5}, Li50/j0;-><init>(IILjava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)V

    .line 179
    .line 180
    .line 181
    iput-object v0, v6, Ll2/u1;->d:Lay0/n;

    .line 182
    .line 183
    :cond_7
    return-void
.end method

.method public final b(Lay0/a;Lx2/s;ZLi1/l;Le1/s0;Lt2/b;Ll2/o;II)V
    .locals 14

    .line 1
    move/from16 v3, p3

    .line 2
    .line 3
    move-object/from16 v7, p6

    .line 4
    .line 5
    move/from16 v8, p8

    .line 6
    .line 7
    move-object/from16 v9, p7

    .line 8
    .line 9
    check-cast v9, Ll2/t;

    .line 10
    .line 11
    const v0, -0x5d873eaf

    .line 12
    .line 13
    .line 14
    invoke-virtual {v9, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 15
    .line 16
    .line 17
    and-int/lit8 v0, v8, 0x6

    .line 18
    .line 19
    if-nez v0, :cond_1

    .line 20
    .line 21
    invoke-virtual {v9, p1}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 22
    .line 23
    .line 24
    move-result v0

    .line 25
    if-eqz v0, :cond_0

    .line 26
    .line 27
    const/4 v0, 0x4

    .line 28
    goto :goto_0

    .line 29
    :cond_0
    const/4 v0, 0x2

    .line 30
    :goto_0
    or-int/2addr v0, v8

    .line 31
    goto :goto_1

    .line 32
    :cond_1
    move v0, v8

    .line 33
    :goto_1
    or-int/lit8 v0, v0, 0x30

    .line 34
    .line 35
    and-int/lit16 v1, v8, 0x180

    .line 36
    .line 37
    if-nez v1, :cond_3

    .line 38
    .line 39
    invoke-virtual {v9, v3}, Ll2/t;->h(Z)Z

    .line 40
    .line 41
    .line 42
    move-result v1

    .line 43
    if-eqz v1, :cond_2

    .line 44
    .line 45
    const/16 v1, 0x100

    .line 46
    .line 47
    goto :goto_2

    .line 48
    :cond_2
    const/16 v1, 0x80

    .line 49
    .line 50
    :goto_2
    or-int/2addr v0, v1

    .line 51
    :cond_3
    and-int/lit8 v1, p9, 0x8

    .line 52
    .line 53
    if-eqz v1, :cond_5

    .line 54
    .line 55
    or-int/lit16 v0, v0, 0xc00

    .line 56
    .line 57
    :cond_4
    move-object/from16 v2, p4

    .line 58
    .line 59
    goto :goto_4

    .line 60
    :cond_5
    and-int/lit16 v2, v8, 0xc00

    .line 61
    .line 62
    if-nez v2, :cond_4

    .line 63
    .line 64
    move-object/from16 v2, p4

    .line 65
    .line 66
    invoke-virtual {v9, v2}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 67
    .line 68
    .line 69
    move-result v4

    .line 70
    if-eqz v4, :cond_6

    .line 71
    .line 72
    const/16 v4, 0x800

    .line 73
    .line 74
    goto :goto_3

    .line 75
    :cond_6
    const/16 v4, 0x400

    .line 76
    .line 77
    :goto_3
    or-int/2addr v0, v4

    .line 78
    :goto_4
    and-int/lit8 v4, p9, 0x10

    .line 79
    .line 80
    if-eqz v4, :cond_8

    .line 81
    .line 82
    or-int/lit16 v0, v0, 0x6000

    .line 83
    .line 84
    :cond_7
    move-object/from16 v5, p5

    .line 85
    .line 86
    goto :goto_6

    .line 87
    :cond_8
    and-int/lit16 v5, v8, 0x6000

    .line 88
    .line 89
    if-nez v5, :cond_7

    .line 90
    .line 91
    move-object/from16 v5, p5

    .line 92
    .line 93
    invoke-virtual {v9, v5}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 94
    .line 95
    .line 96
    move-result v6

    .line 97
    if-eqz v6, :cond_9

    .line 98
    .line 99
    const/16 v6, 0x4000

    .line 100
    .line 101
    goto :goto_5

    .line 102
    :cond_9
    const/16 v6, 0x2000

    .line 103
    .line 104
    :goto_5
    or-int/2addr v0, v6

    .line 105
    :goto_6
    const/high16 v6, 0x30000

    .line 106
    .line 107
    and-int/2addr v6, v8

    .line 108
    if-nez v6, :cond_b

    .line 109
    .line 110
    invoke-virtual {v9, v7}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 111
    .line 112
    .line 113
    move-result v6

    .line 114
    if-eqz v6, :cond_a

    .line 115
    .line 116
    const/high16 v6, 0x20000

    .line 117
    .line 118
    goto :goto_7

    .line 119
    :cond_a
    const/high16 v6, 0x10000

    .line 120
    .line 121
    :goto_7
    or-int/2addr v0, v6

    .line 122
    :cond_b
    move v10, v0

    .line 123
    const v0, 0x12493

    .line 124
    .line 125
    .line 126
    and-int/2addr v0, v10

    .line 127
    const v6, 0x12492

    .line 128
    .line 129
    .line 130
    const/4 v11, 0x1

    .line 131
    const/4 v12, 0x0

    .line 132
    if-eq v0, v6, :cond_c

    .line 133
    .line 134
    move v0, v11

    .line 135
    goto :goto_8

    .line 136
    :cond_c
    move v0, v12

    .line 137
    :goto_8
    and-int/lit8 v6, v10, 0x1

    .line 138
    .line 139
    invoke-virtual {v9, v6, v0}, Ll2/t;->O(IZ)Z

    .line 140
    .line 141
    .line 142
    move-result v0

    .line 143
    if-eqz v0, :cond_14

    .line 144
    .line 145
    if-eqz v1, :cond_e

    .line 146
    .line 147
    invoke-virtual {v9}, Ll2/t;->L()Ljava/lang/Object;

    .line 148
    .line 149
    .line 150
    move-result-object v0

    .line 151
    sget-object v1, Ll2/n;->a:Ll2/x0;

    .line 152
    .line 153
    if-ne v0, v1, :cond_d

    .line 154
    .line 155
    invoke-static {v9}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->g(Ll2/t;)Li1/l;

    .line 156
    .line 157
    .line 158
    move-result-object v0

    .line 159
    :cond_d
    check-cast v0, Li1/l;

    .line 160
    .line 161
    move-object v1, v0

    .line 162
    goto :goto_9

    .line 163
    :cond_e
    move-object v1, v2

    .line 164
    :goto_9
    if-eqz v4, :cond_f

    .line 165
    .line 166
    const/4 v0, 0x0

    .line 167
    move-object v2, v0

    .line 168
    goto :goto_a

    .line 169
    :cond_f
    move-object v2, v5

    .line 170
    :goto_a
    sget-object v0, Lj91/a;->a:Ll2/u2;

    .line 171
    .line 172
    invoke-virtual {v9, v0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 173
    .line 174
    .line 175
    move-result-object v4

    .line 176
    check-cast v4, Lj91/c;

    .line 177
    .line 178
    iget v4, v4, Lj91/c;->m:F

    .line 179
    .line 180
    invoke-virtual {v9, v0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 181
    .line 182
    .line 183
    move-result-object v0

    .line 184
    check-cast v0, Lj91/c;

    .line 185
    .line 186
    iget v0, v0, Lj91/c;->m:F

    .line 187
    .line 188
    const/4 v5, 0x0

    .line 189
    const/16 v6, 0xc

    .line 190
    .line 191
    sget-object v13, Lx2/p;->b:Lx2/p;

    .line 192
    .line 193
    invoke-static {v13, v4, v0, v5, v6}, Landroidx/compose/foundation/layout/d;->q(Lx2/s;FFFI)Lx2/s;

    .line 194
    .line 195
    .line 196
    move-result-object v0

    .line 197
    if-eqz v3, :cond_10

    .line 198
    .line 199
    new-instance v4, Ld4/i;

    .line 200
    .line 201
    invoke-direct {v4, v12}, Ld4/i;-><init>(I)V

    .line 202
    .line 203
    .line 204
    const/16 v6, 0x8

    .line 205
    .line 206
    move-object v5, p1

    .line 207
    invoke-static/range {v0 .. v6}, Landroidx/compose/foundation/a;->d(Lx2/s;Li1/l;Le1/s0;ZLd4/i;Lay0/a;I)Lx2/s;

    .line 208
    .line 209
    .line 210
    move-result-object v0

    .line 211
    :cond_10
    sget-object v3, Lx2/c;->i:Lx2/j;

    .line 212
    .line 213
    invoke-static {v3, v12}, Lk1/n;->d(Lx2/e;Z)Lt3/q0;

    .line 214
    .line 215
    .line 216
    move-result-object v3

    .line 217
    iget-wide v4, v9, Ll2/t;->T:J

    .line 218
    .line 219
    invoke-static {v4, v5}, Ljava/lang/Long;->hashCode(J)I

    .line 220
    .line 221
    .line 222
    move-result v4

    .line 223
    invoke-virtual {v9}, Ll2/t;->m()Ll2/p1;

    .line 224
    .line 225
    .line 226
    move-result-object v5

    .line 227
    invoke-static {v9, v0}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 228
    .line 229
    .line 230
    move-result-object v0

    .line 231
    sget-object v6, Lv3/k;->m1:Lv3/j;

    .line 232
    .line 233
    invoke-virtual {v6}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 234
    .line 235
    .line 236
    sget-object v6, Lv3/j;->b:Lv3/i;

    .line 237
    .line 238
    invoke-virtual {v9}, Ll2/t;->c0()V

    .line 239
    .line 240
    .line 241
    iget-boolean v12, v9, Ll2/t;->S:Z

    .line 242
    .line 243
    if-eqz v12, :cond_11

    .line 244
    .line 245
    invoke-virtual {v9, v6}, Ll2/t;->l(Lay0/a;)V

    .line 246
    .line 247
    .line 248
    goto :goto_b

    .line 249
    :cond_11
    invoke-virtual {v9}, Ll2/t;->m0()V

    .line 250
    .line 251
    .line 252
    :goto_b
    sget-object v6, Lv3/j;->g:Lv3/h;

    .line 253
    .line 254
    invoke-static {v6, v3, v9}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 255
    .line 256
    .line 257
    sget-object v3, Lv3/j;->f:Lv3/h;

    .line 258
    .line 259
    invoke-static {v3, v5, v9}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 260
    .line 261
    .line 262
    sget-object v3, Lv3/j;->j:Lv3/h;

    .line 263
    .line 264
    iget-boolean v5, v9, Ll2/t;->S:Z

    .line 265
    .line 266
    if-nez v5, :cond_12

    .line 267
    .line 268
    invoke-virtual {v9}, Ll2/t;->L()Ljava/lang/Object;

    .line 269
    .line 270
    .line 271
    move-result-object v5

    .line 272
    invoke-static {v4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 273
    .line 274
    .line 275
    move-result-object v6

    .line 276
    invoke-static {v5, v6}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 277
    .line 278
    .line 279
    move-result v5

    .line 280
    if-nez v5, :cond_13

    .line 281
    .line 282
    :cond_12
    invoke-static {v4, v9, v4, v3}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 283
    .line 284
    .line 285
    :cond_13
    sget-object v3, Lv3/j;->d:Lv3/h;

    .line 286
    .line 287
    invoke-static {v3, v0, v9}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 288
    .line 289
    .line 290
    shr-int/lit8 v0, v10, 0xf

    .line 291
    .line 292
    and-int/lit8 v0, v0, 0xe

    .line 293
    .line 294
    invoke-static {v0, v7, v9, v11}, Lia/b;->r(ILt2/b;Ll2/t;Z)V

    .line 295
    .line 296
    .line 297
    move-object v5, v1

    .line 298
    move-object v6, v2

    .line 299
    move-object v3, v13

    .line 300
    goto :goto_c

    .line 301
    :cond_14
    invoke-virtual {v9}, Ll2/t;->R()V

    .line 302
    .line 303
    .line 304
    move-object/from16 v3, p2

    .line 305
    .line 306
    move-object v6, v5

    .line 307
    move-object v5, v2

    .line 308
    :goto_c
    invoke-virtual {v9}, Ll2/t;->s()Ll2/u1;

    .line 309
    .line 310
    .line 311
    move-result-object v10

    .line 312
    if-eqz v10, :cond_15

    .line 313
    .line 314
    new-instance v0, Lh2/t0;

    .line 315
    .line 316
    move-object v1, p0

    .line 317
    move-object v2, p1

    .line 318
    move/from16 v4, p3

    .line 319
    .line 320
    move/from16 v9, p9

    .line 321
    .line 322
    invoke-direct/range {v0 .. v9}, Lh2/t0;-><init>(Li91/k2;Lay0/a;Lx2/s;ZLi1/l;Le1/s0;Lt2/b;II)V

    .line 323
    .line 324
    .line 325
    iput-object v0, v10, Ll2/u1;->d:Lay0/n;

    .line 326
    .line 327
    :cond_15
    return-void
.end method

.method public final c(Li91/v1;ZJLjava/lang/String;Ll2/o;I)V
    .locals 19

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v2, p1

    .line 4
    .line 5
    move/from16 v5, p2

    .line 6
    .line 7
    move-object/from16 v1, p5

    .line 8
    .line 9
    move/from16 v10, p7

    .line 10
    .line 11
    const-string v3, "metaContent"

    .line 12
    .line 13
    invoke-static {v2, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    move-object/from16 v7, p6

    .line 17
    .line 18
    check-cast v7, Ll2/t;

    .line 19
    .line 20
    const v3, 0x1bfa0b1

    .line 21
    .line 22
    .line 23
    invoke-virtual {v7, v3}, Ll2/t;->a0(I)Ll2/t;

    .line 24
    .line 25
    .line 26
    and-int/lit8 v3, v10, 0x6

    .line 27
    .line 28
    if-nez v3, :cond_2

    .line 29
    .line 30
    and-int/lit8 v3, v10, 0x8

    .line 31
    .line 32
    if-nez v3, :cond_0

    .line 33
    .line 34
    invoke-virtual {v7, v2}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 35
    .line 36
    .line 37
    move-result v3

    .line 38
    goto :goto_0

    .line 39
    :cond_0
    invoke-virtual {v7, v2}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 40
    .line 41
    .line 42
    move-result v3

    .line 43
    :goto_0
    if-eqz v3, :cond_1

    .line 44
    .line 45
    const/4 v3, 0x4

    .line 46
    goto :goto_1

    .line 47
    :cond_1
    const/4 v3, 0x2

    .line 48
    :goto_1
    or-int/2addr v3, v10

    .line 49
    goto :goto_2

    .line 50
    :cond_2
    move v3, v10

    .line 51
    :goto_2
    and-int/lit8 v4, v10, 0x30

    .line 52
    .line 53
    if-nez v4, :cond_4

    .line 54
    .line 55
    invoke-virtual {v7, v5}, Ll2/t;->h(Z)Z

    .line 56
    .line 57
    .line 58
    move-result v4

    .line 59
    if-eqz v4, :cond_3

    .line 60
    .line 61
    const/16 v4, 0x20

    .line 62
    .line 63
    goto :goto_3

    .line 64
    :cond_3
    const/16 v4, 0x10

    .line 65
    .line 66
    :goto_3
    or-int/2addr v3, v4

    .line 67
    :cond_4
    and-int/lit16 v4, v10, 0x180

    .line 68
    .line 69
    move-wide/from16 v11, p3

    .line 70
    .line 71
    if-nez v4, :cond_6

    .line 72
    .line 73
    invoke-virtual {v7, v11, v12}, Ll2/t;->f(J)Z

    .line 74
    .line 75
    .line 76
    move-result v4

    .line 77
    if-eqz v4, :cond_5

    .line 78
    .line 79
    const/16 v4, 0x100

    .line 80
    .line 81
    goto :goto_4

    .line 82
    :cond_5
    const/16 v4, 0x80

    .line 83
    .line 84
    :goto_4
    or-int/2addr v3, v4

    .line 85
    :cond_6
    and-int/lit16 v4, v10, 0xc00

    .line 86
    .line 87
    if-nez v4, :cond_8

    .line 88
    .line 89
    invoke-virtual {v7, v1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 90
    .line 91
    .line 92
    move-result v4

    .line 93
    if-eqz v4, :cond_7

    .line 94
    .line 95
    const/16 v4, 0x800

    .line 96
    .line 97
    goto :goto_5

    .line 98
    :cond_7
    const/16 v4, 0x400

    .line 99
    .line 100
    :goto_5
    or-int/2addr v3, v4

    .line 101
    :cond_8
    and-int/lit16 v4, v10, 0x6000

    .line 102
    .line 103
    if-nez v4, :cond_a

    .line 104
    .line 105
    invoke-virtual {v7, v0}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 106
    .line 107
    .line 108
    move-result v4

    .line 109
    if-eqz v4, :cond_9

    .line 110
    .line 111
    const/16 v4, 0x4000

    .line 112
    .line 113
    goto :goto_6

    .line 114
    :cond_9
    const/16 v4, 0x2000

    .line 115
    .line 116
    :goto_6
    or-int/2addr v3, v4

    .line 117
    :cond_a
    move v9, v3

    .line 118
    and-int/lit16 v3, v9, 0x2493

    .line 119
    .line 120
    const/16 v4, 0x2492

    .line 121
    .line 122
    const/4 v14, 0x0

    .line 123
    if-eq v3, v4, :cond_b

    .line 124
    .line 125
    const/4 v3, 0x1

    .line 126
    goto :goto_7

    .line 127
    :cond_b
    move v3, v14

    .line 128
    :goto_7
    and-int/lit8 v4, v9, 0x1

    .line 129
    .line 130
    invoke-virtual {v7, v4, v3}, Ll2/t;->O(IZ)Z

    .line 131
    .line 132
    .line 133
    move-result v3

    .line 134
    if-eqz v3, :cond_20

    .line 135
    .line 136
    sget-object v3, Lx2/c;->i:Lx2/j;

    .line 137
    .line 138
    sget-object v4, Lx2/p;->b:Lx2/p;

    .line 139
    .line 140
    const/4 v15, 0x0

    .line 141
    const/4 v6, 0x3

    .line 142
    invoke-static {v4, v15, v6}, Landroidx/compose/foundation/layout/d;->w(Lx2/s;Lx2/h;I)Lx2/s;

    .line 143
    .line 144
    .line 145
    move-result-object v8

    .line 146
    invoke-static {v3, v14}, Lk1/n;->d(Lx2/e;Z)Lt3/q0;

    .line 147
    .line 148
    .line 149
    move-result-object v3

    .line 150
    iget-wide v13, v7, Ll2/t;->T:J

    .line 151
    .line 152
    invoke-static {v13, v14}, Ljava/lang/Long;->hashCode(J)I

    .line 153
    .line 154
    .line 155
    move-result v13

    .line 156
    invoke-virtual {v7}, Ll2/t;->m()Ll2/p1;

    .line 157
    .line 158
    .line 159
    move-result-object v14

    .line 160
    invoke-static {v7, v8}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 161
    .line 162
    .line 163
    move-result-object v8

    .line 164
    sget-object v16, Lv3/k;->m1:Lv3/j;

    .line 165
    .line 166
    invoke-virtual/range {v16 .. v16}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 167
    .line 168
    .line 169
    move/from16 v16, v6

    .line 170
    .line 171
    sget-object v6, Lv3/j;->b:Lv3/i;

    .line 172
    .line 173
    invoke-virtual {v7}, Ll2/t;->c0()V

    .line 174
    .line 175
    .line 176
    iget-boolean v15, v7, Ll2/t;->S:Z

    .line 177
    .line 178
    if-eqz v15, :cond_c

    .line 179
    .line 180
    invoke-virtual {v7, v6}, Ll2/t;->l(Lay0/a;)V

    .line 181
    .line 182
    .line 183
    goto :goto_8

    .line 184
    :cond_c
    invoke-virtual {v7}, Ll2/t;->m0()V

    .line 185
    .line 186
    .line 187
    :goto_8
    sget-object v6, Lv3/j;->g:Lv3/h;

    .line 188
    .line 189
    invoke-static {v6, v3, v7}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 190
    .line 191
    .line 192
    sget-object v3, Lv3/j;->f:Lv3/h;

    .line 193
    .line 194
    invoke-static {v3, v14, v7}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 195
    .line 196
    .line 197
    sget-object v3, Lv3/j;->j:Lv3/h;

    .line 198
    .line 199
    iget-boolean v6, v7, Ll2/t;->S:Z

    .line 200
    .line 201
    if-nez v6, :cond_d

    .line 202
    .line 203
    invoke-virtual {v7}, Ll2/t;->L()Ljava/lang/Object;

    .line 204
    .line 205
    .line 206
    move-result-object v6

    .line 207
    invoke-static {v13}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 208
    .line 209
    .line 210
    move-result-object v14

    .line 211
    invoke-static {v6, v14}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 212
    .line 213
    .line 214
    move-result v6

    .line 215
    if-nez v6, :cond_e

    .line 216
    .line 217
    :cond_d
    invoke-static {v13, v7, v13, v3}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 218
    .line 219
    .line 220
    :cond_e
    sget-object v3, Lv3/j;->d:Lv3/h;

    .line 221
    .line 222
    invoke-static {v3, v8, v7}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 223
    .line 224
    .line 225
    if-eqz v5, :cond_f

    .line 226
    .line 227
    invoke-interface {v2}, Li91/v1;->a()Lay0/a;

    .line 228
    .line 229
    .line 230
    move-result-object v3

    .line 231
    if-eqz v3, :cond_f

    .line 232
    .line 233
    const/4 v3, 0x1

    .line 234
    goto :goto_9

    .line 235
    :cond_f
    const/4 v3, 0x0

    .line 236
    :goto_9
    invoke-interface {v2}, Li91/v1;->a()Lay0/a;

    .line 237
    .line 238
    .line 239
    move-result-object v6

    .line 240
    sget-object v8, Ll2/n;->a:Ll2/x0;

    .line 241
    .line 242
    if-nez v6, :cond_11

    .line 243
    .line 244
    const v6, -0x3ad5a22b

    .line 245
    .line 246
    .line 247
    invoke-virtual {v7, v6}, Ll2/t;->Y(I)V

    .line 248
    .line 249
    .line 250
    invoke-virtual {v7}, Ll2/t;->L()Ljava/lang/Object;

    .line 251
    .line 252
    .line 253
    move-result-object v6

    .line 254
    if-ne v6, v8, :cond_10

    .line 255
    .line 256
    new-instance v6, Lz81/g;

    .line 257
    .line 258
    const/4 v13, 0x2

    .line 259
    invoke-direct {v6, v13}, Lz81/g;-><init>(I)V

    .line 260
    .line 261
    .line 262
    invoke-virtual {v7, v6}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 263
    .line 264
    .line 265
    :cond_10
    check-cast v6, Lay0/a;

    .line 266
    .line 267
    const/4 v13, 0x0

    .line 268
    :goto_a
    invoke-virtual {v7, v13}, Ll2/t;->q(Z)V

    .line 269
    .line 270
    .line 271
    goto :goto_b

    .line 272
    :cond_11
    const/4 v13, 0x0

    .line 273
    const v14, 0x79f91904

    .line 274
    .line 275
    .line 276
    invoke-virtual {v7, v14}, Ll2/t;->Y(I)V

    .line 277
    .line 278
    .line 279
    goto :goto_a

    .line 280
    :goto_b
    instance-of v13, v2, Li91/y1;

    .line 281
    .line 282
    if-eqz v13, :cond_12

    .line 283
    .line 284
    const v3, -0x3ad3f921

    .line 285
    .line 286
    .line 287
    invoke-virtual {v7, v3}, Ll2/t;->Y(I)V

    .line 288
    .line 289
    .line 290
    move-object v3, v2

    .line 291
    check-cast v3, Li91/y1;

    .line 292
    .line 293
    iget-object v6, v3, Li91/y1;->c:Ljava/lang/String;

    .line 294
    .line 295
    const-string v8, "list_item_switch"

    .line 296
    .line 297
    invoke-static {v6, v1, v8}, Li91/z3;->e(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 298
    .line 299
    .line 300
    move-result-object v6

    .line 301
    invoke-static {v4, v6}, Landroidx/compose/ui/platform/a;->a(Lx2/s;Ljava/lang/String;)Lx2/s;

    .line 302
    .line 303
    .line 304
    move-result-object v4

    .line 305
    iget-boolean v6, v3, Li91/y1;->a:Z

    .line 306
    .line 307
    iget-object v3, v3, Li91/y1;->b:Lay0/k;

    .line 308
    .line 309
    shl-int/lit8 v8, v9, 0x3

    .line 310
    .line 311
    and-int/lit16 v8, v8, 0x380

    .line 312
    .line 313
    const/4 v9, 0x0

    .line 314
    move/from16 v18, v6

    .line 315
    .line 316
    move-object v6, v3

    .line 317
    move/from16 v3, v18

    .line 318
    .line 319
    invoke-static/range {v3 .. v9}, Li91/y3;->b(ZLx2/s;ZLay0/k;Ll2/o;II)V

    .line 320
    .line 321
    .line 322
    const/4 v13, 0x0

    .line 323
    invoke-virtual {v7, v13}, Ll2/t;->q(Z)V

    .line 324
    .line 325
    .line 326
    move-object v13, v1

    .line 327
    move-object v15, v2

    .line 328
    :goto_c
    const/4 v0, 0x1

    .line 329
    goto/16 :goto_10

    .line 330
    .line 331
    :cond_12
    instance-of v5, v2, Li91/w1;

    .line 332
    .line 333
    const v13, 0x30c00

    .line 334
    .line 335
    .line 336
    const/high16 v14, 0x380000

    .line 337
    .line 338
    if-eqz v5, :cond_14

    .line 339
    .line 340
    const v4, -0x3acb2b55

    .line 341
    .line 342
    .line 343
    invoke-virtual {v7, v4}, Ll2/t;->Y(I)V

    .line 344
    .line 345
    .line 346
    invoke-virtual {v7}, Ll2/t;->L()Ljava/lang/Object;

    .line 347
    .line 348
    .line 349
    move-result-object v4

    .line 350
    if-ne v4, v8, :cond_13

    .line 351
    .line 352
    invoke-static {v7}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->g(Ll2/t;)Li1/l;

    .line 353
    .line 354
    .line 355
    move-result-object v4

    .line 356
    :cond_13
    check-cast v4, Li1/l;

    .line 357
    .line 358
    new-instance v1, Li91/e2;

    .line 359
    .line 360
    move-object v5, v6

    .line 361
    move-object v6, v4

    .line 362
    move-object v4, v5

    .line 363
    move v5, v3

    .line 364
    move-object/from16 v3, p5

    .line 365
    .line 366
    invoke-direct/range {v1 .. v6}, Li91/e2;-><init>(Li91/v1;Ljava/lang/String;Lay0/a;ZLi1/l;)V

    .line 367
    .line 368
    .line 369
    move-object v15, v2

    .line 370
    move v3, v5

    .line 371
    move-object v2, v1

    .line 372
    move-object v1, v4

    .line 373
    move-object v4, v6

    .line 374
    const v5, 0x328683a6

    .line 375
    .line 376
    .line 377
    invoke-static {v5, v7, v2}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 378
    .line 379
    .line 380
    move-result-object v6

    .line 381
    shl-int/lit8 v2, v9, 0x6

    .line 382
    .line 383
    and-int/2addr v2, v14

    .line 384
    or-int v8, v2, v13

    .line 385
    .line 386
    const/16 v9, 0x12

    .line 387
    .line 388
    const/4 v2, 0x0

    .line 389
    const/4 v5, 0x0

    .line 390
    invoke-virtual/range {v0 .. v9}, Li91/k2;->b(Lay0/a;Lx2/s;ZLi1/l;Le1/s0;Lt2/b;Ll2/o;II)V

    .line 391
    .line 392
    .line 393
    const/4 v13, 0x0

    .line 394
    invoke-virtual {v7, v13}, Ll2/t;->q(Z)V

    .line 395
    .line 396
    .line 397
    move-object/from16 v13, p5

    .line 398
    .line 399
    goto :goto_c

    .line 400
    :cond_14
    move-object v15, v6

    .line 401
    move-object v6, v1

    .line 402
    move-object v1, v15

    .line 403
    move-object v15, v2

    .line 404
    instance-of v0, v15, Li91/o1;

    .line 405
    .line 406
    if-eqz v0, :cond_17

    .line 407
    .line 408
    const v0, -0x3abc0456

    .line 409
    .line 410
    .line 411
    invoke-virtual {v7, v0}, Ll2/t;->Y(I)V

    .line 412
    .line 413
    .line 414
    invoke-virtual {v7}, Ll2/t;->L()Ljava/lang/Object;

    .line 415
    .line 416
    .line 417
    move-result-object v0

    .line 418
    if-ne v0, v8, :cond_15

    .line 419
    .line 420
    invoke-static {v7}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->g(Ll2/t;)Li1/l;

    .line 421
    .line 422
    .line 423
    move-result-object v0

    .line 424
    :cond_15
    move-object v4, v0

    .line 425
    check-cast v4, Li1/l;

    .line 426
    .line 427
    move-object v0, v15

    .line 428
    check-cast v0, Li91/o1;

    .line 429
    .line 430
    if-nez v6, :cond_16

    .line 431
    .line 432
    const-string v0, "list_item_check_box"

    .line 433
    .line 434
    goto :goto_d

    .line 435
    :cond_16
    const-string v0, "_list_item_check_box"

    .line 436
    .line 437
    invoke-virtual {v6, v0}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 438
    .line 439
    .line 440
    move-result-object v0

    .line 441
    :goto_d
    new-instance v2, Li91/e2;

    .line 442
    .line 443
    move-object v5, v4

    .line 444
    move v4, v3

    .line 445
    move-object v3, v1

    .line 446
    move-object v1, v0

    .line 447
    move-object v0, v2

    .line 448
    move-object v2, v15

    .line 449
    invoke-direct/range {v0 .. v5}, Li91/e2;-><init>(Ljava/lang/String;Li91/v1;Lay0/a;ZLi1/l;)V

    .line 450
    .line 451
    .line 452
    move-object v1, v3

    .line 453
    move v3, v4

    .line 454
    move-object v4, v5

    .line 455
    const v2, 0x6e8aef67

    .line 456
    .line 457
    .line 458
    invoke-static {v2, v7, v0}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 459
    .line 460
    .line 461
    move-result-object v0

    .line 462
    shl-int/lit8 v2, v9, 0x6

    .line 463
    .line 464
    and-int/2addr v2, v14

    .line 465
    or-int v8, v2, v13

    .line 466
    .line 467
    const/16 v9, 0x12

    .line 468
    .line 469
    const/4 v2, 0x0

    .line 470
    const/4 v5, 0x0

    .line 471
    move-object v13, v6

    .line 472
    move-object v6, v0

    .line 473
    move-object/from16 v0, p0

    .line 474
    .line 475
    invoke-virtual/range {v0 .. v9}, Li91/k2;->b(Lay0/a;Lx2/s;ZLi1/l;Le1/s0;Lt2/b;Ll2/o;II)V

    .line 476
    .line 477
    .line 478
    const/4 v0, 0x0

    .line 479
    invoke-virtual {v7, v0}, Ll2/t;->q(Z)V

    .line 480
    .line 481
    .line 482
    goto/16 :goto_c

    .line 483
    .line 484
    :cond_17
    move-object/from16 v16, v1

    .line 485
    .line 486
    move-object v13, v6

    .line 487
    move v6, v3

    .line 488
    instance-of v0, v15, Li91/n1;

    .line 489
    .line 490
    if-eqz v0, :cond_19

    .line 491
    .line 492
    const v0, -0x3aad1641

    .line 493
    .line 494
    .line 495
    invoke-virtual {v7, v0}, Ll2/t;->Y(I)V

    .line 496
    .line 497
    .line 498
    move-object v0, v15

    .line 499
    check-cast v0, Li91/n1;

    .line 500
    .line 501
    const-string v1, "list_item_badge"

    .line 502
    .line 503
    const/4 v2, 0x0

    .line 504
    invoke-static {v2, v13, v1}, Li91/z3;->e(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 505
    .line 506
    .line 507
    move-result-object v1

    .line 508
    invoke-static {v4, v1}, Landroidx/compose/ui/platform/a;->a(Lx2/s;Ljava/lang/String;)Lx2/s;

    .line 509
    .line 510
    .line 511
    move-result-object v1

    .line 512
    iget-object v0, v0, Li91/n1;->a:Ljava/lang/String;

    .line 513
    .line 514
    if-eqz p2, :cond_18

    .line 515
    .line 516
    sget-object v2, Li91/e1;->d:Li91/e1;

    .line 517
    .line 518
    :goto_e
    const/4 v3, 0x0

    .line 519
    goto :goto_f

    .line 520
    :cond_18
    sget-object v2, Li91/e1;->e:Li91/e1;

    .line 521
    .line 522
    goto :goto_e

    .line 523
    :goto_f
    invoke-static {v0, v2, v1, v7, v3}, Li91/j0;->f(Ljava/lang/String;Li91/e1;Lx2/s;Ll2/o;I)V

    .line 524
    .line 525
    .line 526
    invoke-virtual {v7, v3}, Ll2/t;->q(Z)V

    .line 527
    .line 528
    .line 529
    goto/16 :goto_c

    .line 530
    .line 531
    :cond_19
    instance-of v0, v15, Li91/p1;

    .line 532
    .line 533
    const-string v1, "list_item_right_icon"

    .line 534
    .line 535
    const/high16 v17, 0x30000

    .line 536
    .line 537
    if-eqz v0, :cond_1a

    .line 538
    .line 539
    const v0, -0x3aa3fa98

    .line 540
    .line 541
    .line 542
    invoke-virtual {v7, v0}, Ll2/t;->Y(I)V

    .line 543
    .line 544
    .line 545
    move-object v0, v15

    .line 546
    check-cast v0, Li91/p1;

    .line 547
    .line 548
    const/4 v2, 0x0

    .line 549
    invoke-static {v2, v13, v1}, Li91/z3;->e(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 550
    .line 551
    .line 552
    move-result-object v1

    .line 553
    new-instance v8, Li91/j2;

    .line 554
    .line 555
    sget-object v0, Lj91/h;->a:Ll2/u2;

    .line 556
    .line 557
    invoke-virtual {v7, v0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 558
    .line 559
    .line 560
    move-result-object v0

    .line 561
    check-cast v0, Lj91/e;

    .line 562
    .line 563
    invoke-virtual {v0}, Lj91/e;->p()J

    .line 564
    .line 565
    .line 566
    move-result-wide v2

    .line 567
    invoke-direct {v8, v2, v3}, Li91/j2;-><init>(J)V

    .line 568
    .line 569
    .line 570
    new-instance v0, Li91/f2;

    .line 571
    .line 572
    const/4 v5, 0x0

    .line 573
    move-wide v3, v11

    .line 574
    move-object v2, v15

    .line 575
    invoke-direct/range {v0 .. v5}, Li91/f2;-><init>(Ljava/lang/String;Li91/v1;JI)V

    .line 576
    .line 577
    .line 578
    const v1, -0x196c3917

    .line 579
    .line 580
    .line 581
    invoke-static {v1, v7, v0}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 582
    .line 583
    .line 584
    move-result-object v0

    .line 585
    shl-int/lit8 v1, v9, 0x6

    .line 586
    .line 587
    and-int/2addr v1, v14

    .line 588
    or-int v1, v1, v17

    .line 589
    .line 590
    const/16 v9, 0xa

    .line 591
    .line 592
    const/4 v2, 0x0

    .line 593
    const/4 v4, 0x0

    .line 594
    move v3, v6

    .line 595
    move-object v5, v8

    .line 596
    move-object v6, v0

    .line 597
    move v8, v1

    .line 598
    move-object/from16 v1, v16

    .line 599
    .line 600
    move-object/from16 v0, p0

    .line 601
    .line 602
    invoke-virtual/range {v0 .. v9}, Li91/k2;->b(Lay0/a;Lx2/s;ZLi1/l;Le1/s0;Lt2/b;Ll2/o;II)V

    .line 603
    .line 604
    .line 605
    move-object v11, v0

    .line 606
    move-object v12, v7

    .line 607
    const/4 v0, 0x0

    .line 608
    invoke-virtual {v12, v0}, Ll2/t;->q(Z)V

    .line 609
    .line 610
    .line 611
    goto/16 :goto_c

    .line 612
    .line 613
    :cond_1a
    move-object/from16 v11, p0

    .line 614
    .line 615
    move-object v12, v7

    .line 616
    move-object/from16 v3, v16

    .line 617
    .line 618
    instance-of v0, v15, Li91/b2;

    .line 619
    .line 620
    if-eqz v0, :cond_1c

    .line 621
    .line 622
    const v0, -0x3a95f5bd

    .line 623
    .line 624
    .line 625
    invoke-virtual {v12, v0}, Ll2/t;->Y(I)V

    .line 626
    .line 627
    .line 628
    move-object v0, v15

    .line 629
    check-cast v0, Li91/b2;

    .line 630
    .line 631
    const-string v0, "list_item_first_right_icon"

    .line 632
    .line 633
    const/4 v2, 0x0

    .line 634
    invoke-static {v2, v13, v0}, Li91/z3;->e(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 635
    .line 636
    .line 637
    move-result-object v1

    .line 638
    const-string v0, "list_item_second_right_icon"

    .line 639
    .line 640
    invoke-static {v2, v13, v0}, Li91/z3;->e(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 641
    .line 642
    .line 643
    move-result-object v0

    .line 644
    invoke-virtual {v12}, Ll2/t;->L()Ljava/lang/Object;

    .line 645
    .line 646
    .line 647
    move-result-object v2

    .line 648
    if-ne v2, v8, :cond_1b

    .line 649
    .line 650
    invoke-static {v12}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->g(Ll2/t;)Li1/l;

    .line 651
    .line 652
    .line 653
    move-result-object v2

    .line 654
    :cond_1b
    move-object v4, v2

    .line 655
    check-cast v4, Li1/l;

    .line 656
    .line 657
    move-object v8, v0

    .line 658
    new-instance v0, Lf2/a;

    .line 659
    .line 660
    move/from16 v5, p2

    .line 661
    .line 662
    move-wide/from16 v6, p3

    .line 663
    .line 664
    move-object v2, v15

    .line 665
    invoke-direct/range {v0 .. v8}, Lf2/a;-><init>(Ljava/lang/String;Li91/v1;Lay0/a;Li1/l;ZJLjava/lang/String;)V

    .line 666
    .line 667
    .line 668
    const v1, 0x6e92ce5d

    .line 669
    .line 670
    .line 671
    invoke-static {v1, v12, v0}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 672
    .line 673
    .line 674
    move-result-object v0

    .line 675
    shr-int/lit8 v1, v9, 0x6

    .line 676
    .line 677
    and-int/lit16 v1, v1, 0x380

    .line 678
    .line 679
    or-int/lit8 v1, v1, 0x30

    .line 680
    .line 681
    const/4 v3, 0x0

    .line 682
    invoke-virtual {v11, v3, v0, v12, v1}, Li91/k2;->a(Lx2/s;Lt2/b;Ll2/o;I)V

    .line 683
    .line 684
    .line 685
    const/4 v0, 0x0

    .line 686
    invoke-virtual {v12, v0}, Ll2/t;->q(Z)V

    .line 687
    .line 688
    .line 689
    move-object v7, v12

    .line 690
    goto/16 :goto_c

    .line 691
    .line 692
    :cond_1c
    move-object/from16 v16, v3

    .line 693
    .line 694
    move-object v2, v15

    .line 695
    const/4 v3, 0x0

    .line 696
    instance-of v0, v2, Li91/a2;

    .line 697
    .line 698
    const-string v5, "list_item_label"

    .line 699
    .line 700
    if-eqz v0, :cond_1d

    .line 701
    .line 702
    const v0, -0x3a713065

    .line 703
    .line 704
    .line 705
    invoke-virtual {v12, v0}, Ll2/t;->Y(I)V

    .line 706
    .line 707
    .line 708
    move-object v0, v2

    .line 709
    check-cast v0, Li91/a2;

    .line 710
    .line 711
    invoke-static {v3, v13, v5}, Li91/z3;->e(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 712
    .line 713
    .line 714
    move-result-object v1

    .line 715
    new-instance v7, Li91/j2;

    .line 716
    .line 717
    sget-object v0, Lj91/h;->a:Ll2/u2;

    .line 718
    .line 719
    invoke-virtual {v12, v0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 720
    .line 721
    .line 722
    move-result-object v0

    .line 723
    check-cast v0, Lj91/e;

    .line 724
    .line 725
    invoke-virtual {v0}, Lj91/e;->p()J

    .line 726
    .line 727
    .line 728
    move-result-wide v3

    .line 729
    invoke-direct {v7, v3, v4}, Li91/j2;-><init>(J)V

    .line 730
    .line 731
    .line 732
    new-instance v0, Li91/f2;

    .line 733
    .line 734
    const/4 v5, 0x1

    .line 735
    move-wide/from16 v3, p3

    .line 736
    .line 737
    invoke-direct/range {v0 .. v5}, Li91/f2;-><init>(Ljava/lang/String;Li91/v1;JI)V

    .line 738
    .line 739
    .line 740
    move-object v15, v2

    .line 741
    const v1, 0x5e9c9e6b

    .line 742
    .line 743
    .line 744
    invoke-static {v1, v12, v0}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 745
    .line 746
    .line 747
    move-result-object v0

    .line 748
    shl-int/lit8 v1, v9, 0x6

    .line 749
    .line 750
    and-int/2addr v1, v14

    .line 751
    or-int v8, v1, v17

    .line 752
    .line 753
    const/16 v9, 0xa

    .line 754
    .line 755
    const/4 v2, 0x0

    .line 756
    const/4 v4, 0x0

    .line 757
    move v3, v6

    .line 758
    move-object v5, v7

    .line 759
    move-object v7, v12

    .line 760
    move-object/from16 v1, v16

    .line 761
    .line 762
    move-object v6, v0

    .line 763
    move-object v0, v11

    .line 764
    invoke-virtual/range {v0 .. v9}, Li91/k2;->b(Lay0/a;Lx2/s;ZLi1/l;Le1/s0;Lt2/b;Ll2/o;II)V

    .line 765
    .line 766
    .line 767
    const/4 v0, 0x0

    .line 768
    invoke-virtual {v7, v0}, Ll2/t;->q(Z)V

    .line 769
    .line 770
    .line 771
    goto/16 :goto_c

    .line 772
    .line 773
    :cond_1d
    move-object v15, v2

    .line 774
    move-object v7, v12

    .line 775
    instance-of v0, v15, Li91/z1;

    .line 776
    .line 777
    if-eqz v0, :cond_1e

    .line 778
    .line 779
    const v0, -0x3a6266e2

    .line 780
    .line 781
    .line 782
    invoke-virtual {v7, v0}, Ll2/t;->Y(I)V

    .line 783
    .line 784
    .line 785
    move-object v0, v15

    .line 786
    check-cast v0, Li91/z1;

    .line 787
    .line 788
    const/4 v2, 0x0

    .line 789
    invoke-static {v2, v13, v5}, Li91/z3;->e(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 790
    .line 791
    .line 792
    move-result-object v0

    .line 793
    invoke-static {v2, v13, v1}, Li91/z3;->e(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 794
    .line 795
    .line 796
    move-result-object v5

    .line 797
    new-instance v8, Li91/j2;

    .line 798
    .line 799
    sget-object v1, Lj91/h;->a:Ll2/u2;

    .line 800
    .line 801
    invoke-virtual {v7, v1}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 802
    .line 803
    .line 804
    move-result-object v1

    .line 805
    check-cast v1, Lj91/e;

    .line 806
    .line 807
    invoke-virtual {v1}, Lj91/e;->p()J

    .line 808
    .line 809
    .line 810
    move-result-wide v1

    .line 811
    invoke-direct {v8, v1, v2}, Li91/j2;-><init>(J)V

    .line 812
    .line 813
    .line 814
    move-object v2, v0

    .line 815
    new-instance v0, Li91/g2;

    .line 816
    .line 817
    move-wide/from16 v3, p3

    .line 818
    .line 819
    move-object v1, v15

    .line 820
    invoke-direct/range {v0 .. v5}, Li91/g2;-><init>(Li91/v1;Ljava/lang/String;JLjava/lang/String;)V

    .line 821
    .line 822
    .line 823
    const v1, -0x655ef5d4

    .line 824
    .line 825
    .line 826
    invoke-static {v1, v7, v0}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 827
    .line 828
    .line 829
    move-result-object v0

    .line 830
    shl-int/lit8 v1, v9, 0x6

    .line 831
    .line 832
    and-int/2addr v1, v14

    .line 833
    or-int v1, v1, v17

    .line 834
    .line 835
    const/16 v9, 0xa

    .line 836
    .line 837
    const/4 v2, 0x0

    .line 838
    const/4 v4, 0x0

    .line 839
    move v3, v6

    .line 840
    move-object v5, v8

    .line 841
    move-object v6, v0

    .line 842
    move v8, v1

    .line 843
    move-object/from16 v1, v16

    .line 844
    .line 845
    move-object/from16 v0, p0

    .line 846
    .line 847
    invoke-virtual/range {v0 .. v9}, Li91/k2;->b(Lay0/a;Lx2/s;ZLi1/l;Le1/s0;Lt2/b;Ll2/o;II)V

    .line 848
    .line 849
    .line 850
    const/4 v0, 0x0

    .line 851
    invoke-virtual {v7, v0}, Ll2/t;->q(Z)V

    .line 852
    .line 853
    .line 854
    goto/16 :goto_c

    .line 855
    .line 856
    :cond_1e
    const/4 v0, 0x0

    .line 857
    instance-of v1, v15, Li91/u1;

    .line 858
    .line 859
    if-eqz v1, :cond_1f

    .line 860
    .line 861
    const v1, -0x3a32f5e8

    .line 862
    .line 863
    .line 864
    invoke-virtual {v7, v1}, Ll2/t;->Y(I)V

    .line 865
    .line 866
    .line 867
    move-object v1, v15

    .line 868
    check-cast v1, Li91/u1;

    .line 869
    .line 870
    const-string v1, "list_item_loading"

    .line 871
    .line 872
    const/4 v2, 0x0

    .line 873
    invoke-static {v2, v13, v1}, Li91/z3;->e(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 874
    .line 875
    .line 876
    move-result-object v1

    .line 877
    invoke-static {v4, v1}, Landroidx/compose/ui/platform/a;->a(Lx2/s;Ljava/lang/String;)Lx2/s;

    .line 878
    .line 879
    .line 880
    move-result-object v1

    .line 881
    invoke-static {v0, v0, v7, v1}, Li91/j0;->N(IILl2/o;Lx2/s;)V

    .line 882
    .line 883
    .line 884
    invoke-virtual {v7, v0}, Ll2/t;->q(Z)V

    .line 885
    .line 886
    .line 887
    goto/16 :goto_c

    .line 888
    .line 889
    :goto_10
    invoke-virtual {v7, v0}, Ll2/t;->q(Z)V

    .line 890
    .line 891
    .line 892
    goto :goto_11

    .line 893
    :cond_1f
    const v1, 0x79f948f9

    .line 894
    .line 895
    .line 896
    invoke-static {v1, v7, v0}, Lf2/m0;->b(ILl2/t;Z)La8/r0;

    .line 897
    .line 898
    .line 899
    move-result-object v0

    .line 900
    throw v0

    .line 901
    :cond_20
    move-object v13, v1

    .line 902
    move-object v15, v2

    .line 903
    invoke-virtual {v7}, Ll2/t;->R()V

    .line 904
    .line 905
    .line 906
    :goto_11
    invoke-virtual {v7}, Ll2/t;->s()Ll2/u1;

    .line 907
    .line 908
    .line 909
    move-result-object v9

    .line 910
    if-eqz v9, :cond_21

    .line 911
    .line 912
    new-instance v0, Li91/h2;

    .line 913
    .line 914
    const/4 v8, 0x0

    .line 915
    move-object/from16 v1, p0

    .line 916
    .line 917
    move/from16 v3, p2

    .line 918
    .line 919
    move-wide/from16 v4, p3

    .line 920
    .line 921
    move v7, v10

    .line 922
    move-object v6, v13

    .line 923
    move-object v2, v15

    .line 924
    invoke-direct/range {v0 .. v8}, Li91/h2;-><init>(Ljava/lang/Object;Ljava/lang/Object;ZJLjava/lang/String;II)V

    .line 925
    .line 926
    .line 927
    iput-object v0, v9, Ll2/u1;->d:Lay0/n;

    .line 928
    .line 929
    :cond_21
    return-void
.end method
