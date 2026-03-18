.class public abstract Ll61/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(FILl2/o;Lx2/s;)V
    .locals 4

    .line 1
    check-cast p2, Ll2/t;

    .line 2
    .line 3
    const v0, 0x54802dc3

    .line 4
    .line 5
    .line 6
    invoke-virtual {p2, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 7
    .line 8
    .line 9
    or-int/lit8 v0, p1, 0x6

    .line 10
    .line 11
    and-int/lit8 v1, p1, 0x30

    .line 12
    .line 13
    if-nez v1, :cond_1

    .line 14
    .line 15
    invoke-virtual {p2, p0}, Ll2/t;->d(F)Z

    .line 16
    .line 17
    .line 18
    move-result v1

    .line 19
    if-eqz v1, :cond_0

    .line 20
    .line 21
    const/16 v1, 0x20

    .line 22
    .line 23
    goto :goto_0

    .line 24
    :cond_0
    const/16 v1, 0x10

    .line 25
    .line 26
    :goto_0
    or-int/2addr v0, v1

    .line 27
    :cond_1
    and-int/lit8 v1, v0, 0x13

    .line 28
    .line 29
    const/16 v2, 0x12

    .line 30
    .line 31
    const/4 v3, 0x1

    .line 32
    if-eq v1, v2, :cond_2

    .line 33
    .line 34
    move v1, v3

    .line 35
    goto :goto_1

    .line 36
    :cond_2
    const/4 v1, 0x0

    .line 37
    :goto_1
    and-int/2addr v0, v3

    .line 38
    invoke-virtual {p2, v0, v1}, Ll2/t;->O(IZ)Z

    .line 39
    .line 40
    .line 41
    move-result v0

    .line 42
    if-eqz v0, :cond_4

    .line 43
    .line 44
    const p3, 0x3f333333    # 0.7f

    .line 45
    .line 46
    .line 47
    mul-float/2addr p3, p0

    .line 48
    sget-wide v0, Ln61/a;->e:J

    .line 49
    .line 50
    sget-object v2, Le3/j0;->a:Le3/i0;

    .line 51
    .line 52
    sget-object v3, Lx2/p;->b:Lx2/p;

    .line 53
    .line 54
    invoke-static {v3, v0, v1, v2}, Landroidx/compose/foundation/a;->b(Lx2/s;JLe3/n0;)Lx2/s;

    .line 55
    .line 56
    .line 57
    move-result-object v0

    .line 58
    const/4 v1, 0x2

    .line 59
    int-to-float v1, v1

    .line 60
    div-float v1, p3, v1

    .line 61
    .line 62
    invoke-static {v0, v1}, Landroidx/compose/foundation/layout/d;->r(Lx2/s;F)Lx2/s;

    .line 63
    .line 64
    .line 65
    move-result-object v0

    .line 66
    invoke-static {v0, p3}, Landroidx/compose/foundation/layout/d;->e(Lx2/s;F)Lx2/s;

    .line 67
    .line 68
    .line 69
    move-result-object p3

    .line 70
    invoke-virtual {p2}, Ll2/t;->L()Ljava/lang/Object;

    .line 71
    .line 72
    .line 73
    move-result-object v0

    .line 74
    sget-object v1, Ll2/n;->a:Ll2/x0;

    .line 75
    .line 76
    if-ne v0, v1, :cond_3

    .line 77
    .line 78
    new-instance v0, Lkq0/a;

    .line 79
    .line 80
    const/4 v1, 0x7

    .line 81
    invoke-direct {v0, v1}, Lkq0/a;-><init>(I)V

    .line 82
    .line 83
    .line 84
    invoke-virtual {p2, v0}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 85
    .line 86
    .line 87
    :cond_3
    check-cast v0, Lay0/k;

    .line 88
    .line 89
    const/16 v1, 0x30

    .line 90
    .line 91
    invoke-static {p3, v0, p2, v1}, Lkp/i;->a(Lx2/s;Lay0/k;Ll2/o;I)V

    .line 92
    .line 93
    .line 94
    move-object p3, v3

    .line 95
    goto :goto_2

    .line 96
    :cond_4
    invoke-virtual {p2}, Ll2/t;->R()V

    .line 97
    .line 98
    .line 99
    :goto_2
    invoke-virtual {p2}, Ll2/t;->s()Ll2/u1;

    .line 100
    .line 101
    .line 102
    move-result-object p2

    .line 103
    if-eqz p2, :cond_5

    .line 104
    .line 105
    new-instance v0, Li91/e3;

    .line 106
    .line 107
    invoke-direct {v0, p3, p0, p1}, Li91/e3;-><init>(Lx2/s;FI)V

    .line 108
    .line 109
    .line 110
    iput-object v0, p2, Ll2/u1;->d:Lay0/n;

    .line 111
    .line 112
    :cond_5
    return-void
.end method

.method public static final b(Lx2/s;FLtechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError;ZLl2/o;I)V
    .locals 9

    .line 1
    check-cast p4, Ll2/t;

    .line 2
    .line 3
    const v0, -0x2e58577

    .line 4
    .line 5
    .line 6
    invoke-virtual {p4, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 7
    .line 8
    .line 9
    invoke-virtual {p4, p1}, Ll2/t;->d(F)Z

    .line 10
    .line 11
    .line 12
    move-result v0

    .line 13
    if-eqz v0, :cond_0

    .line 14
    .line 15
    const/16 v0, 0x20

    .line 16
    .line 17
    goto :goto_0

    .line 18
    :cond_0
    const/16 v0, 0x10

    .line 19
    .line 20
    :goto_0
    or-int/2addr v0, p5

    .line 21
    invoke-virtual {p4, p2}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 22
    .line 23
    .line 24
    move-result v1

    .line 25
    if-eqz v1, :cond_1

    .line 26
    .line 27
    const/16 v1, 0x100

    .line 28
    .line 29
    goto :goto_1

    .line 30
    :cond_1
    const/16 v1, 0x80

    .line 31
    .line 32
    :goto_1
    or-int/2addr v0, v1

    .line 33
    invoke-virtual {p4, p3}, Ll2/t;->h(Z)Z

    .line 34
    .line 35
    .line 36
    move-result v1

    .line 37
    if-eqz v1, :cond_2

    .line 38
    .line 39
    const/16 v1, 0x800

    .line 40
    .line 41
    goto :goto_2

    .line 42
    :cond_2
    const/16 v1, 0x400

    .line 43
    .line 44
    :goto_2
    or-int/2addr v0, v1

    .line 45
    and-int/lit16 v1, v0, 0x493

    .line 46
    .line 47
    const/16 v2, 0x492

    .line 48
    .line 49
    const/4 v3, 0x0

    .line 50
    const/4 v4, 0x1

    .line 51
    if-eq v1, v2, :cond_3

    .line 52
    .line 53
    move v1, v4

    .line 54
    goto :goto_3

    .line 55
    :cond_3
    move v1, v3

    .line 56
    :goto_3
    and-int/lit8 v2, v0, 0x1

    .line 57
    .line 58
    invoke-virtual {p4, v2, v1}, Ll2/t;->O(IZ)Z

    .line 59
    .line 60
    .line 61
    move-result v1

    .line 62
    if-eqz v1, :cond_d

    .line 63
    .line 64
    sget-object v1, Lx2/c;->h:Lx2/j;

    .line 65
    .line 66
    invoke-static {v1, v3}, Lk1/n;->d(Lx2/e;Z)Lt3/q0;

    .line 67
    .line 68
    .line 69
    move-result-object v1

    .line 70
    iget-wide v5, p4, Ll2/t;->T:J

    .line 71
    .line 72
    invoke-static {v5, v6}, Ljava/lang/Long;->hashCode(J)I

    .line 73
    .line 74
    .line 75
    move-result v2

    .line 76
    invoke-virtual {p4}, Ll2/t;->m()Ll2/p1;

    .line 77
    .line 78
    .line 79
    move-result-object v5

    .line 80
    invoke-static {p4, p0}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 81
    .line 82
    .line 83
    move-result-object v6

    .line 84
    sget-object v7, Lv3/k;->m1:Lv3/j;

    .line 85
    .line 86
    invoke-virtual {v7}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 87
    .line 88
    .line 89
    sget-object v7, Lv3/j;->b:Lv3/i;

    .line 90
    .line 91
    invoke-virtual {p4}, Ll2/t;->c0()V

    .line 92
    .line 93
    .line 94
    iget-boolean v8, p4, Ll2/t;->S:Z

    .line 95
    .line 96
    if-eqz v8, :cond_4

    .line 97
    .line 98
    invoke-virtual {p4, v7}, Ll2/t;->l(Lay0/a;)V

    .line 99
    .line 100
    .line 101
    goto :goto_4

    .line 102
    :cond_4
    invoke-virtual {p4}, Ll2/t;->m0()V

    .line 103
    .line 104
    .line 105
    :goto_4
    sget-object v7, Lv3/j;->g:Lv3/h;

    .line 106
    .line 107
    invoke-static {v7, v1, p4}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 108
    .line 109
    .line 110
    sget-object v1, Lv3/j;->f:Lv3/h;

    .line 111
    .line 112
    invoke-static {v1, v5, p4}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 113
    .line 114
    .line 115
    sget-object v1, Lv3/j;->j:Lv3/h;

    .line 116
    .line 117
    iget-boolean v5, p4, Ll2/t;->S:Z

    .line 118
    .line 119
    if-nez v5, :cond_5

    .line 120
    .line 121
    invoke-virtual {p4}, Ll2/t;->L()Ljava/lang/Object;

    .line 122
    .line 123
    .line 124
    move-result-object v5

    .line 125
    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 126
    .line 127
    .line 128
    move-result-object v7

    .line 129
    invoke-static {v5, v7}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 130
    .line 131
    .line 132
    move-result v5

    .line 133
    if-nez v5, :cond_6

    .line 134
    .line 135
    :cond_5
    invoke-static {v2, p4, v2, v1}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 136
    .line 137
    .line 138
    :cond_6
    sget-object v1, Lv3/j;->d:Lv3/h;

    .line 139
    .line 140
    invoke-static {v1, v6, p4}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 141
    .line 142
    .line 143
    instance-of v1, p2, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError$ObstacleDetected;

    .line 144
    .line 145
    const/4 v2, 0x0

    .line 146
    if-eqz v1, :cond_a

    .line 147
    .line 148
    const v1, 0x5619a360

    .line 149
    .line 150
    .line 151
    invoke-virtual {p4, v1}, Ll2/t;->Y(I)V

    .line 152
    .line 153
    .line 154
    move-object v1, p2

    .line 155
    check-cast v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError$ObstacleDetected;

    .line 156
    .line 157
    invoke-virtual {v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError$ObstacleDetected;->getPosition()Ls71/f;

    .line 158
    .line 159
    .line 160
    move-result-object v1

    .line 161
    invoke-virtual {v1}, Ljava/lang/Enum;->ordinal()I

    .line 162
    .line 163
    .line 164
    move-result v1

    .line 165
    if-eq v1, v4, :cond_9

    .line 166
    .line 167
    const/4 v5, 0x2

    .line 168
    if-eq v1, v5, :cond_8

    .line 169
    .line 170
    const/4 v5, 0x3

    .line 171
    if-eq v1, v5, :cond_7

    .line 172
    .line 173
    const v0, 0x5627661d

    .line 174
    .line 175
    .line 176
    invoke-virtual {p4, v0}, Ll2/t;->Y(I)V

    .line 177
    .line 178
    .line 179
    invoke-virtual {p4, v3}, Ll2/t;->q(Z)V

    .line 180
    .line 181
    .line 182
    goto :goto_5

    .line 183
    :cond_7
    const v1, 0x56237f74

    .line 184
    .line 185
    .line 186
    invoke-virtual {p4, v1}, Ll2/t;->Y(I)V

    .line 187
    .line 188
    .line 189
    const v1, 0x7f0805b3

    .line 190
    .line 191
    .line 192
    and-int/lit8 v0, v0, 0x70

    .line 193
    .line 194
    invoke-static {v2, p1, v1, p4, v0}, Ll61/c;->c(Lx2/s;FILl2/o;I)V

    .line 195
    .line 196
    .line 197
    invoke-virtual {p4, v3}, Ll2/t;->q(Z)V

    .line 198
    .line 199
    .line 200
    goto :goto_5

    .line 201
    :cond_8
    const v1, 0x561aa3bb

    .line 202
    .line 203
    .line 204
    invoke-virtual {p4, v1}, Ll2/t;->Y(I)V

    .line 205
    .line 206
    .line 207
    const v1, 0x7f0805b4

    .line 208
    .line 209
    .line 210
    and-int/lit8 v0, v0, 0x70

    .line 211
    .line 212
    invoke-static {v2, p1, v1, p4, v0}, Ll61/c;->c(Lx2/s;FILl2/o;I)V

    .line 213
    .line 214
    .line 215
    invoke-virtual {p4, v3}, Ll2/t;->q(Z)V

    .line 216
    .line 217
    .line 218
    goto :goto_5

    .line 219
    :cond_9
    const v1, 0x561eecb8

    .line 220
    .line 221
    .line 222
    invoke-virtual {p4, v1}, Ll2/t;->Y(I)V

    .line 223
    .line 224
    .line 225
    const v1, 0x7f0805b2

    .line 226
    .line 227
    .line 228
    and-int/lit8 v0, v0, 0x70

    .line 229
    .line 230
    invoke-static {v2, p1, v1, p4, v0}, Ll61/c;->c(Lx2/s;FILl2/o;I)V

    .line 231
    .line 232
    .line 233
    invoke-virtual {p4, v3}, Ll2/t;->q(Z)V

    .line 234
    .line 235
    .line 236
    :goto_5
    invoke-virtual {p4, v3}, Ll2/t;->q(Z)V

    .line 237
    .line 238
    .line 239
    goto :goto_7

    .line 240
    :cond_a
    instance-of v1, p2, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError$KeyOutOfRange;

    .line 241
    .line 242
    if-eqz v1, :cond_b

    .line 243
    .line 244
    const v1, 0x5628fcbf

    .line 245
    .line 246
    .line 247
    invoke-virtual {p4, v1}, Ll2/t;->Y(I)V

    .line 248
    .line 249
    .line 250
    const v1, 0x7f080233

    .line 251
    .line 252
    .line 253
    and-int/lit8 v0, v0, 0x70

    .line 254
    .line 255
    invoke-static {v2, p1, v1, p4, v0}, Ll61/c;->c(Lx2/s;FILl2/o;I)V

    .line 256
    .line 257
    .line 258
    invoke-virtual {p4, v3}, Ll2/t;->q(Z)V

    .line 259
    .line 260
    .line 261
    goto :goto_7

    .line 262
    :cond_b
    if-eqz p3, :cond_c

    .line 263
    .line 264
    const v1, 0x562c40e6

    .line 265
    .line 266
    .line 267
    invoke-virtual {p4, v1}, Ll2/t;->Y(I)V

    .line 268
    .line 269
    .line 270
    and-int/lit8 v0, v0, 0x70

    .line 271
    .line 272
    invoke-static {p1, v0, p4, v2}, Ll61/c;->a(FILl2/o;Lx2/s;)V

    .line 273
    .line 274
    .line 275
    :goto_6
    invoke-virtual {p4, v3}, Ll2/t;->q(Z)V

    .line 276
    .line 277
    .line 278
    goto :goto_7

    .line 279
    :cond_c
    const v0, 0x55f186bf

    .line 280
    .line 281
    .line 282
    invoke-virtual {p4, v0}, Ll2/t;->Y(I)V

    .line 283
    .line 284
    .line 285
    goto :goto_6

    .line 286
    :goto_7
    invoke-virtual {p4, v4}, Ll2/t;->q(Z)V

    .line 287
    .line 288
    .line 289
    goto :goto_8

    .line 290
    :cond_d
    invoke-virtual {p4}, Ll2/t;->R()V

    .line 291
    .line 292
    .line 293
    :goto_8
    invoke-virtual {p4}, Ll2/t;->s()Ll2/u1;

    .line 294
    .line 295
    .line 296
    move-result-object p4

    .line 297
    if-eqz p4, :cond_e

    .line 298
    .line 299
    new-instance v0, Ll61/a;

    .line 300
    .line 301
    move-object v1, p0

    .line 302
    move v2, p1

    .line 303
    move-object v3, p2

    .line 304
    move v4, p3

    .line 305
    move v5, p5

    .line 306
    invoke-direct/range {v0 .. v5}, Ll61/a;-><init>(Lx2/s;FLtechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError;ZI)V

    .line 307
    .line 308
    .line 309
    iput-object v0, p4, Ll2/u1;->d:Lay0/n;

    .line 310
    .line 311
    :cond_e
    return-void
.end method

.method public static final c(Lx2/s;FILl2/o;I)V
    .locals 11

    .line 1
    move-object v7, p3

    .line 2
    check-cast v7, Ll2/t;

    .line 3
    .line 4
    const p3, 0x170d1ad1

    .line 5
    .line 6
    .line 7
    invoke-virtual {v7, p3}, Ll2/t;->a0(I)Ll2/t;

    .line 8
    .line 9
    .line 10
    or-int/lit8 p3, p4, 0x6

    .line 11
    .line 12
    and-int/lit8 v0, p4, 0x30

    .line 13
    .line 14
    if-nez v0, :cond_1

    .line 15
    .line 16
    invoke-virtual {v7, p1}, Ll2/t;->d(F)Z

    .line 17
    .line 18
    .line 19
    move-result v0

    .line 20
    if-eqz v0, :cond_0

    .line 21
    .line 22
    const/16 v0, 0x20

    .line 23
    .line 24
    goto :goto_0

    .line 25
    :cond_0
    const/16 v0, 0x10

    .line 26
    .line 27
    :goto_0
    or-int/2addr p3, v0

    .line 28
    :cond_1
    invoke-virtual {v7, p2}, Ll2/t;->e(I)Z

    .line 29
    .line 30
    .line 31
    move-result v0

    .line 32
    if-eqz v0, :cond_2

    .line 33
    .line 34
    const/16 v0, 0x100

    .line 35
    .line 36
    goto :goto_1

    .line 37
    :cond_2
    const/16 v0, 0x80

    .line 38
    .line 39
    :goto_1
    or-int/2addr p3, v0

    .line 40
    and-int/lit16 v0, p3, 0x93

    .line 41
    .line 42
    const/16 v1, 0x92

    .line 43
    .line 44
    const/4 v2, 0x0

    .line 45
    const/4 v10, 0x1

    .line 46
    if-eq v0, v1, :cond_3

    .line 47
    .line 48
    move v0, v10

    .line 49
    goto :goto_2

    .line 50
    :cond_3
    move v0, v2

    .line 51
    :goto_2
    and-int/lit8 v1, p3, 0x1

    .line 52
    .line 53
    invoke-virtual {v7, v1, v0}, Ll2/t;->O(IZ)Z

    .line 54
    .line 55
    .line 56
    move-result v0

    .line 57
    if-eqz v0, :cond_7

    .line 58
    .line 59
    sget-object p0, Landroidx/compose/foundation/layout/d;->c:Landroidx/compose/foundation/layout/FillElement;

    .line 60
    .line 61
    sget-object v0, Lx2/c;->d:Lx2/j;

    .line 62
    .line 63
    invoke-static {v0, v2}, Lk1/n;->d(Lx2/e;Z)Lt3/q0;

    .line 64
    .line 65
    .line 66
    move-result-object v0

    .line 67
    iget-wide v1, v7, Ll2/t;->T:J

    .line 68
    .line 69
    invoke-static {v1, v2}, Ljava/lang/Long;->hashCode(J)I

    .line 70
    .line 71
    .line 72
    move-result v1

    .line 73
    invoke-virtual {v7}, Ll2/t;->m()Ll2/p1;

    .line 74
    .line 75
    .line 76
    move-result-object v2

    .line 77
    invoke-static {v7, p0}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 78
    .line 79
    .line 80
    move-result-object p0

    .line 81
    sget-object v3, Lv3/k;->m1:Lv3/j;

    .line 82
    .line 83
    invoke-virtual {v3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 84
    .line 85
    .line 86
    sget-object v3, Lv3/j;->b:Lv3/i;

    .line 87
    .line 88
    invoke-virtual {v7}, Ll2/t;->c0()V

    .line 89
    .line 90
    .line 91
    iget-boolean v4, v7, Ll2/t;->S:Z

    .line 92
    .line 93
    if-eqz v4, :cond_4

    .line 94
    .line 95
    invoke-virtual {v7, v3}, Ll2/t;->l(Lay0/a;)V

    .line 96
    .line 97
    .line 98
    goto :goto_3

    .line 99
    :cond_4
    invoke-virtual {v7}, Ll2/t;->m0()V

    .line 100
    .line 101
    .line 102
    :goto_3
    sget-object v3, Lv3/j;->g:Lv3/h;

    .line 103
    .line 104
    invoke-static {v3, v0, v7}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 105
    .line 106
    .line 107
    sget-object v0, Lv3/j;->f:Lv3/h;

    .line 108
    .line 109
    invoke-static {v0, v2, v7}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 110
    .line 111
    .line 112
    sget-object v0, Lv3/j;->j:Lv3/h;

    .line 113
    .line 114
    iget-boolean v2, v7, Ll2/t;->S:Z

    .line 115
    .line 116
    if-nez v2, :cond_5

    .line 117
    .line 118
    invoke-virtual {v7}, Ll2/t;->L()Ljava/lang/Object;

    .line 119
    .line 120
    .line 121
    move-result-object v2

    .line 122
    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 123
    .line 124
    .line 125
    move-result-object v3

    .line 126
    invoke-static {v2, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 127
    .line 128
    .line 129
    move-result v2

    .line 130
    if-nez v2, :cond_6

    .line 131
    .line 132
    :cond_5
    invoke-static {v1, v7, v1, v0}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 133
    .line 134
    .line 135
    :cond_6
    sget-object v0, Lv3/j;->d:Lv3/h;

    .line 136
    .line 137
    invoke-static {v0, p0, v7}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 138
    .line 139
    .line 140
    sget-object p0, Lx2/p;->b:Lx2/p;

    .line 141
    .line 142
    invoke-static {p0, p1}, Landroidx/compose/foundation/layout/d;->n(Lx2/s;F)Lx2/s;

    .line 143
    .line 144
    .line 145
    move-result-object v0

    .line 146
    sget-object v1, Lx2/c;->h:Lx2/j;

    .line 147
    .line 148
    sget-object v2, Landroidx/compose/foundation/layout/b;->a:Landroidx/compose/foundation/layout/b;

    .line 149
    .line 150
    invoke-virtual {v2, v0, v1}, Landroidx/compose/foundation/layout/b;->a(Lx2/s;Lx2/e;)Lx2/s;

    .line 151
    .line 152
    .line 153
    move-result-object v2

    .line 154
    shr-int/lit8 p3, p3, 0x6

    .line 155
    .line 156
    and-int/lit8 p3, p3, 0xe

    .line 157
    .line 158
    invoke-static {p2, p3, v7}, Ljp/fa;->b(IILl2/o;)Li3/c;

    .line 159
    .line 160
    .line 161
    move-result-object v0

    .line 162
    const/16 v8, 0x6030

    .line 163
    .line 164
    const/16 v9, 0x68

    .line 165
    .line 166
    const-string v1, "Drive interrupts image"

    .line 167
    .line 168
    const/4 v3, 0x0

    .line 169
    sget-object v4, Lt3/j;->b:Lt3/x0;

    .line 170
    .line 171
    const/4 v5, 0x0

    .line 172
    const/4 v6, 0x0

    .line 173
    invoke-static/range {v0 .. v9}, Lkp/m;->a(Li3/c;Ljava/lang/String;Lx2/s;Lx2/e;Lt3/k;FLe3/m;Ll2/o;II)V

    .line 174
    .line 175
    .line 176
    invoke-virtual {v7, v10}, Ll2/t;->q(Z)V

    .line 177
    .line 178
    .line 179
    goto :goto_4

    .line 180
    :cond_7
    invoke-virtual {v7}, Ll2/t;->R()V

    .line 181
    .line 182
    .line 183
    :goto_4
    invoke-virtual {v7}, Ll2/t;->s()Ll2/u1;

    .line 184
    .line 185
    .line 186
    move-result-object p3

    .line 187
    if-eqz p3, :cond_8

    .line 188
    .line 189
    new-instance v0, Ll61/b;

    .line 190
    .line 191
    invoke-direct {v0, p0, p1, p2, p4}, Ll61/b;-><init>(Lx2/s;FII)V

    .line 192
    .line 193
    .line 194
    iput-object v0, p3, Ll2/u1;->d:Lay0/n;

    .line 195
    .line 196
    :cond_8
    return-void
.end method
