.class public abstract Lh2/r7;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:F

.field public static final b:F

.field public static final c:F


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    const/4 v0, 0x2

    .line 2
    int-to-float v0, v0

    .line 3
    sput v0, Lh2/r7;->a:F

    .line 4
    .line 5
    const/16 v1, 0xc

    .line 6
    .line 7
    int-to-float v1, v1

    .line 8
    sput v1, Lh2/r7;->b:F

    .line 9
    .line 10
    sput v0, Lh2/r7;->c:F

    .line 11
    .line 12
    return-void
.end method

.method public static final a(ZLx2/s;ZLh2/o7;Ll2/o;I)V
    .locals 9

    .line 1
    move-object v3, p4

    .line 2
    check-cast v3, Ll2/t;

    .line 3
    .line 4
    const p4, 0x185a72e8

    .line 5
    .line 6
    .line 7
    invoke-virtual {v3, p4}, Ll2/t;->a0(I)Ll2/t;

    .line 8
    .line 9
    .line 10
    and-int/lit8 p4, p5, 0x6

    .line 11
    .line 12
    const/4 v7, 0x2

    .line 13
    if-nez p4, :cond_1

    .line 14
    .line 15
    invoke-virtual {v3, p0}, Ll2/t;->h(Z)Z

    .line 16
    .line 17
    .line 18
    move-result p4

    .line 19
    if-eqz p4, :cond_0

    .line 20
    .line 21
    const/4 p4, 0x4

    .line 22
    goto :goto_0

    .line 23
    :cond_0
    move p4, v7

    .line 24
    :goto_0
    or-int/2addr p4, p5

    .line 25
    goto :goto_1

    .line 26
    :cond_1
    move p4, p5

    .line 27
    :goto_1
    and-int/lit8 v0, p5, 0x30

    .line 28
    .line 29
    if-nez v0, :cond_3

    .line 30
    .line 31
    const/4 v0, 0x0

    .line 32
    invoke-virtual {v3, v0}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 33
    .line 34
    .line 35
    move-result v0

    .line 36
    if-eqz v0, :cond_2

    .line 37
    .line 38
    const/16 v0, 0x20

    .line 39
    .line 40
    goto :goto_2

    .line 41
    :cond_2
    const/16 v0, 0x10

    .line 42
    .line 43
    :goto_2
    or-int/2addr p4, v0

    .line 44
    :cond_3
    and-int/lit16 v0, p5, 0x180

    .line 45
    .line 46
    if-nez v0, :cond_5

    .line 47
    .line 48
    invoke-virtual {v3, p1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 49
    .line 50
    .line 51
    move-result v0

    .line 52
    if-eqz v0, :cond_4

    .line 53
    .line 54
    const/16 v0, 0x100

    .line 55
    .line 56
    goto :goto_3

    .line 57
    :cond_4
    const/16 v0, 0x80

    .line 58
    .line 59
    :goto_3
    or-int/2addr p4, v0

    .line 60
    :cond_5
    and-int/lit16 v0, p5, 0xc00

    .line 61
    .line 62
    if-nez v0, :cond_7

    .line 63
    .line 64
    invoke-virtual {v3, p2}, Ll2/t;->h(Z)Z

    .line 65
    .line 66
    .line 67
    move-result v0

    .line 68
    if-eqz v0, :cond_6

    .line 69
    .line 70
    const/16 v0, 0x800

    .line 71
    .line 72
    goto :goto_4

    .line 73
    :cond_6
    const/16 v0, 0x400

    .line 74
    .line 75
    :goto_4
    or-int/2addr p4, v0

    .line 76
    :cond_7
    and-int/lit16 v0, p5, 0x6000

    .line 77
    .line 78
    if-nez v0, :cond_9

    .line 79
    .line 80
    invoke-virtual {v3, p3}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 81
    .line 82
    .line 83
    move-result v0

    .line 84
    if-eqz v0, :cond_8

    .line 85
    .line 86
    const/16 v0, 0x4000

    .line 87
    .line 88
    goto :goto_5

    .line 89
    :cond_8
    const/16 v0, 0x2000

    .line 90
    .line 91
    :goto_5
    or-int/2addr p4, v0

    .line 92
    :cond_9
    const/high16 v0, 0x30000

    .line 93
    .line 94
    or-int/2addr p4, v0

    .line 95
    const v0, 0x12493

    .line 96
    .line 97
    .line 98
    and-int/2addr v0, p4

    .line 99
    const v1, 0x12492

    .line 100
    .line 101
    .line 102
    const/4 v8, 0x0

    .line 103
    const/4 v2, 0x1

    .line 104
    if-eq v0, v1, :cond_a

    .line 105
    .line 106
    move v0, v2

    .line 107
    goto :goto_6

    .line 108
    :cond_a
    move v0, v8

    .line 109
    :goto_6
    and-int/2addr p4, v2

    .line 110
    invoke-virtual {v3, p4, v0}, Ll2/t;->O(IZ)Z

    .line 111
    .line 112
    .line 113
    move-result p4

    .line 114
    if-eqz p4, :cond_14

    .line 115
    .line 116
    invoke-virtual {v3}, Ll2/t;->T()V

    .line 117
    .line 118
    .line 119
    and-int/lit8 p4, p5, 0x1

    .line 120
    .line 121
    if-eqz p4, :cond_c

    .line 122
    .line 123
    invoke-virtual {v3}, Ll2/t;->y()Z

    .line 124
    .line 125
    .line 126
    move-result p4

    .line 127
    if-eqz p4, :cond_b

    .line 128
    .line 129
    goto :goto_7

    .line 130
    :cond_b
    invoke-virtual {v3}, Ll2/t;->R()V

    .line 131
    .line 132
    .line 133
    :cond_c
    :goto_7
    invoke-virtual {v3}, Ll2/t;->r()V

    .line 134
    .line 135
    .line 136
    if-eqz p0, :cond_d

    .line 137
    .line 138
    sget p4, Lh2/r7;->b:F

    .line 139
    .line 140
    int-to-float v0, v7

    .line 141
    div-float/2addr p4, v0

    .line 142
    :goto_8
    move v0, p4

    .line 143
    goto :goto_9

    .line 144
    :cond_d
    int-to-float p4, v8

    .line 145
    goto :goto_8

    .line 146
    :goto_9
    sget-object p4, Lk2/w;->e:Lk2/w;

    .line 147
    .line 148
    invoke-static {p4, v3}, Lh2/r;->C(Lk2/w;Ll2/o;)Lc1/f1;

    .line 149
    .line 150
    .line 151
    move-result-object v1

    .line 152
    const/4 v4, 0x0

    .line 153
    const/16 v5, 0xc

    .line 154
    .line 155
    const/4 v2, 0x0

    .line 156
    invoke-static/range {v0 .. v5}, Lc1/e;->a(FLc1/a0;Lay0/k;Ll2/o;II)Ll2/t2;

    .line 157
    .line 158
    .line 159
    move-result-object p4

    .line 160
    if-eqz p2, :cond_e

    .line 161
    .line 162
    if-eqz p0, :cond_e

    .line 163
    .line 164
    iget-wide v0, p3, Lh2/o7;->a:J

    .line 165
    .line 166
    goto :goto_a

    .line 167
    :cond_e
    if-eqz p2, :cond_f

    .line 168
    .line 169
    if-nez p0, :cond_f

    .line 170
    .line 171
    iget-wide v0, p3, Lh2/o7;->b:J

    .line 172
    .line 173
    goto :goto_a

    .line 174
    :cond_f
    if-nez p2, :cond_10

    .line 175
    .line 176
    if-eqz p0, :cond_10

    .line 177
    .line 178
    iget-wide v0, p3, Lh2/o7;->c:J

    .line 179
    .line 180
    goto :goto_a

    .line 181
    :cond_10
    iget-wide v0, p3, Lh2/o7;->d:J

    .line 182
    .line 183
    :goto_a
    if-eqz p2, :cond_11

    .line 184
    .line 185
    const v2, 0x47359f1d

    .line 186
    .line 187
    .line 188
    invoke-virtual {v3, v2}, Ll2/t;->Y(I)V

    .line 189
    .line 190
    .line 191
    sget-object v2, Lk2/w;->f:Lk2/w;

    .line 192
    .line 193
    invoke-static {v2, v3}, Lh2/r;->C(Lk2/w;Ll2/o;)Lc1/f1;

    .line 194
    .line 195
    .line 196
    move-result-object v2

    .line 197
    const/4 v5, 0x0

    .line 198
    const/16 v6, 0xc

    .line 199
    .line 200
    move-object v4, v3

    .line 201
    const/4 v3, 0x0

    .line 202
    invoke-static/range {v0 .. v6}, Lb1/a1;->a(JLc1/f1;Ljava/lang/String;Ll2/o;II)Ll2/t2;

    .line 203
    .line 204
    .line 205
    move-result-object v0

    .line 206
    move-object v3, v4

    .line 207
    invoke-virtual {v3, v8}, Ll2/t;->q(Z)V

    .line 208
    .line 209
    .line 210
    goto :goto_b

    .line 211
    :cond_11
    const v2, 0x4738551a

    .line 212
    .line 213
    .line 214
    invoke-virtual {v3, v2}, Ll2/t;->Y(I)V

    .line 215
    .line 216
    .line 217
    new-instance v2, Le3/s;

    .line 218
    .line 219
    invoke-direct {v2, v0, v1}, Le3/s;-><init>(J)V

    .line 220
    .line 221
    .line 222
    invoke-static {v2, v3}, Ll2/b;->s(Ljava/lang/Object;Ll2/o;)Ll2/b1;

    .line 223
    .line 224
    .line 225
    move-result-object v0

    .line 226
    invoke-virtual {v3, v8}, Ll2/t;->q(Z)V

    .line 227
    .line 228
    .line 229
    :goto_b
    sget-object v1, Lx2/p;->b:Lx2/p;

    .line 230
    .line 231
    invoke-interface {p1, v1}, Lx2/s;->g(Lx2/s;)Lx2/s;

    .line 232
    .line 233
    .line 234
    move-result-object v2

    .line 235
    invoke-interface {v2, v1}, Lx2/s;->g(Lx2/s;)Lx2/s;

    .line 236
    .line 237
    .line 238
    move-result-object v1

    .line 239
    sget-object v2, Lx2/c;->h:Lx2/j;

    .line 240
    .line 241
    invoke-static {v1, v2, v7}, Landroidx/compose/foundation/layout/d;->v(Lx2/s;Lx2/j;I)Lx2/s;

    .line 242
    .line 243
    .line 244
    move-result-object v1

    .line 245
    sget v2, Lh2/r7;->a:F

    .line 246
    .line 247
    invoke-static {v1, v2}, Landroidx/compose/foundation/layout/a;->m(Lx2/s;F)Lx2/s;

    .line 248
    .line 249
    .line 250
    move-result-object v1

    .line 251
    sget v2, Lk2/d0;->c:F

    .line 252
    .line 253
    invoke-static {v1, v2}, Landroidx/compose/foundation/layout/d;->j(Lx2/s;F)Lx2/s;

    .line 254
    .line 255
    .line 256
    move-result-object v1

    .line 257
    invoke-virtual {v3, v0}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 258
    .line 259
    .line 260
    move-result v2

    .line 261
    invoke-virtual {v3, p4}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 262
    .line 263
    .line 264
    move-result v4

    .line 265
    or-int/2addr v2, v4

    .line 266
    invoke-virtual {v3}, Ll2/t;->L()Ljava/lang/Object;

    .line 267
    .line 268
    .line 269
    move-result-object v4

    .line 270
    if-nez v2, :cond_12

    .line 271
    .line 272
    sget-object v2, Ll2/n;->a:Ll2/x0;

    .line 273
    .line 274
    if-ne v4, v2, :cond_13

    .line 275
    .line 276
    :cond_12
    new-instance v4, Lh2/p7;

    .line 277
    .line 278
    const/4 v2, 0x0

    .line 279
    invoke-direct {v4, v0, p4, v2}, Lh2/p7;-><init>(Ll2/t2;Ll2/t2;I)V

    .line 280
    .line 281
    .line 282
    invoke-virtual {v3, v4}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 283
    .line 284
    .line 285
    :cond_13
    check-cast v4, Lay0/k;

    .line 286
    .line 287
    invoke-static {v1, v4, v3, v8}, Lkp/i;->a(Lx2/s;Lay0/k;Ll2/o;I)V

    .line 288
    .line 289
    .line 290
    goto :goto_c

    .line 291
    :cond_14
    invoke-virtual {v3}, Ll2/t;->R()V

    .line 292
    .line 293
    .line 294
    :goto_c
    invoke-virtual {v3}, Ll2/t;->s()Ll2/u1;

    .line 295
    .line 296
    .line 297
    move-result-object p4

    .line 298
    if-eqz p4, :cond_15

    .line 299
    .line 300
    new-instance v0, Lh2/q7;

    .line 301
    .line 302
    const/4 v6, 0x0

    .line 303
    move v1, p0

    .line 304
    move-object v2, p1

    .line 305
    move v3, p2

    .line 306
    move-object v4, p3

    .line 307
    move v5, p5

    .line 308
    invoke-direct/range {v0 .. v6}, Lh2/q7;-><init>(ZLjava/lang/Object;ZLjava/lang/Object;II)V

    .line 309
    .line 310
    .line 311
    iput-object v0, p4, Ll2/u1;->d:Lay0/n;

    .line 312
    .line 313
    :cond_15
    return-void
.end method
