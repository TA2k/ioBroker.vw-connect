.class public final synthetic Lwk/g;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:F

.field public final synthetic e:Lp1/v;

.field public final synthetic f:Lzb/e0;

.field public final synthetic g:Lzh/j;

.field public final synthetic h:Lay0/k;

.field public final synthetic i:Ll2/g1;


# direct methods
.method public synthetic constructor <init>(FLp1/b;Lzb/e0;Lzh/j;Lay0/k;Ll2/g1;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput p1, p0, Lwk/g;->d:F

    .line 5
    .line 6
    iput-object p2, p0, Lwk/g;->e:Lp1/v;

    .line 7
    .line 8
    iput-object p3, p0, Lwk/g;->f:Lzb/e0;

    .line 9
    .line 10
    iput-object p4, p0, Lwk/g;->g:Lzh/j;

    .line 11
    .line 12
    iput-object p5, p0, Lwk/g;->h:Lay0/k;

    .line 13
    .line 14
    iput-object p6, p0, Lwk/g;->i:Ll2/g1;

    .line 15
    .line 16
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 23

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    check-cast v1, Ll2/o;

    .line 6
    .line 7
    move-object/from16 v2, p2

    .line 8
    .line 9
    check-cast v2, Ljava/lang/Integer;

    .line 10
    .line 11
    invoke-virtual {v2}, Ljava/lang/Integer;->intValue()I

    .line 12
    .line 13
    .line 14
    move-result v2

    .line 15
    and-int/lit8 v3, v2, 0x3

    .line 16
    .line 17
    const/4 v4, 0x2

    .line 18
    const/4 v5, 0x0

    .line 19
    const/4 v6, 0x1

    .line 20
    if-eq v3, v4, :cond_0

    .line 21
    .line 22
    move v3, v6

    .line 23
    goto :goto_0

    .line 24
    :cond_0
    move v3, v5

    .line 25
    :goto_0
    and-int/2addr v2, v6

    .line 26
    move-object v14, v1

    .line 27
    check-cast v14, Ll2/t;

    .line 28
    .line 29
    invoke-virtual {v14, v2, v3}, Ll2/t;->O(IZ)Z

    .line 30
    .line 31
    .line 32
    move-result v1

    .line 33
    if-eqz v1, :cond_4

    .line 34
    .line 35
    const/high16 v1, 0x3f800000    # 1.0f

    .line 36
    .line 37
    sget-object v2, Lx2/p;->b:Lx2/p;

    .line 38
    .line 39
    invoke-static {v2, v1}, Landroidx/compose/foundation/layout/d;->c(Lx2/s;F)Lx2/s;

    .line 40
    .line 41
    .line 42
    move-result-object v1

    .line 43
    invoke-static {v5, v6, v14}, Lkp/n;->b(IILl2/o;)Le1/n1;

    .line 44
    .line 45
    .line 46
    move-result-object v3

    .line 47
    const/16 v4, 0xe

    .line 48
    .line 49
    invoke-static {v1, v3, v4}, Lkp/n;->d(Lx2/s;Le1/n1;I)Lx2/s;

    .line 50
    .line 51
    .line 52
    move-result-object v1

    .line 53
    sget-object v3, Lk1/j;->c:Lk1/e;

    .line 54
    .line 55
    sget-object v4, Lx2/c;->p:Lx2/h;

    .line 56
    .line 57
    invoke-static {v3, v4, v14, v5}, Lk1/r;->a(Lk1/i;Lx2/d;Ll2/o;I)Lk1/s;

    .line 58
    .line 59
    .line 60
    move-result-object v3

    .line 61
    iget-wide v4, v14, Ll2/t;->T:J

    .line 62
    .line 63
    invoke-static {v4, v5}, Ljava/lang/Long;->hashCode(J)I

    .line 64
    .line 65
    .line 66
    move-result v4

    .line 67
    invoke-virtual {v14}, Ll2/t;->m()Ll2/p1;

    .line 68
    .line 69
    .line 70
    move-result-object v5

    .line 71
    invoke-static {v14, v1}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 72
    .line 73
    .line 74
    move-result-object v1

    .line 75
    sget-object v7, Lv3/k;->m1:Lv3/j;

    .line 76
    .line 77
    invoke-virtual {v7}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 78
    .line 79
    .line 80
    sget-object v7, Lv3/j;->b:Lv3/i;

    .line 81
    .line 82
    invoke-virtual {v14}, Ll2/t;->c0()V

    .line 83
    .line 84
    .line 85
    iget-boolean v8, v14, Ll2/t;->S:Z

    .line 86
    .line 87
    if-eqz v8, :cond_1

    .line 88
    .line 89
    invoke-virtual {v14, v7}, Ll2/t;->l(Lay0/a;)V

    .line 90
    .line 91
    .line 92
    goto :goto_1

    .line 93
    :cond_1
    invoke-virtual {v14}, Ll2/t;->m0()V

    .line 94
    .line 95
    .line 96
    :goto_1
    sget-object v7, Lv3/j;->g:Lv3/h;

    .line 97
    .line 98
    invoke-static {v7, v3, v14}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 99
    .line 100
    .line 101
    sget-object v3, Lv3/j;->f:Lv3/h;

    .line 102
    .line 103
    invoke-static {v3, v5, v14}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 104
    .line 105
    .line 106
    sget-object v3, Lv3/j;->j:Lv3/h;

    .line 107
    .line 108
    iget-boolean v5, v14, Ll2/t;->S:Z

    .line 109
    .line 110
    if-nez v5, :cond_2

    .line 111
    .line 112
    invoke-virtual {v14}, Ll2/t;->L()Ljava/lang/Object;

    .line 113
    .line 114
    .line 115
    move-result-object v5

    .line 116
    invoke-static {v4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 117
    .line 118
    .line 119
    move-result-object v7

    .line 120
    invoke-static {v5, v7}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 121
    .line 122
    .line 123
    move-result v5

    .line 124
    if-nez v5, :cond_3

    .line 125
    .line 126
    :cond_2
    invoke-static {v4, v14, v4, v3}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 127
    .line 128
    .line 129
    :cond_3
    sget-object v3, Lv3/j;->d:Lv3/h;

    .line 130
    .line 131
    invoke-static {v3, v1, v14}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 132
    .line 133
    .line 134
    iget v1, v0, Lwk/g;->d:F

    .line 135
    .line 136
    invoke-static {v2, v1}, Landroidx/compose/foundation/layout/d;->e(Lx2/s;F)Lx2/s;

    .line 137
    .line 138
    .line 139
    move-result-object v20

    .line 140
    const/16 v1, 0x12

    .line 141
    .line 142
    int-to-float v1, v1

    .line 143
    new-instance v13, Lk1/a1;

    .line 144
    .line 145
    invoke-direct {v13, v1, v1, v1, v1}, Lk1/a1;-><init>(FFFF)V

    .line 146
    .line 147
    .line 148
    const/16 v1, 0x10

    .line 149
    .line 150
    int-to-float v7, v1

    .line 151
    new-instance v3, Ldl/h;

    .line 152
    .line 153
    const/16 v4, 0xb

    .line 154
    .line 155
    iget-object v5, v0, Lwk/g;->g:Lzh/j;

    .line 156
    .line 157
    iget-object v8, v0, Lwk/g;->h:Lay0/k;

    .line 158
    .line 159
    invoke-direct {v3, v4, v5, v8}, Ldl/h;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 160
    .line 161
    .line 162
    const v4, 0x5702316b

    .line 163
    .line 164
    .line 165
    invoke-static {v4, v14, v3}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 166
    .line 167
    .line 168
    move-result-object v18

    .line 169
    move-object v3, v8

    .line 170
    const/16 v9, 0x3fd0

    .line 171
    .line 172
    const/4 v10, 0x0

    .line 173
    const/4 v11, 0x0

    .line 174
    const/4 v12, 0x0

    .line 175
    const/4 v15, 0x0

    .line 176
    iget-object v4, v0, Lwk/g;->f:Lzb/e0;

    .line 177
    .line 178
    iget-object v8, v0, Lwk/g;->e:Lp1/v;

    .line 179
    .line 180
    const/16 v19, 0x0

    .line 181
    .line 182
    const/16 v21, 0x0

    .line 183
    .line 184
    const/16 v22, 0x0

    .line 185
    .line 186
    move-object/from16 v16, v4

    .line 187
    .line 188
    move-object/from16 v17, v8

    .line 189
    .line 190
    const v8, 0x30180

    .line 191
    .line 192
    .line 193
    invoke-static/range {v7 .. v22}, Ljp/ad;->b(FIILe1/j;Lh1/g;Lh1/n;Lk1/z0;Ll2/o;Lo3/a;Lp1/f;Lp1/v;Lt2/b;Lx2/i;Lx2/s;ZZ)V

    .line 194
    .line 195
    .line 196
    move v4, v7

    .line 197
    iget-object v7, v5, Lzh/j;->a:Ljava/util/ArrayList;

    .line 198
    .line 199
    invoke-virtual {v7}, Ljava/util/ArrayList;->size()I

    .line 200
    .line 201
    .line 202
    move-result v13

    .line 203
    invoke-virtual/range {v17 .. v17}, Lp1/v;->k()I

    .line 204
    .line 205
    .line 206
    move-result v15

    .line 207
    invoke-static {v14, v1}, Lwk/a;->x(Ll2/o;I)F

    .line 208
    .line 209
    .line 210
    move-result v9

    .line 211
    const/4 v11, 0x0

    .line 212
    const/16 v12, 0xd

    .line 213
    .line 214
    const/4 v8, 0x0

    .line 215
    const/4 v10, 0x0

    .line 216
    move-object v7, v2

    .line 217
    invoke-static/range {v7 .. v12}, Landroidx/compose/foundation/layout/a;->q(Lx2/s;FFFFI)Lx2/s;

    .line 218
    .line 219
    .line 220
    move-result-object v1

    .line 221
    sget-object v7, Lx2/c;->q:Lx2/h;

    .line 222
    .line 223
    invoke-static {v7, v1}, Lia/b;->p(Lx2/h;Lx2/s;)Lx2/s;

    .line 224
    .line 225
    .line 226
    move-result-object v12

    .line 227
    const/4 v9, 0x0

    .line 228
    const/4 v10, 0x0

    .line 229
    move v7, v13

    .line 230
    move-object v11, v14

    .line 231
    move v8, v15

    .line 232
    invoke-static/range {v7 .. v12}, Li91/a3;->a(IIIILl2/o;Lx2/s;)V

    .line 233
    .line 234
    .line 235
    invoke-static {v2, v4}, Landroidx/compose/foundation/layout/d;->e(Lx2/s;F)Lx2/s;

    .line 236
    .line 237
    .line 238
    move-result-object v1

    .line 239
    invoke-static {v14, v1}, Lk1/d;->d(Ll2/o;Lx2/s;)V

    .line 240
    .line 241
    .line 242
    iget-object v1, v5, Lzh/j;->a:Ljava/util/ArrayList;

    .line 243
    .line 244
    iget-object v0, v0, Lwk/g;->i:Ll2/g1;

    .line 245
    .line 246
    invoke-virtual {v0}, Ll2/g1;->o()I

    .line 247
    .line 248
    .line 249
    move-result v0

    .line 250
    invoke-virtual {v1, v0}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 251
    .line 252
    .line 253
    move-result-object v0

    .line 254
    check-cast v0, Lzh/a;

    .line 255
    .line 256
    const/16 v1, 0x8

    .line 257
    .line 258
    invoke-static {v0, v3, v14, v1}, Lwk/a;->d(Lzh/a;Lay0/k;Ll2/o;I)V

    .line 259
    .line 260
    .line 261
    invoke-virtual {v14, v6}, Ll2/t;->q(Z)V

    .line 262
    .line 263
    .line 264
    goto :goto_2

    .line 265
    :cond_4
    invoke-virtual {v14}, Ll2/t;->R()V

    .line 266
    .line 267
    .line 268
    :goto_2
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 269
    .line 270
    return-object v0
.end method
