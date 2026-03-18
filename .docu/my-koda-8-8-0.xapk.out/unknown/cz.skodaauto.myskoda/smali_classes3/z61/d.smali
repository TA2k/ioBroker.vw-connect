.class public final synthetic Lz61/d;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/o;


# instance fields
.field public final synthetic d:Z

.field public final synthetic e:Z

.field public final synthetic f:Z

.field public final synthetic g:Lay0/a;

.field public final synthetic h:Lay0/a;

.field public final synthetic i:Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError;

.field public final synthetic j:J


# direct methods
.method public synthetic constructor <init>(ZZZLay0/a;Lay0/a;Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError;J)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-boolean p1, p0, Lz61/d;->d:Z

    .line 5
    .line 6
    iput-boolean p2, p0, Lz61/d;->e:Z

    .line 7
    .line 8
    iput-boolean p3, p0, Lz61/d;->f:Z

    .line 9
    .line 10
    iput-object p4, p0, Lz61/d;->g:Lay0/a;

    .line 11
    .line 12
    iput-object p5, p0, Lz61/d;->h:Lay0/a;

    .line 13
    .line 14
    iput-object p6, p0, Lz61/d;->i:Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError;

    .line 15
    .line 16
    iput-wide p7, p0, Lz61/d;->j:J

    .line 17
    .line 18
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 18

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    check-cast v1, Lk1/q;

    .line 6
    .line 7
    move-object/from16 v2, p2

    .line 8
    .line 9
    check-cast v2, Ll2/o;

    .line 10
    .line 11
    move-object/from16 v3, p3

    .line 12
    .line 13
    check-cast v3, Ljava/lang/Integer;

    .line 14
    .line 15
    invoke-virtual {v3}, Ljava/lang/Integer;->intValue()I

    .line 16
    .line 17
    .line 18
    move-result v3

    .line 19
    const-string v4, "$this$FuSiScaffold"

    .line 20
    .line 21
    invoke-static {v1, v4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 22
    .line 23
    .line 24
    and-int/lit8 v4, v3, 0x6

    .line 25
    .line 26
    if-nez v4, :cond_1

    .line 27
    .line 28
    move-object v4, v2

    .line 29
    check-cast v4, Ll2/t;

    .line 30
    .line 31
    invoke-virtual {v4, v1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 32
    .line 33
    .line 34
    move-result v4

    .line 35
    if-eqz v4, :cond_0

    .line 36
    .line 37
    const/4 v4, 0x4

    .line 38
    goto :goto_0

    .line 39
    :cond_0
    const/4 v4, 0x2

    .line 40
    :goto_0
    or-int/2addr v3, v4

    .line 41
    :cond_1
    and-int/lit8 v4, v3, 0x13

    .line 42
    .line 43
    const/16 v5, 0x12

    .line 44
    .line 45
    const/4 v6, 0x1

    .line 46
    const/4 v7, 0x0

    .line 47
    if-eq v4, v5, :cond_2

    .line 48
    .line 49
    move v4, v6

    .line 50
    goto :goto_1

    .line 51
    :cond_2
    move v4, v7

    .line 52
    :goto_1
    and-int/2addr v3, v6

    .line 53
    move-object v14, v2

    .line 54
    check-cast v14, Ll2/t;

    .line 55
    .line 56
    invoke-virtual {v14, v3, v4}, Ll2/t;->O(IZ)Z

    .line 57
    .line 58
    .line 59
    move-result v2

    .line 60
    if-eqz v2, :cond_8

    .line 61
    .line 62
    sget-object v2, Lx2/p;->b:Lx2/p;

    .line 63
    .line 64
    const/high16 v3, 0x3f800000    # 1.0f

    .line 65
    .line 66
    invoke-static {v2, v3}, Landroidx/compose/foundation/layout/d;->d(Lx2/s;F)Lx2/s;

    .line 67
    .line 68
    .line 69
    move-result-object v2

    .line 70
    sget-object v4, Lx2/c;->h:Lx2/j;

    .line 71
    .line 72
    invoke-interface {v1, v2, v4}, Lk1/q;->a(Lx2/s;Lx2/e;)Lx2/s;

    .line 73
    .line 74
    .line 75
    move-result-object v1

    .line 76
    sget-object v2, Lx2/c;->q:Lx2/h;

    .line 77
    .line 78
    sget-object v4, Lk1/j;->e:Lk1/f;

    .line 79
    .line 80
    const/16 v5, 0x36

    .line 81
    .line 82
    invoke-static {v4, v2, v14, v5}, Lk1/r;->a(Lk1/i;Lx2/d;Ll2/o;I)Lk1/s;

    .line 83
    .line 84
    .line 85
    move-result-object v2

    .line 86
    iget-wide v4, v14, Ll2/t;->T:J

    .line 87
    .line 88
    invoke-static {v4, v5}, Ljava/lang/Long;->hashCode(J)I

    .line 89
    .line 90
    .line 91
    move-result v4

    .line 92
    invoke-virtual {v14}, Ll2/t;->m()Ll2/p1;

    .line 93
    .line 94
    .line 95
    move-result-object v5

    .line 96
    invoke-static {v14, v1}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 97
    .line 98
    .line 99
    move-result-object v1

    .line 100
    sget-object v8, Lv3/k;->m1:Lv3/j;

    .line 101
    .line 102
    invoke-virtual {v8}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 103
    .line 104
    .line 105
    sget-object v8, Lv3/j;->b:Lv3/i;

    .line 106
    .line 107
    invoke-virtual {v14}, Ll2/t;->c0()V

    .line 108
    .line 109
    .line 110
    iget-boolean v9, v14, Ll2/t;->S:Z

    .line 111
    .line 112
    if-eqz v9, :cond_3

    .line 113
    .line 114
    invoke-virtual {v14, v8}, Ll2/t;->l(Lay0/a;)V

    .line 115
    .line 116
    .line 117
    goto :goto_2

    .line 118
    :cond_3
    invoke-virtual {v14}, Ll2/t;->m0()V

    .line 119
    .line 120
    .line 121
    :goto_2
    sget-object v8, Lv3/j;->g:Lv3/h;

    .line 122
    .line 123
    invoke-static {v8, v2, v14}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 124
    .line 125
    .line 126
    sget-object v2, Lv3/j;->f:Lv3/h;

    .line 127
    .line 128
    invoke-static {v2, v5, v14}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 129
    .line 130
    .line 131
    sget-object v2, Lv3/j;->j:Lv3/h;

    .line 132
    .line 133
    iget-boolean v5, v14, Ll2/t;->S:Z

    .line 134
    .line 135
    if-nez v5, :cond_4

    .line 136
    .line 137
    invoke-virtual {v14}, Ll2/t;->L()Ljava/lang/Object;

    .line 138
    .line 139
    .line 140
    move-result-object v5

    .line 141
    invoke-static {v4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 142
    .line 143
    .line 144
    move-result-object v8

    .line 145
    invoke-static {v5, v8}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 146
    .line 147
    .line 148
    move-result v5

    .line 149
    if-nez v5, :cond_5

    .line 150
    .line 151
    :cond_4
    invoke-static {v4, v14, v4, v2}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 152
    .line 153
    .line 154
    :cond_5
    sget-object v2, Lv3/j;->d:Lv3/h;

    .line 155
    .line 156
    invoke-static {v2, v1, v14}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 157
    .line 158
    .line 159
    float-to-double v1, v3

    .line 160
    const-wide/16 v4, 0x0

    .line 161
    .line 162
    cmpl-double v1, v1, v4

    .line 163
    .line 164
    if-lez v1, :cond_6

    .line 165
    .line 166
    goto :goto_3

    .line 167
    :cond_6
    const-string v1, "invalid weight; must be greater than zero"

    .line 168
    .line 169
    invoke-static {v1}, Ll1/a;->a(Ljava/lang/String;)V

    .line 170
    .line 171
    .line 172
    :goto_3
    new-instance v8, Landroidx/compose/foundation/layout/LayoutWeightElement;

    .line 173
    .line 174
    invoke-direct {v8, v3, v7}, Landroidx/compose/foundation/layout/LayoutWeightElement;-><init>(FZ)V

    .line 175
    .line 176
    .line 177
    iget-boolean v1, v0, Lz61/d;->d:Z

    .line 178
    .line 179
    iget-boolean v9, v0, Lz61/d;->e:Z

    .line 180
    .line 181
    iget-boolean v10, v0, Lz61/d;->f:Z

    .line 182
    .line 183
    iget-object v11, v0, Lz61/d;->g:Lay0/a;

    .line 184
    .line 185
    iget-object v12, v0, Lz61/d;->h:Lay0/a;

    .line 186
    .line 187
    if-eqz v1, :cond_7

    .line 188
    .line 189
    const v0, 0x14a89f2d

    .line 190
    .line 191
    .line 192
    invoke-virtual {v14, v0}, Ll2/t;->Y(I)V

    .line 193
    .line 194
    .line 195
    sget-object v0, Lh71/u;->a:Ll2/u2;

    .line 196
    .line 197
    invoke-virtual {v14, v0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 198
    .line 199
    .line 200
    move-result-object v1

    .line 201
    check-cast v1, Lh71/t;

    .line 202
    .line 203
    iget v1, v1, Lh71/t;->e:F

    .line 204
    .line 205
    invoke-virtual {v14, v0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 206
    .line 207
    .line 208
    move-result-object v0

    .line 209
    check-cast v0, Lh71/t;

    .line 210
    .line 211
    iget v0, v0, Lh71/t;->e:F

    .line 212
    .line 213
    invoke-static {v8, v1, v0}, Landroidx/compose/foundation/layout/a;->n(Lx2/s;FF)Lx2/s;

    .line 214
    .line 215
    .line 216
    move-result-object v0

    .line 217
    const v1, 0x3f4ccccd    # 0.8f

    .line 218
    .line 219
    .line 220
    invoke-static {v0, v1}, Landroidx/compose/foundation/layout/d;->d(Lx2/s;F)Lx2/s;

    .line 221
    .line 222
    .line 223
    move-result-object v8

    .line 224
    const/4 v15, 0x0

    .line 225
    move-object v13, v12

    .line 226
    invoke-static/range {v8 .. v15}, Lz61/h;->a(Lx2/s;ZZLay0/a;Lay0/a;Lay0/a;Ll2/o;I)V

    .line 227
    .line 228
    .line 229
    invoke-virtual {v14, v7}, Ll2/t;->q(Z)V

    .line 230
    .line 231
    .line 232
    goto :goto_4

    .line 233
    :cond_7
    const v1, 0x14b53844

    .line 234
    .line 235
    .line 236
    invoke-virtual {v14, v1}, Ll2/t;->Y(I)V

    .line 237
    .line 238
    .line 239
    const/16 v17, 0x0

    .line 240
    .line 241
    move-object/from16 v16, v14

    .line 242
    .line 243
    move-object v14, v11

    .line 244
    move v11, v10

    .line 245
    iget-object v10, v0, Lz61/d;->i:Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError;

    .line 246
    .line 247
    iget-wide v0, v0, Lz61/d;->j:J

    .line 248
    .line 249
    move-object v15, v12

    .line 250
    move-wide v12, v0

    .line 251
    invoke-static/range {v8 .. v17}, Lz61/h;->b(Landroidx/compose/foundation/layout/LayoutWeightElement;ZLtechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/InterruptionError;ZJLay0/a;Lay0/a;Ll2/o;I)V

    .line 252
    .line 253
    .line 254
    move-object/from16 v14, v16

    .line 255
    .line 256
    invoke-virtual {v14, v7}, Ll2/t;->q(Z)V

    .line 257
    .line 258
    .line 259
    :goto_4
    invoke-virtual {v14, v6}, Ll2/t;->q(Z)V

    .line 260
    .line 261
    .line 262
    goto :goto_5

    .line 263
    :cond_8
    invoke-virtual {v14}, Ll2/t;->R()V

    .line 264
    .line 265
    .line 266
    :goto_5
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 267
    .line 268
    return-object v0
.end method
