.class public abstract Lvv/x;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:J

.field public static final b:J

.field public static final c:J

.field public static final d:Lvv/b;

.field public static final e:Lvv/b;

.field public static final f:Ll2/e0;


# direct methods
.method static constructor <clinit>()V
    .locals 3

    .line 1
    const/16 v0, 0x8

    .line 2
    .line 3
    invoke-static {v0}, Lgq/b;->c(I)J

    .line 4
    .line 5
    .line 6
    move-result-wide v0

    .line 7
    sput-wide v0, Lvv/x;->a:J

    .line 8
    .line 9
    const/4 v0, 0x4

    .line 10
    invoke-static {v0}, Lgq/b;->c(I)J

    .line 11
    .line 12
    .line 13
    move-result-wide v1

    .line 14
    sput-wide v1, Lvv/x;->b:J

    .line 15
    .line 16
    invoke-static {v0}, Lgq/b;->c(I)J

    .line 17
    .line 18
    .line 19
    move-result-wide v0

    .line 20
    sput-wide v0, Lvv/x;->c:J

    .line 21
    .line 22
    sget-object v0, Lvv/b;->l:Lvv/b;

    .line 23
    .line 24
    sput-object v0, Lvv/x;->d:Lvv/b;

    .line 25
    .line 26
    sget-object v0, Lvv/b;->m:Lvv/b;

    .line 27
    .line 28
    sput-object v0, Lvv/x;->e:Lvv/b;

    .line 29
    .line 30
    sget-object v0, Lvv/s;->g:Lvv/s;

    .line 31
    .line 32
    new-instance v1, Ll2/e0;

    .line 33
    .line 34
    invoke-direct {v1, v0}, Ll2/e0;-><init>(Lay0/a;)V

    .line 35
    .line 36
    .line 37
    sput-object v1, Lvv/x;->f:Ll2/e0;

    .line 38
    .line 39
    return-void
.end method

.method public static final a(Lvv/m0;Lvv/g0;Ljava/util/List;ILt2/b;Ll2/o;II)V
    .locals 12

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    move-object/from16 v6, p5

    .line 7
    .line 8
    check-cast v6, Ll2/t;

    .line 9
    .line 10
    const v0, 0x7698c83e

    .line 11
    .line 12
    .line 13
    invoke-virtual {v6, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 14
    .line 15
    .line 16
    and-int/lit8 v0, p7, 0x4

    .line 17
    .line 18
    if-eqz v0, :cond_0

    .line 19
    .line 20
    const/4 v0, 0x0

    .line 21
    move v4, v0

    .line 22
    goto :goto_0

    .line 23
    :cond_0
    move v4, p3

    .line 24
    :goto_0
    invoke-static {p0, v6}, Lvv/o0;->b(Lvv/m0;Ll2/o;)Lvv/n0;

    .line 25
    .line 26
    .line 27
    move-result-object v0

    .line 28
    invoke-static {v0}, Lvv/o0;->c(Lvv/n0;)Lvv/n0;

    .line 29
    .line 30
    .line 31
    move-result-object v0

    .line 32
    iget-object v2, v0, Lvv/n0;->c:Lvv/f0;

    .line 33
    .line 34
    invoke-static {v2}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 35
    .line 36
    .line 37
    sget-object v0, Lw3/h1;->h:Ll2/u2;

    .line 38
    .line 39
    invoke-virtual {v6, v0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 40
    .line 41
    .line 42
    move-result-object v0

    .line 43
    check-cast v0, Lt4/c;

    .line 44
    .line 45
    iget-object v3, v2, Lvv/f0;->a:Lt4/o;

    .line 46
    .line 47
    invoke-static {v3}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 48
    .line 49
    .line 50
    iget-wide v7, v3, Lt4/o;->a:J

    .line 51
    .line 52
    invoke-interface {v0, v7, v8}, Lt4/c;->s(J)F

    .line 53
    .line 54
    .line 55
    move-result v3

    .line 56
    iget-object v5, v2, Lvv/f0;->b:Lt4/o;

    .line 57
    .line 58
    invoke-static {v5}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 59
    .line 60
    .line 61
    iget-wide v7, v5, Lt4/o;->a:J

    .line 62
    .line 63
    invoke-interface {v0, v7, v8}, Lt4/c;->s(J)F

    .line 64
    .line 65
    .line 66
    move-result v5

    .line 67
    iget-object v7, v2, Lvv/f0;->c:Lt4/o;

    .line 68
    .line 69
    invoke-static {v7}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 70
    .line 71
    .line 72
    iget-wide v7, v7, Lt4/o;->a:J

    .line 73
    .line 74
    invoke-interface {v0, v7, v8}, Lt4/c;->s(J)F

    .line 75
    .line 76
    .line 77
    move-result v7

    .line 78
    sget-object v0, Lvv/x;->f:Ll2/e0;

    .line 79
    .line 80
    invoke-virtual {v6, v0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 81
    .line 82
    .line 83
    move-result-object v0

    .line 84
    check-cast v0, Ljava/lang/Number;

    .line 85
    .line 86
    invoke-virtual {v0}, Ljava/lang/Number;->intValue()I

    .line 87
    .line 88
    .line 89
    move-result v0

    .line 90
    invoke-interface {p2}, Ljava/util/List;->size()I

    .line 91
    .line 92
    .line 93
    move-result v8

    .line 94
    const/16 v9, 0xa

    .line 95
    .line 96
    const/4 v10, 0x0

    .line 97
    invoke-static {v3, v10, v5, v10, v9}, Landroidx/compose/foundation/layout/a;->c(FFFFI)Lk1/a1;

    .line 98
    .line 99
    .line 100
    move-result-object v9

    .line 101
    move v3, v0

    .line 102
    new-instance v0, Lvv/p;

    .line 103
    .line 104
    move-object v1, p1

    .line 105
    move v5, v4

    .line 106
    move v4, v3

    .line 107
    move-object v3, p0

    .line 108
    invoke-direct/range {v0 .. v5}, Lvv/p;-><init>(Lvv/g0;Lvv/f0;Lvv/m0;II)V

    .line 109
    .line 110
    .line 111
    move v3, v4

    .line 112
    move v10, v5

    .line 113
    const v1, 0x21dac50f

    .line 114
    .line 115
    .line 116
    invoke-static {v1, v6, v0}, Lt2/c;->b(ILl2/o;Llx0/e;)Lt2/b;

    .line 117
    .line 118
    .line 119
    move-result-object v11

    .line 120
    new-instance v0, Lvv/r;

    .line 121
    .line 122
    move-object v1, p0

    .line 123
    move-object v5, p2

    .line 124
    move-object/from16 v4, p4

    .line 125
    .line 126
    invoke-direct/range {v0 .. v5}, Lvv/r;-><init>(Lvv/m0;Lvv/f0;ILt2/b;Ljava/util/List;)V

    .line 127
    .line 128
    .line 129
    const v1, -0x136d9830

    .line 130
    .line 131
    .line 132
    invoke-static {v1, v6, v0}, Lt2/c;->b(ILl2/o;Llx0/e;)Lt2/b;

    .line 133
    .line 134
    .line 135
    move-result-object v5

    .line 136
    move v2, v7

    .line 137
    const/16 v7, 0x6c00

    .line 138
    .line 139
    move v1, v8

    .line 140
    move-object v3, v9

    .line 141
    move-object v4, v11

    .line 142
    invoke-static/range {v1 .. v7}, Lvv/x;->b(IFLk1/a1;Lt2/b;Lt2/b;Ll2/o;I)V

    .line 143
    .line 144
    .line 145
    invoke-virtual {v6}, Ll2/t;->s()Ll2/u1;

    .line 146
    .line 147
    .line 148
    move-result-object v8

    .line 149
    if-eqz v8, :cond_1

    .line 150
    .line 151
    new-instance v0, Lym/h;

    .line 152
    .line 153
    move-object v1, p0

    .line 154
    move-object v2, p1

    .line 155
    move-object v3, p2

    .line 156
    move-object/from16 v5, p4

    .line 157
    .line 158
    move/from16 v6, p6

    .line 159
    .line 160
    move/from16 v7, p7

    .line 161
    .line 162
    move v4, v10

    .line 163
    invoke-direct/range {v0 .. v7}, Lym/h;-><init>(Lvv/m0;Lvv/g0;Ljava/util/List;ILt2/b;II)V

    .line 164
    .line 165
    .line 166
    iput-object v0, v8, Ll2/u1;->d:Lay0/n;

    .line 167
    .line 168
    :cond_1
    return-void
.end method

.method public static final b(IFLk1/a1;Lt2/b;Lt2/b;Ll2/o;I)V
    .locals 7

    .line 1
    check-cast p5, Ll2/t;

    .line 2
    .line 3
    const v0, -0x63f200dc

    .line 4
    .line 5
    .line 6
    invoke-virtual {p5, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 7
    .line 8
    .line 9
    invoke-virtual {p5, p0}, Ll2/t;->e(I)Z

    .line 10
    .line 11
    .line 12
    move-result v0

    .line 13
    if-eqz v0, :cond_0

    .line 14
    .line 15
    const/4 v0, 0x4

    .line 16
    goto :goto_0

    .line 17
    :cond_0
    const/4 v0, 0x2

    .line 18
    :goto_0
    or-int/2addr v0, p6

    .line 19
    invoke-virtual {p5, p1}, Ll2/t;->d(F)Z

    .line 20
    .line 21
    .line 22
    move-result v1

    .line 23
    if-eqz v1, :cond_1

    .line 24
    .line 25
    const/16 v1, 0x20

    .line 26
    .line 27
    goto :goto_1

    .line 28
    :cond_1
    const/16 v1, 0x10

    .line 29
    .line 30
    :goto_1
    or-int/2addr v0, v1

    .line 31
    invoke-virtual {p5, p2}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 32
    .line 33
    .line 34
    move-result v1

    .line 35
    if-eqz v1, :cond_2

    .line 36
    .line 37
    const/16 v1, 0x100

    .line 38
    .line 39
    goto :goto_2

    .line 40
    :cond_2
    const/16 v1, 0x80

    .line 41
    .line 42
    :goto_2
    or-int/2addr v0, v1

    .line 43
    const v1, 0xb6db

    .line 44
    .line 45
    .line 46
    and-int/2addr v0, v1

    .line 47
    const/16 v1, 0x2492

    .line 48
    .line 49
    if-ne v0, v1, :cond_4

    .line 50
    .line 51
    invoke-virtual {p5}, Ll2/t;->A()Z

    .line 52
    .line 53
    .line 54
    move-result v0

    .line 55
    if-nez v0, :cond_3

    .line 56
    .line 57
    goto :goto_3

    .line 58
    :cond_3
    invoke-virtual {p5}, Ll2/t;->R()V

    .line 59
    .line 60
    .line 61
    goto/16 :goto_6

    .line 62
    .line 63
    :cond_4
    :goto_3
    const v0, -0x6ad704ba

    .line 64
    .line 65
    .line 66
    invoke-virtual {p5, v0}, Ll2/t;->Z(I)V

    .line 67
    .line 68
    .line 69
    invoke-virtual {p5, p0}, Ll2/t;->e(I)Z

    .line 70
    .line 71
    .line 72
    move-result v0

    .line 73
    invoke-virtual {p5, p1}, Ll2/t;->d(F)Z

    .line 74
    .line 75
    .line 76
    move-result v1

    .line 77
    or-int/2addr v0, v1

    .line 78
    invoke-virtual {p5}, Ll2/t;->L()Ljava/lang/Object;

    .line 79
    .line 80
    .line 81
    move-result-object v1

    .line 82
    if-nez v0, :cond_5

    .line 83
    .line 84
    sget-object v0, Ll2/n;->a:Ll2/x0;

    .line 85
    .line 86
    if-ne v1, v0, :cond_6

    .line 87
    .line 88
    :cond_5
    new-instance v1, Lvv/u;

    .line 89
    .line 90
    invoke-direct {v1, p0, p1}, Lvv/u;-><init>(IF)V

    .line 91
    .line 92
    .line 93
    invoke-virtual {p5, v1}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 94
    .line 95
    .line 96
    :cond_6
    check-cast v1, Lt3/q0;

    .line 97
    .line 98
    const/4 v0, 0x0

    .line 99
    invoke-virtual {p5, v0}, Ll2/t;->q(Z)V

    .line 100
    .line 101
    .line 102
    const v2, -0x4ee9b9da

    .line 103
    .line 104
    .line 105
    invoke-virtual {p5, v2}, Ll2/t;->Z(I)V

    .line 106
    .line 107
    .line 108
    iget-wide v2, p5, Ll2/t;->T:J

    .line 109
    .line 110
    invoke-static {v2, v3}, Ljava/lang/Long;->hashCode(J)I

    .line 111
    .line 112
    .line 113
    move-result v2

    .line 114
    invoke-virtual {p5}, Ll2/t;->m()Ll2/p1;

    .line 115
    .line 116
    .line 117
    move-result-object v3

    .line 118
    sget-object v4, Lv3/k;->m1:Lv3/j;

    .line 119
    .line 120
    invoke-virtual {v4}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 121
    .line 122
    .line 123
    sget-object v4, Lv3/j;->b:Lv3/i;

    .line 124
    .line 125
    sget-object v5, Lx2/p;->b:Lx2/p;

    .line 126
    .line 127
    invoke-static {v5}, Lt3/k1;->k(Lx2/s;)Lt2/b;

    .line 128
    .line 129
    .line 130
    move-result-object v5

    .line 131
    invoke-virtual {p5}, Ll2/t;->c0()V

    .line 132
    .line 133
    .line 134
    iget-boolean v6, p5, Ll2/t;->S:Z

    .line 135
    .line 136
    if-eqz v6, :cond_7

    .line 137
    .line 138
    invoke-virtual {p5, v4}, Ll2/t;->l(Lay0/a;)V

    .line 139
    .line 140
    .line 141
    goto :goto_4

    .line 142
    :cond_7
    invoke-virtual {p5}, Ll2/t;->m0()V

    .line 143
    .line 144
    .line 145
    :goto_4
    sget-object v4, Lv3/j;->g:Lv3/h;

    .line 146
    .line 147
    invoke-static {v4, v1, p5}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 148
    .line 149
    .line 150
    sget-object v1, Lv3/j;->f:Lv3/h;

    .line 151
    .line 152
    invoke-static {v1, v3, p5}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 153
    .line 154
    .line 155
    sget-object v1, Lv3/j;->j:Lv3/h;

    .line 156
    .line 157
    iget-boolean v3, p5, Ll2/t;->S:Z

    .line 158
    .line 159
    if-nez v3, :cond_8

    .line 160
    .line 161
    invoke-virtual {p5}, Ll2/t;->L()Ljava/lang/Object;

    .line 162
    .line 163
    .line 164
    move-result-object v3

    .line 165
    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 166
    .line 167
    .line 168
    move-result-object v4

    .line 169
    invoke-static {v3, v4}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 170
    .line 171
    .line 172
    move-result v3

    .line 173
    if-nez v3, :cond_9

    .line 174
    .line 175
    :cond_8
    invoke-static {v2, p5, v2, v1}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 176
    .line 177
    .line 178
    :cond_9
    new-instance v1, Ll2/d2;

    .line 179
    .line 180
    invoke-direct {v1, p5}, Ll2/d2;-><init>(Ll2/o;)V

    .line 181
    .line 182
    .line 183
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 184
    .line 185
    .line 186
    move-result-object v2

    .line 187
    invoke-virtual {v5, v1, p5, v2}, Lt2/b;->invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 188
    .line 189
    .line 190
    const v1, 0x7ab4aae9

    .line 191
    .line 192
    .line 193
    invoke-virtual {p5, v1}, Ll2/t;->Z(I)V

    .line 194
    .line 195
    .line 196
    new-instance v1, Ljn/g;

    .line 197
    .line 198
    invoke-direct {v1, p0, p2, p3}, Ljn/g;-><init>(ILk1/a1;Lt2/b;)V

    .line 199
    .line 200
    .line 201
    const v2, -0x762e8b14

    .line 202
    .line 203
    .line 204
    invoke-static {v2, p5, v1}, Lt2/c;->b(ILl2/o;Llx0/e;)Lt2/b;

    .line 205
    .line 206
    .line 207
    move-result-object v1

    .line 208
    const/4 v2, 0x6

    .line 209
    invoke-static {v1, p5, v2}, Lkp/r;->a(Lt2/b;Ll2/o;I)V

    .line 210
    .line 211
    .line 212
    const v1, -0x1717c186

    .line 213
    .line 214
    .line 215
    invoke-virtual {p5, v1}, Ll2/t;->Z(I)V

    .line 216
    .line 217
    .line 218
    move v1, v0

    .line 219
    :goto_5
    if-ge v1, p0, :cond_a

    .line 220
    .line 221
    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 222
    .line 223
    .line 224
    move-result-object v2

    .line 225
    const/16 v3, 0x30

    .line 226
    .line 227
    invoke-static {v3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 228
    .line 229
    .line 230
    move-result-object v3

    .line 231
    invoke-virtual {p4, v2, p5, v3}, Lt2/b;->invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 232
    .line 233
    .line 234
    add-int/lit8 v1, v1, 0x1

    .line 235
    .line 236
    goto :goto_5

    .line 237
    :cond_a
    invoke-virtual {p5, v0}, Ll2/t;->q(Z)V

    .line 238
    .line 239
    .line 240
    invoke-virtual {p5, v0}, Ll2/t;->q(Z)V

    .line 241
    .line 242
    .line 243
    const/4 v1, 0x1

    .line 244
    invoke-virtual {p5, v1}, Ll2/t;->q(Z)V

    .line 245
    .line 246
    .line 247
    invoke-virtual {p5, v0}, Ll2/t;->q(Z)V

    .line 248
    .line 249
    .line 250
    :goto_6
    invoke-virtual {p5}, Ll2/t;->s()Ll2/u1;

    .line 251
    .line 252
    .line 253
    move-result-object p5

    .line 254
    if-eqz p5, :cond_b

    .line 255
    .line 256
    new-instance v0, Lvv/v;

    .line 257
    .line 258
    move v1, p0

    .line 259
    move v2, p1

    .line 260
    move-object v3, p2

    .line 261
    move-object v4, p3

    .line 262
    move-object v5, p4

    .line 263
    move v6, p6

    .line 264
    invoke-direct/range {v0 .. v6}, Lvv/v;-><init>(IFLk1/a1;Lt2/b;Lt2/b;I)V

    .line 265
    .line 266
    .line 267
    iput-object v0, p5, Ll2/u1;->d:Lay0/n;

    .line 268
    .line 269
    :cond_b
    return-void
.end method

.method public static final c(Lt2/b;Ll2/o;I)V
    .locals 3

    .line 1
    check-cast p1, Ll2/t;

    .line 2
    .line 3
    const v0, -0xf682291    # -3.7599947E29f

    .line 4
    .line 5
    .line 6
    invoke-virtual {p1, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 7
    .line 8
    .line 9
    and-int/lit8 v0, p2, 0xb

    .line 10
    .line 11
    const/4 v1, 0x2

    .line 12
    if-ne v0, v1, :cond_1

    .line 13
    .line 14
    invoke-virtual {p1}, Ll2/t;->A()Z

    .line 15
    .line 16
    .line 17
    move-result v0

    .line 18
    if-nez v0, :cond_0

    .line 19
    .line 20
    goto :goto_0

    .line 21
    :cond_0
    invoke-virtual {p1}, Ll2/t;->R()V

    .line 22
    .line 23
    .line 24
    goto :goto_1

    .line 25
    :cond_1
    :goto_0
    const/4 v0, 0x0

    .line 26
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 27
    .line 28
    .line 29
    move-result-object v0

    .line 30
    sget-object v1, Lvv/x;->f:Ll2/e0;

    .line 31
    .line 32
    invoke-virtual {v1, v0}, Ll2/e0;->a(Ljava/lang/Object;)Ll2/t1;

    .line 33
    .line 34
    .line 35
    move-result-object v0

    .line 36
    new-instance v1, Lvv/w;

    .line 37
    .line 38
    const/4 v2, 0x0

    .line 39
    invoke-direct {v1, p0, v2}, Lvv/w;-><init>(Lt2/b;I)V

    .line 40
    .line 41
    .line 42
    const v2, -0x65c9df51

    .line 43
    .line 44
    .line 45
    invoke-static {v2, p1, v1}, Lt2/c;->b(ILl2/o;Llx0/e;)Lt2/b;

    .line 46
    .line 47
    .line 48
    move-result-object v1

    .line 49
    const/16 v2, 0x38

    .line 50
    .line 51
    invoke-static {v0, v1, p1, v2}, Ll2/b;->a(Ll2/t1;Lay0/n;Ll2/o;I)V

    .line 52
    .line 53
    .line 54
    :goto_1
    invoke-virtual {p1}, Ll2/t;->s()Ll2/u1;

    .line 55
    .line 56
    .line 57
    move-result-object p1

    .line 58
    if-eqz p1, :cond_2

    .line 59
    .line 60
    new-instance v0, Lvv/w;

    .line 61
    .line 62
    const/4 v1, 0x1

    .line 63
    invoke-direct {v0, p0, p2, v1}, Lvv/w;-><init>(Lt2/b;II)V

    .line 64
    .line 65
    .line 66
    iput-object v0, p1, Ll2/u1;->d:Lay0/n;

    .line 67
    .line 68
    :cond_2
    return-void
.end method

.method public static final varargs d(Lvv/m0;[Ljava/lang/String;)Lvv/d1;
    .locals 2

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    new-instance v0, Lb1/z;

    .line 7
    .line 8
    const/4 v1, 0x1

    .line 9
    invoke-direct {v0, v1, p0, p1}, Lb1/z;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 10
    .line 11
    .line 12
    new-instance p0, Lt2/b;

    .line 13
    .line 14
    const/4 p1, 0x1

    .line 15
    const v1, 0xe90c41

    .line 16
    .line 17
    .line 18
    invoke-direct {p0, v0, p1, v1}, Lt2/b;-><init>(Ljava/lang/Object;ZI)V

    .line 19
    .line 20
    .line 21
    new-instance p1, Lvv/d1;

    .line 22
    .line 23
    invoke-direct {p1, p0}, Lvv/d1;-><init>(Lt2/b;)V

    .line 24
    .line 25
    .line 26
    return-object p1
.end method
