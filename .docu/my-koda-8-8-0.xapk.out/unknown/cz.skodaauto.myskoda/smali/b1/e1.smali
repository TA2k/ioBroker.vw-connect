.class public final Lb1/e1;
.super Lb1/z0;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public s:Lc1/j;

.field public t:J

.field public u:J

.field public v:Z

.field public final w:Ll2/j1;


# direct methods
.method public constructor <init>(Lc1/j;)V
    .locals 2

    .line 1
    const/4 v0, 0x0

    .line 2
    invoke-direct {p0, v0}, Lb1/z0;-><init>(I)V

    .line 3
    .line 4
    .line 5
    iput-object p1, p0, Lb1/e1;->s:Lc1/j;

    .line 6
    .line 7
    sget-wide v0, Landroidx/compose/animation/c;->a:J

    .line 8
    .line 9
    iput-wide v0, p0, Lb1/e1;->t:J

    .line 10
    .line 11
    const/4 p1, 0x0

    .line 12
    const/16 v0, 0xf

    .line 13
    .line 14
    invoke-static {p1, p1, v0}, Lt4/b;->b(III)J

    .line 15
    .line 16
    .line 17
    move-result-wide v0

    .line 18
    iput-wide v0, p0, Lb1/e1;->u:J

    .line 19
    .line 20
    const/4 p1, 0x0

    .line 21
    invoke-static {p1}, Ll2/b;->n(Ljava/lang/Object;)Ll2/j1;

    .line 22
    .line 23
    .line 24
    move-result-object p1

    .line 25
    iput-object p1, p0, Lb1/e1;->w:Ll2/j1;

    .line 26
    .line 27
    return-void
.end method


# virtual methods
.method public final P0()V
    .locals 2

    .line 1
    sget-wide v0, Landroidx/compose/animation/c;->a:J

    .line 2
    .line 3
    iput-wide v0, p0, Lb1/e1;->t:J

    .line 4
    .line 5
    const/4 v0, 0x0

    .line 6
    iput-boolean v0, p0, Lb1/e1;->v:Z

    .line 7
    .line 8
    return-void
.end method

.method public final R0()V
    .locals 1

    .line 1
    const/4 v0, 0x0

    .line 2
    iget-object p0, p0, Lb1/e1;->w:Ll2/j1;

    .line 3
    .line 4
    invoke-virtual {p0, v0}, Ll2/j1;->setValue(Ljava/lang/Object;)V

    .line 5
    .line 6
    .line 7
    return-void
.end method

.method public final c(Lt3/s0;Lt3/p0;J)Lt3/r0;
    .locals 20

    .line 1
    move-object/from16 v1, p0

    .line 2
    .line 3
    move-wide/from16 v6, p3

    .line 4
    .line 5
    invoke-interface/range {p1 .. p1}, Lt3/t;->I()Z

    .line 6
    .line 7
    .line 8
    move-result v0

    .line 9
    const/4 v2, 0x1

    .line 10
    if-eqz v0, :cond_0

    .line 11
    .line 12
    iput-wide v6, v1, Lb1/e1;->u:J

    .line 13
    .line 14
    iput-boolean v2, v1, Lb1/e1;->v:Z

    .line 15
    .line 16
    invoke-interface/range {p2 .. p4}, Lt3/p0;->L(J)Lt3/e1;

    .line 17
    .line 18
    .line 19
    move-result-object v0

    .line 20
    :goto_0
    move-object v8, v0

    .line 21
    goto :goto_3

    .line 22
    :cond_0
    iget-boolean v0, v1, Lb1/e1;->v:Z

    .line 23
    .line 24
    if-eqz v0, :cond_1

    .line 25
    .line 26
    iget-wide v3, v1, Lb1/e1;->u:J

    .line 27
    .line 28
    :goto_1
    move-object/from16 v0, p2

    .line 29
    .line 30
    goto :goto_2

    .line 31
    :cond_1
    move-wide v3, v6

    .line 32
    goto :goto_1

    .line 33
    :goto_2
    invoke-interface {v0, v3, v4}, Lt3/p0;->L(J)Lt3/e1;

    .line 34
    .line 35
    .line 36
    move-result-object v0

    .line 37
    goto :goto_0

    .line 38
    :goto_3
    iget v0, v8, Lt3/e1;->d:I

    .line 39
    .line 40
    iget v3, v8, Lt3/e1;->e:I

    .line 41
    .line 42
    int-to-long v4, v0

    .line 43
    const/16 v9, 0x20

    .line 44
    .line 45
    shl-long/2addr v4, v9

    .line 46
    int-to-long v10, v3

    .line 47
    const-wide v12, 0xffffffffL

    .line 48
    .line 49
    .line 50
    .line 51
    .line 52
    and-long/2addr v10, v12

    .line 53
    or-long/2addr v10, v4

    .line 54
    invoke-interface/range {p1 .. p1}, Lt3/t;->I()Z

    .line 55
    .line 56
    .line 57
    move-result v0

    .line 58
    if-eqz v0, :cond_2

    .line 59
    .line 60
    iput-wide v10, v1, Lb1/e1;->t:J

    .line 61
    .line 62
    move/from16 p2, v9

    .line 63
    .line 64
    move-wide v0, v10

    .line 65
    move-wide/from16 v16, v0

    .line 66
    .line 67
    goto/16 :goto_9

    .line 68
    .line 69
    :cond_2
    iget-wide v3, v1, Lb1/e1;->t:J

    .line 70
    .line 71
    sget-wide v14, Landroidx/compose/animation/c;->a:J

    .line 72
    .line 73
    invoke-static {v3, v4, v14, v15}, Lt4/l;->a(JJ)Z

    .line 74
    .line 75
    .line 76
    move-result v0

    .line 77
    if-nez v0, :cond_3

    .line 78
    .line 79
    iget-wide v3, v1, Lb1/e1;->t:J

    .line 80
    .line 81
    goto :goto_4

    .line 82
    :cond_3
    move-wide v3, v10

    .line 83
    :goto_4
    iget-object v14, v1, Lb1/e1;->w:Ll2/j1;

    .line 84
    .line 85
    invoke-virtual {v14}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 86
    .line 87
    .line 88
    move-result-object v0

    .line 89
    check-cast v0, Lb1/b1;

    .line 90
    .line 91
    if-eqz v0, :cond_7

    .line 92
    .line 93
    iget-object v5, v0, Lb1/b1;->a:Lc1/c;

    .line 94
    .line 95
    invoke-virtual {v5}, Lc1/c;->d()Ljava/lang/Object;

    .line 96
    .line 97
    .line 98
    move-result-object v15

    .line 99
    check-cast v15, Lt4/l;

    .line 100
    .line 101
    move/from16 p2, v9

    .line 102
    .line 103
    move-wide/from16 v16, v10

    .line 104
    .line 105
    iget-wide v9, v15, Lt4/l;->a:J

    .line 106
    .line 107
    invoke-static {v3, v4, v9, v10}, Lt4/l;->a(JJ)Z

    .line 108
    .line 109
    .line 110
    move-result v9

    .line 111
    if-nez v9, :cond_4

    .line 112
    .line 113
    invoke-virtual {v5}, Lc1/c;->e()Z

    .line 114
    .line 115
    .line 116
    move-result v9

    .line 117
    if-nez v9, :cond_4

    .line 118
    .line 119
    goto :goto_5

    .line 120
    :cond_4
    const/4 v2, 0x0

    .line 121
    :goto_5
    iget-object v9, v5, Lc1/c;->e:Ll2/j1;

    .line 122
    .line 123
    invoke-virtual {v9}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 124
    .line 125
    .line 126
    move-result-object v9

    .line 127
    check-cast v9, Lt4/l;

    .line 128
    .line 129
    iget-wide v9, v9, Lt4/l;->a:J

    .line 130
    .line 131
    invoke-static {v3, v4, v9, v10}, Lt4/l;->a(JJ)Z

    .line 132
    .line 133
    .line 134
    move-result v9

    .line 135
    if-eqz v9, :cond_6

    .line 136
    .line 137
    if-eqz v2, :cond_5

    .line 138
    .line 139
    goto :goto_6

    .line 140
    :cond_5
    move-object v1, v0

    .line 141
    goto :goto_7

    .line 142
    :cond_6
    :goto_6
    invoke-virtual {v5}, Lc1/c;->d()Ljava/lang/Object;

    .line 143
    .line 144
    .line 145
    move-result-object v2

    .line 146
    check-cast v2, Lt4/l;

    .line 147
    .line 148
    iget-wide v9, v2, Lt4/l;->a:J

    .line 149
    .line 150
    iput-wide v9, v0, Lb1/b1;->b:J

    .line 151
    .line 152
    invoke-virtual {v1}, Lx2/r;->L0()Lvy0/b0;

    .line 153
    .line 154
    .line 155
    move-result-object v9

    .line 156
    move-object v1, v0

    .line 157
    new-instance v0, Lb1/c1;

    .line 158
    .line 159
    const/4 v5, 0x0

    .line 160
    move-wide v2, v3

    .line 161
    move-object/from16 v4, p0

    .line 162
    .line 163
    invoke-direct/range {v0 .. v5}, Lb1/c1;-><init>(Lb1/b1;JLb1/e1;Lkotlin/coroutines/Continuation;)V

    .line 164
    .line 165
    .line 166
    const/4 v2, 0x3

    .line 167
    const/4 v3, 0x0

    .line 168
    invoke-static {v9, v3, v3, v0, v2}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 169
    .line 170
    .line 171
    :goto_7
    move-object v0, v1

    .line 172
    goto :goto_8

    .line 173
    :cond_7
    move/from16 p2, v9

    .line 174
    .line 175
    move-wide/from16 v16, v10

    .line 176
    .line 177
    new-instance v0, Lb1/b1;

    .line 178
    .line 179
    new-instance v1, Lc1/c;

    .line 180
    .line 181
    new-instance v5, Lt4/l;

    .line 182
    .line 183
    invoke-direct {v5, v3, v4}, Lt4/l;-><init>(J)V

    .line 184
    .line 185
    .line 186
    sget-object v9, Lc1/d;->q:Lc1/b2;

    .line 187
    .line 188
    int-to-long v10, v2

    .line 189
    shl-long v18, v10, p2

    .line 190
    .line 191
    and-long/2addr v10, v12

    .line 192
    or-long v10, v18, v10

    .line 193
    .line 194
    new-instance v2, Lt4/l;

    .line 195
    .line 196
    invoke-direct {v2, v10, v11}, Lt4/l;-><init>(J)V

    .line 197
    .line 198
    .line 199
    const/16 v10, 0x8

    .line 200
    .line 201
    invoke-direct {v1, v5, v9, v2, v10}, Lc1/c;-><init>(Ljava/lang/Object;Lc1/b2;Ljava/lang/Object;I)V

    .line 202
    .line 203
    .line 204
    invoke-direct {v0, v1, v3, v4}, Lb1/b1;-><init>(Lc1/c;J)V

    .line 205
    .line 206
    .line 207
    :goto_8
    invoke-virtual {v14, v0}, Ll2/j1;->setValue(Ljava/lang/Object;)V

    .line 208
    .line 209
    .line 210
    iget-object v0, v0, Lb1/b1;->a:Lc1/c;

    .line 211
    .line 212
    invoke-virtual {v0}, Lc1/c;->d()Ljava/lang/Object;

    .line 213
    .line 214
    .line 215
    move-result-object v0

    .line 216
    check-cast v0, Lt4/l;

    .line 217
    .line 218
    iget-wide v0, v0, Lt4/l;->a:J

    .line 219
    .line 220
    invoke-static {v6, v7, v0, v1}, Lt4/b;->d(JJ)J

    .line 221
    .line 222
    .line 223
    move-result-wide v0

    .line 224
    :goto_9
    shr-long v2, v0, p2

    .line 225
    .line 226
    long-to-int v4, v2

    .line 227
    and-long/2addr v0, v12

    .line 228
    long-to-int v5, v0

    .line 229
    new-instance v0, Lb1/d1;

    .line 230
    .line 231
    move-object/from16 v1, p0

    .line 232
    .line 233
    move-object/from16 v6, p1

    .line 234
    .line 235
    move-object v7, v8

    .line 236
    move-wide/from16 v2, v16

    .line 237
    .line 238
    invoke-direct/range {v0 .. v7}, Lb1/d1;-><init>(Lb1/e1;JIILt3/s0;Lt3/e1;)V

    .line 239
    .line 240
    .line 241
    sget-object v1, Lmx0/t;->d:Lmx0/t;

    .line 242
    .line 243
    invoke-interface {v6, v4, v5, v1, v0}, Lt3/s0;->c0(IILjava/util/Map;Lay0/k;)Lt3/r0;

    .line 244
    .line 245
    .line 246
    move-result-object v0

    .line 247
    return-object v0
.end method
