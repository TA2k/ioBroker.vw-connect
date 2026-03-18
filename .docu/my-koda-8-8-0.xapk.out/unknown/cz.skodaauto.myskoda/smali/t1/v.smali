.class public final Lt1/v;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:Lt1/p0;

.field public final synthetic e:Lg4/p0;

.field public final synthetic f:I

.field public final synthetic g:I

.field public final synthetic h:Lt1/h1;

.field public final synthetic i:Ll4/v;

.field public final synthetic j:Ll4/d0;

.field public final synthetic k:Lx2/s;

.field public final synthetic l:Lx2/s;

.field public final synthetic m:Lx2/s;

.field public final synthetic n:Lx2/s;

.field public final synthetic o:Lq1/b;

.field public final synthetic p:Le2/w0;

.field public final synthetic q:Z

.field public final synthetic r:Z

.field public final synthetic s:Lay0/k;

.field public final synthetic t:Ll4/p;

.field public final synthetic u:Lt4/c;


# direct methods
.method public constructor <init>(Lt1/p0;Lg4/p0;IILt1/h1;Ll4/v;Ll4/d0;Lx2/s;Lx2/s;Lx2/s;Lx2/s;Lq1/b;Le2/w0;ZZLay0/k;Ll4/p;Lt4/c;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lt1/v;->d:Lt1/p0;

    .line 5
    .line 6
    iput-object p2, p0, Lt1/v;->e:Lg4/p0;

    .line 7
    .line 8
    iput p3, p0, Lt1/v;->f:I

    .line 9
    .line 10
    iput p4, p0, Lt1/v;->g:I

    .line 11
    .line 12
    iput-object p5, p0, Lt1/v;->h:Lt1/h1;

    .line 13
    .line 14
    iput-object p6, p0, Lt1/v;->i:Ll4/v;

    .line 15
    .line 16
    iput-object p7, p0, Lt1/v;->j:Ll4/d0;

    .line 17
    .line 18
    iput-object p8, p0, Lt1/v;->k:Lx2/s;

    .line 19
    .line 20
    iput-object p9, p0, Lt1/v;->l:Lx2/s;

    .line 21
    .line 22
    iput-object p10, p0, Lt1/v;->m:Lx2/s;

    .line 23
    .line 24
    iput-object p11, p0, Lt1/v;->n:Lx2/s;

    .line 25
    .line 26
    iput-object p12, p0, Lt1/v;->o:Lq1/b;

    .line 27
    .line 28
    iput-object p13, p0, Lt1/v;->p:Le2/w0;

    .line 29
    .line 30
    iput-boolean p14, p0, Lt1/v;->q:Z

    .line 31
    .line 32
    iput-boolean p15, p0, Lt1/v;->r:Z

    .line 33
    .line 34
    move-object/from16 p1, p16

    .line 35
    .line 36
    iput-object p1, p0, Lt1/v;->s:Lay0/k;

    .line 37
    .line 38
    move-object/from16 p1, p17

    .line 39
    .line 40
    iput-object p1, p0, Lt1/v;->t:Ll4/p;

    .line 41
    .line 42
    move-object/from16 p1, p18

    .line 43
    .line 44
    iput-object p1, p0, Lt1/v;->u:Lt4/c;

    .line 45
    .line 46
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 16

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
    check-cast v2, Ljava/lang/Number;

    .line 10
    .line 11
    invoke-virtual {v2}, Ljava/lang/Number;->intValue()I

    .line 12
    .line 13
    .line 14
    move-result v2

    .line 15
    and-int/lit8 v3, v2, 0x3

    .line 16
    .line 17
    const/4 v4, 0x1

    .line 18
    const/4 v5, 0x2

    .line 19
    if-eq v3, v5, :cond_0

    .line 20
    .line 21
    move v3, v4

    .line 22
    goto :goto_0

    .line 23
    :cond_0
    const/4 v3, 0x0

    .line 24
    :goto_0
    and-int/2addr v2, v4

    .line 25
    check-cast v1, Ll2/t;

    .line 26
    .line 27
    invoke-virtual {v1, v2, v3}, Ll2/t;->O(IZ)Z

    .line 28
    .line 29
    .line 30
    move-result v2

    .line 31
    if-eqz v2, :cond_7

    .line 32
    .line 33
    iget-object v8, v0, Lt1/v;->d:Lt1/p0;

    .line 34
    .line 35
    iget-object v2, v8, Lt1/p0;->g:Ll2/j1;

    .line 36
    .line 37
    invoke-virtual {v2}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 38
    .line 39
    .line 40
    move-result-object v2

    .line 41
    check-cast v2, Lt4/f;

    .line 42
    .line 43
    iget v2, v2, Lt4/f;->d:F

    .line 44
    .line 45
    const/4 v3, 0x0

    .line 46
    sget-object v6, Lx2/p;->b:Lx2/p;

    .line 47
    .line 48
    invoke-static {v6, v2, v3, v5}, Landroidx/compose/foundation/layout/d;->g(Lx2/s;FFI)Lx2/s;

    .line 49
    .line 50
    .line 51
    move-result-object v2

    .line 52
    new-instance v3, Lt1/d0;

    .line 53
    .line 54
    iget v5, v0, Lt1/v;->f:I

    .line 55
    .line 56
    iget v6, v0, Lt1/v;->g:I

    .line 57
    .line 58
    iget-object v7, v0, Lt1/v;->e:Lg4/p0;

    .line 59
    .line 60
    invoke-direct {v3, v5, v6, v7}, Lt1/d0;-><init>(IILg4/p0;)V

    .line 61
    .line 62
    .line 63
    invoke-static {v2, v3}, Lx2/a;->a(Lx2/s;Lay0/o;)Lx2/s;

    .line 64
    .line 65
    .line 66
    move-result-object v2

    .line 67
    invoke-virtual {v1, v8}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 68
    .line 69
    .line 70
    move-result v3

    .line 71
    invoke-virtual {v1}, Ll2/t;->L()Ljava/lang/Object;

    .line 72
    .line 73
    .line 74
    move-result-object v5

    .line 75
    if-nez v3, :cond_1

    .line 76
    .line 77
    sget-object v3, Ll2/n;->a:Ll2/x0;

    .line 78
    .line 79
    if-ne v5, v3, :cond_2

    .line 80
    .line 81
    :cond_1
    new-instance v5, Lr1/b;

    .line 82
    .line 83
    const/16 v3, 0x10

    .line 84
    .line 85
    invoke-direct {v5, v8, v3}, Lr1/b;-><init>(Ljava/lang/Object;I)V

    .line 86
    .line 87
    .line 88
    invoke-virtual {v1, v5}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 89
    .line 90
    .line 91
    :cond_2
    check-cast v5, Lay0/a;

    .line 92
    .line 93
    iget-object v3, v0, Lt1/v;->h:Lt1/h1;

    .line 94
    .line 95
    iget-object v6, v3, Lt1/h1;->f:Ll2/j1;

    .line 96
    .line 97
    invoke-virtual {v6}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 98
    .line 99
    .line 100
    move-result-object v6

    .line 101
    check-cast v6, Lg1/w1;

    .line 102
    .line 103
    iget-object v9, v0, Lt1/v;->i:Ll4/v;

    .line 104
    .line 105
    iget-wide v10, v9, Ll4/v;->b:J

    .line 106
    .line 107
    sget v12, Lg4/o0;->c:I

    .line 108
    .line 109
    const/16 v12, 0x20

    .line 110
    .line 111
    shr-long v13, v10, v12

    .line 112
    .line 113
    long-to-int v13, v13

    .line 114
    iget-wide v14, v3, Lt1/h1;->e:J

    .line 115
    .line 116
    move-object/from16 p2, v5

    .line 117
    .line 118
    shr-long v4, v14, v12

    .line 119
    .line 120
    long-to-int v4, v4

    .line 121
    if-eq v13, v4, :cond_3

    .line 122
    .line 123
    goto :goto_1

    .line 124
    :cond_3
    const-wide v4, 0xffffffffL

    .line 125
    .line 126
    .line 127
    .line 128
    .line 129
    and-long v12, v10, v4

    .line 130
    .line 131
    long-to-int v13, v12

    .line 132
    and-long/2addr v4, v14

    .line 133
    long-to-int v4, v4

    .line 134
    if-eq v13, v4, :cond_4

    .line 135
    .line 136
    goto :goto_1

    .line 137
    :cond_4
    invoke-static {v10, v11}, Lg4/o0;->f(J)I

    .line 138
    .line 139
    .line 140
    move-result v13

    .line 141
    :goto_1
    iget-wide v4, v9, Ll4/v;->b:J

    .line 142
    .line 143
    iput-wide v4, v3, Lt1/h1;->e:J

    .line 144
    .line 145
    iget-object v4, v9, Ll4/v;->a:Lg4/g;

    .line 146
    .line 147
    iget-object v5, v0, Lt1/v;->j:Ll4/d0;

    .line 148
    .line 149
    invoke-static {v5, v4}, Lt1/o1;->a(Ll4/d0;Lg4/g;)Ll4/b0;

    .line 150
    .line 151
    .line 152
    move-result-object v4

    .line 153
    invoke-virtual {v6}, Ljava/lang/Enum;->ordinal()I

    .line 154
    .line 155
    .line 156
    move-result v5

    .line 157
    if-eqz v5, :cond_6

    .line 158
    .line 159
    const/4 v6, 0x1

    .line 160
    if-ne v5, v6, :cond_5

    .line 161
    .line 162
    new-instance v5, Lt1/e0;

    .line 163
    .line 164
    move-object/from16 v6, p2

    .line 165
    .line 166
    invoke-direct {v5, v3, v13, v4, v6}, Lt1/e0;-><init>(Lt1/h1;ILl4/b0;Lay0/a;)V

    .line 167
    .line 168
    .line 169
    goto :goto_2

    .line 170
    :cond_5
    new-instance v0, La8/r0;

    .line 171
    .line 172
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 173
    .line 174
    .line 175
    throw v0

    .line 176
    :cond_6
    move-object/from16 v6, p2

    .line 177
    .line 178
    new-instance v5, Lt1/p1;

    .line 179
    .line 180
    invoke-direct {v5, v3, v13, v4, v6}, Lt1/p1;-><init>(Lt1/h1;ILl4/b0;Lay0/a;)V

    .line 181
    .line 182
    .line 183
    :goto_2
    invoke-static {v2}, Ljp/ba;->d(Lx2/s;)Lx2/s;

    .line 184
    .line 185
    .line 186
    move-result-object v2

    .line 187
    invoke-interface {v2, v5}, Lx2/s;->g(Lx2/s;)Lx2/s;

    .line 188
    .line 189
    .line 190
    move-result-object v2

    .line 191
    iget-object v3, v0, Lt1/v;->k:Lx2/s;

    .line 192
    .line 193
    invoke-interface {v2, v3}, Lx2/s;->g(Lx2/s;)Lx2/s;

    .line 194
    .line 195
    .line 196
    move-result-object v2

    .line 197
    iget-object v3, v0, Lt1/v;->l:Lx2/s;

    .line 198
    .line 199
    invoke-interface {v2, v3}, Lx2/s;->g(Lx2/s;)Lx2/s;

    .line 200
    .line 201
    .line 202
    move-result-object v2

    .line 203
    new-instance v3, Le1/u;

    .line 204
    .line 205
    const/16 v4, 0x9

    .line 206
    .line 207
    invoke-direct {v3, v7, v4}, Le1/u;-><init>(Ljava/lang/Object;I)V

    .line 208
    .line 209
    .line 210
    invoke-static {v2, v3}, Lx2/a;->a(Lx2/s;Lay0/o;)Lx2/s;

    .line 211
    .line 212
    .line 213
    move-result-object v2

    .line 214
    iget-object v3, v0, Lt1/v;->m:Lx2/s;

    .line 215
    .line 216
    invoke-interface {v2, v3}, Lx2/s;->g(Lx2/s;)Lx2/s;

    .line 217
    .line 218
    .line 219
    move-result-object v2

    .line 220
    iget-object v3, v0, Lt1/v;->n:Lx2/s;

    .line 221
    .line 222
    invoke-interface {v2, v3}, Lx2/s;->g(Lx2/s;)Lx2/s;

    .line 223
    .line 224
    .line 225
    move-result-object v2

    .line 226
    iget-object v3, v0, Lt1/v;->o:Lq1/b;

    .line 227
    .line 228
    invoke-static {v2, v3}, Landroidx/compose/foundation/relocation/a;->a(Lx2/s;Lq1/b;)Lx2/s;

    .line 229
    .line 230
    .line 231
    move-result-object v2

    .line 232
    new-instance v6, Lt1/u;

    .line 233
    .line 234
    iget-object v14, v0, Lt1/v;->u:Lt4/c;

    .line 235
    .line 236
    iget v15, v0, Lt1/v;->g:I

    .line 237
    .line 238
    iget-object v7, v0, Lt1/v;->p:Le2/w0;

    .line 239
    .line 240
    iget-boolean v9, v0, Lt1/v;->q:Z

    .line 241
    .line 242
    iget-boolean v10, v0, Lt1/v;->r:Z

    .line 243
    .line 244
    iget-object v11, v0, Lt1/v;->s:Lay0/k;

    .line 245
    .line 246
    iget-object v12, v0, Lt1/v;->i:Ll4/v;

    .line 247
    .line 248
    iget-object v13, v0, Lt1/v;->t:Ll4/p;

    .line 249
    .line 250
    invoke-direct/range {v6 .. v15}, Lt1/u;-><init>(Le2/w0;Lt1/p0;ZZLay0/k;Ll4/v;Ll4/p;Lt4/c;I)V

    .line 251
    .line 252
    .line 253
    const v0, 0x54340ce8

    .line 254
    .line 255
    .line 256
    invoke-static {v0, v1, v6}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 257
    .line 258
    .line 259
    move-result-object v0

    .line 260
    const/16 v3, 0x30

    .line 261
    .line 262
    invoke-static {v2, v0, v1, v3}, Lkp/v;->a(Lx2/s;Lt2/b;Ll2/o;I)V

    .line 263
    .line 264
    .line 265
    goto :goto_3

    .line 266
    :cond_7
    invoke-virtual {v1}, Ll2/t;->R()V

    .line 267
    .line 268
    .line 269
    :goto_3
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 270
    .line 271
    return-object v0
.end method
