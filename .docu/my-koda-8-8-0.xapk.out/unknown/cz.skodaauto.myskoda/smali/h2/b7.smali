.class public final Lh2/b7;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:Lx2/s;

.field public final synthetic e:Lay0/n;

.field public final synthetic f:Z

.field public final synthetic g:Lh2/eb;

.field public final synthetic h:Ll4/v;

.field public final synthetic i:Lay0/k;

.field public final synthetic j:Z

.field public final synthetic k:Lg4/p0;

.field public final synthetic l:Lt1/o0;

.field public final synthetic m:Lt1/n0;

.field public final synthetic n:Z

.field public final synthetic o:I

.field public final synthetic p:I

.field public final synthetic q:Ll4/d0;

.field public final synthetic r:Li1/l;

.field public final synthetic s:Lay0/n;

.field public final synthetic t:Lay0/n;

.field public final synthetic u:Le3/n0;


# direct methods
.method public constructor <init>(Lx2/s;Lay0/n;ZLh2/eb;Ll4/v;Lay0/k;ZLg4/p0;Lt1/o0;Lt1/n0;ZIILl4/d0;Li1/l;Lay0/n;Lay0/n;Le3/n0;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lh2/b7;->d:Lx2/s;

    .line 5
    .line 6
    iput-object p2, p0, Lh2/b7;->e:Lay0/n;

    .line 7
    .line 8
    iput-boolean p3, p0, Lh2/b7;->f:Z

    .line 9
    .line 10
    iput-object p4, p0, Lh2/b7;->g:Lh2/eb;

    .line 11
    .line 12
    iput-object p5, p0, Lh2/b7;->h:Ll4/v;

    .line 13
    .line 14
    iput-object p6, p0, Lh2/b7;->i:Lay0/k;

    .line 15
    .line 16
    iput-boolean p7, p0, Lh2/b7;->j:Z

    .line 17
    .line 18
    iput-object p8, p0, Lh2/b7;->k:Lg4/p0;

    .line 19
    .line 20
    iput-object p9, p0, Lh2/b7;->l:Lt1/o0;

    .line 21
    .line 22
    iput-object p10, p0, Lh2/b7;->m:Lt1/n0;

    .line 23
    .line 24
    iput-boolean p11, p0, Lh2/b7;->n:Z

    .line 25
    .line 26
    iput p12, p0, Lh2/b7;->o:I

    .line 27
    .line 28
    iput p13, p0, Lh2/b7;->p:I

    .line 29
    .line 30
    iput-object p14, p0, Lh2/b7;->q:Ll4/d0;

    .line 31
    .line 32
    iput-object p15, p0, Lh2/b7;->r:Li1/l;

    .line 33
    .line 34
    move-object/from16 p1, p16

    .line 35
    .line 36
    iput-object p1, p0, Lh2/b7;->s:Lay0/n;

    .line 37
    .line 38
    move-object/from16 p1, p17

    .line 39
    .line 40
    iput-object p1, p0, Lh2/b7;->t:Lay0/n;

    .line 41
    .line 42
    move-object/from16 p1, p18

    .line 43
    .line 44
    iput-object p1, p0, Lh2/b7;->u:Le3/n0;

    .line 45
    .line 46
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 27

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
    const/4 v4, 0x2

    .line 18
    const/4 v5, 0x1

    .line 19
    const/4 v6, 0x0

    .line 20
    if-eq v3, v4, :cond_0

    .line 21
    .line 22
    move v3, v5

    .line 23
    goto :goto_0

    .line 24
    :cond_0
    move v3, v6

    .line 25
    :goto_0
    and-int/2addr v2, v5

    .line 26
    check-cast v1, Ll2/t;

    .line 27
    .line 28
    invoke-virtual {v1, v2, v3}, Ll2/t;->O(IZ)Z

    .line 29
    .line 30
    .line 31
    move-result v2

    .line 32
    if-eqz v2, :cond_5

    .line 33
    .line 34
    iget-object v2, v0, Lh2/b7;->e:Lay0/n;

    .line 35
    .line 36
    sget-object v3, Lx2/p;->b:Lx2/p;

    .line 37
    .line 38
    if-eqz v2, :cond_2

    .line 39
    .line 40
    const v2, -0x715731da

    .line 41
    .line 42
    .line 43
    invoke-virtual {v1, v2}, Ll2/t;->Y(I)V

    .line 44
    .line 45
    .line 46
    invoke-virtual {v1}, Ll2/t;->L()Ljava/lang/Object;

    .line 47
    .line 48
    .line 49
    move-result-object v2

    .line 50
    sget-object v4, Ll2/n;->a:Ll2/x0;

    .line 51
    .line 52
    if-ne v2, v4, :cond_1

    .line 53
    .line 54
    new-instance v2, Lh10/d;

    .line 55
    .line 56
    const/4 v4, 0x5

    .line 57
    invoke-direct {v2, v4}, Lh10/d;-><init>(I)V

    .line 58
    .line 59
    .line 60
    invoke-virtual {v1, v2}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 61
    .line 62
    .line 63
    :cond_1
    check-cast v2, Lay0/k;

    .line 64
    .line 65
    invoke-static {v3, v5, v2}, Ld4/n;->b(Lx2/s;ZLay0/k;)Lx2/s;

    .line 66
    .line 67
    .line 68
    move-result-object v7

    .line 69
    invoke-static {v1}, Li2/h1;->d(Ll2/o;)F

    .line 70
    .line 71
    .line 72
    move-result v9

    .line 73
    const/4 v11, 0x0

    .line 74
    const/16 v12, 0xd

    .line 75
    .line 76
    const/4 v8, 0x0

    .line 77
    const/4 v10, 0x0

    .line 78
    invoke-static/range {v7 .. v12}, Landroidx/compose/foundation/layout/a;->q(Lx2/s;FFFFI)Lx2/s;

    .line 79
    .line 80
    .line 81
    move-result-object v3

    .line 82
    invoke-virtual {v1, v6}, Ll2/t;->q(Z)V

    .line 83
    .line 84
    .line 85
    goto :goto_1

    .line 86
    :cond_2
    const v2, -0x71515713

    .line 87
    .line 88
    .line 89
    invoke-virtual {v1, v2}, Ll2/t;->Y(I)V

    .line 90
    .line 91
    .line 92
    invoke-virtual {v1, v6}, Ll2/t;->q(Z)V

    .line 93
    .line 94
    .line 95
    :goto_1
    iget-object v2, v0, Lh2/b7;->d:Lx2/s;

    .line 96
    .line 97
    invoke-interface {v2, v3}, Lx2/s;->g(Lx2/s;)Lx2/s;

    .line 98
    .line 99
    .line 100
    move-result-object v2

    .line 101
    const v3, 0x7f1201ef

    .line 102
    .line 103
    .line 104
    invoke-static {v1, v3}, Li2/a1;->k(Ll2/o;I)Ljava/lang/String;

    .line 105
    .line 106
    .line 107
    move-result-object v3

    .line 108
    sget v4, Li2/h1;->a:F

    .line 109
    .line 110
    iget-boolean v4, v0, Lh2/b7;->f:Z

    .line 111
    .line 112
    if-eqz v4, :cond_3

    .line 113
    .line 114
    new-instance v5, Lac0/r;

    .line 115
    .line 116
    const/16 v7, 0x18

    .line 117
    .line 118
    invoke-direct {v5, v3, v7}, Lac0/r;-><init>(Ljava/lang/String;I)V

    .line 119
    .line 120
    .line 121
    invoke-static {v2, v6, v5}, Ld4/n;->b(Lx2/s;ZLay0/k;)Lx2/s;

    .line 122
    .line 123
    .line 124
    move-result-object v2

    .line 125
    :cond_3
    sget v3, Lh2/v6;->c:F

    .line 126
    .line 127
    sget v5, Lh2/v6;->b:F

    .line 128
    .line 129
    invoke-static {v2, v3, v5}, Landroidx/compose/foundation/layout/d;->a(Lx2/s;FF)Lx2/s;

    .line 130
    .line 131
    .line 132
    move-result-object v9

    .line 133
    new-instance v2, Le3/p0;

    .line 134
    .line 135
    iget-object v3, v0, Lh2/b7;->g:Lh2/eb;

    .line 136
    .line 137
    if-eqz v4, :cond_4

    .line 138
    .line 139
    iget-wide v4, v3, Lh2/eb;->j:J

    .line 140
    .line 141
    goto :goto_2

    .line 142
    :cond_4
    iget-wide v4, v3, Lh2/eb;->i:J

    .line 143
    .line 144
    :goto_2
    invoke-direct {v2, v4, v5}, Le3/p0;-><init>(J)V

    .line 145
    .line 146
    .line 147
    new-instance v10, Lh2/a7;

    .line 148
    .line 149
    iget-object v4, v0, Lh2/b7;->t:Lay0/n;

    .line 150
    .line 151
    iget-object v5, v0, Lh2/b7;->u:Le3/n0;

    .line 152
    .line 153
    iget-object v7, v0, Lh2/b7;->h:Ll4/v;

    .line 154
    .line 155
    iget-boolean v12, v0, Lh2/b7;->j:Z

    .line 156
    .line 157
    iget-boolean v13, v0, Lh2/b7;->n:Z

    .line 158
    .line 159
    iget-object v14, v0, Lh2/b7;->q:Ll4/d0;

    .line 160
    .line 161
    iget-object v15, v0, Lh2/b7;->r:Li1/l;

    .line 162
    .line 163
    iget-boolean v6, v0, Lh2/b7;->f:Z

    .line 164
    .line 165
    iget-object v8, v0, Lh2/b7;->e:Lay0/n;

    .line 166
    .line 167
    iget-object v11, v0, Lh2/b7;->s:Lay0/n;

    .line 168
    .line 169
    move-object/from16 v20, v3

    .line 170
    .line 171
    move-object/from16 v19, v4

    .line 172
    .line 173
    move-object/from16 v21, v5

    .line 174
    .line 175
    move/from16 v16, v6

    .line 176
    .line 177
    move-object/from16 v17, v8

    .line 178
    .line 179
    move-object/from16 v18, v11

    .line 180
    .line 181
    move-object v11, v7

    .line 182
    invoke-direct/range {v10 .. v21}, Lh2/a7;-><init>(Ll4/v;ZZLl4/d0;Li1/l;ZLay0/n;Lay0/n;Lay0/n;Lh2/eb;Le3/n0;)V

    .line 183
    .line 184
    .line 185
    const v3, 0x2834ae32

    .line 186
    .line 187
    .line 188
    invoke-static {v3, v1, v10}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 189
    .line 190
    .line 191
    move-result-object v22

    .line 192
    const/high16 v25, 0x30000

    .line 193
    .line 194
    const/16 v26, 0x1000

    .line 195
    .line 196
    iget-object v8, v0, Lh2/b7;->i:Lay0/k;

    .line 197
    .line 198
    const/4 v11, 0x0

    .line 199
    move v10, v12

    .line 200
    iget-object v12, v0, Lh2/b7;->k:Lg4/p0;

    .line 201
    .line 202
    move-object/from16 v20, v15

    .line 203
    .line 204
    move v15, v13

    .line 205
    iget-object v13, v0, Lh2/b7;->l:Lt1/o0;

    .line 206
    .line 207
    move-object/from16 v18, v14

    .line 208
    .line 209
    iget-object v14, v0, Lh2/b7;->m:Lt1/n0;

    .line 210
    .line 211
    iget v3, v0, Lh2/b7;->o:I

    .line 212
    .line 213
    iget v0, v0, Lh2/b7;->p:I

    .line 214
    .line 215
    const/16 v19, 0x0

    .line 216
    .line 217
    const/16 v24, 0x0

    .line 218
    .line 219
    move/from16 v17, v0

    .line 220
    .line 221
    move-object/from16 v23, v1

    .line 222
    .line 223
    move-object/from16 v21, v2

    .line 224
    .line 225
    move/from16 v16, v3

    .line 226
    .line 227
    invoke-static/range {v7 .. v26}, Lt1/h;->b(Ll4/v;Lay0/k;Lx2/s;ZZLg4/p0;Lt1/o0;Lt1/n0;ZIILl4/d0;Lay0/k;Li1/l;Le3/p0;Lt2/b;Ll2/o;III)V

    .line 228
    .line 229
    .line 230
    goto :goto_3

    .line 231
    :cond_5
    move-object/from16 v23, v1

    .line 232
    .line 233
    invoke-virtual/range {v23 .. v23}, Ll2/t;->R()V

    .line 234
    .line 235
    .line 236
    :goto_3
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 237
    .line 238
    return-object v0
.end method
