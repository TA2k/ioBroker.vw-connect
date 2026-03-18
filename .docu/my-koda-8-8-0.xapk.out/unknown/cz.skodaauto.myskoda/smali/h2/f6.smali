.class public final Lh2/f6;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:J

.field public final synthetic e:Lay0/a;

.field public final synthetic f:Lh2/r8;

.field public final synthetic g:Lh2/k6;

.field public final synthetic h:Lc1/c;

.field public final synthetic i:Lvy0/b0;

.field public final synthetic j:Lay0/k;

.field public final synthetic k:Lx2/s;

.field public final synthetic l:F

.field public final synthetic m:Z

.field public final synthetic n:Le3/n0;

.field public final synthetic o:J

.field public final synthetic p:J

.field public final synthetic q:F

.field public final synthetic r:Lay0/n;

.field public final synthetic s:Lay0/n;

.field public final synthetic t:Lt2/b;


# direct methods
.method public constructor <init>(JLay0/a;Lh2/r8;Lh2/k6;Lc1/c;Lvy0/b0;Lay0/k;Lx2/s;FZLe3/n0;JJFLay0/n;Lay0/n;Lt2/b;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-wide p1, p0, Lh2/f6;->d:J

    .line 5
    .line 6
    iput-object p3, p0, Lh2/f6;->e:Lay0/a;

    .line 7
    .line 8
    iput-object p4, p0, Lh2/f6;->f:Lh2/r8;

    .line 9
    .line 10
    iput-object p5, p0, Lh2/f6;->g:Lh2/k6;

    .line 11
    .line 12
    iput-object p6, p0, Lh2/f6;->h:Lc1/c;

    .line 13
    .line 14
    iput-object p7, p0, Lh2/f6;->i:Lvy0/b0;

    .line 15
    .line 16
    iput-object p8, p0, Lh2/f6;->j:Lay0/k;

    .line 17
    .line 18
    iput-object p9, p0, Lh2/f6;->k:Lx2/s;

    .line 19
    .line 20
    iput p10, p0, Lh2/f6;->l:F

    .line 21
    .line 22
    iput-boolean p11, p0, Lh2/f6;->m:Z

    .line 23
    .line 24
    iput-object p12, p0, Lh2/f6;->n:Le3/n0;

    .line 25
    .line 26
    iput-wide p13, p0, Lh2/f6;->o:J

    .line 27
    .line 28
    move-wide p1, p15

    .line 29
    iput-wide p1, p0, Lh2/f6;->p:J

    .line 30
    .line 31
    move/from16 p1, p17

    .line 32
    .line 33
    iput p1, p0, Lh2/f6;->q:F

    .line 34
    .line 35
    move-object/from16 p1, p18

    .line 36
    .line 37
    iput-object p1, p0, Lh2/f6;->r:Lay0/n;

    .line 38
    .line 39
    move-object/from16 p1, p19

    .line 40
    .line 41
    iput-object p1, p0, Lh2/f6;->s:Lay0/n;

    .line 42
    .line 43
    move-object/from16 p1, p20

    .line 44
    .line 45
    iput-object p1, p0, Lh2/f6;->t:Lt2/b;

    .line 46
    .line 47
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 26

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
    move-object v12, v1

    .line 27
    check-cast v12, Ll2/t;

    .line 28
    .line 29
    invoke-virtual {v12, v2, v3}, Ll2/t;->O(IZ)Z

    .line 30
    .line 31
    .line 32
    move-result v1

    .line 33
    if-eqz v1, :cond_6

    .line 34
    .line 35
    sget-object v1, Landroidx/compose/foundation/layout/d;->c:Landroidx/compose/foundation/layout/FillElement;

    .line 36
    .line 37
    invoke-static {v1}, Lk1/d;->k(Lx2/s;)Lx2/s;

    .line 38
    .line 39
    .line 40
    move-result-object v1

    .line 41
    invoke-virtual {v12}, Ll2/t;->L()Ljava/lang/Object;

    .line 42
    .line 43
    .line 44
    move-result-object v2

    .line 45
    sget-object v3, Ll2/n;->a:Ll2/x0;

    .line 46
    .line 47
    if-ne v2, v3, :cond_1

    .line 48
    .line 49
    new-instance v2, Lh10/d;

    .line 50
    .line 51
    const/16 v3, 0xe

    .line 52
    .line 53
    invoke-direct {v2, v3}, Lh10/d;-><init>(I)V

    .line 54
    .line 55
    .line 56
    invoke-virtual {v12, v2}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 57
    .line 58
    .line 59
    :cond_1
    check-cast v2, Lay0/k;

    .line 60
    .line 61
    invoke-static {v1, v5, v2}, Ld4/n;->b(Lx2/s;ZLay0/k;)Lx2/s;

    .line 62
    .line 63
    .line 64
    move-result-object v1

    .line 65
    sget-object v2, Lx2/c;->d:Lx2/j;

    .line 66
    .line 67
    invoke-static {v2, v5}, Lk1/n;->d(Lx2/e;Z)Lt3/q0;

    .line 68
    .line 69
    .line 70
    move-result-object v2

    .line 71
    iget-wide v3, v12, Ll2/t;->T:J

    .line 72
    .line 73
    invoke-static {v3, v4}, Ljava/lang/Long;->hashCode(J)I

    .line 74
    .line 75
    .line 76
    move-result v3

    .line 77
    invoke-virtual {v12}, Ll2/t;->m()Ll2/p1;

    .line 78
    .line 79
    .line 80
    move-result-object v4

    .line 81
    invoke-static {v12, v1}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 82
    .line 83
    .line 84
    move-result-object v1

    .line 85
    sget-object v7, Lv3/k;->m1:Lv3/j;

    .line 86
    .line 87
    invoke-virtual {v7}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 88
    .line 89
    .line 90
    sget-object v7, Lv3/j;->b:Lv3/i;

    .line 91
    .line 92
    invoke-virtual {v12}, Ll2/t;->c0()V

    .line 93
    .line 94
    .line 95
    iget-boolean v8, v12, Ll2/t;->S:Z

    .line 96
    .line 97
    if-eqz v8, :cond_2

    .line 98
    .line 99
    invoke-virtual {v12, v7}, Ll2/t;->l(Lay0/a;)V

    .line 100
    .line 101
    .line 102
    goto :goto_1

    .line 103
    :cond_2
    invoke-virtual {v12}, Ll2/t;->m0()V

    .line 104
    .line 105
    .line 106
    :goto_1
    sget-object v7, Lv3/j;->g:Lv3/h;

    .line 107
    .line 108
    invoke-static {v7, v2, v12}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 109
    .line 110
    .line 111
    sget-object v2, Lv3/j;->f:Lv3/h;

    .line 112
    .line 113
    invoke-static {v2, v4, v12}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 114
    .line 115
    .line 116
    sget-object v2, Lv3/j;->j:Lv3/h;

    .line 117
    .line 118
    iget-boolean v4, v12, Ll2/t;->S:Z

    .line 119
    .line 120
    if-nez v4, :cond_3

    .line 121
    .line 122
    invoke-virtual {v12}, Ll2/t;->L()Ljava/lang/Object;

    .line 123
    .line 124
    .line 125
    move-result-object v4

    .line 126
    invoke-static {v3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 127
    .line 128
    .line 129
    move-result-object v7

    .line 130
    invoke-static {v4, v7}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 131
    .line 132
    .line 133
    move-result v4

    .line 134
    if-nez v4, :cond_4

    .line 135
    .line 136
    :cond_3
    invoke-static {v3, v12, v3, v2}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 137
    .line 138
    .line 139
    :cond_4
    sget-object v2, Lv3/j;->d:Lv3/h;

    .line 140
    .line 141
    invoke-static {v2, v1, v12}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 142
    .line 143
    .line 144
    iget-object v1, v0, Lh2/f6;->f:Lh2/r8;

    .line 145
    .line 146
    iget-object v2, v1, Lh2/r8;->e:Li2/p;

    .line 147
    .line 148
    iget-object v2, v2, Li2/p;->h:Ll2/h0;

    .line 149
    .line 150
    invoke-virtual {v2}, Ll2/h0;->getValue()Ljava/lang/Object;

    .line 151
    .line 152
    .line 153
    move-result-object v2

    .line 154
    check-cast v2, Lh2/s8;

    .line 155
    .line 156
    sget-object v3, Lh2/s8;->d:Lh2/s8;

    .line 157
    .line 158
    if-eq v2, v3, :cond_5

    .line 159
    .line 160
    move v10, v6

    .line 161
    goto :goto_2

    .line 162
    :cond_5
    move v10, v5

    .line 163
    :goto_2
    iget-object v2, v0, Lh2/f6;->g:Lh2/k6;

    .line 164
    .line 165
    iget-boolean v11, v2, Lh2/k6;->c:Z

    .line 166
    .line 167
    const/4 v13, 0x0

    .line 168
    iget-wide v7, v0, Lh2/f6;->d:J

    .line 169
    .line 170
    iget-object v9, v0, Lh2/f6;->e:Lay0/a;

    .line 171
    .line 172
    invoke-static/range {v7 .. v13}, Lh2/j6;->c(JLay0/a;ZZLl2/o;I)V

    .line 173
    .line 174
    .line 175
    move-object/from16 v24, v12

    .line 176
    .line 177
    const/16 v25, 0x46

    .line 178
    .line 179
    iget-object v7, v0, Lh2/f6;->h:Lc1/c;

    .line 180
    .line 181
    iget-object v8, v0, Lh2/f6;->i:Lvy0/b0;

    .line 182
    .line 183
    iget-object v10, v0, Lh2/f6;->j:Lay0/k;

    .line 184
    .line 185
    iget-object v11, v0, Lh2/f6;->k:Lx2/s;

    .line 186
    .line 187
    iget v13, v0, Lh2/f6;->l:F

    .line 188
    .line 189
    iget-boolean v14, v0, Lh2/f6;->m:Z

    .line 190
    .line 191
    iget-object v15, v0, Lh2/f6;->n:Le3/n0;

    .line 192
    .line 193
    iget-wide v2, v0, Lh2/f6;->o:J

    .line 194
    .line 195
    iget-wide v4, v0, Lh2/f6;->p:J

    .line 196
    .line 197
    iget v12, v0, Lh2/f6;->q:F

    .line 198
    .line 199
    iget-object v6, v0, Lh2/f6;->r:Lay0/n;

    .line 200
    .line 201
    move-object/from16 v16, v1

    .line 202
    .line 203
    iget-object v1, v0, Lh2/f6;->s:Lay0/n;

    .line 204
    .line 205
    iget-object v0, v0, Lh2/f6;->t:Lt2/b;

    .line 206
    .line 207
    move-object/from16 v23, v0

    .line 208
    .line 209
    move-object/from16 v22, v1

    .line 210
    .line 211
    move-wide/from16 v18, v4

    .line 212
    .line 213
    move-object/from16 v21, v6

    .line 214
    .line 215
    move/from16 v20, v12

    .line 216
    .line 217
    move-object/from16 v12, v16

    .line 218
    .line 219
    move-wide/from16 v16, v2

    .line 220
    .line 221
    invoke-static/range {v7 .. v25}, Lh2/j6;->b(Lc1/c;Lvy0/b0;Lay0/a;Lay0/k;Lx2/s;Lh2/r8;FZLe3/n0;JJFLay0/n;Lay0/n;Lt2/b;Ll2/o;I)V

    .line 222
    .line 223
    .line 224
    move-object/from16 v12, v24

    .line 225
    .line 226
    const/4 v0, 0x1

    .line 227
    invoke-virtual {v12, v0}, Ll2/t;->q(Z)V

    .line 228
    .line 229
    .line 230
    goto :goto_3

    .line 231
    :cond_6
    invoke-virtual {v12}, Ll2/t;->R()V

    .line 232
    .line 233
    .line 234
    :goto_3
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 235
    .line 236
    return-object v0
.end method
