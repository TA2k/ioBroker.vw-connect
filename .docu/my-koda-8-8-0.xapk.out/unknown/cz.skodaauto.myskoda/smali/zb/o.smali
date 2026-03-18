.class public final synthetic Lzb/o;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:J

.field public final synthetic e:F

.field public final synthetic f:F

.field public final synthetic g:J

.field public final synthetic h:Ls1/e;

.field public final synthetic i:Lt2/b;


# direct methods
.method public synthetic constructor <init>(JFFJLs1/e;Lt2/b;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-wide p1, p0, Lzb/o;->d:J

    .line 5
    .line 6
    iput p3, p0, Lzb/o;->e:F

    .line 7
    .line 8
    iput p4, p0, Lzb/o;->f:F

    .line 9
    .line 10
    iput-wide p5, p0, Lzb/o;->g:J

    .line 11
    .line 12
    iput-object p7, p0, Lzb/o;->h:Ls1/e;

    .line 13
    .line 14
    iput-object p8, p0, Lzb/o;->i:Lt2/b;

    .line 15
    .line 16
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 21

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
    check-cast v1, Ll2/t;

    .line 27
    .line 28
    invoke-virtual {v1, v2, v3}, Ll2/t;->O(IZ)Z

    .line 29
    .line 30
    .line 31
    move-result v2

    .line 32
    if-eqz v2, :cond_7

    .line 33
    .line 34
    sget-object v2, Landroidx/compose/foundation/layout/d;->c:Landroidx/compose/foundation/layout/FillElement;

    .line 35
    .line 36
    sget-object v3, Le3/j0;->a:Le3/i0;

    .line 37
    .line 38
    iget-wide v7, v0, Lzb/o;->d:J

    .line 39
    .line 40
    invoke-static {v2, v7, v8, v3}, Landroidx/compose/foundation/a;->b(Lx2/s;JLe3/n0;)Lx2/s;

    .line 41
    .line 42
    .line 43
    move-result-object v2

    .line 44
    iget v3, v0, Lzb/o;->e:F

    .line 45
    .line 46
    invoke-static {v2, v3}, Landroidx/compose/foundation/layout/a;->m(Lx2/s;F)Lx2/s;

    .line 47
    .line 48
    .line 49
    move-result-object v2

    .line 50
    sget-object v3, Lx2/c;->h:Lx2/j;

    .line 51
    .line 52
    invoke-static {v3, v5}, Lk1/n;->d(Lx2/e;Z)Lt3/q0;

    .line 53
    .line 54
    .line 55
    move-result-object v3

    .line 56
    iget-wide v7, v1, Ll2/t;->T:J

    .line 57
    .line 58
    invoke-static {v7, v8}, Ljava/lang/Long;->hashCode(J)I

    .line 59
    .line 60
    .line 61
    move-result v4

    .line 62
    invoke-virtual {v1}, Ll2/t;->m()Ll2/p1;

    .line 63
    .line 64
    .line 65
    move-result-object v7

    .line 66
    invoke-static {v1, v2}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 67
    .line 68
    .line 69
    move-result-object v2

    .line 70
    sget-object v8, Lv3/k;->m1:Lv3/j;

    .line 71
    .line 72
    invoke-virtual {v8}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 73
    .line 74
    .line 75
    sget-object v8, Lv3/j;->b:Lv3/i;

    .line 76
    .line 77
    invoke-virtual {v1}, Ll2/t;->c0()V

    .line 78
    .line 79
    .line 80
    iget-boolean v9, v1, Ll2/t;->S:Z

    .line 81
    .line 82
    if-eqz v9, :cond_1

    .line 83
    .line 84
    invoke-virtual {v1, v8}, Ll2/t;->l(Lay0/a;)V

    .line 85
    .line 86
    .line 87
    goto :goto_1

    .line 88
    :cond_1
    invoke-virtual {v1}, Ll2/t;->m0()V

    .line 89
    .line 90
    .line 91
    :goto_1
    sget-object v9, Lv3/j;->g:Lv3/h;

    .line 92
    .line 93
    invoke-static {v9, v3, v1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 94
    .line 95
    .line 96
    sget-object v3, Lv3/j;->f:Lv3/h;

    .line 97
    .line 98
    invoke-static {v3, v7, v1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 99
    .line 100
    .line 101
    sget-object v7, Lv3/j;->j:Lv3/h;

    .line 102
    .line 103
    iget-boolean v10, v1, Ll2/t;->S:Z

    .line 104
    .line 105
    if-nez v10, :cond_2

    .line 106
    .line 107
    invoke-virtual {v1}, Ll2/t;->L()Ljava/lang/Object;

    .line 108
    .line 109
    .line 110
    move-result-object v10

    .line 111
    invoke-static {v4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 112
    .line 113
    .line 114
    move-result-object v11

    .line 115
    invoke-static {v10, v11}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 116
    .line 117
    .line 118
    move-result v10

    .line 119
    if-nez v10, :cond_3

    .line 120
    .line 121
    :cond_2
    invoke-static {v4, v1, v4, v7}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 122
    .line 123
    .line 124
    :cond_3
    sget-object v4, Lv3/j;->d:Lv3/h;

    .line 125
    .line 126
    invoke-static {v4, v2, v1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 127
    .line 128
    .line 129
    sget-object v2, Lx2/p;->b:Lx2/p;

    .line 130
    .line 131
    const/4 v10, 0x0

    .line 132
    const/4 v11, 0x3

    .line 133
    invoke-static {v2, v10, v11}, Landroidx/compose/foundation/layout/d;->v(Lx2/s;Lx2/j;I)Lx2/s;

    .line 134
    .line 135
    .line 136
    move-result-object v12

    .line 137
    const-wide/16 v18, 0x0

    .line 138
    .line 139
    const/16 v20, 0x1e

    .line 140
    .line 141
    iget v13, v0, Lzb/o;->f:F

    .line 142
    .line 143
    const/4 v14, 0x0

    .line 144
    const/4 v15, 0x0

    .line 145
    const-wide/16 v16, 0x0

    .line 146
    .line 147
    invoke-static/range {v12 .. v20}, Ljp/ea;->b(Lx2/s;FLe3/n0;ZJJI)Lx2/s;

    .line 148
    .line 149
    .line 150
    move-result-object v2

    .line 151
    iget-wide v10, v0, Lzb/o;->g:J

    .line 152
    .line 153
    iget-object v12, v0, Lzb/o;->h:Ls1/e;

    .line 154
    .line 155
    invoke-static {v2, v10, v11, v12}, Landroidx/compose/foundation/a;->b(Lx2/s;JLe3/n0;)Lx2/s;

    .line 156
    .line 157
    .line 158
    move-result-object v2

    .line 159
    sget-object v10, Lx2/c;->d:Lx2/j;

    .line 160
    .line 161
    invoke-static {v10, v5}, Lk1/n;->d(Lx2/e;Z)Lt3/q0;

    .line 162
    .line 163
    .line 164
    move-result-object v10

    .line 165
    iget-wide v11, v1, Ll2/t;->T:J

    .line 166
    .line 167
    invoke-static {v11, v12}, Ljava/lang/Long;->hashCode(J)I

    .line 168
    .line 169
    .line 170
    move-result v11

    .line 171
    invoke-virtual {v1}, Ll2/t;->m()Ll2/p1;

    .line 172
    .line 173
    .line 174
    move-result-object v12

    .line 175
    invoke-static {v1, v2}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 176
    .line 177
    .line 178
    move-result-object v2

    .line 179
    invoke-virtual {v1}, Ll2/t;->c0()V

    .line 180
    .line 181
    .line 182
    iget-boolean v13, v1, Ll2/t;->S:Z

    .line 183
    .line 184
    if-eqz v13, :cond_4

    .line 185
    .line 186
    invoke-virtual {v1, v8}, Ll2/t;->l(Lay0/a;)V

    .line 187
    .line 188
    .line 189
    goto :goto_2

    .line 190
    :cond_4
    invoke-virtual {v1}, Ll2/t;->m0()V

    .line 191
    .line 192
    .line 193
    :goto_2
    invoke-static {v9, v10, v1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 194
    .line 195
    .line 196
    invoke-static {v3, v12, v1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 197
    .line 198
    .line 199
    iget-boolean v3, v1, Ll2/t;->S:Z

    .line 200
    .line 201
    if-nez v3, :cond_5

    .line 202
    .line 203
    invoke-virtual {v1}, Ll2/t;->L()Ljava/lang/Object;

    .line 204
    .line 205
    .line 206
    move-result-object v3

    .line 207
    invoke-static {v11}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 208
    .line 209
    .line 210
    move-result-object v8

    .line 211
    invoke-static {v3, v8}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 212
    .line 213
    .line 214
    move-result v3

    .line 215
    if-nez v3, :cond_6

    .line 216
    .line 217
    :cond_5
    invoke-static {v11, v1, v11, v7}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 218
    .line 219
    .line 220
    :cond_6
    invoke-static {v4, v2, v1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 221
    .line 222
    .line 223
    invoke-static {v5}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 224
    .line 225
    .line 226
    move-result-object v2

    .line 227
    iget-object v0, v0, Lzb/o;->i:Lt2/b;

    .line 228
    .line 229
    invoke-virtual {v0, v1, v2}, Lt2/b;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 230
    .line 231
    .line 232
    invoke-virtual {v1, v6}, Ll2/t;->q(Z)V

    .line 233
    .line 234
    .line 235
    invoke-virtual {v1, v6}, Ll2/t;->q(Z)V

    .line 236
    .line 237
    .line 238
    goto :goto_3

    .line 239
    :cond_7
    invoke-virtual {v1}, Ll2/t;->R()V

    .line 240
    .line 241
    .line 242
    :goto_3
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 243
    .line 244
    return-object v0
.end method
