.class public final synthetic Lf2/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lay0/a;

.field public final synthetic f:Z

.field public final synthetic g:J

.field public final synthetic h:Ljava/lang/Object;

.field public final synthetic i:Ljava/lang/Object;

.field public final synthetic j:Ljava/lang/Object;

.field public final synthetic k:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Ljava/lang/String;Li91/v1;Lay0/a;Li1/l;ZJLjava/lang/String;)V
    .locals 1

    .line 1
    const/4 v0, 0x1

    iput v0, p0, Lf2/a;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lf2/a;->h:Ljava/lang/Object;

    iput-object p2, p0, Lf2/a;->i:Ljava/lang/Object;

    iput-object p3, p0, Lf2/a;->e:Lay0/a;

    iput-object p4, p0, Lf2/a;->j:Ljava/lang/Object;

    iput-boolean p5, p0, Lf2/a;->f:Z

    iput-wide p6, p0, Lf2/a;->g:J

    iput-object p8, p0, Lf2/a;->k:Ljava/lang/Object;

    return-void
.end method

.method public synthetic constructor <init>(ZLay0/a;Lx2/s;JLe1/n1;Lx4/w;Lt2/b;I)V
    .locals 0

    .line 2
    const/4 p9, 0x0

    iput p9, p0, Lf2/a;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-boolean p1, p0, Lf2/a;->f:Z

    iput-object p2, p0, Lf2/a;->e:Lay0/a;

    iput-object p3, p0, Lf2/a;->h:Ljava/lang/Object;

    iput-wide p4, p0, Lf2/a;->g:J

    iput-object p6, p0, Lf2/a;->i:Ljava/lang/Object;

    iput-object p7, p0, Lf2/a;->j:Ljava/lang/Object;

    iput-object p8, p0, Lf2/a;->k:Ljava/lang/Object;

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 20

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Lf2/a;->d:I

    .line 4
    .line 5
    packed-switch v1, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    iget-object v1, v0, Lf2/a;->h:Ljava/lang/Object;

    .line 9
    .line 10
    check-cast v1, Ljava/lang/String;

    .line 11
    .line 12
    iget-object v2, v0, Lf2/a;->i:Ljava/lang/Object;

    .line 13
    .line 14
    check-cast v2, Li91/v1;

    .line 15
    .line 16
    iget-object v3, v0, Lf2/a;->j:Ljava/lang/Object;

    .line 17
    .line 18
    move-object v5, v3

    .line 19
    check-cast v5, Li1/l;

    .line 20
    .line 21
    iget-object v3, v0, Lf2/a;->k:Ljava/lang/Object;

    .line 22
    .line 23
    check-cast v3, Ljava/lang/String;

    .line 24
    .line 25
    move-object/from16 v4, p1

    .line 26
    .line 27
    check-cast v4, Ll2/o;

    .line 28
    .line 29
    move-object/from16 v6, p2

    .line 30
    .line 31
    check-cast v6, Ljava/lang/Integer;

    .line 32
    .line 33
    invoke-virtual {v6}, Ljava/lang/Integer;->intValue()I

    .line 34
    .line 35
    .line 36
    move-result v6

    .line 37
    and-int/lit8 v7, v6, 0x3

    .line 38
    .line 39
    const/4 v8, 0x2

    .line 40
    const/4 v9, 0x1

    .line 41
    const/4 v11, 0x0

    .line 42
    if-eq v7, v8, :cond_0

    .line 43
    .line 44
    move v7, v9

    .line 45
    goto :goto_0

    .line 46
    :cond_0
    move v7, v11

    .line 47
    :goto_0
    and-int/2addr v6, v9

    .line 48
    move-object v12, v4

    .line 49
    check-cast v12, Ll2/t;

    .line 50
    .line 51
    invoke-virtual {v12, v6, v7}, Ll2/t;->O(IZ)Z

    .line 52
    .line 53
    .line 54
    move-result v4

    .line 55
    if-eqz v4, :cond_2

    .line 56
    .line 57
    sget-object v13, Lx2/p;->b:Lx2/p;

    .line 58
    .line 59
    invoke-static {v13, v1}, Landroidx/compose/ui/platform/a;->a(Lx2/s;Ljava/lang/String;)Lx2/s;

    .line 60
    .line 61
    .line 62
    move-result-object v4

    .line 63
    check-cast v2, Li91/b2;

    .line 64
    .line 65
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 66
    .line 67
    .line 68
    new-instance v6, Li91/j2;

    .line 69
    .line 70
    sget-object v1, Lj91/h;->a:Ll2/u2;

    .line 71
    .line 72
    invoke-virtual {v12, v1}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 73
    .line 74
    .line 75
    move-result-object v7

    .line 76
    check-cast v7, Lj91/e;

    .line 77
    .line 78
    invoke-virtual {v7}, Lj91/e;->p()J

    .line 79
    .line 80
    .line 81
    move-result-wide v7

    .line 82
    invoke-direct {v6, v7, v8}, Li91/j2;-><init>(J)V

    .line 83
    .line 84
    .line 85
    new-instance v8, Ld4/i;

    .line 86
    .line 87
    invoke-direct {v8, v11}, Ld4/i;-><init>(I)V

    .line 88
    .line 89
    .line 90
    const/16 v10, 0x8

    .line 91
    .line 92
    iget-boolean v7, v0, Lf2/a;->f:Z

    .line 93
    .line 94
    iget-object v9, v0, Lf2/a;->e:Lay0/a;

    .line 95
    .line 96
    invoke-static/range {v4 .. v10}, Landroidx/compose/foundation/a;->d(Lx2/s;Li1/l;Le1/s0;ZLd4/i;Lay0/a;I)Lx2/s;

    .line 97
    .line 98
    .line 99
    move-result-object v14

    .line 100
    const/16 v4, 0x20

    .line 101
    .line 102
    int-to-float v4, v4

    .line 103
    const/16 v18, 0x0

    .line 104
    .line 105
    const/16 v19, 0xb

    .line 106
    .line 107
    const/4 v15, 0x0

    .line 108
    const/16 v16, 0x0

    .line 109
    .line 110
    move/from16 v17, v4

    .line 111
    .line 112
    invoke-static/range {v14 .. v19}, Landroidx/compose/foundation/layout/a;->q(Lx2/s;FFFFI)Lx2/s;

    .line 113
    .line 114
    .line 115
    move-result-object v14

    .line 116
    iget v4, v2, Li91/b2;->a:I

    .line 117
    .line 118
    invoke-static {v4, v11, v12}, Ljp/fa;->b(IILl2/o;)Li3/c;

    .line 119
    .line 120
    .line 121
    move-result-object v4

    .line 122
    iget-object v2, v2, Li91/b2;->b:Le3/s;

    .line 123
    .line 124
    iget-wide v10, v0, Lf2/a;->g:J

    .line 125
    .line 126
    move-object v6, v4

    .line 127
    move-object/from16 p2, v5

    .line 128
    .line 129
    if-eqz v2, :cond_1

    .line 130
    .line 131
    iget-wide v4, v2, Le3/s;->a:J

    .line 132
    .line 133
    move-wide v15, v4

    .line 134
    goto :goto_1

    .line 135
    :cond_1
    move-wide v15, v10

    .line 136
    :goto_1
    const/16 v18, 0x30

    .line 137
    .line 138
    const/16 v19, 0x0

    .line 139
    .line 140
    move-object v0, v13

    .line 141
    const-string v13, ""

    .line 142
    .line 143
    move-object/from16 v17, v12

    .line 144
    .line 145
    move-object v12, v6

    .line 146
    invoke-static/range {v12 .. v19}, Lh2/f5;->a(Li3/c;Ljava/lang/String;Lx2/s;JLl2/o;II)V

    .line 147
    .line 148
    .line 149
    move-object/from16 v2, v17

    .line 150
    .line 151
    invoke-static {v0, v3}, Landroidx/compose/ui/platform/a;->a(Lx2/s;Ljava/lang/String;)Lx2/s;

    .line 152
    .line 153
    .line 154
    move-result-object v4

    .line 155
    new-instance v6, Li91/j2;

    .line 156
    .line 157
    invoke-virtual {v2, v1}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 158
    .line 159
    .line 160
    move-result-object v0

    .line 161
    check-cast v0, Lj91/e;

    .line 162
    .line 163
    invoke-virtual {v0}, Lj91/e;->p()J

    .line 164
    .line 165
    .line 166
    move-result-wide v0

    .line 167
    invoke-direct {v6, v0, v1}, Li91/j2;-><init>(J)V

    .line 168
    .line 169
    .line 170
    new-instance v8, Ld4/i;

    .line 171
    .line 172
    const/4 v0, 0x0

    .line 173
    invoke-direct {v8, v0}, Ld4/i;-><init>(I)V

    .line 174
    .line 175
    .line 176
    move-wide v15, v10

    .line 177
    const/16 v10, 0x8

    .line 178
    .line 179
    move-object/from16 v5, p2

    .line 180
    .line 181
    invoke-static/range {v4 .. v10}, Landroidx/compose/foundation/a;->d(Lx2/s;Li1/l;Le1/s0;ZLd4/i;Lay0/a;I)Lx2/s;

    .line 182
    .line 183
    .line 184
    move-result-object v14

    .line 185
    const v1, 0x7f08033b

    .line 186
    .line 187
    .line 188
    invoke-static {v1, v0, v2}, Ljp/fa;->b(IILl2/o;)Li3/c;

    .line 189
    .line 190
    .line 191
    move-result-object v12

    .line 192
    const-string v13, ""

    .line 193
    .line 194
    invoke-static/range {v12 .. v19}, Lh2/f5;->a(Li3/c;Ljava/lang/String;Lx2/s;JLl2/o;II)V

    .line 195
    .line 196
    .line 197
    goto :goto_2

    .line 198
    :cond_2
    move-object/from16 v17, v12

    .line 199
    .line 200
    invoke-virtual/range {v17 .. v17}, Ll2/t;->R()V

    .line 201
    .line 202
    .line 203
    :goto_2
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 204
    .line 205
    return-object v0

    .line 206
    :pswitch_0
    iget-object v1, v0, Lf2/a;->h:Ljava/lang/Object;

    .line 207
    .line 208
    move-object v4, v1

    .line 209
    check-cast v4, Lx2/s;

    .line 210
    .line 211
    iget-object v1, v0, Lf2/a;->i:Ljava/lang/Object;

    .line 212
    .line 213
    move-object v7, v1

    .line 214
    check-cast v7, Le1/n1;

    .line 215
    .line 216
    iget-object v1, v0, Lf2/a;->j:Ljava/lang/Object;

    .line 217
    .line 218
    move-object v8, v1

    .line 219
    check-cast v8, Lx4/w;

    .line 220
    .line 221
    iget-object v1, v0, Lf2/a;->k:Ljava/lang/Object;

    .line 222
    .line 223
    move-object v9, v1

    .line 224
    check-cast v9, Lt2/b;

    .line 225
    .line 226
    move-object/from16 v10, p1

    .line 227
    .line 228
    check-cast v10, Ll2/o;

    .line 229
    .line 230
    move-object/from16 v1, p2

    .line 231
    .line 232
    check-cast v1, Ljava/lang/Integer;

    .line 233
    .line 234
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 235
    .line 236
    .line 237
    const v1, 0x180001

    .line 238
    .line 239
    .line 240
    invoke-static {v1}, Ll2/b;->x(I)I

    .line 241
    .line 242
    .line 243
    move-result v11

    .line 244
    iget-boolean v2, v0, Lf2/a;->f:Z

    .line 245
    .line 246
    iget-object v3, v0, Lf2/a;->e:Lay0/a;

    .line 247
    .line 248
    iget-wide v5, v0, Lf2/a;->g:J

    .line 249
    .line 250
    invoke-static/range {v2 .. v11}, Lf2/b;->a(ZLay0/a;Lx2/s;JLe1/n1;Lx4/w;Lt2/b;Ll2/o;I)V

    .line 251
    .line 252
    .line 253
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 254
    .line 255
    return-object v0

    .line 256
    nop

    .line 257
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
