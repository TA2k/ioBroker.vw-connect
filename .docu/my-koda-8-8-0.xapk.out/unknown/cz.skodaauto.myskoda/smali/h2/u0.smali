.class public final Lh2/u0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:J

.field public final synthetic f:Ljava/lang/Object;

.field public final synthetic g:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(JLjava/lang/Object;Ljava/lang/Object;I)V
    .locals 0

    .line 1
    iput p5, p0, Lh2/u0;->d:I

    .line 2
    .line 3
    iput-wide p1, p0, Lh2/u0;->e:J

    .line 4
    .line 5
    iput-object p3, p0, Lh2/u0;->f:Ljava/lang/Object;

    .line 6
    .line 7
    iput-object p4, p0, Lh2/u0;->g:Ljava/lang/Object;

    .line 8
    .line 9
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 10
    .line 11
    .line 12
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 19

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Lh2/u0;->d:I

    .line 4
    .line 5
    sget-object v2, Llx0/b0;->a:Llx0/b0;

    .line 6
    .line 7
    iget-object v3, v0, Lh2/u0;->g:Ljava/lang/Object;

    .line 8
    .line 9
    iget-object v4, v0, Lh2/u0;->f:Ljava/lang/Object;

    .line 10
    .line 11
    const/4 v5, 0x0

    .line 12
    const/4 v6, 0x1

    .line 13
    const/4 v7, 0x2

    .line 14
    packed-switch v1, :pswitch_data_0

    .line 15
    .line 16
    .line 17
    move-object/from16 v1, p1

    .line 18
    .line 19
    check-cast v1, Ll2/o;

    .line 20
    .line 21
    move-object/from16 v8, p2

    .line 22
    .line 23
    check-cast v8, Ljava/lang/Number;

    .line 24
    .line 25
    invoke-virtual {v8}, Ljava/lang/Number;->intValue()I

    .line 26
    .line 27
    .line 28
    move-result v8

    .line 29
    and-int/lit8 v9, v8, 0x3

    .line 30
    .line 31
    if-eq v9, v7, :cond_0

    .line 32
    .line 33
    move v5, v6

    .line 34
    :cond_0
    and-int/2addr v6, v8

    .line 35
    move-object v11, v1

    .line 36
    check-cast v11, Ll2/t;

    .line 37
    .line 38
    invoke-virtual {v11, v6, v5}, Ll2/t;->O(IZ)Z

    .line 39
    .line 40
    .line 41
    move-result v1

    .line 42
    if-eqz v1, :cond_1

    .line 43
    .line 44
    move-object v9, v4

    .line 45
    check-cast v9, Lg4/p0;

    .line 46
    .line 47
    move-object v10, v3

    .line 48
    check-cast v10, Lay0/n;

    .line 49
    .line 50
    const/4 v12, 0x0

    .line 51
    iget-wide v7, v0, Lh2/u0;->e:J

    .line 52
    .line 53
    invoke-static/range {v7 .. v12}, Li2/h1;->b(JLg4/p0;Lay0/n;Ll2/o;I)V

    .line 54
    .line 55
    .line 56
    goto :goto_0

    .line 57
    :cond_1
    invoke-virtual {v11}, Ll2/t;->R()V

    .line 58
    .line 59
    .line 60
    :goto_0
    return-object v2

    .line 61
    :pswitch_0
    move-object/from16 v1, p1

    .line 62
    .line 63
    check-cast v1, Ll2/o;

    .line 64
    .line 65
    move-object/from16 v8, p2

    .line 66
    .line 67
    check-cast v8, Ljava/lang/Number;

    .line 68
    .line 69
    invoke-virtual {v8}, Ljava/lang/Number;->intValue()I

    .line 70
    .line 71
    .line 72
    move-result v8

    .line 73
    check-cast v4, Lh2/t9;

    .line 74
    .line 75
    and-int/lit8 v9, v8, 0x3

    .line 76
    .line 77
    if-eq v9, v7, :cond_2

    .line 78
    .line 79
    move v5, v6

    .line 80
    :cond_2
    and-int/2addr v8, v6

    .line 81
    check-cast v1, Ll2/t;

    .line 82
    .line 83
    invoke-virtual {v1, v8, v5}, Ll2/t;->O(IZ)Z

    .line 84
    .line 85
    .line 86
    move-result v5

    .line 87
    if-eqz v5, :cond_5

    .line 88
    .line 89
    sget-object v5, Lh2/o0;->a:Lk1/a1;

    .line 90
    .line 91
    iget-wide v8, v0, Lh2/u0;->e:J

    .line 92
    .line 93
    invoke-static {v8, v9, v1}, Lh2/o0;->d(JLl2/o;)Lh2/n0;

    .line 94
    .line 95
    .line 96
    move-result-object v13

    .line 97
    invoke-virtual {v1, v4}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 98
    .line 99
    .line 100
    move-result v0

    .line 101
    invoke-virtual {v1}, Ll2/t;->L()Ljava/lang/Object;

    .line 102
    .line 103
    .line 104
    move-result-object v5

    .line 105
    if-nez v0, :cond_3

    .line 106
    .line 107
    sget-object v0, Ll2/n;->a:Ll2/x0;

    .line 108
    .line 109
    if-ne v5, v0, :cond_4

    .line 110
    .line 111
    :cond_3
    new-instance v5, Lh2/v9;

    .line 112
    .line 113
    invoke-direct {v5, v4, v6}, Lh2/v9;-><init>(Lh2/t9;I)V

    .line 114
    .line 115
    .line 116
    invoke-virtual {v1, v5}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 117
    .line 118
    .line 119
    :cond_4
    move-object v9, v5

    .line 120
    check-cast v9, Lay0/a;

    .line 121
    .line 122
    new-instance v0, Lh2/f3;

    .line 123
    .line 124
    check-cast v3, Ljava/lang/String;

    .line 125
    .line 126
    invoke-direct {v0, v3, v7}, Lh2/f3;-><init>(Ljava/lang/String;I)V

    .line 127
    .line 128
    .line 129
    const v3, 0x1f0f8424

    .line 130
    .line 131
    .line 132
    invoke-static {v3, v1, v0}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 133
    .line 134
    .line 135
    move-result-object v15

    .line 136
    const/high16 v17, 0x30000000

    .line 137
    .line 138
    const/16 v18, 0x1ee

    .line 139
    .line 140
    const/4 v10, 0x0

    .line 141
    const/4 v11, 0x0

    .line 142
    const/4 v12, 0x0

    .line 143
    const/4 v14, 0x0

    .line 144
    move-object/from16 v16, v1

    .line 145
    .line 146
    invoke-static/range {v9 .. v18}, Lh2/r;->u(Lay0/a;Lx2/s;ZLe3/n0;Lh2/n0;Lk1/z0;Lt2/b;Ll2/o;II)V

    .line 147
    .line 148
    .line 149
    goto :goto_1

    .line 150
    :cond_5
    move-object/from16 v16, v1

    .line 151
    .line 152
    invoke-virtual/range {v16 .. v16}, Ll2/t;->R()V

    .line 153
    .line 154
    .line 155
    :goto_1
    return-object v2

    .line 156
    :pswitch_1
    move-object/from16 v1, p1

    .line 157
    .line 158
    check-cast v1, Ll2/o;

    .line 159
    .line 160
    move-object/from16 v8, p2

    .line 161
    .line 162
    check-cast v8, Ljava/lang/Number;

    .line 163
    .line 164
    invoke-virtual {v8}, Ljava/lang/Number;->intValue()I

    .line 165
    .line 166
    .line 167
    move-result v8

    .line 168
    and-int/lit8 v9, v8, 0x3

    .line 169
    .line 170
    if-eq v9, v7, :cond_6

    .line 171
    .line 172
    move v5, v6

    .line 173
    :cond_6
    and-int/2addr v6, v8

    .line 174
    move-object v12, v1

    .line 175
    check-cast v12, Ll2/t;

    .line 176
    .line 177
    invoke-virtual {v12, v6, v5}, Ll2/t;->O(IZ)Z

    .line 178
    .line 179
    .line 180
    move-result v1

    .line 181
    if-eqz v1, :cond_7

    .line 182
    .line 183
    sget-object v1, Lh2/ec;->a:Ll2/u2;

    .line 184
    .line 185
    invoke-virtual {v12, v1}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 186
    .line 187
    .line 188
    move-result-object v1

    .line 189
    check-cast v1, Lh2/dc;

    .line 190
    .line 191
    iget-object v10, v1, Lh2/dc;->m:Lg4/p0;

    .line 192
    .line 193
    new-instance v1, Lf2/e;

    .line 194
    .line 195
    check-cast v4, Lk1/z0;

    .line 196
    .line 197
    check-cast v3, Lt2/b;

    .line 198
    .line 199
    invoke-direct {v1, v4, v3, v7}, Lf2/e;-><init>(Lk1/z0;Lt2/b;I)V

    .line 200
    .line 201
    .line 202
    const v3, 0x18e49c83

    .line 203
    .line 204
    .line 205
    invoke-static {v3, v12, v1}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 206
    .line 207
    .line 208
    move-result-object v11

    .line 209
    const/16 v13, 0x180

    .line 210
    .line 211
    iget-wide v8, v0, Lh2/u0;->e:J

    .line 212
    .line 213
    invoke-static/range {v8 .. v13}, Li2/a1;->d(JLg4/p0;Lay0/n;Ll2/o;I)V

    .line 214
    .line 215
    .line 216
    goto :goto_2

    .line 217
    :cond_7
    invoke-virtual {v12}, Ll2/t;->R()V

    .line 218
    .line 219
    .line 220
    :goto_2
    return-object v2

    .line 221
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
