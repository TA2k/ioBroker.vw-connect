.class public final synthetic Li91/l3;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ljava/lang/String;

.field public final synthetic f:Z

.field public final synthetic g:Lh2/eb;


# direct methods
.method public synthetic constructor <init>(Ljava/lang/String;ZLh2/eb;I)V
    .locals 0

    .line 1
    iput p4, p0, Li91/l3;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Li91/l3;->e:Ljava/lang/String;

    .line 4
    .line 5
    iput-boolean p2, p0, Li91/l3;->f:Z

    .line 6
    .line 7
    iput-object p3, p0, Li91/l3;->g:Lh2/eb;

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
    .locals 27

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Li91/l3;->d:I

    .line 4
    .line 5
    packed-switch v1, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    move-object/from16 v1, p1

    .line 9
    .line 10
    check-cast v1, Ll2/o;

    .line 11
    .line 12
    move-object/from16 v2, p2

    .line 13
    .line 14
    check-cast v2, Ljava/lang/Integer;

    .line 15
    .line 16
    invoke-virtual {v2}, Ljava/lang/Integer;->intValue()I

    .line 17
    .line 18
    .line 19
    move-result v2

    .line 20
    and-int/lit8 v3, v2, 0x3

    .line 21
    .line 22
    const/4 v4, 0x2

    .line 23
    const/4 v5, 0x1

    .line 24
    if-eq v3, v4, :cond_0

    .line 25
    .line 26
    move v3, v5

    .line 27
    goto :goto_0

    .line 28
    :cond_0
    const/4 v3, 0x0

    .line 29
    :goto_0
    and-int/2addr v2, v5

    .line 30
    check-cast v1, Ll2/t;

    .line 31
    .line 32
    invoke-virtual {v1, v2, v3}, Ll2/t;->O(IZ)Z

    .line 33
    .line 34
    .line 35
    move-result v2

    .line 36
    if-eqz v2, :cond_2

    .line 37
    .line 38
    sget-object v2, Lj91/j;->a:Ll2/u2;

    .line 39
    .line 40
    invoke-virtual {v1, v2}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 41
    .line 42
    .line 43
    move-result-object v2

    .line 44
    check-cast v2, Lj91/f;

    .line 45
    .line 46
    invoke-virtual {v2}, Lj91/f;->b()Lg4/p0;

    .line 47
    .line 48
    .line 49
    move-result-object v3

    .line 50
    iget-boolean v2, v0, Li91/l3;->f:Z

    .line 51
    .line 52
    iget-object v4, v0, Li91/l3;->g:Lh2/eb;

    .line 53
    .line 54
    if-eqz v2, :cond_1

    .line 55
    .line 56
    iget-wide v4, v4, Lh2/eb;->B:J

    .line 57
    .line 58
    goto :goto_1

    .line 59
    :cond_1
    iget-wide v4, v4, Lh2/eb;->D:J

    .line 60
    .line 61
    :goto_1
    const/16 v16, 0x0

    .line 62
    .line 63
    const v17, 0xfffffe

    .line 64
    .line 65
    .line 66
    const-wide/16 v6, 0x0

    .line 67
    .line 68
    const/4 v8, 0x0

    .line 69
    const/4 v9, 0x0

    .line 70
    const-wide/16 v10, 0x0

    .line 71
    .line 72
    const/4 v12, 0x0

    .line 73
    const-wide/16 v13, 0x0

    .line 74
    .line 75
    const/4 v15, 0x0

    .line 76
    invoke-static/range {v3 .. v17}, Lg4/p0;->a(Lg4/p0;JJLk4/x;Lk4/n;JIJLg4/y;Lr4/i;I)Lg4/p0;

    .line 77
    .line 78
    .line 79
    move-result-object v22

    .line 80
    const/16 v25, 0x0

    .line 81
    .line 82
    const v26, 0x1fffe

    .line 83
    .line 84
    .line 85
    iget-object v4, v0, Li91/l3;->e:Ljava/lang/String;

    .line 86
    .line 87
    const/4 v5, 0x0

    .line 88
    const-wide/16 v8, 0x0

    .line 89
    .line 90
    const/4 v10, 0x0

    .line 91
    const-wide/16 v11, 0x0

    .line 92
    .line 93
    const/4 v13, 0x0

    .line 94
    const/4 v14, 0x0

    .line 95
    const-wide/16 v15, 0x0

    .line 96
    .line 97
    const/16 v17, 0x0

    .line 98
    .line 99
    const/16 v18, 0x0

    .line 100
    .line 101
    const/16 v19, 0x0

    .line 102
    .line 103
    const/16 v20, 0x0

    .line 104
    .line 105
    const/16 v21, 0x0

    .line 106
    .line 107
    const/16 v24, 0x0

    .line 108
    .line 109
    move-object/from16 v23, v1

    .line 110
    .line 111
    invoke-static/range {v4 .. v26}, Lh2/rb;->b(Ljava/lang/String;Lx2/s;JJLk4/x;JLr4/l;Lr4/k;JIZIILay0/k;Lg4/p0;Ll2/o;III)V

    .line 112
    .line 113
    .line 114
    goto :goto_2

    .line 115
    :cond_2
    move-object/from16 v23, v1

    .line 116
    .line 117
    invoke-virtual/range {v23 .. v23}, Ll2/t;->R()V

    .line 118
    .line 119
    .line 120
    :goto_2
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 121
    .line 122
    return-object v0

    .line 123
    :pswitch_0
    move-object/from16 v1, p1

    .line 124
    .line 125
    check-cast v1, Ll2/o;

    .line 126
    .line 127
    move-object/from16 v2, p2

    .line 128
    .line 129
    check-cast v2, Ljava/lang/Integer;

    .line 130
    .line 131
    invoke-virtual {v2}, Ljava/lang/Integer;->intValue()I

    .line 132
    .line 133
    .line 134
    move-result v2

    .line 135
    and-int/lit8 v3, v2, 0x3

    .line 136
    .line 137
    const/4 v4, 0x2

    .line 138
    const/4 v5, 0x1

    .line 139
    if-eq v3, v4, :cond_3

    .line 140
    .line 141
    move v3, v5

    .line 142
    goto :goto_3

    .line 143
    :cond_3
    const/4 v3, 0x0

    .line 144
    :goto_3
    and-int/2addr v2, v5

    .line 145
    check-cast v1, Ll2/t;

    .line 146
    .line 147
    invoke-virtual {v1, v2, v3}, Ll2/t;->O(IZ)Z

    .line 148
    .line 149
    .line 150
    move-result v2

    .line 151
    if-eqz v2, :cond_5

    .line 152
    .line 153
    sget-object v2, Lj91/j;->a:Ll2/u2;

    .line 154
    .line 155
    invoke-virtual {v1, v2}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 156
    .line 157
    .line 158
    move-result-object v2

    .line 159
    check-cast v2, Lj91/f;

    .line 160
    .line 161
    invoke-virtual {v2}, Lj91/f;->b()Lg4/p0;

    .line 162
    .line 163
    .line 164
    move-result-object v3

    .line 165
    iget-boolean v2, v0, Li91/l3;->f:Z

    .line 166
    .line 167
    iget-object v4, v0, Li91/l3;->g:Lh2/eb;

    .line 168
    .line 169
    if-eqz v2, :cond_4

    .line 170
    .line 171
    iget-wide v4, v4, Lh2/eb;->B:J

    .line 172
    .line 173
    goto :goto_4

    .line 174
    :cond_4
    iget-wide v4, v4, Lh2/eb;->D:J

    .line 175
    .line 176
    :goto_4
    const/16 v16, 0x0

    .line 177
    .line 178
    const v17, 0xfffffe

    .line 179
    .line 180
    .line 181
    const-wide/16 v6, 0x0

    .line 182
    .line 183
    const/4 v8, 0x0

    .line 184
    const/4 v9, 0x0

    .line 185
    const-wide/16 v10, 0x0

    .line 186
    .line 187
    const/4 v12, 0x0

    .line 188
    const-wide/16 v13, 0x0

    .line 189
    .line 190
    const/4 v15, 0x0

    .line 191
    invoke-static/range {v3 .. v17}, Lg4/p0;->a(Lg4/p0;JJLk4/x;Lk4/n;JIJLg4/y;Lr4/i;I)Lg4/p0;

    .line 192
    .line 193
    .line 194
    move-result-object v22

    .line 195
    const/16 v25, 0x0

    .line 196
    .line 197
    const v26, 0x1fffe

    .line 198
    .line 199
    .line 200
    iget-object v4, v0, Li91/l3;->e:Ljava/lang/String;

    .line 201
    .line 202
    const/4 v5, 0x0

    .line 203
    const-wide/16 v8, 0x0

    .line 204
    .line 205
    const/4 v10, 0x0

    .line 206
    const-wide/16 v11, 0x0

    .line 207
    .line 208
    const/4 v13, 0x0

    .line 209
    const/4 v14, 0x0

    .line 210
    const-wide/16 v15, 0x0

    .line 211
    .line 212
    const/16 v17, 0x0

    .line 213
    .line 214
    const/16 v18, 0x0

    .line 215
    .line 216
    const/16 v19, 0x0

    .line 217
    .line 218
    const/16 v20, 0x0

    .line 219
    .line 220
    const/16 v21, 0x0

    .line 221
    .line 222
    const/16 v24, 0x0

    .line 223
    .line 224
    move-object/from16 v23, v1

    .line 225
    .line 226
    invoke-static/range {v4 .. v26}, Lh2/rb;->b(Ljava/lang/String;Lx2/s;JJLk4/x;JLr4/l;Lr4/k;JIZIILay0/k;Lg4/p0;Ll2/o;III)V

    .line 227
    .line 228
    .line 229
    goto :goto_5

    .line 230
    :cond_5
    move-object/from16 v23, v1

    .line 231
    .line 232
    invoke-virtual/range {v23 .. v23}, Ll2/t;->R()V

    .line 233
    .line 234
    .line 235
    :goto_5
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 236
    .line 237
    return-object v0

    .line 238
    nop

    .line 239
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
