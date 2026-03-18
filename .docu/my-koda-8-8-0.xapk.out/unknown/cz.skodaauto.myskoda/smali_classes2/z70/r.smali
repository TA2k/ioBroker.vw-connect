.class public final synthetic Lz70/r;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ly70/h0;


# direct methods
.method public synthetic constructor <init>(Ly70/h0;I)V
    .locals 0

    .line 1
    iput p2, p0, Lz70/r;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lz70/r;->e:Ly70/h0;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 26

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Lz70/r;->d:I

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
    if-eqz v2, :cond_1

    .line 37
    .line 38
    iget-object v0, v0, Lz70/r;->e:Ly70/h0;

    .line 39
    .line 40
    iget-object v4, v0, Ly70/h0;->s:Ljava/lang/String;

    .line 41
    .line 42
    sget-object v0, Lj91/j;->a:Ll2/u2;

    .line 43
    .line 44
    invoke-virtual {v1, v0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 45
    .line 46
    .line 47
    move-result-object v0

    .line 48
    check-cast v0, Lj91/f;

    .line 49
    .line 50
    invoke-virtual {v0}, Lj91/f;->b()Lg4/p0;

    .line 51
    .line 52
    .line 53
    move-result-object v5

    .line 54
    sget-object v0, Lj91/h;->a:Ll2/u2;

    .line 55
    .line 56
    invoke-virtual {v1, v0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 57
    .line 58
    .line 59
    move-result-object v0

    .line 60
    check-cast v0, Lj91/e;

    .line 61
    .line 62
    invoke-virtual {v0}, Lj91/e;->q()J

    .line 63
    .line 64
    .line 65
    move-result-wide v7

    .line 66
    const/16 v24, 0x0

    .line 67
    .line 68
    const v25, 0xfff4

    .line 69
    .line 70
    .line 71
    const/4 v6, 0x0

    .line 72
    const-wide/16 v9, 0x0

    .line 73
    .line 74
    const/4 v11, 0x0

    .line 75
    const-wide/16 v12, 0x0

    .line 76
    .line 77
    const/4 v14, 0x0

    .line 78
    const/4 v15, 0x0

    .line 79
    const-wide/16 v16, 0x0

    .line 80
    .line 81
    const/16 v18, 0x0

    .line 82
    .line 83
    const/16 v19, 0x0

    .line 84
    .line 85
    const/16 v20, 0x0

    .line 86
    .line 87
    const/16 v21, 0x0

    .line 88
    .line 89
    const/16 v23, 0x0

    .line 90
    .line 91
    move-object/from16 v22, v1

    .line 92
    .line 93
    invoke-static/range {v4 .. v25}, Li91/z3;->d(Ljava/lang/String;Lg4/p0;Lx2/s;JJLk4/x;JLr4/l;Lr4/k;JIZILay0/k;Ll2/o;III)V

    .line 94
    .line 95
    .line 96
    goto :goto_1

    .line 97
    :cond_1
    move-object/from16 v22, v1

    .line 98
    .line 99
    invoke-virtual/range {v22 .. v22}, Ll2/t;->R()V

    .line 100
    .line 101
    .line 102
    :goto_1
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 103
    .line 104
    return-object v0

    .line 105
    :pswitch_0
    move-object/from16 v1, p1

    .line 106
    .line 107
    check-cast v1, Ll2/o;

    .line 108
    .line 109
    move-object/from16 v2, p2

    .line 110
    .line 111
    check-cast v2, Ljava/lang/Integer;

    .line 112
    .line 113
    invoke-virtual {v2}, Ljava/lang/Integer;->intValue()I

    .line 114
    .line 115
    .line 116
    move-result v2

    .line 117
    and-int/lit8 v3, v2, 0x3

    .line 118
    .line 119
    const/4 v4, 0x2

    .line 120
    const/4 v5, 0x1

    .line 121
    if-eq v3, v4, :cond_2

    .line 122
    .line 123
    move v3, v5

    .line 124
    goto :goto_2

    .line 125
    :cond_2
    const/4 v3, 0x0

    .line 126
    :goto_2
    and-int/2addr v2, v5

    .line 127
    check-cast v1, Ll2/t;

    .line 128
    .line 129
    invoke-virtual {v1, v2, v3}, Ll2/t;->O(IZ)Z

    .line 130
    .line 131
    .line 132
    move-result v2

    .line 133
    if-eqz v2, :cond_3

    .line 134
    .line 135
    iget-object v0, v0, Lz70/r;->e:Ly70/h0;

    .line 136
    .line 137
    iget-object v4, v0, Ly70/h0;->h:Ljava/lang/String;

    .line 138
    .line 139
    sget-object v0, Lj91/j;->a:Ll2/u2;

    .line 140
    .line 141
    invoke-virtual {v1, v0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 142
    .line 143
    .line 144
    move-result-object v0

    .line 145
    check-cast v0, Lj91/f;

    .line 146
    .line 147
    invoke-virtual {v0}, Lj91/f;->b()Lg4/p0;

    .line 148
    .line 149
    .line 150
    move-result-object v5

    .line 151
    sget-object v0, Lj91/h;->a:Ll2/u2;

    .line 152
    .line 153
    invoke-virtual {v1, v0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 154
    .line 155
    .line 156
    move-result-object v0

    .line 157
    check-cast v0, Lj91/e;

    .line 158
    .line 159
    invoke-virtual {v0}, Lj91/e;->q()J

    .line 160
    .line 161
    .line 162
    move-result-wide v7

    .line 163
    const/16 v24, 0x0

    .line 164
    .line 165
    const v25, 0xfff4

    .line 166
    .line 167
    .line 168
    const/4 v6, 0x0

    .line 169
    const-wide/16 v9, 0x0

    .line 170
    .line 171
    const/4 v11, 0x0

    .line 172
    const-wide/16 v12, 0x0

    .line 173
    .line 174
    const/4 v14, 0x0

    .line 175
    const/4 v15, 0x0

    .line 176
    const-wide/16 v16, 0x0

    .line 177
    .line 178
    const/16 v18, 0x0

    .line 179
    .line 180
    const/16 v19, 0x0

    .line 181
    .line 182
    const/16 v20, 0x0

    .line 183
    .line 184
    const/16 v21, 0x0

    .line 185
    .line 186
    const/16 v23, 0x0

    .line 187
    .line 188
    move-object/from16 v22, v1

    .line 189
    .line 190
    invoke-static/range {v4 .. v25}, Li91/z3;->d(Ljava/lang/String;Lg4/p0;Lx2/s;JJLk4/x;JLr4/l;Lr4/k;JIZILay0/k;Ll2/o;III)V

    .line 191
    .line 192
    .line 193
    goto :goto_3

    .line 194
    :cond_3
    move-object/from16 v22, v1

    .line 195
    .line 196
    invoke-virtual/range {v22 .. v22}, Ll2/t;->R()V

    .line 197
    .line 198
    .line 199
    :goto_3
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 200
    .line 201
    return-object v0

    .line 202
    nop

    .line 203
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
