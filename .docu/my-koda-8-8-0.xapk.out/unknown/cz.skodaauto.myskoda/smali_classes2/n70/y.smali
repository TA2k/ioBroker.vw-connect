.class public final synthetic Ln70/y;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lm70/k0;

.field public final synthetic f:Ljava/lang/String;

.field public final synthetic g:Lay0/k;


# direct methods
.method public synthetic constructor <init>(Lm70/k0;Ljava/lang/String;Lay0/k;I)V
    .locals 0

    .line 1
    iput p4, p0, Ln70/y;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Ln70/y;->e:Lm70/k0;

    .line 4
    .line 5
    iput-object p2, p0, Ln70/y;->f:Ljava/lang/String;

    .line 6
    .line 7
    iput-object p3, p0, Ln70/y;->g:Lay0/k;

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
    .locals 18

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Ln70/y;->d:I

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
    move-object v14, v1

    .line 31
    check-cast v14, Ll2/t;

    .line 32
    .line 33
    invoke-virtual {v14, v2, v3}, Ll2/t;->O(IZ)Z

    .line 34
    .line 35
    .line 36
    move-result v1

    .line 37
    if-eqz v1, :cond_3

    .line 38
    .line 39
    const v1, 0x7f121476

    .line 40
    .line 41
    .line 42
    invoke-static {v14, v1}, Ljp/ga;->d(Ll2/o;I)Ljava/lang/String;

    .line 43
    .line 44
    .line 45
    move-result-object v4

    .line 46
    iget-object v1, v0, Ln70/y;->e:Lm70/k0;

    .line 47
    .line 48
    iget-object v6, v1, Lm70/k0;->r:Ljava/lang/String;

    .line 49
    .line 50
    new-instance v8, Li91/z1;

    .line 51
    .line 52
    new-instance v1, Lg4/g;

    .line 53
    .line 54
    iget-object v2, v0, Ln70/y;->f:Ljava/lang/String;

    .line 55
    .line 56
    invoke-direct {v1, v2}, Lg4/g;-><init>(Ljava/lang/String;)V

    .line 57
    .line 58
    .line 59
    const v2, 0x7f08033b

    .line 60
    .line 61
    .line 62
    invoke-direct {v8, v1, v2}, Li91/z1;-><init>(Lg4/g;I)V

    .line 63
    .line 64
    .line 65
    iget-object v0, v0, Ln70/y;->g:Lay0/k;

    .line 66
    .line 67
    invoke-virtual {v14, v0}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 68
    .line 69
    .line 70
    move-result v1

    .line 71
    invoke-virtual {v14}, Ll2/t;->L()Ljava/lang/Object;

    .line 72
    .line 73
    .line 74
    move-result-object v2

    .line 75
    if-nez v1, :cond_1

    .line 76
    .line 77
    sget-object v1, Ll2/n;->a:Ll2/x0;

    .line 78
    .line 79
    if-ne v2, v1, :cond_2

    .line 80
    .line 81
    :cond_1
    new-instance v2, Llk/f;

    .line 82
    .line 83
    const/16 v1, 0x1b

    .line 84
    .line 85
    invoke-direct {v2, v1, v0}, Llk/f;-><init>(ILay0/k;)V

    .line 86
    .line 87
    .line 88
    invoke-virtual {v14, v2}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 89
    .line 90
    .line 91
    :cond_2
    move-object v11, v2

    .line 92
    check-cast v11, Lay0/a;

    .line 93
    .line 94
    const/16 v16, 0x30

    .line 95
    .line 96
    const/16 v17, 0x76a

    .line 97
    .line 98
    const/4 v5, 0x0

    .line 99
    const/4 v7, 0x0

    .line 100
    const/4 v9, 0x0

    .line 101
    const/4 v10, 0x0

    .line 102
    const/4 v12, 0x0

    .line 103
    const-string v13, "trip_detail_price_cng"

    .line 104
    .line 105
    const/4 v15, 0x0

    .line 106
    invoke-static/range {v4 .. v17}, Li91/j0;->L(Ljava/lang/String;Lx2/s;Ljava/lang/String;Li91/x1;Li91/v1;ZLi91/t1;Lay0/a;FLjava/lang/String;Ll2/o;III)V

    .line 107
    .line 108
    .line 109
    goto :goto_1

    .line 110
    :cond_3
    invoke-virtual {v14}, Ll2/t;->R()V

    .line 111
    .line 112
    .line 113
    :goto_1
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 114
    .line 115
    return-object v0

    .line 116
    :pswitch_0
    move-object/from16 v1, p1

    .line 117
    .line 118
    check-cast v1, Ll2/o;

    .line 119
    .line 120
    move-object/from16 v2, p2

    .line 121
    .line 122
    check-cast v2, Ljava/lang/Integer;

    .line 123
    .line 124
    invoke-virtual {v2}, Ljava/lang/Integer;->intValue()I

    .line 125
    .line 126
    .line 127
    move-result v2

    .line 128
    and-int/lit8 v3, v2, 0x3

    .line 129
    .line 130
    const/4 v4, 0x2

    .line 131
    const/4 v5, 0x1

    .line 132
    if-eq v3, v4, :cond_4

    .line 133
    .line 134
    move v3, v5

    .line 135
    goto :goto_2

    .line 136
    :cond_4
    const/4 v3, 0x0

    .line 137
    :goto_2
    and-int/2addr v2, v5

    .line 138
    move-object v14, v1

    .line 139
    check-cast v14, Ll2/t;

    .line 140
    .line 141
    invoke-virtual {v14, v2, v3}, Ll2/t;->O(IZ)Z

    .line 142
    .line 143
    .line 144
    move-result v1

    .line 145
    if-eqz v1, :cond_7

    .line 146
    .line 147
    const v1, 0x7f121477

    .line 148
    .line 149
    .line 150
    invoke-static {v14, v1}, Ljp/ga;->d(Ll2/o;I)Ljava/lang/String;

    .line 151
    .line 152
    .line 153
    move-result-object v4

    .line 154
    iget-object v1, v0, Ln70/y;->e:Lm70/k0;

    .line 155
    .line 156
    iget-object v6, v1, Lm70/k0;->n:Ljava/lang/String;

    .line 157
    .line 158
    new-instance v8, Li91/z1;

    .line 159
    .line 160
    new-instance v1, Lg4/g;

    .line 161
    .line 162
    iget-object v2, v0, Ln70/y;->f:Ljava/lang/String;

    .line 163
    .line 164
    invoke-direct {v1, v2}, Lg4/g;-><init>(Ljava/lang/String;)V

    .line 165
    .line 166
    .line 167
    const v2, 0x7f08033b

    .line 168
    .line 169
    .line 170
    invoke-direct {v8, v1, v2}, Li91/z1;-><init>(Lg4/g;I)V

    .line 171
    .line 172
    .line 173
    iget-object v0, v0, Ln70/y;->g:Lay0/k;

    .line 174
    .line 175
    invoke-virtual {v14, v0}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 176
    .line 177
    .line 178
    move-result v1

    .line 179
    invoke-virtual {v14}, Ll2/t;->L()Ljava/lang/Object;

    .line 180
    .line 181
    .line 182
    move-result-object v2

    .line 183
    if-nez v1, :cond_5

    .line 184
    .line 185
    sget-object v1, Ll2/n;->a:Ll2/x0;

    .line 186
    .line 187
    if-ne v2, v1, :cond_6

    .line 188
    .line 189
    :cond_5
    new-instance v2, Llk/f;

    .line 190
    .line 191
    const/16 v1, 0x1a

    .line 192
    .line 193
    invoke-direct {v2, v1, v0}, Llk/f;-><init>(ILay0/k;)V

    .line 194
    .line 195
    .line 196
    invoke-virtual {v14, v2}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 197
    .line 198
    .line 199
    :cond_6
    move-object v11, v2

    .line 200
    check-cast v11, Lay0/a;

    .line 201
    .line 202
    const/16 v16, 0x30

    .line 203
    .line 204
    const/16 v17, 0x76a

    .line 205
    .line 206
    const/4 v5, 0x0

    .line 207
    const/4 v7, 0x0

    .line 208
    const/4 v9, 0x0

    .line 209
    const/4 v10, 0x0

    .line 210
    const/4 v12, 0x0

    .line 211
    const-string v13, "trip_detail_price_fuel"

    .line 212
    .line 213
    const/4 v15, 0x0

    .line 214
    invoke-static/range {v4 .. v17}, Li91/j0;->L(Ljava/lang/String;Lx2/s;Ljava/lang/String;Li91/x1;Li91/v1;ZLi91/t1;Lay0/a;FLjava/lang/String;Ll2/o;III)V

    .line 215
    .line 216
    .line 217
    goto :goto_3

    .line 218
    :cond_7
    invoke-virtual {v14}, Ll2/t;->R()V

    .line 219
    .line 220
    .line 221
    :goto_3
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 222
    .line 223
    return-object v0

    .line 224
    nop

    .line 225
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
