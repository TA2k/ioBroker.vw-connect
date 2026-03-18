.class public final synthetic Lba/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Z

.field public final synthetic f:Lay0/n;


# direct methods
.method public synthetic constructor <init>(ZLay0/n;)V
    .locals 1

    .line 1
    const/4 v0, 0x1

    iput v0, p0, Lba/a;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-boolean p1, p0, Lba/a;->e:Z

    iput-object p2, p0, Lba/a;->f:Lay0/n;

    return-void
.end method

.method public synthetic constructor <init>(ZLay0/n;I)V
    .locals 0

    .line 2
    const/4 p3, 0x0

    iput p3, p0, Lba/a;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-boolean p1, p0, Lba/a;->e:Z

    iput-object p2, p0, Lba/a;->f:Lay0/n;

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 12

    .line 1
    iget v0, p0, Lba/a;->d:I

    .line 2
    .line 3
    check-cast p1, Ll2/o;

    .line 4
    .line 5
    check-cast p2, Ljava/lang/Integer;

    .line 6
    .line 7
    packed-switch v0, :pswitch_data_0

    .line 8
    .line 9
    .line 10
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 11
    .line 12
    .line 13
    move-result p2

    .line 14
    and-int/lit8 v0, p2, 0x3

    .line 15
    .line 16
    const/4 v1, 0x2

    .line 17
    const/4 v2, 0x1

    .line 18
    const/4 v3, 0x0

    .line 19
    if-eq v0, v1, :cond_0

    .line 20
    .line 21
    move v0, v2

    .line 22
    goto :goto_0

    .line 23
    :cond_0
    move v0, v3

    .line 24
    :goto_0
    and-int/2addr p2, v2

    .line 25
    check-cast p1, Ll2/t;

    .line 26
    .line 27
    invoke-virtual {p1, p2, v0}, Ll2/t;->O(IZ)Z

    .line 28
    .line 29
    .line 30
    move-result p2

    .line 31
    if-eqz p2, :cond_9

    .line 32
    .line 33
    const p2, 0x3f6808c0

    .line 34
    .line 35
    .line 36
    invoke-virtual {p1, p2}, Ll2/t;->Y(I)V

    .line 37
    .line 38
    .line 39
    iget-boolean p2, p0, Lba/a;->e:Z

    .line 40
    .line 41
    if-nez p2, :cond_1

    .line 42
    .line 43
    const-wide/16 v0, 0x0

    .line 44
    .line 45
    goto :goto_1

    .line 46
    :cond_1
    invoke-static {p1}, Lkp/k;->c(Ll2/o;)Z

    .line 47
    .line 48
    .line 49
    move-result p2

    .line 50
    if-eqz p2, :cond_2

    .line 51
    .line 52
    const-wide v0, 0xff161718L

    .line 53
    .line 54
    .line 55
    .line 56
    .line 57
    goto :goto_1

    .line 58
    :cond_2
    const-wide v0, 0xffffffffL

    .line 59
    .line 60
    .line 61
    .line 62
    .line 63
    :goto_1
    invoke-virtual {p1, v3}, Ll2/t;->q(Z)V

    .line 64
    .line 65
    .line 66
    sget-object p2, Lk1/j;->c:Lk1/e;

    .line 67
    .line 68
    sget-object v4, Lx2/c;->p:Lx2/h;

    .line 69
    .line 70
    invoke-static {p2, v4, p1, v3}, Lk1/r;->a(Lk1/i;Lx2/d;Ll2/o;I)Lk1/s;

    .line 71
    .line 72
    .line 73
    move-result-object p2

    .line 74
    iget-wide v4, p1, Ll2/t;->T:J

    .line 75
    .line 76
    invoke-static {v4, v5}, Ljava/lang/Long;->hashCode(J)I

    .line 77
    .line 78
    .line 79
    move-result v4

    .line 80
    invoke-virtual {p1}, Ll2/t;->m()Ll2/p1;

    .line 81
    .line 82
    .line 83
    move-result-object v5

    .line 84
    sget-object v6, Lx2/p;->b:Lx2/p;

    .line 85
    .line 86
    invoke-static {p1, v6}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 87
    .line 88
    .line 89
    move-result-object v7

    .line 90
    sget-object v8, Lv3/k;->m1:Lv3/j;

    .line 91
    .line 92
    invoke-virtual {v8}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 93
    .line 94
    .line 95
    sget-object v8, Lv3/j;->b:Lv3/i;

    .line 96
    .line 97
    invoke-virtual {p1}, Ll2/t;->c0()V

    .line 98
    .line 99
    .line 100
    iget-boolean v9, p1, Ll2/t;->S:Z

    .line 101
    .line 102
    if-eqz v9, :cond_3

    .line 103
    .line 104
    invoke-virtual {p1, v8}, Ll2/t;->l(Lay0/a;)V

    .line 105
    .line 106
    .line 107
    goto :goto_2

    .line 108
    :cond_3
    invoke-virtual {p1}, Ll2/t;->m0()V

    .line 109
    .line 110
    .line 111
    :goto_2
    sget-object v9, Lv3/j;->g:Lv3/h;

    .line 112
    .line 113
    invoke-static {v9, p2, p1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 114
    .line 115
    .line 116
    sget-object p2, Lv3/j;->f:Lv3/h;

    .line 117
    .line 118
    invoke-static {p2, v5, p1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 119
    .line 120
    .line 121
    sget-object v5, Lv3/j;->j:Lv3/h;

    .line 122
    .line 123
    iget-boolean v10, p1, Ll2/t;->S:Z

    .line 124
    .line 125
    if-nez v10, :cond_4

    .line 126
    .line 127
    invoke-virtual {p1}, Ll2/t;->L()Ljava/lang/Object;

    .line 128
    .line 129
    .line 130
    move-result-object v10

    .line 131
    invoke-static {v4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 132
    .line 133
    .line 134
    move-result-object v11

    .line 135
    invoke-static {v10, v11}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 136
    .line 137
    .line 138
    move-result v10

    .line 139
    if-nez v10, :cond_5

    .line 140
    .line 141
    :cond_4
    invoke-static {v4, p1, v4, v5}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 142
    .line 143
    .line 144
    :cond_5
    sget-object v4, Lv3/j;->d:Lv3/h;

    .line 145
    .line 146
    invoke-static {v4, v7, p1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 147
    .line 148
    .line 149
    invoke-static {v0, v1}, Le3/j0;->e(J)J

    .line 150
    .line 151
    .line 152
    move-result-wide v0

    .line 153
    sget-object v7, Le3/j0;->a:Le3/i0;

    .line 154
    .line 155
    invoke-static {v6, v0, v1, v7}, Landroidx/compose/foundation/a;->b(Lx2/s;JLe3/n0;)Lx2/s;

    .line 156
    .line 157
    .line 158
    move-result-object v0

    .line 159
    sget-object v1, Lx2/c;->d:Lx2/j;

    .line 160
    .line 161
    invoke-static {v1, v3}, Lk1/n;->d(Lx2/e;Z)Lt3/q0;

    .line 162
    .line 163
    .line 164
    move-result-object v1

    .line 165
    iget-wide v6, p1, Ll2/t;->T:J

    .line 166
    .line 167
    invoke-static {v6, v7}, Ljava/lang/Long;->hashCode(J)I

    .line 168
    .line 169
    .line 170
    move-result v6

    .line 171
    invoke-virtual {p1}, Ll2/t;->m()Ll2/p1;

    .line 172
    .line 173
    .line 174
    move-result-object v7

    .line 175
    invoke-static {p1, v0}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 176
    .line 177
    .line 178
    move-result-object v0

    .line 179
    invoke-virtual {p1}, Ll2/t;->c0()V

    .line 180
    .line 181
    .line 182
    iget-boolean v10, p1, Ll2/t;->S:Z

    .line 183
    .line 184
    if-eqz v10, :cond_6

    .line 185
    .line 186
    invoke-virtual {p1, v8}, Ll2/t;->l(Lay0/a;)V

    .line 187
    .line 188
    .line 189
    goto :goto_3

    .line 190
    :cond_6
    invoke-virtual {p1}, Ll2/t;->m0()V

    .line 191
    .line 192
    .line 193
    :goto_3
    invoke-static {v9, v1, p1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 194
    .line 195
    .line 196
    invoke-static {p2, v7, p1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 197
    .line 198
    .line 199
    iget-boolean p2, p1, Ll2/t;->S:Z

    .line 200
    .line 201
    if-nez p2, :cond_7

    .line 202
    .line 203
    invoke-virtual {p1}, Ll2/t;->L()Ljava/lang/Object;

    .line 204
    .line 205
    .line 206
    move-result-object p2

    .line 207
    invoke-static {v6}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 208
    .line 209
    .line 210
    move-result-object v1

    .line 211
    invoke-static {p2, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 212
    .line 213
    .line 214
    move-result p2

    .line 215
    if-nez p2, :cond_8

    .line 216
    .line 217
    :cond_7
    invoke-static {v6, p1, v6, v5}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 218
    .line 219
    .line 220
    :cond_8
    invoke-static {v4, v0, p1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 221
    .line 222
    .line 223
    iget-object p0, p0, Lba/a;->f:Lay0/n;

    .line 224
    .line 225
    invoke-static {v3, p0, p1, v2, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->v(ILay0/n;Ll2/t;ZZ)V

    .line 226
    .line 227
    .line 228
    goto :goto_4

    .line 229
    :cond_9
    invoke-virtual {p1}, Ll2/t;->R()V

    .line 230
    .line 231
    .line 232
    :goto_4
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 233
    .line 234
    return-object p0

    .line 235
    :pswitch_0
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 236
    .line 237
    .line 238
    const/4 p2, 0x1

    .line 239
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 240
    .line 241
    .line 242
    move-result p2

    .line 243
    iget-boolean v0, p0, Lba/a;->e:Z

    .line 244
    .line 245
    iget-object p0, p0, Lba/a;->f:Lay0/n;

    .line 246
    .line 247
    invoke-static {v0, p0, p1, p2}, Ljp/la;->b(ZLay0/n;Ll2/o;I)V

    .line 248
    .line 249
    .line 250
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 251
    .line 252
    return-object p0

    .line 253
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
