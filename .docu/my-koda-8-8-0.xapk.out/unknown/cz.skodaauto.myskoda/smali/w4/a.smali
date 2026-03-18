.class public final Lw4/a;
.super Landroidx/datastore/preferences/protobuf/k;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final synthetic f:I

.field public final synthetic g:Landroid/view/ViewGroup;


# direct methods
.method public synthetic constructor <init>(Landroid/view/ViewGroup;I)V
    .locals 0

    .line 1
    iput p2, p0, Lw4/a;->f:I

    .line 2
    .line 3
    iput-object p1, p0, Lw4/a;->g:Landroid/view/ViewGroup;

    .line 4
    .line 5
    const/4 p1, 0x1

    .line 6
    invoke-direct {p0, p1}, Landroidx/datastore/preferences/protobuf/k;-><init>(I)V

    .line 7
    .line 8
    .line 9
    return-void
.end method


# virtual methods
.method public final i(Ld6/w1;Ljava/util/List;)Ld6/w1;
    .locals 5

    .line 1
    iget p2, p0, Lw4/a;->f:I

    .line 2
    .line 3
    packed-switch p2, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lw4/a;->g:Landroid/view/ViewGroup;

    .line 7
    .line 8
    check-cast p0, Lx4/o;

    .line 9
    .line 10
    iget-boolean p2, p0, Lx4/o;->o:Z

    .line 11
    .line 12
    if-eqz p2, :cond_0

    .line 13
    .line 14
    goto :goto_0

    .line 15
    :cond_0
    const/4 p2, 0x0

    .line 16
    invoke-virtual {p0, p2}, Landroid/view/ViewGroup;->getChildAt(I)Landroid/view/View;

    .line 17
    .line 18
    .line 19
    move-result-object v0

    .line 20
    invoke-virtual {v0}, Landroid/view/View;->getLeft()I

    .line 21
    .line 22
    .line 23
    move-result v1

    .line 24
    invoke-static {p2, v1}, Ljava/lang/Math;->max(II)I

    .line 25
    .line 26
    .line 27
    move-result v1

    .line 28
    invoke-virtual {v0}, Landroid/view/View;->getTop()I

    .line 29
    .line 30
    .line 31
    move-result v2

    .line 32
    invoke-static {p2, v2}, Ljava/lang/Math;->max(II)I

    .line 33
    .line 34
    .line 35
    move-result v2

    .line 36
    invoke-virtual {p0}, Landroid/view/View;->getWidth()I

    .line 37
    .line 38
    .line 39
    move-result v3

    .line 40
    invoke-virtual {v0}, Landroid/view/View;->getRight()I

    .line 41
    .line 42
    .line 43
    move-result v4

    .line 44
    sub-int/2addr v3, v4

    .line 45
    invoke-static {p2, v3}, Ljava/lang/Math;->max(II)I

    .line 46
    .line 47
    .line 48
    move-result v3

    .line 49
    invoke-virtual {p0}, Landroid/view/View;->getHeight()I

    .line 50
    .line 51
    .line 52
    move-result p0

    .line 53
    invoke-virtual {v0}, Landroid/view/View;->getBottom()I

    .line 54
    .line 55
    .line 56
    move-result v0

    .line 57
    sub-int/2addr p0, v0

    .line 58
    invoke-static {p2, p0}, Ljava/lang/Math;->max(II)I

    .line 59
    .line 60
    .line 61
    move-result p0

    .line 62
    if-nez v1, :cond_1

    .line 63
    .line 64
    if-nez v2, :cond_1

    .line 65
    .line 66
    if-nez v3, :cond_1

    .line 67
    .line 68
    if-nez p0, :cond_1

    .line 69
    .line 70
    goto :goto_0

    .line 71
    :cond_1
    iget-object p1, p1, Ld6/w1;->a:Ld6/s1;

    .line 72
    .line 73
    invoke-virtual {p1, v1, v2, v3, p0}, Ld6/s1;->n(IIII)Ld6/w1;

    .line 74
    .line 75
    .line 76
    move-result-object p1

    .line 77
    :goto_0
    return-object p1

    .line 78
    :pswitch_0
    iget-object p0, p0, Lw4/a;->g:Landroid/view/ViewGroup;

    .line 79
    .line 80
    check-cast p0, Lw4/o;

    .line 81
    .line 82
    invoke-virtual {p0, p1}, Lw4/g;->m(Ld6/w1;)Ld6/w1;

    .line 83
    .line 84
    .line 85
    move-result-object p0

    .line 86
    return-object p0

    .line 87
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final j(Ld6/f1;Lb81/d;)Lb81/d;
    .locals 12

    .line 1
    iget p1, p0, Lw4/a;->f:I

    .line 2
    .line 3
    packed-switch p1, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lw4/a;->g:Landroid/view/ViewGroup;

    .line 7
    .line 8
    check-cast p0, Lx4/o;

    .line 9
    .line 10
    iget-boolean p1, p0, Lx4/o;->o:Z

    .line 11
    .line 12
    if-eqz p1, :cond_0

    .line 13
    .line 14
    goto :goto_0

    .line 15
    :cond_0
    const/4 p1, 0x0

    .line 16
    invoke-virtual {p0, p1}, Landroid/view/ViewGroup;->getChildAt(I)Landroid/view/View;

    .line 17
    .line 18
    .line 19
    move-result-object v0

    .line 20
    invoke-virtual {v0}, Landroid/view/View;->getLeft()I

    .line 21
    .line 22
    .line 23
    move-result v1

    .line 24
    invoke-static {p1, v1}, Ljava/lang/Math;->max(II)I

    .line 25
    .line 26
    .line 27
    move-result v1

    .line 28
    invoke-virtual {v0}, Landroid/view/View;->getTop()I

    .line 29
    .line 30
    .line 31
    move-result v2

    .line 32
    invoke-static {p1, v2}, Ljava/lang/Math;->max(II)I

    .line 33
    .line 34
    .line 35
    move-result v2

    .line 36
    invoke-virtual {p0}, Landroid/view/View;->getWidth()I

    .line 37
    .line 38
    .line 39
    move-result v3

    .line 40
    invoke-virtual {v0}, Landroid/view/View;->getRight()I

    .line 41
    .line 42
    .line 43
    move-result v4

    .line 44
    sub-int/2addr v3, v4

    .line 45
    invoke-static {p1, v3}, Ljava/lang/Math;->max(II)I

    .line 46
    .line 47
    .line 48
    move-result v3

    .line 49
    invoke-virtual {p0}, Landroid/view/View;->getHeight()I

    .line 50
    .line 51
    .line 52
    move-result p0

    .line 53
    invoke-virtual {v0}, Landroid/view/View;->getBottom()I

    .line 54
    .line 55
    .line 56
    move-result v0

    .line 57
    sub-int/2addr p0, v0

    .line 58
    invoke-static {p1, p0}, Ljava/lang/Math;->max(II)I

    .line 59
    .line 60
    .line 61
    move-result p0

    .line 62
    if-nez v1, :cond_1

    .line 63
    .line 64
    if-nez v2, :cond_1

    .line 65
    .line 66
    if-nez v3, :cond_1

    .line 67
    .line 68
    if-nez p0, :cond_1

    .line 69
    .line 70
    goto :goto_0

    .line 71
    :cond_1
    invoke-static {v1, v2, v3, p0}, Ls5/b;->b(IIII)Ls5/b;

    .line 72
    .line 73
    .line 74
    move-result-object p0

    .line 75
    iget p1, p0, Ls5/b;->a:I

    .line 76
    .line 77
    new-instance v0, Lb81/d;

    .line 78
    .line 79
    iget-object v1, p2, Lb81/d;->e:Ljava/lang/Object;

    .line 80
    .line 81
    check-cast v1, Ls5/b;

    .line 82
    .line 83
    iget v2, p0, Ls5/b;->b:I

    .line 84
    .line 85
    iget v3, p0, Ls5/b;->c:I

    .line 86
    .line 87
    iget p0, p0, Ls5/b;->d:I

    .line 88
    .line 89
    invoke-static {v1, p1, v2, v3, p0}, Ld6/w1;->f(Ls5/b;IIII)Ls5/b;

    .line 90
    .line 91
    .line 92
    move-result-object v1

    .line 93
    iget-object p2, p2, Lb81/d;->f:Ljava/lang/Object;

    .line 94
    .line 95
    check-cast p2, Ls5/b;

    .line 96
    .line 97
    invoke-static {p2, p1, v2, v3, p0}, Ld6/w1;->f(Ls5/b;IIII)Ls5/b;

    .line 98
    .line 99
    .line 100
    move-result-object p0

    .line 101
    const/4 p1, 0x3

    .line 102
    invoke-direct {v0, p1, v1, p0}, Lb81/d;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 103
    .line 104
    .line 105
    move-object p2, v0

    .line 106
    :goto_0
    return-object p2

    .line 107
    :pswitch_0
    iget-object p0, p0, Lw4/a;->g:Landroid/view/ViewGroup;

    .line 108
    .line 109
    check-cast p0, Lw4/o;

    .line 110
    .line 111
    iget-object p0, p0, Lw4/g;->B:Lv3/h0;

    .line 112
    .line 113
    iget-object p0, p0, Lv3/h0;->H:Lg1/q;

    .line 114
    .line 115
    iget-object p0, p0, Lg1/q;->d:Ljava/lang/Object;

    .line 116
    .line 117
    check-cast p0, Lv3/u;

    .line 118
    .line 119
    iget-object p1, p0, Lv3/u;->S:Lv3/z1;

    .line 120
    .line 121
    iget-boolean p1, p1, Lx2/r;->q:Z

    .line 122
    .line 123
    if-nez p1, :cond_2

    .line 124
    .line 125
    goto/16 :goto_2

    .line 126
    .line 127
    :cond_2
    const-wide/16 v0, 0x0

    .line 128
    .line 129
    invoke-virtual {p0, v0, v1}, Lv3/f1;->R(J)J

    .line 130
    .line 131
    .line 132
    move-result-wide v0

    .line 133
    invoke-static {v0, v1}, Lkp/d9;->b(J)J

    .line 134
    .line 135
    .line 136
    move-result-wide v0

    .line 137
    const/16 p1, 0x20

    .line 138
    .line 139
    shr-long v2, v0, p1

    .line 140
    .line 141
    long-to-int v2, v2

    .line 142
    const/4 v3, 0x0

    .line 143
    if-gez v2, :cond_3

    .line 144
    .line 145
    move v2, v3

    .line 146
    :cond_3
    const-wide v4, 0xffffffffL

    .line 147
    .line 148
    .line 149
    .line 150
    .line 151
    and-long/2addr v0, v4

    .line 152
    long-to-int v0, v0

    .line 153
    if-gez v0, :cond_4

    .line 154
    .line 155
    move v0, v3

    .line 156
    :cond_4
    invoke-static {p0}, Lt3/k1;->i(Lt3/y;)Lt3/y;

    .line 157
    .line 158
    .line 159
    move-result-object v1

    .line 160
    invoke-interface {v1}, Lt3/y;->h()J

    .line 161
    .line 162
    .line 163
    move-result-wide v6

    .line 164
    shr-long v8, v6, p1

    .line 165
    .line 166
    long-to-int v1, v8

    .line 167
    and-long/2addr v6, v4

    .line 168
    long-to-int v6, v6

    .line 169
    iget-wide v7, p0, Lt3/e1;->f:J

    .line 170
    .line 171
    shr-long v9, v7, p1

    .line 172
    .line 173
    long-to-int v9, v9

    .line 174
    and-long/2addr v7, v4

    .line 175
    long-to-int v7, v7

    .line 176
    int-to-float v8, v9

    .line 177
    int-to-float v7, v7

    .line 178
    invoke-static {v8}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 179
    .line 180
    .line 181
    move-result v8

    .line 182
    int-to-long v8, v8

    .line 183
    invoke-static {v7}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 184
    .line 185
    .line 186
    move-result v7

    .line 187
    int-to-long v10, v7

    .line 188
    shl-long v7, v8, p1

    .line 189
    .line 190
    and-long v9, v10, v4

    .line 191
    .line 192
    or-long/2addr v7, v9

    .line 193
    invoke-virtual {p0, v7, v8}, Lv3/f1;->R(J)J

    .line 194
    .line 195
    .line 196
    move-result-wide v7

    .line 197
    invoke-static {v7, v8}, Lkp/d9;->b(J)J

    .line 198
    .line 199
    .line 200
    move-result-wide v7

    .line 201
    shr-long p0, v7, p1

    .line 202
    .line 203
    long-to-int p0, p0

    .line 204
    sub-int/2addr v1, p0

    .line 205
    if-gez v1, :cond_5

    .line 206
    .line 207
    move v1, v3

    .line 208
    :cond_5
    and-long p0, v7, v4

    .line 209
    .line 210
    long-to-int p0, p0

    .line 211
    sub-int/2addr v6, p0

    .line 212
    if-gez v6, :cond_6

    .line 213
    .line 214
    goto :goto_1

    .line 215
    :cond_6
    move v3, v6

    .line 216
    :goto_1
    if-nez v2, :cond_7

    .line 217
    .line 218
    if-nez v0, :cond_7

    .line 219
    .line 220
    if-nez v1, :cond_7

    .line 221
    .line 222
    if-nez v3, :cond_7

    .line 223
    .line 224
    goto :goto_2

    .line 225
    :cond_7
    new-instance p0, Lb81/d;

    .line 226
    .line 227
    iget-object p1, p2, Lb81/d;->e:Ljava/lang/Object;

    .line 228
    .line 229
    check-cast p1, Ls5/b;

    .line 230
    .line 231
    invoke-static {p1, v2, v0, v1, v3}, Lw4/g;->l(Ls5/b;IIII)Ls5/b;

    .line 232
    .line 233
    .line 234
    move-result-object p1

    .line 235
    iget-object p2, p2, Lb81/d;->f:Ljava/lang/Object;

    .line 236
    .line 237
    check-cast p2, Ls5/b;

    .line 238
    .line 239
    invoke-static {p2, v2, v0, v1, v3}, Lw4/g;->l(Ls5/b;IIII)Ls5/b;

    .line 240
    .line 241
    .line 242
    move-result-object p2

    .line 243
    const/4 v0, 0x3

    .line 244
    invoke-direct {p0, v0, p1, p2}, Lb81/d;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 245
    .line 246
    .line 247
    move-object p2, p0

    .line 248
    :goto_2
    return-object p2

    .line 249
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
