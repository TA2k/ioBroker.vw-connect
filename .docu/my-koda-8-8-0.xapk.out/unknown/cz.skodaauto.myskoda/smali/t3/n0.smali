.class public final Lt3/n0;
.super Lt3/d1;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final synthetic e:I

.field public final f:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Ljava/lang/Object;I)V
    .locals 0

    .line 1
    iput p2, p0, Lt3/n0;->e:I

    .line 2
    .line 3
    iput-object p1, p0, Lt3/n0;->f:Ljava/lang/Object;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final a()F
    .locals 1

    .line 1
    iget v0, p0, Lt3/n0;->e:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lt3/n0;->f:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast p0, Lw3/t;

    .line 9
    .line 10
    invoke-virtual {p0}, Lw3/t;->getDensity()Lt4/c;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    invoke-interface {p0}, Lt4/c;->a()F

    .line 15
    .line 16
    .line 17
    move-result p0

    .line 18
    return p0

    .line 19
    :pswitch_0
    iget-object p0, p0, Lt3/n0;->f:Ljava/lang/Object;

    .line 20
    .line 21
    check-cast p0, Lv3/p0;

    .line 22
    .line 23
    invoke-interface {p0}, Lt4/c;->a()F

    .line 24
    .line 25
    .line 26
    move-result p0

    .line 27
    return p0

    .line 28
    nop

    .line 29
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public c(Lt3/q;)F
    .locals 7

    .line 1
    iget v0, p0, Lt3/n0;->e:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    invoke-super {p0, p1}, Lt3/d1;->c(Lt3/q;)F

    .line 7
    .line 8
    .line 9
    move-result p0

    .line 10
    return p0

    .line 11
    :pswitch_0
    iget-object v0, p1, Lt3/q;->a:Lay0/n;

    .line 12
    .line 13
    const/high16 v1, 0x7fc00000    # Float.NaN

    .line 14
    .line 15
    if-eqz v0, :cond_0

    .line 16
    .line 17
    invoke-static {v1}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 18
    .line 19
    .line 20
    move-result-object p1

    .line 21
    invoke-interface {v0, p0, p1}, Lay0/n;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 22
    .line 23
    .line 24
    move-result-object p0

    .line 25
    check-cast p0, Ljava/lang/Number;

    .line 26
    .line 27
    invoke-virtual {p0}, Ljava/lang/Number;->floatValue()F

    .line 28
    .line 29
    .line 30
    move-result v1

    .line 31
    goto/16 :goto_4

    .line 32
    .line 33
    :cond_0
    iget-object p0, p0, Lt3/n0;->f:Ljava/lang/Object;

    .line 34
    .line 35
    check-cast p0, Lv3/p0;

    .line 36
    .line 37
    iget-boolean v0, p0, Lv3/p0;->n:Z

    .line 38
    .line 39
    if-eqz v0, :cond_1

    .line 40
    .line 41
    goto/16 :goto_4

    .line 42
    .line 43
    :cond_1
    move-object v0, p0

    .line 44
    :goto_0
    iget-object v2, v0, Lv3/p0;->p:Lca/j;

    .line 45
    .line 46
    if-eqz v2, :cond_3

    .line 47
    .line 48
    iget-object v3, v2, Lca/j;->b:Ljava/lang/Object;

    .line 49
    .line 50
    check-cast v3, [Lt3/q;

    .line 51
    .line 52
    invoke-static {p1, v3}, Lmx0/n;->D(Ljava/lang/Object;[Ljava/lang/Object;)I

    .line 53
    .line 54
    .line 55
    move-result v3

    .line 56
    if-gez v3, :cond_2

    .line 57
    .line 58
    goto :goto_1

    .line 59
    :cond_2
    iget-object v2, v2, Lca/j;->c:Ljava/lang/Object;

    .line 60
    .line 61
    check-cast v2, [F

    .line 62
    .line 63
    aget v2, v2, v3

    .line 64
    .line 65
    goto :goto_2

    .line 66
    :cond_3
    :goto_1
    move v2, v1

    .line 67
    :goto_2
    invoke-static {v2}, Ljava/lang/Float;->isNaN(F)Z

    .line 68
    .line 69
    .line 70
    move-result v3

    .line 71
    if-nez v3, :cond_4

    .line 72
    .line 73
    invoke-virtual {p0}, Lv3/p0;->M0()Lv3/h0;

    .line 74
    .line 75
    .line 76
    move-result-object v1

    .line 77
    invoke-virtual {v0, v1, p1}, Lv3/p0;->B0(Lv3/h0;Lt3/q;)V

    .line 78
    .line 79
    .line 80
    invoke-virtual {v0}, Lv3/p0;->J0()Lt3/y;

    .line 81
    .line 82
    .line 83
    move-result-object v0

    .line 84
    invoke-virtual {p0}, Lv3/p0;->J0()Lt3/y;

    .line 85
    .line 86
    .line 87
    move-result-object p0

    .line 88
    iget p1, p1, Lt3/q;->b:I

    .line 89
    .line 90
    packed-switch p1, :pswitch_data_1

    .line 91
    .line 92
    .line 93
    invoke-interface {v0}, Lt3/y;->h()J

    .line 94
    .line 95
    .line 96
    move-result-wide v3

    .line 97
    const-wide v5, 0xffffffffL

    .line 98
    .line 99
    .line 100
    .line 101
    .line 102
    and-long/2addr v3, v5

    .line 103
    long-to-int p1, v3

    .line 104
    int-to-float p1, p1

    .line 105
    const/high16 v1, 0x40000000    # 2.0f

    .line 106
    .line 107
    div-float/2addr p1, v1

    .line 108
    invoke-static {v2}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 109
    .line 110
    .line 111
    move-result v1

    .line 112
    int-to-long v1, v1

    .line 113
    invoke-static {p1}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 114
    .line 115
    .line 116
    move-result p1

    .line 117
    int-to-long v3, p1

    .line 118
    const/16 p1, 0x20

    .line 119
    .line 120
    shl-long/2addr v1, p1

    .line 121
    and-long/2addr v3, v5

    .line 122
    or-long/2addr v1, v3

    .line 123
    invoke-interface {p0, v0, v1, v2}, Lt3/y;->Z(Lt3/y;J)J

    .line 124
    .line 125
    .line 126
    move-result-wide v0

    .line 127
    shr-long p0, v0, p1

    .line 128
    .line 129
    long-to-int p0, p0

    .line 130
    invoke-static {p0}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 131
    .line 132
    .line 133
    move-result p0

    .line 134
    :goto_3
    move v1, p0

    .line 135
    goto :goto_4

    .line 136
    :pswitch_1
    invoke-interface {v0}, Lt3/y;->h()J

    .line 137
    .line 138
    .line 139
    move-result-wide v3

    .line 140
    const/16 p1, 0x20

    .line 141
    .line 142
    shr-long/2addr v3, p1

    .line 143
    long-to-int v1, v3

    .line 144
    int-to-float v1, v1

    .line 145
    const/high16 v3, 0x40000000    # 2.0f

    .line 146
    .line 147
    div-float/2addr v1, v3

    .line 148
    invoke-static {v1}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 149
    .line 150
    .line 151
    move-result v1

    .line 152
    int-to-long v3, v1

    .line 153
    invoke-static {v2}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 154
    .line 155
    .line 156
    move-result v1

    .line 157
    int-to-long v1, v1

    .line 158
    shl-long/2addr v3, p1

    .line 159
    const-wide v5, 0xffffffffL

    .line 160
    .line 161
    .line 162
    .line 163
    .line 164
    and-long/2addr v1, v5

    .line 165
    or-long/2addr v1, v3

    .line 166
    invoke-interface {p0, v0, v1, v2}, Lt3/y;->Z(Lt3/y;J)J

    .line 167
    .line 168
    .line 169
    move-result-wide p0

    .line 170
    and-long/2addr p0, v5

    .line 171
    long-to-int p0, p0

    .line 172
    invoke-static {p0}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 173
    .line 174
    .line 175
    move-result p0

    .line 176
    goto :goto_3

    .line 177
    :cond_4
    invoke-virtual {v0}, Lv3/p0;->O0()Lv3/p0;

    .line 178
    .line 179
    .line 180
    move-result-object v2

    .line 181
    if-nez v2, :cond_5

    .line 182
    .line 183
    invoke-virtual {p0}, Lv3/p0;->M0()Lv3/h0;

    .line 184
    .line 185
    .line 186
    move-result-object p0

    .line 187
    invoke-virtual {v0, p0, p1}, Lv3/p0;->B0(Lv3/h0;Lt3/q;)V

    .line 188
    .line 189
    .line 190
    :goto_4
    return v1

    .line 191
    :cond_5
    move-object v0, v2

    .line 192
    goto/16 :goto_0

    .line 193
    .line 194
    nop

    .line 195
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch

    .line 196
    .line 197
    .line 198
    .line 199
    .line 200
    .line 201
    :pswitch_data_1
    .packed-switch 0x0
        :pswitch_1
    .end packed-switch
.end method

.method public final d()Lt4/m;
    .locals 1

    .line 1
    iget v0, p0, Lt3/n0;->e:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lt3/n0;->f:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast p0, Lw3/t;

    .line 9
    .line 10
    invoke-virtual {p0}, Lw3/t;->getLayoutDirection()Lt4/m;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    return-object p0

    .line 15
    :pswitch_0
    iget-object p0, p0, Lt3/n0;->f:Ljava/lang/Object;

    .line 16
    .line 17
    check-cast p0, Lv3/p0;

    .line 18
    .line 19
    invoke-interface {p0}, Lt3/t;->getLayoutDirection()Lt4/m;

    .line 20
    .line 21
    .line 22
    move-result-object p0

    .line 23
    return-object p0

    .line 24
    nop

    .line 25
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final f()I
    .locals 1

    .line 1
    iget v0, p0, Lt3/n0;->e:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lt3/n0;->f:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast p0, Lw3/t;

    .line 9
    .line 10
    invoke-virtual {p0}, Lw3/t;->getRoot()Lv3/h0;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    iget-object p0, p0, Lv3/h0;->I:Lv3/l0;

    .line 15
    .line 16
    iget-object p0, p0, Lv3/l0;->p:Lv3/y0;

    .line 17
    .line 18
    iget p0, p0, Lt3/e1;->d:I

    .line 19
    .line 20
    return p0

    .line 21
    :pswitch_0
    iget-object p0, p0, Lt3/n0;->f:Ljava/lang/Object;

    .line 22
    .line 23
    check-cast p0, Lv3/p0;

    .line 24
    .line 25
    invoke-virtual {p0}, Lt3/e1;->d0()I

    .line 26
    .line 27
    .line 28
    move-result p0

    .line 29
    return p0

    .line 30
    nop

    .line 31
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final t0()F
    .locals 1

    .line 1
    iget v0, p0, Lt3/n0;->e:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lt3/n0;->f:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast p0, Lw3/t;

    .line 9
    .line 10
    invoke-virtual {p0}, Lw3/t;->getDensity()Lt4/c;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    invoke-interface {p0}, Lt4/c;->t0()F

    .line 15
    .line 16
    .line 17
    move-result p0

    .line 18
    return p0

    .line 19
    :pswitch_0
    iget-object p0, p0, Lt3/n0;->f:Ljava/lang/Object;

    .line 20
    .line 21
    check-cast p0, Lv3/p0;

    .line 22
    .line 23
    invoke-interface {p0}, Lt4/c;->t0()F

    .line 24
    .line 25
    .line 26
    move-result p0

    .line 27
    return p0

    .line 28
    nop

    .line 29
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
