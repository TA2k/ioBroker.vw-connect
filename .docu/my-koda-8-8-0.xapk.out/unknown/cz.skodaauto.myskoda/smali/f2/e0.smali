.class public final synthetic Lf2/e0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:I

.field public final synthetic f:Ljava/lang/Object;

.field public final synthetic g:I


# direct methods
.method public synthetic constructor <init>(ILt3/e1;II)V
    .locals 0

    .line 1
    iput p4, p0, Lf2/e0;->d:I

    iput p1, p0, Lf2/e0;->e:I

    iput-object p2, p0, Lf2/e0;->f:Ljava/lang/Object;

    iput p3, p0, Lf2/e0;->g:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(Ljava/lang/Object;III)V
    .locals 0

    .line 2
    iput p4, p0, Lf2/e0;->d:I

    iput-object p1, p0, Lf2/e0;->f:Ljava/lang/Object;

    iput p2, p0, Lf2/e0;->e:I

    iput p3, p0, Lf2/e0;->g:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 7

    .line 1
    iget v0, p0, Lf2/e0;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lf2/e0;->f:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast v0, Le3/i;

    .line 9
    .line 10
    check-cast p1, Lg4/q;

    .line 11
    .line 12
    iget-object v1, p1, Lg4/q;->a:Lg4/a;

    .line 13
    .line 14
    iget v2, p0, Lf2/e0;->e:I

    .line 15
    .line 16
    invoke-virtual {p1, v2}, Lg4/q;->d(I)I

    .line 17
    .line 18
    .line 19
    move-result v2

    .line 20
    iget p0, p0, Lf2/e0;->g:I

    .line 21
    .line 22
    invoke-virtual {p1, p0}, Lg4/q;->d(I)I

    .line 23
    .line 24
    .line 25
    move-result p0

    .line 26
    iget-object v3, v1, Lg4/a;->e:Ljava/lang/CharSequence;

    .line 27
    .line 28
    if-ltz v2, :cond_0

    .line 29
    .line 30
    if-gt v2, p0, :cond_0

    .line 31
    .line 32
    invoke-interface {v3}, Ljava/lang/CharSequence;->length()I

    .line 33
    .line 34
    .line 35
    move-result v4

    .line 36
    if-gt p0, v4, :cond_0

    .line 37
    .line 38
    goto :goto_0

    .line 39
    :cond_0
    const-string v4, ") or end("

    .line 40
    .line 41
    const-string v5, ") is out of range [0.."

    .line 42
    .line 43
    const-string v6, "start("

    .line 44
    .line 45
    invoke-static {v2, p0, v6, v4, v5}, Lu/w;->j(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 46
    .line 47
    .line 48
    move-result-object v4

    .line 49
    invoke-interface {v3}, Ljava/lang/CharSequence;->length()I

    .line 50
    .line 51
    .line 52
    move-result v3

    .line 53
    invoke-virtual {v4, v3}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 54
    .line 55
    .line 56
    const-string v3, "], or start > end!"

    .line 57
    .line 58
    invoke-virtual {v4, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 59
    .line 60
    .line 61
    invoke-virtual {v4}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 62
    .line 63
    .line 64
    move-result-object v3

    .line 65
    invoke-static {v3}, Lm4/a;->a(Ljava/lang/String;)V

    .line 66
    .line 67
    .line 68
    :goto_0
    new-instance v3, Landroid/graphics/Path;

    .line 69
    .line 70
    invoke-direct {v3}, Landroid/graphics/Path;-><init>()V

    .line 71
    .line 72
    .line 73
    iget-object v1, v1, Lg4/a;->d:Lh4/j;

    .line 74
    .line 75
    iget-object v4, v1, Lh4/j;->f:Landroid/text/Layout;

    .line 76
    .line 77
    invoke-virtual {v4, v2, p0, v3}, Landroid/text/Layout;->getSelectionPath(IILandroid/graphics/Path;)V

    .line 78
    .line 79
    .line 80
    iget p0, v1, Lh4/j;->h:I

    .line 81
    .line 82
    const/4 v1, 0x0

    .line 83
    if-eqz p0, :cond_1

    .line 84
    .line 85
    invoke-virtual {v3}, Landroid/graphics/Path;->isEmpty()Z

    .line 86
    .line 87
    .line 88
    move-result v2

    .line 89
    if-nez v2, :cond_1

    .line 90
    .line 91
    int-to-float p0, p0

    .line 92
    invoke-virtual {v3, v1, p0}, Landroid/graphics/Path;->offset(FF)V

    .line 93
    .line 94
    .line 95
    :cond_1
    new-instance p0, Le3/i;

    .line 96
    .line 97
    invoke-direct {p0, v3}, Le3/i;-><init>(Landroid/graphics/Path;)V

    .line 98
    .line 99
    .line 100
    iget p1, p1, Lg4/q;->f:F

    .line 101
    .line 102
    invoke-static {v1}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 103
    .line 104
    .line 105
    move-result v1

    .line 106
    int-to-long v1, v1

    .line 107
    invoke-static {p1}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 108
    .line 109
    .line 110
    move-result p1

    .line 111
    int-to-long v3, p1

    .line 112
    const/16 p1, 0x20

    .line 113
    .line 114
    shl-long/2addr v1, p1

    .line 115
    const-wide v5, 0xffffffffL

    .line 116
    .line 117
    .line 118
    .line 119
    .line 120
    and-long/2addr v3, v5

    .line 121
    or-long/2addr v1, v3

    .line 122
    invoke-virtual {p0, v1, v2}, Le3/i;->m(J)V

    .line 123
    .line 124
    .line 125
    invoke-static {v0, p0}, Le3/i;->a(Le3/i;Le3/i;)V

    .line 126
    .line 127
    .line 128
    :goto_1
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 129
    .line 130
    return-object p0

    .line 131
    :pswitch_0
    iget-object v0, p0, Lf2/e0;->f:Ljava/lang/Object;

    .line 132
    .line 133
    check-cast v0, Lt3/e1;

    .line 134
    .line 135
    iget v1, p0, Lf2/e0;->g:I

    .line 136
    .line 137
    check-cast p1, Lt3/d1;

    .line 138
    .line 139
    iget p0, p0, Lf2/e0;->e:I

    .line 140
    .line 141
    invoke-static {p1, v0, p0, v1}, Lt3/d1;->h(Lt3/d1;Lt3/e1;II)V

    .line 142
    .line 143
    .line 144
    goto :goto_1

    .line 145
    :pswitch_1
    iget-object v0, p0, Lf2/e0;->f:Ljava/lang/Object;

    .line 146
    .line 147
    check-cast v0, Lt3/e1;

    .line 148
    .line 149
    iget v1, p0, Lf2/e0;->g:I

    .line 150
    .line 151
    check-cast p1, Lt3/d1;

    .line 152
    .line 153
    iget p0, p0, Lf2/e0;->e:I

    .line 154
    .line 155
    invoke-static {p1, v0, p0, v1}, Lt3/d1;->h(Lt3/d1;Lt3/e1;II)V

    .line 156
    .line 157
    .line 158
    goto :goto_1

    .line 159
    :pswitch_2
    iget-object v0, p0, Lf2/e0;->f:Ljava/lang/Object;

    .line 160
    .line 161
    check-cast v0, Lt3/e1;

    .line 162
    .line 163
    check-cast p1, Lt3/d1;

    .line 164
    .line 165
    iget v1, v0, Lt3/e1;->d:I

    .line 166
    .line 167
    iget v2, p0, Lf2/e0;->e:I

    .line 168
    .line 169
    sub-int/2addr v2, v1

    .line 170
    int-to-float v1, v2

    .line 171
    const/high16 v2, 0x40000000    # 2.0f

    .line 172
    .line 173
    div-float/2addr v1, v2

    .line 174
    invoke-static {v1}, Lcy0/a;->i(F)I

    .line 175
    .line 176
    .line 177
    move-result v1

    .line 178
    iget v3, v0, Lt3/e1;->e:I

    .line 179
    .line 180
    iget p0, p0, Lf2/e0;->g:I

    .line 181
    .line 182
    sub-int/2addr p0, v3

    .line 183
    int-to-float p0, p0

    .line 184
    div-float/2addr p0, v2

    .line 185
    invoke-static {p0}, Lcy0/a;->i(F)I

    .line 186
    .line 187
    .line 188
    move-result p0

    .line 189
    invoke-static {p1, v0, v1, p0}, Lt3/d1;->h(Lt3/d1;Lt3/e1;II)V

    .line 190
    .line 191
    .line 192
    goto :goto_1

    .line 193
    :pswitch_3
    iget-object v0, p0, Lf2/e0;->f:Ljava/lang/Object;

    .line 194
    .line 195
    check-cast v0, Lt3/e1;

    .line 196
    .line 197
    check-cast p1, Lt3/d1;

    .line 198
    .line 199
    iget v1, v0, Lt3/e1;->d:I

    .line 200
    .line 201
    iget v2, p0, Lf2/e0;->e:I

    .line 202
    .line 203
    sub-int/2addr v2, v1

    .line 204
    int-to-float v1, v2

    .line 205
    const/high16 v2, 0x40000000    # 2.0f

    .line 206
    .line 207
    div-float/2addr v1, v2

    .line 208
    invoke-static {v1}, Lcy0/a;->i(F)I

    .line 209
    .line 210
    .line 211
    move-result v1

    .line 212
    iget v3, v0, Lt3/e1;->e:I

    .line 213
    .line 214
    iget p0, p0, Lf2/e0;->g:I

    .line 215
    .line 216
    sub-int/2addr p0, v3

    .line 217
    int-to-float p0, p0

    .line 218
    div-float/2addr p0, v2

    .line 219
    invoke-static {p0}, Lcy0/a;->i(F)I

    .line 220
    .line 221
    .line 222
    move-result p0

    .line 223
    invoke-static {p1, v0, v1, p0}, Lt3/d1;->h(Lt3/d1;Lt3/e1;II)V

    .line 224
    .line 225
    .line 226
    goto :goto_1

    .line 227
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
