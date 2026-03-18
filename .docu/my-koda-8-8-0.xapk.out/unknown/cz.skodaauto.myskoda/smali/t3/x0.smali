.class public final Lt3/x0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lt3/q1;
.implements Lt3/k;


# static fields
.field public static final e:Lt3/x0;


# instance fields
.field public final synthetic d:I


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Lt3/x0;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-direct {v0, v1}, Lt3/x0;-><init>(I)V

    .line 5
    .line 6
    .line 7
    sput-object v0, Lt3/x0;->e:Lt3/x0;

    .line 8
    .line 9
    return-void
.end method

.method public synthetic constructor <init>(I)V
    .locals 0

    .line 1
    iput p1, p0, Lt3/x0;->d:I

    .line 2
    .line 3
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public a(JJ)J
    .locals 5

    .line 1
    iget p0, p0, Lt3/x0;->d:I

    .line 2
    .line 3
    const/16 v0, 0x20

    .line 4
    .line 5
    const-wide v1, 0xffffffffL

    .line 6
    .line 7
    .line 8
    .line 9
    .line 10
    packed-switch p0, :pswitch_data_0

    .line 11
    .line 12
    .line 13
    shr-long v3, p1, v0

    .line 14
    .line 15
    long-to-int p0, v3

    .line 16
    invoke-static {p0}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 17
    .line 18
    .line 19
    move-result p0

    .line 20
    shr-long v3, p3, v0

    .line 21
    .line 22
    long-to-int v3, v3

    .line 23
    invoke-static {v3}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 24
    .line 25
    .line 26
    move-result v3

    .line 27
    cmpg-float p0, p0, v3

    .line 28
    .line 29
    if-gtz p0, :cond_0

    .line 30
    .line 31
    and-long v3, p1, v1

    .line 32
    .line 33
    long-to-int p0, v3

    .line 34
    invoke-static {p0}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 35
    .line 36
    .line 37
    move-result p0

    .line 38
    and-long v3, p3, v1

    .line 39
    .line 40
    long-to-int v3, v3

    .line 41
    invoke-static {v3}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 42
    .line 43
    .line 44
    move-result v3

    .line 45
    cmpg-float p0, p0, v3

    .line 46
    .line 47
    if-gtz p0, :cond_0

    .line 48
    .line 49
    const/high16 p0, 0x3f800000    # 1.0f

    .line 50
    .line 51
    invoke-static {p0}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 52
    .line 53
    .line 54
    move-result p1

    .line 55
    int-to-long p1, p1

    .line 56
    invoke-static {p0}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 57
    .line 58
    .line 59
    move-result p0

    .line 60
    int-to-long p3, p0

    .line 61
    shl-long p0, p1, v0

    .line 62
    .line 63
    and-long p2, p3, v1

    .line 64
    .line 65
    or-long/2addr p0, p2

    .line 66
    sget p2, Lt3/j1;->a:I

    .line 67
    .line 68
    goto :goto_0

    .line 69
    :cond_0
    invoke-static {p1, p2, p3, p4}, Lt3/k1;->d(JJ)F

    .line 70
    .line 71
    .line 72
    move-result p0

    .line 73
    invoke-static {p0}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 74
    .line 75
    .line 76
    move-result p1

    .line 77
    int-to-long p1, p1

    .line 78
    invoke-static {p0}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 79
    .line 80
    .line 81
    move-result p0

    .line 82
    int-to-long p3, p0

    .line 83
    shl-long p0, p1, v0

    .line 84
    .line 85
    and-long p2, p3, v1

    .line 86
    .line 87
    or-long/2addr p0, p2

    .line 88
    sget p2, Lt3/j1;->a:I

    .line 89
    .line 90
    :goto_0
    return-wide p0

    .line 91
    :pswitch_0
    invoke-static {p1, p2, p3, p4}, Lt3/k1;->d(JJ)F

    .line 92
    .line 93
    .line 94
    move-result p0

    .line 95
    invoke-static {p0}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 96
    .line 97
    .line 98
    move-result p1

    .line 99
    int-to-long p1, p1

    .line 100
    invoke-static {p0}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 101
    .line 102
    .line 103
    move-result p0

    .line 104
    int-to-long p3, p0

    .line 105
    shl-long p0, p1, v0

    .line 106
    .line 107
    and-long p2, p3, v1

    .line 108
    .line 109
    or-long/2addr p0, p2

    .line 110
    sget p2, Lt3/j1;->a:I

    .line 111
    .line 112
    return-wide p0

    .line 113
    :pswitch_1
    shr-long/2addr p3, v0

    .line 114
    long-to-int p0, p3

    .line 115
    invoke-static {p0}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 116
    .line 117
    .line 118
    move-result p0

    .line 119
    shr-long/2addr p1, v0

    .line 120
    long-to-int p1, p1

    .line 121
    invoke-static {p1}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 122
    .line 123
    .line 124
    move-result p1

    .line 125
    div-float/2addr p0, p1

    .line 126
    invoke-static {p0}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 127
    .line 128
    .line 129
    move-result p1

    .line 130
    int-to-long p1, p1

    .line 131
    invoke-static {p0}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 132
    .line 133
    .line 134
    move-result p0

    .line 135
    int-to-long p3, p0

    .line 136
    shl-long p0, p1, v0

    .line 137
    .line 138
    and-long p2, p3, v1

    .line 139
    .line 140
    or-long/2addr p0, p2

    .line 141
    sget p2, Lt3/j1;->a:I

    .line 142
    .line 143
    return-wide p0

    .line 144
    :pswitch_2
    and-long/2addr p3, v1

    .line 145
    long-to-int p0, p3

    .line 146
    invoke-static {p0}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 147
    .line 148
    .line 149
    move-result p0

    .line 150
    and-long/2addr p1, v1

    .line 151
    long-to-int p1, p1

    .line 152
    invoke-static {p1}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 153
    .line 154
    .line 155
    move-result p1

    .line 156
    div-float/2addr p0, p1

    .line 157
    invoke-static {p0}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 158
    .line 159
    .line 160
    move-result p1

    .line 161
    int-to-long p1, p1

    .line 162
    invoke-static {p0}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 163
    .line 164
    .line 165
    move-result p0

    .line 166
    int-to-long p3, p0

    .line 167
    shl-long p0, p1, v0

    .line 168
    .line 169
    and-long p2, p3, v1

    .line 170
    .line 171
    or-long/2addr p0, p2

    .line 172
    sget p2, Lt3/j1;->a:I

    .line 173
    .line 174
    return-wide p0

    .line 175
    :pswitch_3
    shr-long v3, p3, v0

    .line 176
    .line 177
    long-to-int p0, v3

    .line 178
    invoke-static {p0}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 179
    .line 180
    .line 181
    move-result p0

    .line 182
    shr-long v3, p1, v0

    .line 183
    .line 184
    long-to-int v3, v3

    .line 185
    invoke-static {v3}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 186
    .line 187
    .line 188
    move-result v3

    .line 189
    div-float/2addr p0, v3

    .line 190
    and-long/2addr p3, v1

    .line 191
    long-to-int p3, p3

    .line 192
    invoke-static {p3}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 193
    .line 194
    .line 195
    move-result p3

    .line 196
    and-long/2addr p1, v1

    .line 197
    long-to-int p1, p1

    .line 198
    invoke-static {p1}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 199
    .line 200
    .line 201
    move-result p1

    .line 202
    div-float/2addr p3, p1

    .line 203
    invoke-static {p0}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 204
    .line 205
    .line 206
    move-result p0

    .line 207
    int-to-long p0, p0

    .line 208
    invoke-static {p3}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 209
    .line 210
    .line 211
    move-result p2

    .line 212
    int-to-long p2, p2

    .line 213
    shl-long/2addr p0, v0

    .line 214
    and-long/2addr p2, v1

    .line 215
    or-long/2addr p0, p2

    .line 216
    sget p2, Lt3/j1;->a:I

    .line 217
    .line 218
    return-wide p0

    .line 219
    :pswitch_4
    shr-long v3, p3, v0

    .line 220
    .line 221
    long-to-int p0, v3

    .line 222
    invoke-static {p0}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 223
    .line 224
    .line 225
    move-result p0

    .line 226
    shr-long v3, p1, v0

    .line 227
    .line 228
    long-to-int v3, v3

    .line 229
    invoke-static {v3}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 230
    .line 231
    .line 232
    move-result v3

    .line 233
    div-float/2addr p0, v3

    .line 234
    and-long/2addr p3, v1

    .line 235
    long-to-int p3, p3

    .line 236
    invoke-static {p3}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 237
    .line 238
    .line 239
    move-result p3

    .line 240
    and-long/2addr p1, v1

    .line 241
    long-to-int p1, p1

    .line 242
    invoke-static {p1}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 243
    .line 244
    .line 245
    move-result p1

    .line 246
    div-float/2addr p3, p1

    .line 247
    invoke-static {p0, p3}, Ljava/lang/Math;->max(FF)F

    .line 248
    .line 249
    .line 250
    move-result p0

    .line 251
    invoke-static {p0}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 252
    .line 253
    .line 254
    move-result p1

    .line 255
    int-to-long p1, p1

    .line 256
    invoke-static {p0}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 257
    .line 258
    .line 259
    move-result p0

    .line 260
    int-to-long p3, p0

    .line 261
    shl-long p0, p1, v0

    .line 262
    .line 263
    and-long p2, p3, v1

    .line 264
    .line 265
    or-long/2addr p0, p2

    .line 266
    sget p2, Lt3/j1;->a:I

    .line 267
    .line 268
    return-wide p0

    .line 269
    :pswitch_data_0
    .packed-switch 0x1
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public r(Landroidx/collection/e1;)V
    .locals 0

    .line 1
    invoke-virtual {p1}, Landroidx/collection/e1;->clear()V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public s(Ljava/lang/Object;Ljava/lang/Object;)Z
    .locals 0

    .line 1
    const/4 p0, 0x0

    .line 2
    return p0
.end method

.method public toString()Ljava/lang/String;
    .locals 1

    .line 1
    iget v0, p0, Lt3/x0;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    invoke-super {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 7
    .line 8
    .line 9
    move-result-object p0

    .line 10
    return-object p0

    .line 11
    :pswitch_0
    const-string p0, "ReusedSlotId"

    .line 12
    .line 13
    return-object p0

    .line 14
    nop

    .line 15
    :pswitch_data_0
    .packed-switch 0x7
        :pswitch_0
    .end packed-switch
.end method
