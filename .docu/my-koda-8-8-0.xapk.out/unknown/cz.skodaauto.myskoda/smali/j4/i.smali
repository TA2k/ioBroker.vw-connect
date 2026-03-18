.class public final Lj4/i;
.super Landroid/text/style/ReplacementSpan;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final d:F

.field public final e:I

.field public final f:F

.field public final g:I

.field public final h:F

.field public final i:I

.field public j:Landroid/graphics/Paint$FontMetricsInt;

.field public k:I

.field public l:I

.field public m:Z


# direct methods
.method public constructor <init>(FIFIFI)V
    .locals 0

    .line 1
    invoke-direct {p0}, Landroid/text/style/ReplacementSpan;-><init>()V

    .line 2
    .line 3
    .line 4
    iput p1, p0, Lj4/i;->d:F

    .line 5
    .line 6
    iput p2, p0, Lj4/i;->e:I

    .line 7
    .line 8
    iput p3, p0, Lj4/i;->f:F

    .line 9
    .line 10
    iput p4, p0, Lj4/i;->g:I

    .line 11
    .line 12
    iput p5, p0, Lj4/i;->h:F

    .line 13
    .line 14
    iput p6, p0, Lj4/i;->i:I

    .line 15
    .line 16
    return-void
.end method


# virtual methods
.method public final a()Landroid/graphics/Paint$FontMetricsInt;
    .locals 0

    .line 1
    iget-object p0, p0, Lj4/i;->j:Landroid/graphics/Paint$FontMetricsInt;

    .line 2
    .line 3
    if-eqz p0, :cond_0

    .line 4
    .line 5
    return-object p0

    .line 6
    :cond_0
    const-string p0, "fontMetrics"

    .line 7
    .line 8
    invoke-static {p0}, Lkotlin/jvm/internal/m;->n(Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    const/4 p0, 0x0

    .line 12
    throw p0
.end method

.method public final b()I
    .locals 1

    .line 1
    iget-boolean v0, p0, Lj4/i;->m:Z

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    const-string v0, "PlaceholderSpan is not laid out yet."

    .line 6
    .line 7
    invoke-static {v0}, Lm4/a;->c(Ljava/lang/String;)V

    .line 8
    .line 9
    .line 10
    :cond_0
    iget p0, p0, Lj4/i;->l:I

    .line 11
    .line 12
    return p0
.end method

.method public final draw(Landroid/graphics/Canvas;Ljava/lang/CharSequence;IIFIIILandroid/graphics/Paint;)V
    .locals 0

    .line 1
    return-void
.end method

.method public final getSize(Landroid/graphics/Paint;Ljava/lang/CharSequence;IILandroid/graphics/Paint$FontMetricsInt;)I
    .locals 3

    .line 1
    const/4 p2, 0x1

    .line 2
    iput-boolean p2, p0, Lj4/i;->m:Z

    .line 3
    .line 4
    invoke-virtual {p1}, Landroid/graphics/Paint;->getTextSize()F

    .line 5
    .line 6
    .line 7
    move-result p3

    .line 8
    invoke-virtual {p1}, Landroid/graphics/Paint;->getFontMetricsInt()Landroid/graphics/Paint$FontMetricsInt;

    .line 9
    .line 10
    .line 11
    move-result-object p1

    .line 12
    iput-object p1, p0, Lj4/i;->j:Landroid/graphics/Paint$FontMetricsInt;

    .line 13
    .line 14
    invoke-virtual {p0}, Lj4/i;->a()Landroid/graphics/Paint$FontMetricsInt;

    .line 15
    .line 16
    .line 17
    move-result-object p1

    .line 18
    iget p1, p1, Landroid/graphics/Paint$FontMetricsInt;->descent:I

    .line 19
    .line 20
    invoke-virtual {p0}, Lj4/i;->a()Landroid/graphics/Paint$FontMetricsInt;

    .line 21
    .line 22
    .line 23
    move-result-object p4

    .line 24
    iget p4, p4, Landroid/graphics/Paint$FontMetricsInt;->ascent:I

    .line 25
    .line 26
    if-le p1, p4, :cond_0

    .line 27
    .line 28
    goto :goto_0

    .line 29
    :cond_0
    const-string p1, "Invalid fontMetrics: line height can not be negative."

    .line 30
    .line 31
    invoke-static {p1}, Lm4/a;->a(Ljava/lang/String;)V

    .line 32
    .line 33
    .line 34
    :goto_0
    iget p1, p0, Lj4/i;->h:F

    .line 35
    .line 36
    iget p4, p0, Lj4/i;->d:F

    .line 37
    .line 38
    const-string v0, "Unsupported unit."

    .line 39
    .line 40
    iget v1, p0, Lj4/i;->e:I

    .line 41
    .line 42
    if-eqz v1, :cond_2

    .line 43
    .line 44
    if-ne v1, p2, :cond_1

    .line 45
    .line 46
    mul-float/2addr p4, p3

    .line 47
    goto :goto_1

    .line 48
    :cond_1
    invoke-static {v0}, Lm4/a;->b(Ljava/lang/String;)Ljava/lang/Void;

    .line 49
    .line 50
    .line 51
    new-instance p0, La8/r0;

    .line 52
    .line 53
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 54
    .line 55
    .line 56
    throw p0

    .line 57
    :cond_2
    mul-float/2addr p4, p1

    .line 58
    :goto_1
    float-to-double v1, p4

    .line 59
    invoke-static {v1, v2}, Ljava/lang/Math;->ceil(D)D

    .line 60
    .line 61
    .line 62
    move-result-wide v1

    .line 63
    double-to-float p4, v1

    .line 64
    float-to-int p4, p4

    .line 65
    iput p4, p0, Lj4/i;->k:I

    .line 66
    .line 67
    iget p4, p0, Lj4/i;->f:F

    .line 68
    .line 69
    iget v1, p0, Lj4/i;->g:I

    .line 70
    .line 71
    if-eqz v1, :cond_4

    .line 72
    .line 73
    if-ne v1, p2, :cond_3

    .line 74
    .line 75
    mul-float/2addr p4, p3

    .line 76
    float-to-double p1, p4

    .line 77
    invoke-static {p1, p2}, Ljava/lang/Math;->ceil(D)D

    .line 78
    .line 79
    .line 80
    move-result-wide p1

    .line 81
    :goto_2
    double-to-float p1, p1

    .line 82
    float-to-int p1, p1

    .line 83
    goto :goto_3

    .line 84
    :cond_3
    invoke-static {v0}, Lm4/a;->b(Ljava/lang/String;)Ljava/lang/Void;

    .line 85
    .line 86
    .line 87
    new-instance p0, La8/r0;

    .line 88
    .line 89
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 90
    .line 91
    .line 92
    throw p0

    .line 93
    :cond_4
    mul-float/2addr p4, p1

    .line 94
    float-to-double p1, p4

    .line 95
    invoke-static {p1, p2}, Ljava/lang/Math;->ceil(D)D

    .line 96
    .line 97
    .line 98
    move-result-wide p1

    .line 99
    goto :goto_2

    .line 100
    :goto_3
    iput p1, p0, Lj4/i;->l:I

    .line 101
    .line 102
    if-eqz p5, :cond_6

    .line 103
    .line 104
    invoke-virtual {p0}, Lj4/i;->a()Landroid/graphics/Paint$FontMetricsInt;

    .line 105
    .line 106
    .line 107
    move-result-object p1

    .line 108
    iget p1, p1, Landroid/graphics/Paint$FontMetricsInt;->ascent:I

    .line 109
    .line 110
    iput p1, p5, Landroid/graphics/Paint$FontMetricsInt;->ascent:I

    .line 111
    .line 112
    invoke-virtual {p0}, Lj4/i;->a()Landroid/graphics/Paint$FontMetricsInt;

    .line 113
    .line 114
    .line 115
    move-result-object p1

    .line 116
    iget p1, p1, Landroid/graphics/Paint$FontMetricsInt;->descent:I

    .line 117
    .line 118
    iput p1, p5, Landroid/graphics/Paint$FontMetricsInt;->descent:I

    .line 119
    .line 120
    invoke-virtual {p0}, Lj4/i;->a()Landroid/graphics/Paint$FontMetricsInt;

    .line 121
    .line 122
    .line 123
    move-result-object p1

    .line 124
    iget p1, p1, Landroid/graphics/Paint$FontMetricsInt;->leading:I

    .line 125
    .line 126
    iput p1, p5, Landroid/graphics/Paint$FontMetricsInt;->leading:I

    .line 127
    .line 128
    iget p1, p0, Lj4/i;->i:I

    .line 129
    .line 130
    packed-switch p1, :pswitch_data_0

    .line 131
    .line 132
    .line 133
    const-string p1, "Unknown verticalAlign."

    .line 134
    .line 135
    invoke-static {p1}, Lm4/a;->a(Ljava/lang/String;)V

    .line 136
    .line 137
    .line 138
    goto :goto_4

    .line 139
    :pswitch_0
    iget p1, p5, Landroid/graphics/Paint$FontMetricsInt;->descent:I

    .line 140
    .line 141
    iget p2, p5, Landroid/graphics/Paint$FontMetricsInt;->ascent:I

    .line 142
    .line 143
    sub-int/2addr p1, p2

    .line 144
    invoke-virtual {p0}, Lj4/i;->b()I

    .line 145
    .line 146
    .line 147
    move-result p2

    .line 148
    if-ge p1, p2, :cond_5

    .line 149
    .line 150
    iget p1, p5, Landroid/graphics/Paint$FontMetricsInt;->ascent:I

    .line 151
    .line 152
    invoke-virtual {p0}, Lj4/i;->b()I

    .line 153
    .line 154
    .line 155
    move-result p2

    .line 156
    iget p3, p5, Landroid/graphics/Paint$FontMetricsInt;->descent:I

    .line 157
    .line 158
    iget p4, p5, Landroid/graphics/Paint$FontMetricsInt;->ascent:I

    .line 159
    .line 160
    sub-int/2addr p3, p4

    .line 161
    sub-int/2addr p2, p3

    .line 162
    div-int/lit8 p2, p2, 0x2

    .line 163
    .line 164
    sub-int/2addr p1, p2

    .line 165
    iput p1, p5, Landroid/graphics/Paint$FontMetricsInt;->ascent:I

    .line 166
    .line 167
    invoke-virtual {p0}, Lj4/i;->b()I

    .line 168
    .line 169
    .line 170
    move-result p2

    .line 171
    add-int/2addr p2, p1

    .line 172
    iput p2, p5, Landroid/graphics/Paint$FontMetricsInt;->descent:I

    .line 173
    .line 174
    goto :goto_4

    .line 175
    :pswitch_1
    iget p1, p5, Landroid/graphics/Paint$FontMetricsInt;->ascent:I

    .line 176
    .line 177
    iget p2, p5, Landroid/graphics/Paint$FontMetricsInt;->descent:I

    .line 178
    .line 179
    invoke-virtual {p0}, Lj4/i;->b()I

    .line 180
    .line 181
    .line 182
    move-result p3

    .line 183
    sub-int/2addr p2, p3

    .line 184
    if-le p1, p2, :cond_5

    .line 185
    .line 186
    iget p1, p5, Landroid/graphics/Paint$FontMetricsInt;->descent:I

    .line 187
    .line 188
    invoke-virtual {p0}, Lj4/i;->b()I

    .line 189
    .line 190
    .line 191
    move-result p2

    .line 192
    sub-int/2addr p1, p2

    .line 193
    iput p1, p5, Landroid/graphics/Paint$FontMetricsInt;->ascent:I

    .line 194
    .line 195
    goto :goto_4

    .line 196
    :pswitch_2
    iget p1, p5, Landroid/graphics/Paint$FontMetricsInt;->ascent:I

    .line 197
    .line 198
    invoke-virtual {p0}, Lj4/i;->b()I

    .line 199
    .line 200
    .line 201
    move-result p2

    .line 202
    add-int/2addr p2, p1

    .line 203
    iget p1, p5, Landroid/graphics/Paint$FontMetricsInt;->descent:I

    .line 204
    .line 205
    if-le p2, p1, :cond_5

    .line 206
    .line 207
    iget p1, p5, Landroid/graphics/Paint$FontMetricsInt;->ascent:I

    .line 208
    .line 209
    invoke-virtual {p0}, Lj4/i;->b()I

    .line 210
    .line 211
    .line 212
    move-result p2

    .line 213
    add-int/2addr p2, p1

    .line 214
    iput p2, p5, Landroid/graphics/Paint$FontMetricsInt;->descent:I

    .line 215
    .line 216
    goto :goto_4

    .line 217
    :pswitch_3
    iget p1, p5, Landroid/graphics/Paint$FontMetricsInt;->ascent:I

    .line 218
    .line 219
    invoke-virtual {p0}, Lj4/i;->b()I

    .line 220
    .line 221
    .line 222
    move-result p2

    .line 223
    neg-int p2, p2

    .line 224
    if-le p1, p2, :cond_5

    .line 225
    .line 226
    invoke-virtual {p0}, Lj4/i;->b()I

    .line 227
    .line 228
    .line 229
    move-result p1

    .line 230
    neg-int p1, p1

    .line 231
    iput p1, p5, Landroid/graphics/Paint$FontMetricsInt;->ascent:I

    .line 232
    .line 233
    :cond_5
    :goto_4
    invoke-virtual {p0}, Lj4/i;->a()Landroid/graphics/Paint$FontMetricsInt;

    .line 234
    .line 235
    .line 236
    move-result-object p1

    .line 237
    iget p1, p1, Landroid/graphics/Paint$FontMetricsInt;->top:I

    .line 238
    .line 239
    iget p2, p5, Landroid/graphics/Paint$FontMetricsInt;->ascent:I

    .line 240
    .line 241
    invoke-static {p1, p2}, Ljava/lang/Math;->min(II)I

    .line 242
    .line 243
    .line 244
    move-result p1

    .line 245
    iput p1, p5, Landroid/graphics/Paint$FontMetricsInt;->top:I

    .line 246
    .line 247
    invoke-virtual {p0}, Lj4/i;->a()Landroid/graphics/Paint$FontMetricsInt;

    .line 248
    .line 249
    .line 250
    move-result-object p1

    .line 251
    iget p1, p1, Landroid/graphics/Paint$FontMetricsInt;->bottom:I

    .line 252
    .line 253
    iget p2, p5, Landroid/graphics/Paint$FontMetricsInt;->descent:I

    .line 254
    .line 255
    invoke-static {p1, p2}, Ljava/lang/Math;->max(II)I

    .line 256
    .line 257
    .line 258
    move-result p1

    .line 259
    iput p1, p5, Landroid/graphics/Paint$FontMetricsInt;->bottom:I

    .line 260
    .line 261
    :cond_6
    iget-boolean p1, p0, Lj4/i;->m:Z

    .line 262
    .line 263
    if-nez p1, :cond_7

    .line 264
    .line 265
    const-string p1, "PlaceholderSpan is not laid out yet."

    .line 266
    .line 267
    invoke-static {p1}, Lm4/a;->c(Ljava/lang/String;)V

    .line 268
    .line 269
    .line 270
    :cond_7
    iget p0, p0, Lj4/i;->k:I

    .line 271
    .line 272
    return p0

    .line 273
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
