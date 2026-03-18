.class public final Ls6/u;
.super Landroid/text/style/ReplacementSpan;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final d:Landroid/graphics/Paint$FontMetricsInt;

.field public final e:Ls6/t;

.field public f:S

.field public g:F

.field public h:Landroid/text/TextPaint;


# direct methods
.method public constructor <init>(Ls6/t;)V
    .locals 1

    .line 1
    invoke-direct {p0}, Landroid/text/style/ReplacementSpan;-><init>()V

    .line 2
    .line 3
    .line 4
    new-instance v0, Landroid/graphics/Paint$FontMetricsInt;

    .line 5
    .line 6
    invoke-direct {v0}, Landroid/graphics/Paint$FontMetricsInt;-><init>()V

    .line 7
    .line 8
    .line 9
    iput-object v0, p0, Ls6/u;->d:Landroid/graphics/Paint$FontMetricsInt;

    .line 10
    .line 11
    const/4 v0, -0x1

    .line 12
    iput-short v0, p0, Ls6/u;->f:S

    .line 13
    .line 14
    const/high16 v0, 0x3f800000    # 1.0f

    .line 15
    .line 16
    iput v0, p0, Ls6/u;->g:F

    .line 17
    .line 18
    const-string v0, "rasterizer cannot be null"

    .line 19
    .line 20
    invoke-static {p1, v0}, Ljp/ed;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 21
    .line 22
    .line 23
    iput-object p1, p0, Ls6/u;->e:Ls6/t;

    .line 24
    .line 25
    return-void
.end method


# virtual methods
.method public final draw(Landroid/graphics/Canvas;Ljava/lang/CharSequence;IIFIIILandroid/graphics/Paint;)V
    .locals 18

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p2

    .line 4
    .line 5
    move-object/from16 v2, p9

    .line 6
    .line 7
    instance-of v3, v1, Landroid/text/Spanned;

    .line 8
    .line 9
    const/4 v4, 0x0

    .line 10
    if-eqz v3, :cond_5

    .line 11
    .line 12
    check-cast v1, Landroid/text/Spanned;

    .line 13
    .line 14
    const-class v3, Landroid/text/style/CharacterStyle;

    .line 15
    .line 16
    move/from16 v5, p3

    .line 17
    .line 18
    move/from16 v6, p4

    .line 19
    .line 20
    invoke-interface {v1, v5, v6, v3}, Landroid/text/Spanned;->getSpans(IILjava/lang/Class;)[Ljava/lang/Object;

    .line 21
    .line 22
    .line 23
    move-result-object v1

    .line 24
    check-cast v1, [Landroid/text/style/CharacterStyle;

    .line 25
    .line 26
    array-length v3, v1

    .line 27
    if-eqz v3, :cond_4

    .line 28
    .line 29
    array-length v3, v1

    .line 30
    const/4 v5, 0x0

    .line 31
    const/4 v6, 0x1

    .line 32
    if-ne v3, v6, :cond_0

    .line 33
    .line 34
    aget-object v3, v1, v5

    .line 35
    .line 36
    if-ne v3, v0, :cond_0

    .line 37
    .line 38
    goto :goto_2

    .line 39
    :cond_0
    iget-object v3, v0, Ls6/u;->h:Landroid/text/TextPaint;

    .line 40
    .line 41
    if-nez v3, :cond_1

    .line 42
    .line 43
    new-instance v3, Landroid/text/TextPaint;

    .line 44
    .line 45
    invoke-direct {v3}, Landroid/text/TextPaint;-><init>()V

    .line 46
    .line 47
    .line 48
    iput-object v3, v0, Ls6/u;->h:Landroid/text/TextPaint;

    .line 49
    .line 50
    :cond_1
    move-object v4, v3

    .line 51
    invoke-virtual {v4, v2}, Landroid/graphics/Paint;->set(Landroid/graphics/Paint;)V

    .line 52
    .line 53
    .line 54
    :goto_0
    array-length v3, v1

    .line 55
    if-ge v5, v3, :cond_3

    .line 56
    .line 57
    aget-object v3, v1, v5

    .line 58
    .line 59
    instance-of v6, v3, Landroid/text/style/MetricAffectingSpan;

    .line 60
    .line 61
    if-nez v6, :cond_2

    .line 62
    .line 63
    invoke-virtual {v3, v4}, Landroid/text/style/CharacterStyle;->updateDrawState(Landroid/text/TextPaint;)V

    .line 64
    .line 65
    .line 66
    :cond_2
    add-int/lit8 v5, v5, 0x1

    .line 67
    .line 68
    goto :goto_0

    .line 69
    :cond_3
    :goto_1
    move-object v10, v4

    .line 70
    goto :goto_3

    .line 71
    :cond_4
    :goto_2
    instance-of v1, v2, Landroid/text/TextPaint;

    .line 72
    .line 73
    if-eqz v1, :cond_3

    .line 74
    .line 75
    move-object v4, v2

    .line 76
    check-cast v4, Landroid/text/TextPaint;

    .line 77
    .line 78
    goto :goto_1

    .line 79
    :cond_5
    instance-of v1, v2, Landroid/text/TextPaint;

    .line 80
    .line 81
    if-eqz v1, :cond_3

    .line 82
    .line 83
    move-object v4, v2

    .line 84
    check-cast v4, Landroid/text/TextPaint;

    .line 85
    .line 86
    goto :goto_1

    .line 87
    :goto_3
    if-eqz v10, :cond_6

    .line 88
    .line 89
    iget v1, v10, Landroid/text/TextPaint;->bgColor:I

    .line 90
    .line 91
    if-eqz v1, :cond_6

    .line 92
    .line 93
    iget-short v1, v0, Ls6/u;->f:S

    .line 94
    .line 95
    int-to-float v1, v1

    .line 96
    add-float v8, p5, v1

    .line 97
    .line 98
    move/from16 v1, p6

    .line 99
    .line 100
    int-to-float v7, v1

    .line 101
    move/from16 v1, p8

    .line 102
    .line 103
    int-to-float v9, v1

    .line 104
    invoke-virtual {v10}, Landroid/graphics/Paint;->getColor()I

    .line 105
    .line 106
    .line 107
    move-result v1

    .line 108
    invoke-virtual {v10}, Landroid/graphics/Paint;->getStyle()Landroid/graphics/Paint$Style;

    .line 109
    .line 110
    .line 111
    move-result-object v3

    .line 112
    iget v4, v10, Landroid/text/TextPaint;->bgColor:I

    .line 113
    .line 114
    invoke-virtual {v10, v4}, Landroid/graphics/Paint;->setColor(I)V

    .line 115
    .line 116
    .line 117
    sget-object v4, Landroid/graphics/Paint$Style;->FILL:Landroid/graphics/Paint$Style;

    .line 118
    .line 119
    invoke-virtual {v10, v4}, Landroid/graphics/Paint;->setStyle(Landroid/graphics/Paint$Style;)V

    .line 120
    .line 121
    .line 122
    move-object/from16 v5, p1

    .line 123
    .line 124
    move/from16 v6, p5

    .line 125
    .line 126
    invoke-virtual/range {v5 .. v10}, Landroid/graphics/Canvas;->drawRect(FFFFLandroid/graphics/Paint;)V

    .line 127
    .line 128
    .line 129
    invoke-virtual {v10, v3}, Landroid/graphics/Paint;->setStyle(Landroid/graphics/Paint$Style;)V

    .line 130
    .line 131
    .line 132
    invoke-virtual {v10, v1}, Landroid/graphics/Paint;->setColor(I)V

    .line 133
    .line 134
    .line 135
    :cond_6
    invoke-static {}, Ls6/h;->a()Ls6/h;

    .line 136
    .line 137
    .line 138
    move-result-object v1

    .line 139
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 140
    .line 141
    .line 142
    move/from16 v1, p7

    .line 143
    .line 144
    int-to-float v1, v1

    .line 145
    if-eqz v10, :cond_7

    .line 146
    .line 147
    goto :goto_4

    .line 148
    :cond_7
    move-object v10, v2

    .line 149
    :goto_4
    iget-object v0, v0, Ls6/u;->e:Ls6/t;

    .line 150
    .line 151
    iget-object v2, v0, Ls6/t;->b:Lcom/google/firebase/messaging/w;

    .line 152
    .line 153
    iget-object v3, v2, Lcom/google/firebase/messaging/w;->h:Ljava/lang/Object;

    .line 154
    .line 155
    check-cast v3, Landroid/graphics/Typeface;

    .line 156
    .line 157
    invoke-virtual {v10}, Landroid/graphics/Paint;->getTypeface()Landroid/graphics/Typeface;

    .line 158
    .line 159
    .line 160
    move-result-object v4

    .line 161
    invoke-virtual {v10, v3}, Landroid/graphics/Paint;->setTypeface(Landroid/graphics/Typeface;)Landroid/graphics/Typeface;

    .line 162
    .line 163
    .line 164
    iget v0, v0, Ls6/t;->a:I

    .line 165
    .line 166
    mul-int/lit8 v13, v0, 0x2

    .line 167
    .line 168
    iget-object v0, v2, Lcom/google/firebase/messaging/w;->f:Ljava/lang/Object;

    .line 169
    .line 170
    move-object v12, v0

    .line 171
    check-cast v12, [C

    .line 172
    .line 173
    const/4 v14, 0x2

    .line 174
    move-object/from16 v11, p1

    .line 175
    .line 176
    move/from16 v15, p5

    .line 177
    .line 178
    move/from16 v16, v1

    .line 179
    .line 180
    move-object/from16 v17, v10

    .line 181
    .line 182
    invoke-virtual/range {v11 .. v17}, Landroid/graphics/Canvas;->drawText([CIIFFLandroid/graphics/Paint;)V

    .line 183
    .line 184
    .line 185
    invoke-virtual {v10, v4}, Landroid/graphics/Paint;->setTypeface(Landroid/graphics/Typeface;)Landroid/graphics/Typeface;

    .line 186
    .line 187
    .line 188
    return-void
.end method

.method public final getSize(Landroid/graphics/Paint;Ljava/lang/CharSequence;IILandroid/graphics/Paint$FontMetricsInt;)I
    .locals 4

    .line 1
    iget-object p2, p0, Ls6/u;->d:Landroid/graphics/Paint$FontMetricsInt;

    .line 2
    .line 3
    invoke-virtual {p1, p2}, Landroid/graphics/Paint;->getFontMetricsInt(Landroid/graphics/Paint$FontMetricsInt;)I

    .line 4
    .line 5
    .line 6
    iget p1, p2, Landroid/graphics/Paint$FontMetricsInt;->descent:I

    .line 7
    .line 8
    iget p3, p2, Landroid/graphics/Paint$FontMetricsInt;->ascent:I

    .line 9
    .line 10
    sub-int/2addr p1, p3

    .line 11
    invoke-static {p1}, Ljava/lang/Math;->abs(I)I

    .line 12
    .line 13
    .line 14
    move-result p1

    .line 15
    int-to-float p1, p1

    .line 16
    const/high16 p3, 0x3f800000    # 1.0f

    .line 17
    .line 18
    mul-float/2addr p1, p3

    .line 19
    iget-object p3, p0, Ls6/u;->e:Ls6/t;

    .line 20
    .line 21
    invoke-virtual {p3}, Ls6/t;->b()Lt6/a;

    .line 22
    .line 23
    .line 24
    move-result-object p4

    .line 25
    const/16 v0, 0xe

    .line 26
    .line 27
    invoke-virtual {p4, v0}, Ld6/h0;->a(I)I

    .line 28
    .line 29
    .line 30
    move-result v1

    .line 31
    const/4 v2, 0x0

    .line 32
    if-eqz v1, :cond_0

    .line 33
    .line 34
    iget-object v3, p4, Ld6/h0;->g:Ljava/lang/Object;

    .line 35
    .line 36
    check-cast v3, Ljava/nio/ByteBuffer;

    .line 37
    .line 38
    iget p4, p4, Ld6/h0;->d:I

    .line 39
    .line 40
    add-int/2addr v1, p4

    .line 41
    invoke-virtual {v3, v1}, Ljava/nio/ByteBuffer;->getShort(I)S

    .line 42
    .line 43
    .line 44
    move-result p4

    .line 45
    goto :goto_0

    .line 46
    :cond_0
    move p4, v2

    .line 47
    :goto_0
    int-to-float p4, p4

    .line 48
    div-float/2addr p1, p4

    .line 49
    iput p1, p0, Ls6/u;->g:F

    .line 50
    .line 51
    invoke-virtual {p3}, Ls6/t;->b()Lt6/a;

    .line 52
    .line 53
    .line 54
    move-result-object p1

    .line 55
    invoke-virtual {p1, v0}, Ld6/h0;->a(I)I

    .line 56
    .line 57
    .line 58
    move-result p4

    .line 59
    if-eqz p4, :cond_1

    .line 60
    .line 61
    iget-object v0, p1, Ld6/h0;->g:Ljava/lang/Object;

    .line 62
    .line 63
    check-cast v0, Ljava/nio/ByteBuffer;

    .line 64
    .line 65
    iget p1, p1, Ld6/h0;->d:I

    .line 66
    .line 67
    add-int/2addr p4, p1

    .line 68
    invoke-virtual {v0, p4}, Ljava/nio/ByteBuffer;->getShort(I)S

    .line 69
    .line 70
    .line 71
    :cond_1
    invoke-virtual {p3}, Ls6/t;->b()Lt6/a;

    .line 72
    .line 73
    .line 74
    move-result-object p1

    .line 75
    const/16 p3, 0xc

    .line 76
    .line 77
    invoke-virtual {p1, p3}, Ld6/h0;->a(I)I

    .line 78
    .line 79
    .line 80
    move-result p3

    .line 81
    if-eqz p3, :cond_2

    .line 82
    .line 83
    iget-object p4, p1, Ld6/h0;->g:Ljava/lang/Object;

    .line 84
    .line 85
    check-cast p4, Ljava/nio/ByteBuffer;

    .line 86
    .line 87
    iget p1, p1, Ld6/h0;->d:I

    .line 88
    .line 89
    add-int/2addr p3, p1

    .line 90
    invoke-virtual {p4, p3}, Ljava/nio/ByteBuffer;->getShort(I)S

    .line 91
    .line 92
    .line 93
    move-result v2

    .line 94
    :cond_2
    int-to-float p1, v2

    .line 95
    iget p3, p0, Ls6/u;->g:F

    .line 96
    .line 97
    mul-float/2addr p1, p3

    .line 98
    float-to-int p1, p1

    .line 99
    int-to-short p1, p1

    .line 100
    iput-short p1, p0, Ls6/u;->f:S

    .line 101
    .line 102
    if-eqz p5, :cond_3

    .line 103
    .line 104
    iget p0, p2, Landroid/graphics/Paint$FontMetricsInt;->ascent:I

    .line 105
    .line 106
    iput p0, p5, Landroid/graphics/Paint$FontMetricsInt;->ascent:I

    .line 107
    .line 108
    iget p0, p2, Landroid/graphics/Paint$FontMetricsInt;->descent:I

    .line 109
    .line 110
    iput p0, p5, Landroid/graphics/Paint$FontMetricsInt;->descent:I

    .line 111
    .line 112
    iget p0, p2, Landroid/graphics/Paint$FontMetricsInt;->top:I

    .line 113
    .line 114
    iput p0, p5, Landroid/graphics/Paint$FontMetricsInt;->top:I

    .line 115
    .line 116
    iget p0, p2, Landroid/graphics/Paint$FontMetricsInt;->bottom:I

    .line 117
    .line 118
    iput p0, p5, Landroid/graphics/Paint$FontMetricsInt;->bottom:I

    .line 119
    .line 120
    :cond_3
    return p1
.end method
