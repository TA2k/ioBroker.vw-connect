.class public abstract Lh4/g;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method static constructor <clinit>()V
    .locals 0

    .line 1
    return-void
.end method

.method public static a(Ljava/lang/CharSequence;Landroid/text/TextPaint;IILandroid/text/TextDirectionHeuristic;Landroid/text/Layout$Alignment;ILandroid/text/TextUtils$TruncateAt;IIZIIII)Landroid/text/StaticLayout;
    .locals 1

    .line 1
    if-ltz p3, :cond_0

    .line 2
    .line 3
    goto :goto_0

    .line 4
    :cond_0
    const-string v0, "invalid start value"

    .line 5
    .line 6
    invoke-static {v0}, Lm4/a;->a(Ljava/lang/String;)V

    .line 7
    .line 8
    .line 9
    :goto_0
    invoke-interface {p0}, Ljava/lang/CharSequence;->length()I

    .line 10
    .line 11
    .line 12
    move-result v0

    .line 13
    if-ltz p3, :cond_1

    .line 14
    .line 15
    if-gt p3, v0, :cond_1

    .line 16
    .line 17
    goto :goto_1

    .line 18
    :cond_1
    const-string v0, "invalid end value"

    .line 19
    .line 20
    invoke-static {v0}, Lm4/a;->a(Ljava/lang/String;)V

    .line 21
    .line 22
    .line 23
    :goto_1
    if-ltz p6, :cond_2

    .line 24
    .line 25
    goto :goto_2

    .line 26
    :cond_2
    const-string v0, "invalid maxLines value"

    .line 27
    .line 28
    invoke-static {v0}, Lm4/a;->a(Ljava/lang/String;)V

    .line 29
    .line 30
    .line 31
    :goto_2
    if-ltz p2, :cond_3

    .line 32
    .line 33
    goto :goto_3

    .line 34
    :cond_3
    const-string v0, "invalid width value"

    .line 35
    .line 36
    invoke-static {v0}, Lm4/a;->a(Ljava/lang/String;)V

    .line 37
    .line 38
    .line 39
    :goto_3
    if-ltz p8, :cond_4

    .line 40
    .line 41
    goto :goto_4

    .line 42
    :cond_4
    const-string v0, "invalid ellipsizedWidth value"

    .line 43
    .line 44
    invoke-static {v0}, Lm4/a;->a(Ljava/lang/String;)V

    .line 45
    .line 46
    .line 47
    :goto_4
    const/4 v0, 0x0

    .line 48
    invoke-static {p0, v0, p3, p1, p2}, Landroid/text/StaticLayout$Builder;->obtain(Ljava/lang/CharSequence;IILandroid/text/TextPaint;I)Landroid/text/StaticLayout$Builder;

    .line 49
    .line 50
    .line 51
    move-result-object p0

    .line 52
    invoke-virtual {p0, p4}, Landroid/text/StaticLayout$Builder;->setTextDirection(Landroid/text/TextDirectionHeuristic;)Landroid/text/StaticLayout$Builder;

    .line 53
    .line 54
    .line 55
    invoke-virtual {p0, p5}, Landroid/text/StaticLayout$Builder;->setAlignment(Landroid/text/Layout$Alignment;)Landroid/text/StaticLayout$Builder;

    .line 56
    .line 57
    .line 58
    invoke-virtual {p0, p6}, Landroid/text/StaticLayout$Builder;->setMaxLines(I)Landroid/text/StaticLayout$Builder;

    .line 59
    .line 60
    .line 61
    invoke-virtual {p0, p7}, Landroid/text/StaticLayout$Builder;->setEllipsize(Landroid/text/TextUtils$TruncateAt;)Landroid/text/StaticLayout$Builder;

    .line 62
    .line 63
    .line 64
    invoke-virtual {p0, p8}, Landroid/text/StaticLayout$Builder;->setEllipsizedWidth(I)Landroid/text/StaticLayout$Builder;

    .line 65
    .line 66
    .line 67
    const/4 p1, 0x0

    .line 68
    const/high16 p2, 0x3f800000    # 1.0f

    .line 69
    .line 70
    invoke-virtual {p0, p1, p2}, Landroid/text/StaticLayout$Builder;->setLineSpacing(FF)Landroid/text/StaticLayout$Builder;

    .line 71
    .line 72
    .line 73
    invoke-virtual {p0, p10}, Landroid/text/StaticLayout$Builder;->setIncludePad(Z)Landroid/text/StaticLayout$Builder;

    .line 74
    .line 75
    .line 76
    invoke-virtual {p0, p11}, Landroid/text/StaticLayout$Builder;->setBreakStrategy(I)Landroid/text/StaticLayout$Builder;

    .line 77
    .line 78
    .line 79
    invoke-virtual {p0, p14}, Landroid/text/StaticLayout$Builder;->setHyphenationFrequency(I)Landroid/text/StaticLayout$Builder;

    .line 80
    .line 81
    .line 82
    const/4 p1, 0x0

    .line 83
    invoke-virtual {p0, p1, p1}, Landroid/text/StaticLayout$Builder;->setIndents([I[I)Landroid/text/StaticLayout$Builder;

    .line 84
    .line 85
    .line 86
    sget p1, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 87
    .line 88
    invoke-virtual {p0, p9}, Landroid/text/StaticLayout$Builder;->setJustificationMode(I)Landroid/text/StaticLayout$Builder;

    .line 89
    .line 90
    .line 91
    const/4 p2, 0x1

    .line 92
    invoke-virtual {p0, p2}, Landroid/text/StaticLayout$Builder;->setUseLineSpacingFromFallbacks(Z)Landroid/text/StaticLayout$Builder;

    .line 93
    .line 94
    .line 95
    const/16 p2, 0x21

    .line 96
    .line 97
    if-lt p1, p2, :cond_5

    .line 98
    .line 99
    invoke-static {}, Lb/s;->e()Landroid/graphics/text/LineBreakConfig$Builder;

    .line 100
    .line 101
    .line 102
    move-result-object p2

    .line 103
    invoke-static {p2, p12}, Lb/s;->f(Landroid/graphics/text/LineBreakConfig$Builder;I)Landroid/graphics/text/LineBreakConfig$Builder;

    .line 104
    .line 105
    .line 106
    move-result-object p2

    .line 107
    invoke-static {p2, p13}, Lb/s;->B(Landroid/graphics/text/LineBreakConfig$Builder;I)Landroid/graphics/text/LineBreakConfig$Builder;

    .line 108
    .line 109
    .line 110
    move-result-object p2

    .line 111
    invoke-static {p2}, Lb/s;->g(Landroid/graphics/text/LineBreakConfig$Builder;)Landroid/graphics/text/LineBreakConfig;

    .line 112
    .line 113
    .line 114
    move-result-object p2

    .line 115
    invoke-static {p0, p2}, Lb/s;->v(Landroid/text/StaticLayout$Builder;Landroid/graphics/text/LineBreakConfig;)V

    .line 116
    .line 117
    .line 118
    :cond_5
    const/16 p2, 0x23

    .line 119
    .line 120
    if-lt p1, p2, :cond_6

    .line 121
    .line 122
    invoke-static {p0}, Lf8/a;->h(Landroid/text/StaticLayout$Builder;)V

    .line 123
    .line 124
    .line 125
    :cond_6
    invoke-virtual {p0}, Landroid/text/StaticLayout$Builder;->build()Landroid/text/StaticLayout;

    .line 126
    .line 127
    .line 128
    move-result-object p0

    .line 129
    return-object p0
.end method

.method public static final b(Landroid/text/TextPaint;Ljava/lang/CharSequence;II)Landroid/graphics/Rect;
    .locals 10

    .line 1
    instance-of v0, p1, Landroid/text/Spanned;

    .line 2
    .line 3
    if-eqz v0, :cond_3

    .line 4
    .line 5
    move-object v0, p1

    .line 6
    check-cast v0, Landroid/text/Spanned;

    .line 7
    .line 8
    add-int/lit8 v1, p2, -0x1

    .line 9
    .line 10
    const-class v2, Landroid/text/style/MetricAffectingSpan;

    .line 11
    .line 12
    invoke-interface {v0, v1, p3, v2}, Landroid/text/Spanned;->nextSpanTransition(IILjava/lang/Class;)I

    .line 13
    .line 14
    .line 15
    move-result v1

    .line 16
    if-eq v1, p3, :cond_3

    .line 17
    .line 18
    new-instance v1, Landroid/graphics/Rect;

    .line 19
    .line 20
    invoke-direct {v1}, Landroid/graphics/Rect;-><init>()V

    .line 21
    .line 22
    .line 23
    new-instance v3, Landroid/graphics/Rect;

    .line 24
    .line 25
    invoke-direct {v3}, Landroid/graphics/Rect;-><init>()V

    .line 26
    .line 27
    .line 28
    new-instance v4, Landroid/text/TextPaint;

    .line 29
    .line 30
    invoke-direct {v4}, Landroid/text/TextPaint;-><init>()V

    .line 31
    .line 32
    .line 33
    :goto_0
    if-ge p2, p3, :cond_2

    .line 34
    .line 35
    invoke-interface {v0, p2, p3, v2}, Landroid/text/Spanned;->nextSpanTransition(IILjava/lang/Class;)I

    .line 36
    .line 37
    .line 38
    move-result v5

    .line 39
    invoke-interface {v0, p2, v5, v2}, Landroid/text/Spanned;->getSpans(IILjava/lang/Class;)[Ljava/lang/Object;

    .line 40
    .line 41
    .line 42
    move-result-object v6

    .line 43
    check-cast v6, [Landroid/text/style/MetricAffectingSpan;

    .line 44
    .line 45
    invoke-virtual {v4, p0}, Landroid/text/TextPaint;->set(Landroid/text/TextPaint;)V

    .line 46
    .line 47
    .line 48
    invoke-static {v6}, Lkotlin/jvm/internal/m;->j([Ljava/lang/Object;)Landroidx/collection/d1;

    .line 49
    .line 50
    .line 51
    move-result-object v6

    .line 52
    :cond_0
    :goto_1
    invoke-virtual {v6}, Landroidx/collection/d1;->hasNext()Z

    .line 53
    .line 54
    .line 55
    move-result v7

    .line 56
    if-eqz v7, :cond_1

    .line 57
    .line 58
    invoke-virtual {v6}, Landroidx/collection/d1;->next()Ljava/lang/Object;

    .line 59
    .line 60
    .line 61
    move-result-object v7

    .line 62
    check-cast v7, Landroid/text/style/MetricAffectingSpan;

    .line 63
    .line 64
    invoke-interface {v0, v7}, Landroid/text/Spanned;->getSpanStart(Ljava/lang/Object;)I

    .line 65
    .line 66
    .line 67
    move-result v8

    .line 68
    invoke-interface {v0, v7}, Landroid/text/Spanned;->getSpanEnd(Ljava/lang/Object;)I

    .line 69
    .line 70
    .line 71
    move-result v9

    .line 72
    if-eq v8, v9, :cond_0

    .line 73
    .line 74
    invoke-virtual {v7, v4}, Landroid/text/style/MetricAffectingSpan;->updateMeasureState(Landroid/text/TextPaint;)V

    .line 75
    .line 76
    .line 77
    goto :goto_1

    .line 78
    :cond_1
    invoke-virtual {v4, p1, p2, v5, v3}, Landroid/graphics/Paint;->getTextBounds(Ljava/lang/CharSequence;IILandroid/graphics/Rect;)V

    .line 79
    .line 80
    .line 81
    iget p2, v1, Landroid/graphics/Rect;->right:I

    .line 82
    .line 83
    invoke-virtual {v3}, Landroid/graphics/Rect;->width()I

    .line 84
    .line 85
    .line 86
    move-result v6

    .line 87
    add-int/2addr v6, p2

    .line 88
    iput v6, v1, Landroid/graphics/Rect;->right:I

    .line 89
    .line 90
    iget p2, v1, Landroid/graphics/Rect;->top:I

    .line 91
    .line 92
    iget v6, v3, Landroid/graphics/Rect;->top:I

    .line 93
    .line 94
    invoke-static {p2, v6}, Ljava/lang/Math;->min(II)I

    .line 95
    .line 96
    .line 97
    move-result p2

    .line 98
    iput p2, v1, Landroid/graphics/Rect;->top:I

    .line 99
    .line 100
    iget p2, v1, Landroid/graphics/Rect;->bottom:I

    .line 101
    .line 102
    iget v6, v3, Landroid/graphics/Rect;->bottom:I

    .line 103
    .line 104
    invoke-static {p2, v6}, Ljava/lang/Math;->max(II)I

    .line 105
    .line 106
    .line 107
    move-result p2

    .line 108
    iput p2, v1, Landroid/graphics/Rect;->bottom:I

    .line 109
    .line 110
    move p2, v5

    .line 111
    goto :goto_0

    .line 112
    :cond_2
    return-object v1

    .line 113
    :cond_3
    new-instance v0, Landroid/graphics/Rect;

    .line 114
    .line 115
    invoke-direct {v0}, Landroid/graphics/Rect;-><init>()V

    .line 116
    .line 117
    .line 118
    invoke-virtual {p0, p1, p2, p3, v0}, Landroid/graphics/Paint;->getTextBounds(Ljava/lang/CharSequence;IILandroid/graphics/Rect;)V

    .line 119
    .line 120
    .line 121
    return-object v0
.end method

.method public static final c(II[F)F
    .locals 0

    .line 1
    sub-int/2addr p0, p1

    .line 2
    mul-int/lit8 p0, p0, 0x2

    .line 3
    .line 4
    add-int/lit8 p0, p0, 0x1

    .line 5
    .line 6
    aget p0, p2, p0

    .line 7
    .line 8
    return p0
.end method

.method public static final d(Landroid/text/Layout;IZ)I
    .locals 2

    .line 1
    if-gtz p1, :cond_0

    .line 2
    .line 3
    const/4 p0, 0x0

    .line 4
    return p0

    .line 5
    :cond_0
    invoke-virtual {p0}, Landroid/text/Layout;->getText()Ljava/lang/CharSequence;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    invoke-interface {v0}, Ljava/lang/CharSequence;->length()I

    .line 10
    .line 11
    .line 12
    move-result v0

    .line 13
    if-lt p1, v0, :cond_1

    .line 14
    .line 15
    invoke-virtual {p0}, Landroid/text/Layout;->getLineCount()I

    .line 16
    .line 17
    .line 18
    move-result p0

    .line 19
    add-int/lit8 p0, p0, -0x1

    .line 20
    .line 21
    return p0

    .line 22
    :cond_1
    invoke-virtual {p0, p1}, Landroid/text/Layout;->getLineForOffset(I)I

    .line 23
    .line 24
    .line 25
    move-result v0

    .line 26
    invoke-virtual {p0, v0}, Landroid/text/Layout;->getLineStart(I)I

    .line 27
    .line 28
    .line 29
    move-result v1

    .line 30
    invoke-virtual {p0, v0}, Landroid/text/Layout;->getLineEnd(I)I

    .line 31
    .line 32
    .line 33
    move-result p0

    .line 34
    if-eq v1, p1, :cond_2

    .line 35
    .line 36
    if-eq p0, p1, :cond_2

    .line 37
    .line 38
    goto :goto_0

    .line 39
    :cond_2
    if-ne v1, p1, :cond_3

    .line 40
    .line 41
    if-eqz p2, :cond_4

    .line 42
    .line 43
    add-int/lit8 v0, v0, -0x1

    .line 44
    .line 45
    return v0

    .line 46
    :cond_3
    if-eqz p2, :cond_5

    .line 47
    .line 48
    :cond_4
    :goto_0
    return v0

    .line 49
    :cond_5
    add-int/lit8 v0, v0, 0x1

    .line 50
    .line 51
    return v0
.end method

.method public static final e(Lh4/j;Landroid/text/Layout;Landroidx/lifecycle/c1;ILandroid/graphics/RectF;Li4/b;La71/a0;Z)I
    .locals 19

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    move-object/from16 v2, p2

    .line 6
    .line 7
    move/from16 v3, p3

    .line 8
    .line 9
    move-object/from16 v4, p4

    .line 10
    .line 11
    move-object/from16 v5, p5

    .line 12
    .line 13
    move-object/from16 v6, p6

    .line 14
    .line 15
    invoke-virtual {v1, v3}, Landroid/text/Layout;->getLineTop(I)I

    .line 16
    .line 17
    .line 18
    move-result v7

    .line 19
    invoke-virtual {v1, v3}, Landroid/text/Layout;->getLineBottom(I)I

    .line 20
    .line 21
    .line 22
    move-result v8

    .line 23
    invoke-virtual {v1, v3}, Landroid/text/Layout;->getLineStart(I)I

    .line 24
    .line 25
    .line 26
    move-result v9

    .line 27
    invoke-virtual {v1, v3}, Landroid/text/Layout;->getLineEnd(I)I

    .line 28
    .line 29
    .line 30
    move-result v1

    .line 31
    if-ne v9, v1, :cond_1

    .line 32
    .line 33
    :cond_0
    const/4 v10, -0x1

    .line 34
    goto/16 :goto_1e

    .line 35
    .line 36
    :cond_1
    sub-int/2addr v1, v9

    .line 37
    mul-int/lit8 v1, v1, 0x2

    .line 38
    .line 39
    new-array v11, v1, [F

    .line 40
    .line 41
    iget-object v12, v0, Lh4/j;->f:Landroid/text/Layout;

    .line 42
    .line 43
    invoke-virtual {v12, v3}, Landroid/text/Layout;->getLineStart(I)I

    .line 44
    .line 45
    .line 46
    move-result v13

    .line 47
    invoke-virtual {v0, v3}, Lh4/j;->f(I)I

    .line 48
    .line 49
    .line 50
    move-result v14

    .line 51
    sub-int v15, v14, v13

    .line 52
    .line 53
    mul-int/lit8 v15, v15, 0x2

    .line 54
    .line 55
    if-lt v1, v15, :cond_2

    .line 56
    .line 57
    goto :goto_0

    .line 58
    :cond_2
    const-string v1, "array.size - arrayStart must be greater or equal than (endOffset - startOffset) * 2"

    .line 59
    .line 60
    invoke-static {v1}, Lm4/a;->a(Ljava/lang/String;)V

    .line 61
    .line 62
    .line 63
    :goto_0
    new-instance v1, Lc4/h;

    .line 64
    .line 65
    invoke-direct {v1, v0}, Lc4/h;-><init>(Lh4/j;)V

    .line 66
    .line 67
    .line 68
    invoke-virtual {v12, v3}, Landroid/text/Layout;->getParagraphDirection(I)I

    .line 69
    .line 70
    .line 71
    move-result v0

    .line 72
    const/4 v15, 0x0

    .line 73
    const/4 v10, 0x1

    .line 74
    if-ne v0, v10, :cond_3

    .line 75
    .line 76
    move v0, v10

    .line 77
    goto :goto_1

    .line 78
    :cond_3
    move v0, v15

    .line 79
    :goto_1
    move/from16 v16, v15

    .line 80
    .line 81
    :goto_2
    if-ge v13, v14, :cond_7

    .line 82
    .line 83
    invoke-virtual {v12, v13}, Landroid/text/Layout;->isRtlCharAt(I)Z

    .line 84
    .line 85
    .line 86
    move-result v17

    .line 87
    if-eqz v0, :cond_4

    .line 88
    .line 89
    if-nez v17, :cond_4

    .line 90
    .line 91
    invoke-virtual {v1, v13, v15, v15, v10}, Lc4/h;->a(IZZZ)F

    .line 92
    .line 93
    .line 94
    move-result v17

    .line 95
    add-int/lit8 v15, v13, 0x1

    .line 96
    .line 97
    invoke-virtual {v1, v15, v10, v10, v10}, Lc4/h;->a(IZZZ)F

    .line 98
    .line 99
    .line 100
    move-result v15

    .line 101
    move/from16 v18, v0

    .line 102
    .line 103
    goto :goto_4

    .line 104
    :cond_4
    if-eqz v0, :cond_5

    .line 105
    .line 106
    if-eqz v17, :cond_5

    .line 107
    .line 108
    const/4 v15, 0x0

    .line 109
    invoke-virtual {v1, v13, v15, v15, v15}, Lc4/h;->a(IZZZ)F

    .line 110
    .line 111
    .line 112
    move-result v17

    .line 113
    move/from16 v18, v0

    .line 114
    .line 115
    add-int/lit8 v0, v13, 0x1

    .line 116
    .line 117
    invoke-virtual {v1, v0, v10, v10, v15}, Lc4/h;->a(IZZZ)F

    .line 118
    .line 119
    .line 120
    move-result v0

    .line 121
    move/from16 v15, v17

    .line 122
    .line 123
    move/from16 v17, v0

    .line 124
    .line 125
    goto :goto_4

    .line 126
    :cond_5
    move/from16 v18, v0

    .line 127
    .line 128
    const/4 v15, 0x0

    .line 129
    if-eqz v17, :cond_6

    .line 130
    .line 131
    invoke-virtual {v1, v13, v15, v15, v10}, Lc4/h;->a(IZZZ)F

    .line 132
    .line 133
    .line 134
    move-result v0

    .line 135
    add-int/lit8 v15, v13, 0x1

    .line 136
    .line 137
    invoke-virtual {v1, v15, v10, v10, v10}, Lc4/h;->a(IZZZ)F

    .line 138
    .line 139
    .line 140
    move-result v17

    .line 141
    :goto_3
    move v15, v0

    .line 142
    goto :goto_4

    .line 143
    :cond_6
    invoke-virtual {v1, v13, v15, v15, v15}, Lc4/h;->a(IZZZ)F

    .line 144
    .line 145
    .line 146
    move-result v17

    .line 147
    add-int/lit8 v0, v13, 0x1

    .line 148
    .line 149
    invoke-virtual {v1, v0, v10, v10, v15}, Lc4/h;->a(IZZZ)F

    .line 150
    .line 151
    .line 152
    move-result v0

    .line 153
    goto :goto_3

    .line 154
    :goto_4
    aput v17, v11, v16

    .line 155
    .line 156
    add-int/lit8 v0, v16, 0x1

    .line 157
    .line 158
    aput v15, v11, v0

    .line 159
    .line 160
    add-int/lit8 v16, v16, 0x2

    .line 161
    .line 162
    add-int/lit8 v13, v13, 0x1

    .line 163
    .line 164
    move/from16 v0, v18

    .line 165
    .line 166
    const/4 v15, 0x0

    .line 167
    goto :goto_2

    .line 168
    :cond_7
    iget-object v0, v2, Landroidx/lifecycle/c1;->e:Ljava/lang/Object;

    .line 169
    .line 170
    check-cast v0, Landroid/text/Layout;

    .line 171
    .line 172
    invoke-virtual {v0, v3}, Landroid/text/Layout;->getLineStart(I)I

    .line 173
    .line 174
    .line 175
    move-result v1

    .line 176
    invoke-virtual {v0, v3}, Landroid/text/Layout;->getLineEnd(I)I

    .line 177
    .line 178
    .line 179
    move-result v3

    .line 180
    const/4 v15, 0x0

    .line 181
    invoke-virtual {v2, v1, v15}, Landroidx/lifecycle/c1;->y(IZ)I

    .line 182
    .line 183
    .line 184
    move-result v12

    .line 185
    invoke-virtual {v2, v12}, Landroidx/lifecycle/c1;->z(I)I

    .line 186
    .line 187
    .line 188
    move-result v13

    .line 189
    sub-int v14, v1, v13

    .line 190
    .line 191
    sub-int v13, v3, v13

    .line 192
    .line 193
    invoke-virtual {v2, v12}, Landroidx/lifecycle/c1;->g(I)Ljava/text/Bidi;

    .line 194
    .line 195
    .line 196
    move-result-object v2

    .line 197
    if-eqz v2, :cond_a

    .line 198
    .line 199
    invoke-virtual {v2, v14, v13}, Ljava/text/Bidi;->createLineBidi(II)Ljava/text/Bidi;

    .line 200
    .line 201
    .line 202
    move-result-object v2

    .line 203
    if-nez v2, :cond_8

    .line 204
    .line 205
    goto :goto_7

    .line 206
    :cond_8
    invoke-virtual {v2}, Ljava/text/Bidi;->getRunCount()I

    .line 207
    .line 208
    .line 209
    move-result v0

    .line 210
    new-array v3, v0, [Lh4/e;

    .line 211
    .line 212
    const/4 v15, 0x0

    .line 213
    :goto_5
    if-ge v15, v0, :cond_b

    .line 214
    .line 215
    new-instance v12, Lh4/e;

    .line 216
    .line 217
    invoke-virtual {v2, v15}, Ljava/text/Bidi;->getRunStart(I)I

    .line 218
    .line 219
    .line 220
    move-result v13

    .line 221
    add-int/2addr v13, v1

    .line 222
    invoke-virtual {v2, v15}, Ljava/text/Bidi;->getRunLimit(I)I

    .line 223
    .line 224
    .line 225
    move-result v14

    .line 226
    add-int/2addr v14, v1

    .line 227
    invoke-virtual {v2, v15}, Ljava/text/Bidi;->getRunLevel(I)I

    .line 228
    .line 229
    .line 230
    move-result v16

    .line 231
    move/from16 p2, v0

    .line 232
    .line 233
    rem-int/lit8 v0, v16, 0x2

    .line 234
    .line 235
    if-ne v0, v10, :cond_9

    .line 236
    .line 237
    move v0, v10

    .line 238
    goto :goto_6

    .line 239
    :cond_9
    const/4 v0, 0x0

    .line 240
    :goto_6
    invoke-direct {v12, v13, v14, v0}, Lh4/e;-><init>(IIZ)V

    .line 241
    .line 242
    .line 243
    aput-object v12, v3, v15

    .line 244
    .line 245
    add-int/lit8 v15, v15, 0x1

    .line 246
    .line 247
    move/from16 v0, p2

    .line 248
    .line 249
    goto :goto_5

    .line 250
    :cond_a
    :goto_7
    new-instance v2, Lh4/e;

    .line 251
    .line 252
    invoke-virtual {v0, v1}, Landroid/text/Layout;->isRtlCharAt(I)Z

    .line 253
    .line 254
    .line 255
    move-result v0

    .line 256
    invoke-direct {v2, v1, v3, v0}, Lh4/e;-><init>(IIZ)V

    .line 257
    .line 258
    .line 259
    filled-new-array {v2}, [Lh4/e;

    .line 260
    .line 261
    .line 262
    move-result-object v3

    .line 263
    :cond_b
    if-eqz p7, :cond_c

    .line 264
    .line 265
    new-instance v0, Lgy0/j;

    .line 266
    .line 267
    array-length v1, v3

    .line 268
    sub-int/2addr v1, v10

    .line 269
    const/4 v15, 0x0

    .line 270
    invoke-direct {v0, v15, v1, v10}, Lgy0/h;-><init>(III)V

    .line 271
    .line 272
    .line 273
    goto :goto_8

    .line 274
    :cond_c
    const/4 v15, 0x0

    .line 275
    array-length v0, v3

    .line 276
    sub-int/2addr v0, v10

    .line 277
    invoke-static {v0, v15}, Lkp/r9;->k(II)Lgy0/h;

    .line 278
    .line 279
    .line 280
    move-result-object v0

    .line 281
    :goto_8
    iget v1, v0, Lgy0/h;->d:I

    .line 282
    .line 283
    iget v2, v0, Lgy0/h;->e:I

    .line 284
    .line 285
    iget v0, v0, Lgy0/h;->f:I

    .line 286
    .line 287
    if-lez v0, :cond_d

    .line 288
    .line 289
    if-le v1, v2, :cond_e

    .line 290
    .line 291
    :cond_d
    if-gez v0, :cond_0

    .line 292
    .line 293
    if-gt v2, v1, :cond_0

    .line 294
    .line 295
    :cond_e
    :goto_9
    aget-object v12, v3, v1

    .line 296
    .line 297
    iget-boolean v13, v12, Lh4/e;->c:Z

    .line 298
    .line 299
    iget v14, v12, Lh4/e;->a:I

    .line 300
    .line 301
    iget v12, v12, Lh4/e;->b:I

    .line 302
    .line 303
    if-eqz v13, :cond_f

    .line 304
    .line 305
    add-int/lit8 v15, v12, -0x1

    .line 306
    .line 307
    sub-int/2addr v15, v9

    .line 308
    mul-int/lit8 v15, v15, 0x2

    .line 309
    .line 310
    aget v15, v11, v15

    .line 311
    .line 312
    goto :goto_a

    .line 313
    :cond_f
    sub-int v15, v14, v9

    .line 314
    .line 315
    mul-int/lit8 v15, v15, 0x2

    .line 316
    .line 317
    aget v15, v11, v15

    .line 318
    .line 319
    :goto_a
    if-eqz v13, :cond_10

    .line 320
    .line 321
    invoke-static {v14, v9, v11}, Lh4/g;->c(II[F)F

    .line 322
    .line 323
    .line 324
    move-result v16

    .line 325
    goto :goto_b

    .line 326
    :cond_10
    add-int/lit8 v10, v12, -0x1

    .line 327
    .line 328
    invoke-static {v10, v9, v11}, Lh4/g;->c(II[F)F

    .line 329
    .line 330
    .line 331
    move-result v16

    .line 332
    :goto_b
    if-eqz p7, :cond_25

    .line 333
    .line 334
    iget v10, v4, Landroid/graphics/RectF;->left:F

    .line 335
    .line 336
    cmpl-float v17, v16, v10

    .line 337
    .line 338
    if-ltz v17, :cond_24

    .line 339
    .line 340
    move/from16 v17, v0

    .line 341
    .line 342
    iget v0, v4, Landroid/graphics/RectF;->right:F

    .line 343
    .line 344
    cmpg-float v18, v15, v0

    .line 345
    .line 346
    if-gtz v18, :cond_19

    .line 347
    .line 348
    if-nez v13, :cond_11

    .line 349
    .line 350
    cmpg-float v10, v10, v15

    .line 351
    .line 352
    if-lez v10, :cond_12

    .line 353
    .line 354
    :cond_11
    if-eqz v13, :cond_13

    .line 355
    .line 356
    cmpl-float v0, v0, v16

    .line 357
    .line 358
    if-ltz v0, :cond_13

    .line 359
    .line 360
    :cond_12
    move v0, v14

    .line 361
    goto :goto_d

    .line 362
    :cond_13
    move v0, v12

    .line 363
    move v10, v14

    .line 364
    :goto_c
    sub-int v15, v0, v10

    .line 365
    .line 366
    move/from16 p3, v0

    .line 367
    .line 368
    const/4 v0, 0x1

    .line 369
    if-le v15, v0, :cond_17

    .line 370
    .line 371
    add-int v0, p3, v10

    .line 372
    .line 373
    div-int/lit8 v0, v0, 0x2

    .line 374
    .line 375
    sub-int v15, v0, v9

    .line 376
    .line 377
    mul-int/lit8 v15, v15, 0x2

    .line 378
    .line 379
    aget v15, v11, v15

    .line 380
    .line 381
    move/from16 v16, v0

    .line 382
    .line 383
    if-nez v13, :cond_14

    .line 384
    .line 385
    iget v0, v4, Landroid/graphics/RectF;->left:F

    .line 386
    .line 387
    cmpl-float v0, v15, v0

    .line 388
    .line 389
    if-gtz v0, :cond_15

    .line 390
    .line 391
    :cond_14
    if-eqz v13, :cond_16

    .line 392
    .line 393
    iget v0, v4, Landroid/graphics/RectF;->right:F

    .line 394
    .line 395
    cmpg-float v0, v15, v0

    .line 396
    .line 397
    if-gez v0, :cond_16

    .line 398
    .line 399
    :cond_15
    move/from16 v0, v16

    .line 400
    .line 401
    goto :goto_c

    .line 402
    :cond_16
    move/from16 v0, p3

    .line 403
    .line 404
    move/from16 v10, v16

    .line 405
    .line 406
    goto :goto_c

    .line 407
    :cond_17
    if-eqz v13, :cond_18

    .line 408
    .line 409
    move/from16 v0, p3

    .line 410
    .line 411
    goto :goto_d

    .line 412
    :cond_18
    move v0, v10

    .line 413
    :goto_d
    invoke-interface {v5, v0}, Li4/b;->f(I)I

    .line 414
    .line 415
    .line 416
    move-result v0

    .line 417
    const/4 v10, -0x1

    .line 418
    if-ne v0, v10, :cond_1b

    .line 419
    .line 420
    :cond_19
    :goto_e
    move-object/from16 v18, v3

    .line 421
    .line 422
    :cond_1a
    :goto_f
    const/4 v14, -0x1

    .line 423
    goto/16 :goto_1d

    .line 424
    .line 425
    :cond_1b
    invoke-interface {v5, v0}, Li4/b;->e(I)I

    .line 426
    .line 427
    .line 428
    move-result v10

    .line 429
    if-lt v10, v12, :cond_1c

    .line 430
    .line 431
    goto :goto_e

    .line 432
    :cond_1c
    if-ge v10, v14, :cond_1d

    .line 433
    .line 434
    goto :goto_10

    .line 435
    :cond_1d
    move v14, v10

    .line 436
    :goto_10
    if-le v0, v12, :cond_1e

    .line 437
    .line 438
    move v0, v12

    .line 439
    :cond_1e
    new-instance v10, Landroid/graphics/RectF;

    .line 440
    .line 441
    int-to-float v15, v7

    .line 442
    move/from16 p3, v0

    .line 443
    .line 444
    int-to-float v0, v8

    .line 445
    move-object/from16 v18, v3

    .line 446
    .line 447
    const/4 v3, 0x0

    .line 448
    invoke-direct {v10, v3, v15, v3, v0}, Landroid/graphics/RectF;-><init>(FFFF)V

    .line 449
    .line 450
    .line 451
    move/from16 v0, p3

    .line 452
    .line 453
    :cond_1f
    :goto_11
    if-eqz v13, :cond_20

    .line 454
    .line 455
    add-int/lit8 v3, v0, -0x1

    .line 456
    .line 457
    sub-int/2addr v3, v9

    .line 458
    mul-int/lit8 v3, v3, 0x2

    .line 459
    .line 460
    aget v3, v11, v3

    .line 461
    .line 462
    goto :goto_12

    .line 463
    :cond_20
    sub-int v3, v14, v9

    .line 464
    .line 465
    mul-int/lit8 v3, v3, 0x2

    .line 466
    .line 467
    aget v3, v11, v3

    .line 468
    .line 469
    :goto_12
    iput v3, v10, Landroid/graphics/RectF;->left:F

    .line 470
    .line 471
    if-eqz v13, :cond_21

    .line 472
    .line 473
    invoke-static {v14, v9, v11}, Lh4/g;->c(II[F)F

    .line 474
    .line 475
    .line 476
    move-result v0

    .line 477
    goto :goto_13

    .line 478
    :cond_21
    add-int/lit8 v0, v0, -0x1

    .line 479
    .line 480
    invoke-static {v0, v9, v11}, Lh4/g;->c(II[F)F

    .line 481
    .line 482
    .line 483
    move-result v0

    .line 484
    :goto_13
    iput v0, v10, Landroid/graphics/RectF;->right:F

    .line 485
    .line 486
    invoke-virtual {v6, v10, v4}, La71/a0;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 487
    .line 488
    .line 489
    move-result-object v0

    .line 490
    check-cast v0, Ljava/lang/Boolean;

    .line 491
    .line 492
    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 493
    .line 494
    .line 495
    move-result v0

    .line 496
    if-eqz v0, :cond_22

    .line 497
    .line 498
    goto/16 :goto_1d

    .line 499
    .line 500
    :cond_22
    invoke-interface {v5, v14}, Li4/b;->d(I)I

    .line 501
    .line 502
    .line 503
    move-result v14

    .line 504
    const/4 v0, -0x1

    .line 505
    if-eq v14, v0, :cond_1a

    .line 506
    .line 507
    if-lt v14, v12, :cond_23

    .line 508
    .line 509
    goto :goto_f

    .line 510
    :cond_23
    invoke-interface {v5, v14}, Li4/b;->f(I)I

    .line 511
    .line 512
    .line 513
    move-result v0

    .line 514
    if-le v0, v12, :cond_1f

    .line 515
    .line 516
    move v0, v12

    .line 517
    goto :goto_11

    .line 518
    :cond_24
    move/from16 v17, v0

    .line 519
    .line 520
    goto :goto_e

    .line 521
    :cond_25
    move/from16 v17, v0

    .line 522
    .line 523
    move-object/from16 v18, v3

    .line 524
    .line 525
    iget v0, v4, Landroid/graphics/RectF;->left:F

    .line 526
    .line 527
    cmpl-float v3, v16, v0

    .line 528
    .line 529
    if-ltz v3, :cond_2e

    .line 530
    .line 531
    iget v3, v4, Landroid/graphics/RectF;->right:F

    .line 532
    .line 533
    cmpg-float v10, v15, v3

    .line 534
    .line 535
    if-gtz v10, :cond_2e

    .line 536
    .line 537
    if-nez v13, :cond_26

    .line 538
    .line 539
    cmpl-float v3, v3, v16

    .line 540
    .line 541
    if-gez v3, :cond_27

    .line 542
    .line 543
    :cond_26
    if-eqz v13, :cond_28

    .line 544
    .line 545
    cmpg-float v0, v0, v15

    .line 546
    .line 547
    if-gtz v0, :cond_28

    .line 548
    .line 549
    :cond_27
    add-int/lit8 v0, v12, -0x1

    .line 550
    .line 551
    :goto_14
    const/4 v15, 0x1

    .line 552
    goto :goto_16

    .line 553
    :cond_28
    move v0, v12

    .line 554
    move v3, v14

    .line 555
    :goto_15
    sub-int v10, v0, v3

    .line 556
    .line 557
    const/4 v15, 0x1

    .line 558
    if-le v10, v15, :cond_2c

    .line 559
    .line 560
    add-int v10, v0, v3

    .line 561
    .line 562
    div-int/lit8 v10, v10, 0x2

    .line 563
    .line 564
    sub-int v15, v10, v9

    .line 565
    .line 566
    mul-int/lit8 v15, v15, 0x2

    .line 567
    .line 568
    aget v15, v11, v15

    .line 569
    .line 570
    move/from16 p3, v0

    .line 571
    .line 572
    if-nez v13, :cond_29

    .line 573
    .line 574
    iget v0, v4, Landroid/graphics/RectF;->right:F

    .line 575
    .line 576
    cmpl-float v0, v15, v0

    .line 577
    .line 578
    if-gtz v0, :cond_2a

    .line 579
    .line 580
    :cond_29
    if-eqz v13, :cond_2b

    .line 581
    .line 582
    iget v0, v4, Landroid/graphics/RectF;->left:F

    .line 583
    .line 584
    cmpg-float v0, v15, v0

    .line 585
    .line 586
    if-gez v0, :cond_2b

    .line 587
    .line 588
    :cond_2a
    move v0, v10

    .line 589
    goto :goto_15

    .line 590
    :cond_2b
    move/from16 v0, p3

    .line 591
    .line 592
    move v3, v10

    .line 593
    goto :goto_15

    .line 594
    :cond_2c
    move/from16 p3, v0

    .line 595
    .line 596
    if-eqz v13, :cond_2d

    .line 597
    .line 598
    move/from16 v0, p3

    .line 599
    .line 600
    goto :goto_14

    .line 601
    :cond_2d
    move v0, v3

    .line 602
    goto :goto_14

    .line 603
    :goto_16
    add-int/2addr v0, v15

    .line 604
    invoke-interface {v5, v0}, Li4/b;->e(I)I

    .line 605
    .line 606
    .line 607
    move-result v0

    .line 608
    const/4 v10, -0x1

    .line 609
    if-ne v0, v10, :cond_2f

    .line 610
    .line 611
    :cond_2e
    :goto_17
    const/4 v10, -0x1

    .line 612
    goto :goto_1c

    .line 613
    :cond_2f
    invoke-interface {v5, v0}, Li4/b;->f(I)I

    .line 614
    .line 615
    .line 616
    move-result v3

    .line 617
    if-gt v3, v14, :cond_30

    .line 618
    .line 619
    goto :goto_17

    .line 620
    :cond_30
    if-ge v0, v14, :cond_31

    .line 621
    .line 622
    move v0, v14

    .line 623
    :cond_31
    if-le v3, v12, :cond_32

    .line 624
    .line 625
    goto :goto_18

    .line 626
    :cond_32
    move v12, v3

    .line 627
    :goto_18
    new-instance v3, Landroid/graphics/RectF;

    .line 628
    .line 629
    int-to-float v10, v7

    .line 630
    int-to-float v15, v8

    .line 631
    move/from16 p3, v0

    .line 632
    .line 633
    const/4 v0, 0x0

    .line 634
    invoke-direct {v3, v0, v10, v0, v15}, Landroid/graphics/RectF;-><init>(FFFF)V

    .line 635
    .line 636
    .line 637
    move/from16 v0, p3

    .line 638
    .line 639
    :cond_33
    :goto_19
    if-eqz v13, :cond_34

    .line 640
    .line 641
    add-int/lit8 v10, v12, -0x1

    .line 642
    .line 643
    sub-int/2addr v10, v9

    .line 644
    mul-int/lit8 v10, v10, 0x2

    .line 645
    .line 646
    aget v10, v11, v10

    .line 647
    .line 648
    goto :goto_1a

    .line 649
    :cond_34
    sub-int v10, v0, v9

    .line 650
    .line 651
    mul-int/lit8 v10, v10, 0x2

    .line 652
    .line 653
    aget v10, v11, v10

    .line 654
    .line 655
    :goto_1a
    iput v10, v3, Landroid/graphics/RectF;->left:F

    .line 656
    .line 657
    if-eqz v13, :cond_35

    .line 658
    .line 659
    invoke-static {v0, v9, v11}, Lh4/g;->c(II[F)F

    .line 660
    .line 661
    .line 662
    move-result v0

    .line 663
    goto :goto_1b

    .line 664
    :cond_35
    add-int/lit8 v0, v12, -0x1

    .line 665
    .line 666
    invoke-static {v0, v9, v11}, Lh4/g;->c(II[F)F

    .line 667
    .line 668
    .line 669
    move-result v0

    .line 670
    :goto_1b
    iput v0, v3, Landroid/graphics/RectF;->right:F

    .line 671
    .line 672
    invoke-virtual {v6, v3, v4}, La71/a0;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 673
    .line 674
    .line 675
    move-result-object v0

    .line 676
    check-cast v0, Ljava/lang/Boolean;

    .line 677
    .line 678
    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 679
    .line 680
    .line 681
    move-result v0

    .line 682
    if-eqz v0, :cond_36

    .line 683
    .line 684
    move v10, v12

    .line 685
    goto :goto_1c

    .line 686
    :cond_36
    invoke-interface {v5, v12}, Li4/b;->i(I)I

    .line 687
    .line 688
    .line 689
    move-result v12

    .line 690
    const/4 v10, -0x1

    .line 691
    if-eq v12, v10, :cond_2e

    .line 692
    .line 693
    if-gt v12, v14, :cond_37

    .line 694
    .line 695
    goto :goto_17

    .line 696
    :cond_37
    invoke-interface {v5, v12}, Li4/b;->e(I)I

    .line 697
    .line 698
    .line 699
    move-result v0

    .line 700
    if-ge v0, v14, :cond_33

    .line 701
    .line 702
    move v0, v14

    .line 703
    goto :goto_19

    .line 704
    :goto_1c
    move v14, v10

    .line 705
    :goto_1d
    if-ltz v14, :cond_38

    .line 706
    .line 707
    return v14

    .line 708
    :cond_38
    if-eq v1, v2, :cond_0

    .line 709
    .line 710
    add-int v1, v1, v17

    .line 711
    .line 712
    move/from16 v0, v17

    .line 713
    .line 714
    move-object/from16 v3, v18

    .line 715
    .line 716
    const/4 v10, 0x1

    .line 717
    goto/16 :goto_9

    .line 718
    .line 719
    :goto_1e
    return v10
.end method

.method public static final f(Landroid/text/Spanned;Ljava/lang/Class;)Z
    .locals 2

    .line 1
    const/4 v0, -0x1

    .line 2
    invoke-interface {p0}, Ljava/lang/CharSequence;->length()I

    .line 3
    .line 4
    .line 5
    move-result v1

    .line 6
    invoke-interface {p0, v0, v1, p1}, Landroid/text/Spanned;->nextSpanTransition(IILjava/lang/Class;)I

    .line 7
    .line 8
    .line 9
    move-result p1

    .line 10
    invoke-interface {p0}, Ljava/lang/CharSequence;->length()I

    .line 11
    .line 12
    .line 13
    move-result p0

    .line 14
    if-eq p1, p0, :cond_0

    .line 15
    .line 16
    const/4 p0, 0x1

    .line 17
    return p0

    .line 18
    :cond_0
    const/4 p0, 0x0

    .line 19
    return p0
.end method
