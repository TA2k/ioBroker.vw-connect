.class public final Lj4/h;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Landroid/text/style/LineHeightSpan;


# instance fields
.field public final d:F

.field public final e:I

.field public final f:Z

.field public final g:Z

.field public final h:F

.field public final i:Z

.field public j:I

.field public k:I

.field public l:I

.field public m:I

.field public n:I

.field public o:I


# direct methods
.method public constructor <init>(FIZZFZ)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput p1, p0, Lj4/h;->d:F

    .line 5
    .line 6
    iput p2, p0, Lj4/h;->e:I

    .line 7
    .line 8
    iput-boolean p3, p0, Lj4/h;->f:Z

    .line 9
    .line 10
    iput-boolean p4, p0, Lj4/h;->g:Z

    .line 11
    .line 12
    iput p5, p0, Lj4/h;->h:F

    .line 13
    .line 14
    iput-boolean p6, p0, Lj4/h;->i:Z

    .line 15
    .line 16
    const/high16 p1, -0x80000000

    .line 17
    .line 18
    iput p1, p0, Lj4/h;->j:I

    .line 19
    .line 20
    iput p1, p0, Lj4/h;->k:I

    .line 21
    .line 22
    iput p1, p0, Lj4/h;->l:I

    .line 23
    .line 24
    iput p1, p0, Lj4/h;->m:I

    .line 25
    .line 26
    const/4 p0, 0x0

    .line 27
    cmpg-float p0, p0, p5

    .line 28
    .line 29
    if-gtz p0, :cond_0

    .line 30
    .line 31
    const/high16 p0, 0x3f800000    # 1.0f

    .line 32
    .line 33
    cmpg-float p0, p5, p0

    .line 34
    .line 35
    if-gtz p0, :cond_0

    .line 36
    .line 37
    goto :goto_0

    .line 38
    :cond_0
    const/high16 p0, -0x40800000    # -1.0f

    .line 39
    .line 40
    cmpg-float p0, p5, p0

    .line 41
    .line 42
    if-nez p0, :cond_1

    .line 43
    .line 44
    :goto_0
    return-void

    .line 45
    :cond_1
    const-string p0, "topRatio should be in [0..1] range or -1"

    .line 46
    .line 47
    invoke-static {p0}, Lm4/a;->c(Ljava/lang/String;)V

    .line 48
    .line 49
    .line 50
    return-void
.end method


# virtual methods
.method public final chooseHeight(Ljava/lang/CharSequence;IIIILandroid/graphics/Paint$FontMetricsInt;)V
    .locals 4

    .line 1
    iget p1, p6, Landroid/graphics/Paint$FontMetricsInt;->descent:I

    .line 2
    .line 3
    iget p4, p6, Landroid/graphics/Paint$FontMetricsInt;->ascent:I

    .line 4
    .line 5
    sub-int p5, p1, p4

    .line 6
    .line 7
    if-gtz p5, :cond_0

    .line 8
    .line 9
    goto :goto_2

    .line 10
    :cond_0
    const/4 p5, 0x1

    .line 11
    const/4 v0, 0x0

    .line 12
    if-nez p2, :cond_1

    .line 13
    .line 14
    move p2, p5

    .line 15
    goto :goto_0

    .line 16
    :cond_1
    move p2, v0

    .line 17
    :goto_0
    iget v1, p0, Lj4/h;->e:I

    .line 18
    .line 19
    if-ne p3, v1, :cond_2

    .line 20
    .line 21
    goto :goto_1

    .line 22
    :cond_2
    move p5, v0

    .line 23
    :goto_1
    iget-boolean p3, p0, Lj4/h;->g:Z

    .line 24
    .line 25
    iget-boolean v1, p0, Lj4/h;->f:Z

    .line 26
    .line 27
    if-eqz p2, :cond_3

    .line 28
    .line 29
    if-eqz p5, :cond_3

    .line 30
    .line 31
    if-eqz v1, :cond_3

    .line 32
    .line 33
    if-eqz p3, :cond_3

    .line 34
    .line 35
    :goto_2
    return-void

    .line 36
    :cond_3
    iget v2, p0, Lj4/h;->j:I

    .line 37
    .line 38
    const/high16 v3, -0x80000000

    .line 39
    .line 40
    if-ne v2, v3, :cond_9

    .line 41
    .line 42
    sub-int/2addr p1, p4

    .line 43
    iget p4, p0, Lj4/h;->d:F

    .line 44
    .line 45
    float-to-double v2, p4

    .line 46
    invoke-static {v2, v3}, Ljava/lang/Math;->ceil(D)D

    .line 47
    .line 48
    .line 49
    move-result-wide v2

    .line 50
    double-to-float p4, v2

    .line 51
    float-to-int p4, p4

    .line 52
    sub-int p1, p4, p1

    .line 53
    .line 54
    iget-boolean v2, p0, Lj4/h;->i:Z

    .line 55
    .line 56
    if-eqz v2, :cond_4

    .line 57
    .line 58
    if-gtz p1, :cond_4

    .line 59
    .line 60
    iget p1, p6, Landroid/graphics/Paint$FontMetricsInt;->ascent:I

    .line 61
    .line 62
    iput p1, p0, Lj4/h;->k:I

    .line 63
    .line 64
    iget p3, p6, Landroid/graphics/Paint$FontMetricsInt;->descent:I

    .line 65
    .line 66
    iput p3, p0, Lj4/h;->l:I

    .line 67
    .line 68
    iput p1, p0, Lj4/h;->j:I

    .line 69
    .line 70
    iput p3, p0, Lj4/h;->m:I

    .line 71
    .line 72
    iput v0, p0, Lj4/h;->n:I

    .line 73
    .line 74
    iput v0, p0, Lj4/h;->o:I

    .line 75
    .line 76
    goto :goto_5

    .line 77
    :cond_4
    const/high16 v0, -0x40800000    # -1.0f

    .line 78
    .line 79
    iget v2, p0, Lj4/h;->h:F

    .line 80
    .line 81
    cmpg-float v0, v2, v0

    .line 82
    .line 83
    if-nez v0, :cond_5

    .line 84
    .line 85
    iget v0, p6, Landroid/graphics/Paint$FontMetricsInt;->ascent:I

    .line 86
    .line 87
    int-to-float v0, v0

    .line 88
    invoke-static {v0}, Ljava/lang/Math;->abs(F)F

    .line 89
    .line 90
    .line 91
    move-result v0

    .line 92
    iget v2, p6, Landroid/graphics/Paint$FontMetricsInt;->descent:I

    .line 93
    .line 94
    iget v3, p6, Landroid/graphics/Paint$FontMetricsInt;->ascent:I

    .line 95
    .line 96
    sub-int/2addr v2, v3

    .line 97
    int-to-float v2, v2

    .line 98
    div-float v2, v0, v2

    .line 99
    .line 100
    :cond_5
    if-gtz p1, :cond_6

    .line 101
    .line 102
    int-to-float p1, p1

    .line 103
    mul-float/2addr p1, v2

    .line 104
    float-to-double v2, p1

    .line 105
    invoke-static {v2, v3}, Ljava/lang/Math;->ceil(D)D

    .line 106
    .line 107
    .line 108
    move-result-wide v2

    .line 109
    :goto_3
    double-to-float p1, v2

    .line 110
    float-to-int p1, p1

    .line 111
    goto :goto_4

    .line 112
    :cond_6
    int-to-float p1, p1

    .line 113
    const/high16 v0, 0x3f800000    # 1.0f

    .line 114
    .line 115
    sub-float/2addr v0, v2

    .line 116
    mul-float/2addr v0, p1

    .line 117
    float-to-double v2, v0

    .line 118
    invoke-static {v2, v3}, Ljava/lang/Math;->ceil(D)D

    .line 119
    .line 120
    .line 121
    move-result-wide v2

    .line 122
    goto :goto_3

    .line 123
    :goto_4
    iget v0, p6, Landroid/graphics/Paint$FontMetricsInt;->descent:I

    .line 124
    .line 125
    add-int/2addr p1, v0

    .line 126
    iput p1, p0, Lj4/h;->l:I

    .line 127
    .line 128
    sub-int p4, p1, p4

    .line 129
    .line 130
    iput p4, p0, Lj4/h;->k:I

    .line 131
    .line 132
    if-eqz v1, :cond_7

    .line 133
    .line 134
    iget p4, p6, Landroid/graphics/Paint$FontMetricsInt;->ascent:I

    .line 135
    .line 136
    :cond_7
    iput p4, p0, Lj4/h;->j:I

    .line 137
    .line 138
    if-eqz p3, :cond_8

    .line 139
    .line 140
    move p1, v0

    .line 141
    :cond_8
    iput p1, p0, Lj4/h;->m:I

    .line 142
    .line 143
    iget p3, p6, Landroid/graphics/Paint$FontMetricsInt;->ascent:I

    .line 144
    .line 145
    sub-int/2addr p3, p4

    .line 146
    iput p3, p0, Lj4/h;->n:I

    .line 147
    .line 148
    sub-int/2addr p1, v0

    .line 149
    iput p1, p0, Lj4/h;->o:I

    .line 150
    .line 151
    :cond_9
    :goto_5
    if-eqz p2, :cond_a

    .line 152
    .line 153
    iget p1, p0, Lj4/h;->j:I

    .line 154
    .line 155
    goto :goto_6

    .line 156
    :cond_a
    iget p1, p0, Lj4/h;->k:I

    .line 157
    .line 158
    :goto_6
    iput p1, p6, Landroid/graphics/Paint$FontMetricsInt;->ascent:I

    .line 159
    .line 160
    if-eqz p5, :cond_b

    .line 161
    .line 162
    iget p0, p0, Lj4/h;->m:I

    .line 163
    .line 164
    goto :goto_7

    .line 165
    :cond_b
    iget p0, p0, Lj4/h;->l:I

    .line 166
    .line 167
    :goto_7
    iput p0, p6, Landroid/graphics/Paint$FontMetricsInt;->descent:I

    .line 168
    .line 169
    return-void
.end method
