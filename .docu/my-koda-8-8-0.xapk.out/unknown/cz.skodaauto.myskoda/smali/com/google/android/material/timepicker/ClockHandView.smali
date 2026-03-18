.class Lcom/google/android/material/timepicker/ClockHandView;
.super Landroid/view/View;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final synthetic y:I


# instance fields
.field public final d:I

.field public final e:Landroid/animation/TimeInterpolator;

.field public final f:Landroid/animation/ValueAnimator;

.field public g:Z

.field public h:F

.field public i:F

.field public j:Z

.field public final k:I

.field public l:Z

.field public final m:Ljava/util/ArrayList;

.field public final n:I

.field public final o:F

.field public final p:Landroid/graphics/Paint;

.field public final q:Landroid/graphics/RectF;

.field public final r:I

.field public s:F

.field public t:Z

.field public u:Lcom/google/android/material/timepicker/n;

.field public v:D

.field public w:I

.field public x:I


# direct methods
.method public constructor <init>(Landroid/content/Context;Landroid/util/AttributeSet;)V
    .locals 7

    .line 1
    const v0, 0x7f04038b

    .line 2
    .line 3
    .line 4
    invoke-direct {p0, p1, p2, v0}, Landroid/view/View;-><init>(Landroid/content/Context;Landroid/util/AttributeSet;I)V

    .line 5
    .line 6
    .line 7
    new-instance v1, Landroid/animation/ValueAnimator;

    .line 8
    .line 9
    invoke-direct {v1}, Landroid/animation/ValueAnimator;-><init>()V

    .line 10
    .line 11
    .line 12
    iput-object v1, p0, Lcom/google/android/material/timepicker/ClockHandView;->f:Landroid/animation/ValueAnimator;

    .line 13
    .line 14
    new-instance v2, Ljava/util/ArrayList;

    .line 15
    .line 16
    invoke-direct {v2}, Ljava/util/ArrayList;-><init>()V

    .line 17
    .line 18
    .line 19
    iput-object v2, p0, Lcom/google/android/material/timepicker/ClockHandView;->m:Ljava/util/ArrayList;

    .line 20
    .line 21
    new-instance v2, Landroid/graphics/Paint;

    .line 22
    .line 23
    invoke-direct {v2}, Landroid/graphics/Paint;-><init>()V

    .line 24
    .line 25
    .line 26
    iput-object v2, p0, Lcom/google/android/material/timepicker/ClockHandView;->p:Landroid/graphics/Paint;

    .line 27
    .line 28
    new-instance v3, Landroid/graphics/RectF;

    .line 29
    .line 30
    invoke-direct {v3}, Landroid/graphics/RectF;-><init>()V

    .line 31
    .line 32
    .line 33
    iput-object v3, p0, Lcom/google/android/material/timepicker/ClockHandView;->q:Landroid/graphics/RectF;

    .line 34
    .line 35
    const/4 v3, 0x1

    .line 36
    iput v3, p0, Lcom/google/android/material/timepicker/ClockHandView;->x:I

    .line 37
    .line 38
    sget-object v4, Ldq/a;->e:[I

    .line 39
    .line 40
    const v5, 0x7f130563

    .line 41
    .line 42
    .line 43
    invoke-virtual {p1, p2, v4, v0, v5}, Landroid/content/Context;->obtainStyledAttributes(Landroid/util/AttributeSet;[III)Landroid/content/res/TypedArray;

    .line 44
    .line 45
    .line 46
    move-result-object p2

    .line 47
    const v0, 0x7f0403e1

    .line 48
    .line 49
    .line 50
    const/16 v4, 0xc8

    .line 51
    .line 52
    invoke-static {p1, v0, v4}, Lkp/o8;->d(Landroid/content/Context;II)I

    .line 53
    .line 54
    .line 55
    move-result v0

    .line 56
    iput v0, p0, Lcom/google/android/material/timepicker/ClockHandView;->d:I

    .line 57
    .line 58
    const v0, 0x7f0403f1

    .line 59
    .line 60
    .line 61
    sget-object v4, Leq/a;->b:Ll7/a;

    .line 62
    .line 63
    invoke-static {p1, v0, v4}, Lkp/o8;->e(Landroid/content/Context;ILandroid/animation/TimeInterpolator;)Landroid/animation/TimeInterpolator;

    .line 64
    .line 65
    .line 66
    move-result-object v0

    .line 67
    iput-object v0, p0, Lcom/google/android/material/timepicker/ClockHandView;->e:Landroid/animation/TimeInterpolator;

    .line 68
    .line 69
    const/4 v0, 0x0

    .line 70
    invoke-virtual {p2, v3, v0}, Landroid/content/res/TypedArray;->getDimensionPixelSize(II)I

    .line 71
    .line 72
    .line 73
    move-result v4

    .line 74
    iput v4, p0, Lcom/google/android/material/timepicker/ClockHandView;->w:I

    .line 75
    .line 76
    const/4 v4, 0x2

    .line 77
    invoke-virtual {p2, v4, v0}, Landroid/content/res/TypedArray;->getDimensionPixelSize(II)I

    .line 78
    .line 79
    .line 80
    move-result v5

    .line 81
    iput v5, p0, Lcom/google/android/material/timepicker/ClockHandView;->n:I

    .line 82
    .line 83
    invoke-virtual {p0}, Landroid/view/View;->getResources()Landroid/content/res/Resources;

    .line 84
    .line 85
    .line 86
    move-result-object v5

    .line 87
    const v6, 0x7f070336

    .line 88
    .line 89
    .line 90
    invoke-virtual {v5, v6}, Landroid/content/res/Resources;->getDimensionPixelSize(I)I

    .line 91
    .line 92
    .line 93
    move-result v6

    .line 94
    iput v6, p0, Lcom/google/android/material/timepicker/ClockHandView;->r:I

    .line 95
    .line 96
    const v6, 0x7f070334

    .line 97
    .line 98
    .line 99
    invoke-virtual {v5, v6}, Landroid/content/res/Resources;->getDimensionPixelSize(I)I

    .line 100
    .line 101
    .line 102
    move-result v5

    .line 103
    int-to-float v5, v5

    .line 104
    iput v5, p0, Lcom/google/android/material/timepicker/ClockHandView;->o:F

    .line 105
    .line 106
    invoke-virtual {p2, v0, v0}, Landroid/content/res/TypedArray;->getColor(II)I

    .line 107
    .line 108
    .line 109
    move-result v5

    .line 110
    invoke-virtual {v2, v3}, Landroid/graphics/Paint;->setAntiAlias(Z)V

    .line 111
    .line 112
    .line 113
    invoke-virtual {v2, v5}, Landroid/graphics/Paint;->setColor(I)V

    .line 114
    .line 115
    .line 116
    const/4 v2, 0x0

    .line 117
    invoke-virtual {p0, v2, v0}, Lcom/google/android/material/timepicker/ClockHandView;->c(FZ)V

    .line 118
    .line 119
    .line 120
    invoke-static {p1}, Landroid/view/ViewConfiguration;->get(Landroid/content/Context;)Landroid/view/ViewConfiguration;

    .line 121
    .line 122
    .line 123
    move-result-object p1

    .line 124
    invoke-virtual {p1}, Landroid/view/ViewConfiguration;->getScaledTouchSlop()I

    .line 125
    .line 126
    .line 127
    move-result p1

    .line 128
    iput p1, p0, Lcom/google/android/material/timepicker/ClockHandView;->k:I

    .line 129
    .line 130
    invoke-virtual {p0, v4}, Landroid/view/View;->setImportantForAccessibility(I)V

    .line 131
    .line 132
    .line 133
    invoke-virtual {p2}, Landroid/content/res/TypedArray;->recycle()V

    .line 134
    .line 135
    .line 136
    new-instance p1, Lcom/google/android/material/timepicker/d;

    .line 137
    .line 138
    invoke-direct {p1, p0}, Lcom/google/android/material/timepicker/d;-><init>(Lcom/google/android/material/timepicker/ClockHandView;)V

    .line 139
    .line 140
    .line 141
    invoke-virtual {v1, p1}, Landroid/animation/ValueAnimator;->addUpdateListener(Landroid/animation/ValueAnimator$AnimatorUpdateListener;)V

    .line 142
    .line 143
    .line 144
    new-instance p0, Lcom/google/android/material/timepicker/e;

    .line 145
    .line 146
    invoke-direct {p0}, Landroid/animation/AnimatorListenerAdapter;-><init>()V

    .line 147
    .line 148
    .line 149
    invoke-virtual {v1, p0}, Landroid/animation/Animator;->addListener(Landroid/animation/Animator$AnimatorListener;)V

    .line 150
    .line 151
    .line 152
    return-void
.end method


# virtual methods
.method public final a(FF)I
    .locals 2

    .line 1
    invoke-virtual {p0}, Landroid/view/View;->getWidth()I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    div-int/lit8 v0, v0, 0x2

    .line 6
    .line 7
    invoke-virtual {p0}, Landroid/view/View;->getHeight()I

    .line 8
    .line 9
    .line 10
    move-result p0

    .line 11
    div-int/lit8 p0, p0, 0x2

    .line 12
    .line 13
    int-to-float v0, v0

    .line 14
    sub-float/2addr p1, v0

    .line 15
    float-to-double v0, p1

    .line 16
    int-to-float p0, p0

    .line 17
    sub-float/2addr p2, p0

    .line 18
    float-to-double p0, p2

    .line 19
    invoke-static {p0, p1, v0, v1}, Ljava/lang/Math;->atan2(DD)D

    .line 20
    .line 21
    .line 22
    move-result-wide p0

    .line 23
    invoke-static {p0, p1}, Ljava/lang/Math;->toDegrees(D)D

    .line 24
    .line 25
    .line 26
    move-result-wide p0

    .line 27
    double-to-int p0, p0

    .line 28
    add-int/lit8 p1, p0, 0x5a

    .line 29
    .line 30
    if-gez p1, :cond_0

    .line 31
    .line 32
    add-int/lit16 p0, p0, 0x1c2

    .line 33
    .line 34
    return p0

    .line 35
    :cond_0
    return p1
.end method

.method public final b(I)I
    .locals 1

    .line 1
    const/4 v0, 0x2

    .line 2
    iget p0, p0, Lcom/google/android/material/timepicker/ClockHandView;->w:I

    .line 3
    .line 4
    if-ne p1, v0, :cond_0

    .line 5
    .line 6
    int-to-float p0, p0

    .line 7
    const p1, 0x3f28f5c3    # 0.66f

    .line 8
    .line 9
    .line 10
    mul-float/2addr p0, p1

    .line 11
    invoke-static {p0}, Ljava/lang/Math;->round(F)I

    .line 12
    .line 13
    .line 14
    move-result p0

    .line 15
    :cond_0
    return p0
.end method

.method public final c(FZ)V
    .locals 5

    .line 1
    iget-object v0, p0, Lcom/google/android/material/timepicker/ClockHandView;->f:Landroid/animation/ValueAnimator;

    .line 2
    .line 3
    invoke-virtual {v0}, Landroid/animation/ValueAnimator;->cancel()V

    .line 4
    .line 5
    .line 6
    const/4 v1, 0x0

    .line 7
    if-nez p2, :cond_0

    .line 8
    .line 9
    invoke-virtual {p0, p1, v1}, Lcom/google/android/material/timepicker/ClockHandView;->d(FZ)V

    .line 10
    .line 11
    .line 12
    return-void

    .line 13
    :cond_0
    iget p2, p0, Lcom/google/android/material/timepicker/ClockHandView;->s:F

    .line 14
    .line 15
    sub-float v2, p2, p1

    .line 16
    .line 17
    invoke-static {v2}, Ljava/lang/Math;->abs(F)F

    .line 18
    .line 19
    .line 20
    move-result v2

    .line 21
    const/high16 v3, 0x43340000    # 180.0f

    .line 22
    .line 23
    cmpl-float v2, v2, v3

    .line 24
    .line 25
    if-lez v2, :cond_2

    .line 26
    .line 27
    cmpl-float v2, p2, v3

    .line 28
    .line 29
    const/high16 v4, 0x43b40000    # 360.0f

    .line 30
    .line 31
    if-lez v2, :cond_1

    .line 32
    .line 33
    cmpg-float v2, p1, v3

    .line 34
    .line 35
    if-gez v2, :cond_1

    .line 36
    .line 37
    add-float/2addr p1, v4

    .line 38
    :cond_1
    cmpg-float v2, p2, v3

    .line 39
    .line 40
    if-gez v2, :cond_2

    .line 41
    .line 42
    cmpl-float v2, p1, v3

    .line 43
    .line 44
    if-lez v2, :cond_2

    .line 45
    .line 46
    add-float/2addr p2, v4

    .line 47
    :cond_2
    new-instance v2, Landroid/util/Pair;

    .line 48
    .line 49
    invoke-static {p2}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 50
    .line 51
    .line 52
    move-result-object p2

    .line 53
    invoke-static {p1}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 54
    .line 55
    .line 56
    move-result-object p1

    .line 57
    invoke-direct {v2, p2, p1}, Landroid/util/Pair;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 58
    .line 59
    .line 60
    iget-object p1, v2, Landroid/util/Pair;->first:Ljava/lang/Object;

    .line 61
    .line 62
    check-cast p1, Ljava/lang/Float;

    .line 63
    .line 64
    invoke-virtual {p1}, Ljava/lang/Float;->floatValue()F

    .line 65
    .line 66
    .line 67
    move-result p1

    .line 68
    iget-object p2, v2, Landroid/util/Pair;->second:Ljava/lang/Object;

    .line 69
    .line 70
    check-cast p2, Ljava/lang/Float;

    .line 71
    .line 72
    invoke-virtual {p2}, Ljava/lang/Float;->floatValue()F

    .line 73
    .line 74
    .line 75
    move-result p2

    .line 76
    const/4 v2, 0x2

    .line 77
    new-array v2, v2, [F

    .line 78
    .line 79
    aput p1, v2, v1

    .line 80
    .line 81
    const/4 p1, 0x1

    .line 82
    aput p2, v2, p1

    .line 83
    .line 84
    invoke-virtual {v0, v2}, Landroid/animation/ValueAnimator;->setFloatValues([F)V

    .line 85
    .line 86
    .line 87
    iget p1, p0, Lcom/google/android/material/timepicker/ClockHandView;->d:I

    .line 88
    .line 89
    int-to-long p1, p1

    .line 90
    invoke-virtual {v0, p1, p2}, Landroid/animation/ValueAnimator;->setDuration(J)Landroid/animation/ValueAnimator;

    .line 91
    .line 92
    .line 93
    iget-object p0, p0, Lcom/google/android/material/timepicker/ClockHandView;->e:Landroid/animation/TimeInterpolator;

    .line 94
    .line 95
    invoke-virtual {v0, p0}, Landroid/animation/ValueAnimator;->setInterpolator(Landroid/animation/TimeInterpolator;)V

    .line 96
    .line 97
    .line 98
    invoke-virtual {v0}, Landroid/animation/ValueAnimator;->start()V

    .line 99
    .line 100
    .line 101
    return-void
.end method

.method public final d(FZ)V
    .locals 6

    .line 1
    const/high16 v0, 0x43b40000    # 360.0f

    .line 2
    .line 3
    rem-float/2addr p1, v0

    .line 4
    iput p1, p0, Lcom/google/android/material/timepicker/ClockHandView;->s:F

    .line 5
    .line 6
    const/high16 v0, 0x42b40000    # 90.0f

    .line 7
    .line 8
    sub-float v0, p1, v0

    .line 9
    .line 10
    float-to-double v0, v0

    .line 11
    invoke-static {v0, v1}, Ljava/lang/Math;->toRadians(D)D

    .line 12
    .line 13
    .line 14
    move-result-wide v0

    .line 15
    iput-wide v0, p0, Lcom/google/android/material/timepicker/ClockHandView;->v:D

    .line 16
    .line 17
    invoke-virtual {p0}, Landroid/view/View;->getHeight()I

    .line 18
    .line 19
    .line 20
    move-result v0

    .line 21
    div-int/lit8 v0, v0, 0x2

    .line 22
    .line 23
    invoke-virtual {p0}, Landroid/view/View;->getWidth()I

    .line 24
    .line 25
    .line 26
    move-result v1

    .line 27
    div-int/lit8 v1, v1, 0x2

    .line 28
    .line 29
    iget v2, p0, Lcom/google/android/material/timepicker/ClockHandView;->x:I

    .line 30
    .line 31
    invoke-virtual {p0, v2}, Lcom/google/android/material/timepicker/ClockHandView;->b(I)I

    .line 32
    .line 33
    .line 34
    move-result v2

    .line 35
    int-to-float v1, v1

    .line 36
    int-to-float v2, v2

    .line 37
    iget-wide v3, p0, Lcom/google/android/material/timepicker/ClockHandView;->v:D

    .line 38
    .line 39
    invoke-static {v3, v4}, Ljava/lang/Math;->cos(D)D

    .line 40
    .line 41
    .line 42
    move-result-wide v3

    .line 43
    double-to-float v3, v3

    .line 44
    mul-float/2addr v3, v2

    .line 45
    add-float/2addr v3, v1

    .line 46
    int-to-float v0, v0

    .line 47
    iget-wide v4, p0, Lcom/google/android/material/timepicker/ClockHandView;->v:D

    .line 48
    .line 49
    invoke-static {v4, v5}, Ljava/lang/Math;->sin(D)D

    .line 50
    .line 51
    .line 52
    move-result-wide v4

    .line 53
    double-to-float v1, v4

    .line 54
    mul-float/2addr v2, v1

    .line 55
    add-float/2addr v2, v0

    .line 56
    iget v0, p0, Lcom/google/android/material/timepicker/ClockHandView;->n:I

    .line 57
    .line 58
    int-to-float v0, v0

    .line 59
    sub-float v1, v3, v0

    .line 60
    .line 61
    sub-float v4, v2, v0

    .line 62
    .line 63
    add-float/2addr v3, v0

    .line 64
    add-float/2addr v2, v0

    .line 65
    iget-object v0, p0, Lcom/google/android/material/timepicker/ClockHandView;->q:Landroid/graphics/RectF;

    .line 66
    .line 67
    invoke-virtual {v0, v1, v4, v3, v2}, Landroid/graphics/RectF;->set(FFFF)V

    .line 68
    .line 69
    .line 70
    iget-object v0, p0, Lcom/google/android/material/timepicker/ClockHandView;->m:Ljava/util/ArrayList;

    .line 71
    .line 72
    invoke-virtual {v0}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 73
    .line 74
    .line 75
    move-result-object v0

    .line 76
    :goto_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 77
    .line 78
    .line 79
    move-result v1

    .line 80
    if-eqz v1, :cond_0

    .line 81
    .line 82
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 83
    .line 84
    .line 85
    move-result-object v1

    .line 86
    check-cast v1, Lcom/google/android/material/timepicker/f;

    .line 87
    .line 88
    invoke-interface {v1, p1, p2}, Lcom/google/android/material/timepicker/f;->a(FZ)V

    .line 89
    .line 90
    .line 91
    goto :goto_0

    .line 92
    :cond_0
    invoke-virtual {p0}, Landroid/view/View;->invalidate()V

    .line 93
    .line 94
    .line 95
    return-void
.end method

.method public final onDraw(Landroid/graphics/Canvas;)V
    .locals 13

    .line 1
    invoke-super {p0, p1}, Landroid/view/View;->onDraw(Landroid/graphics/Canvas;)V

    .line 2
    .line 3
    .line 4
    invoke-virtual {p0}, Landroid/view/View;->getHeight()I

    .line 5
    .line 6
    .line 7
    move-result v0

    .line 8
    div-int/lit8 v0, v0, 0x2

    .line 9
    .line 10
    invoke-virtual {p0}, Landroid/view/View;->getWidth()I

    .line 11
    .line 12
    .line 13
    move-result v1

    .line 14
    div-int/lit8 v1, v1, 0x2

    .line 15
    .line 16
    iget v2, p0, Lcom/google/android/material/timepicker/ClockHandView;->x:I

    .line 17
    .line 18
    invoke-virtual {p0, v2}, Lcom/google/android/material/timepicker/ClockHandView;->b(I)I

    .line 19
    .line 20
    .line 21
    move-result v2

    .line 22
    int-to-float v4, v1

    .line 23
    int-to-float v3, v2

    .line 24
    iget-wide v5, p0, Lcom/google/android/material/timepicker/ClockHandView;->v:D

    .line 25
    .line 26
    invoke-static {v5, v6}, Ljava/lang/Math;->cos(D)D

    .line 27
    .line 28
    .line 29
    move-result-wide v5

    .line 30
    double-to-float v5, v5

    .line 31
    mul-float/2addr v5, v3

    .line 32
    add-float/2addr v5, v4

    .line 33
    move v6, v5

    .line 34
    int-to-float v5, v0

    .line 35
    iget-wide v7, p0, Lcom/google/android/material/timepicker/ClockHandView;->v:D

    .line 36
    .line 37
    invoke-static {v7, v8}, Ljava/lang/Math;->sin(D)D

    .line 38
    .line 39
    .line 40
    move-result-wide v7

    .line 41
    double-to-float v7, v7

    .line 42
    mul-float/2addr v3, v7

    .line 43
    add-float/2addr v3, v5

    .line 44
    const/4 v7, 0x0

    .line 45
    iget-object v8, p0, Lcom/google/android/material/timepicker/ClockHandView;->p:Landroid/graphics/Paint;

    .line 46
    .line 47
    invoke-virtual {v8, v7}, Landroid/graphics/Paint;->setStrokeWidth(F)V

    .line 48
    .line 49
    .line 50
    iget v7, p0, Lcom/google/android/material/timepicker/ClockHandView;->n:I

    .line 51
    .line 52
    int-to-float v9, v7

    .line 53
    invoke-virtual {p1, v6, v3, v9, v8}, Landroid/graphics/Canvas;->drawCircle(FFFLandroid/graphics/Paint;)V

    .line 54
    .line 55
    .line 56
    iget-wide v9, p0, Lcom/google/android/material/timepicker/ClockHandView;->v:D

    .line 57
    .line 58
    invoke-static {v9, v10}, Ljava/lang/Math;->sin(D)D

    .line 59
    .line 60
    .line 61
    move-result-wide v9

    .line 62
    iget-wide v11, p0, Lcom/google/android/material/timepicker/ClockHandView;->v:D

    .line 63
    .line 64
    invoke-static {v11, v12}, Ljava/lang/Math;->cos(D)D

    .line 65
    .line 66
    .line 67
    move-result-wide v11

    .line 68
    sub-int/2addr v2, v7

    .line 69
    int-to-float v2, v2

    .line 70
    float-to-double v2, v2

    .line 71
    mul-double/2addr v11, v2

    .line 72
    double-to-int v6, v11

    .line 73
    add-int/2addr v1, v6

    .line 74
    int-to-float v6, v1

    .line 75
    mul-double/2addr v2, v9

    .line 76
    double-to-int v1, v2

    .line 77
    add-int/2addr v0, v1

    .line 78
    int-to-float v7, v0

    .line 79
    iget v0, p0, Lcom/google/android/material/timepicker/ClockHandView;->r:I

    .line 80
    .line 81
    int-to-float v0, v0

    .line 82
    invoke-virtual {v8, v0}, Landroid/graphics/Paint;->setStrokeWidth(F)V

    .line 83
    .line 84
    .line 85
    move-object v3, p1

    .line 86
    invoke-virtual/range {v3 .. v8}, Landroid/graphics/Canvas;->drawLine(FFFFLandroid/graphics/Paint;)V

    .line 87
    .line 88
    .line 89
    iget p0, p0, Lcom/google/android/material/timepicker/ClockHandView;->o:F

    .line 90
    .line 91
    invoke-virtual {v3, v4, v5, p0, v8}, Landroid/graphics/Canvas;->drawCircle(FFFLandroid/graphics/Paint;)V

    .line 92
    .line 93
    .line 94
    return-void
.end method

.method public final onLayout(ZIIII)V
    .locals 0

    .line 1
    invoke-super/range {p0 .. p5}, Landroid/view/View;->onLayout(ZIIII)V

    .line 2
    .line 3
    .line 4
    iget-object p1, p0, Lcom/google/android/material/timepicker/ClockHandView;->f:Landroid/animation/ValueAnimator;

    .line 5
    .line 6
    invoke-virtual {p1}, Landroid/animation/ValueAnimator;->isRunning()Z

    .line 7
    .line 8
    .line 9
    move-result p1

    .line 10
    if-nez p1, :cond_0

    .line 11
    .line 12
    iget p1, p0, Lcom/google/android/material/timepicker/ClockHandView;->s:F

    .line 13
    .line 14
    const/4 p2, 0x0

    .line 15
    invoke-virtual {p0, p1, p2}, Lcom/google/android/material/timepicker/ClockHandView;->c(FZ)V

    .line 16
    .line 17
    .line 18
    :cond_0
    return-void
.end method

.method public final onTouchEvent(Landroid/view/MotionEvent;)Z
    .locals 11

    .line 1
    invoke-virtual {p1}, Landroid/view/MotionEvent;->getActionMasked()I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    invoke-virtual {p1}, Landroid/view/MotionEvent;->getX()F

    .line 6
    .line 7
    .line 8
    move-result v1

    .line 9
    invoke-virtual {p1}, Landroid/view/MotionEvent;->getY()F

    .line 10
    .line 11
    .line 12
    move-result p1

    .line 13
    const/16 v2, 0xc

    .line 14
    .line 15
    const/4 v3, 0x1

    .line 16
    const/4 v4, 0x0

    .line 17
    if-eqz v0, :cond_5

    .line 18
    .line 19
    const/4 v5, 0x2

    .line 20
    if-eq v0, v3, :cond_0

    .line 21
    .line 22
    if-eq v0, v5, :cond_0

    .line 23
    .line 24
    move v0, v4

    .line 25
    move v5, v0

    .line 26
    move v6, v5

    .line 27
    goto/16 :goto_3

    .line 28
    .line 29
    :cond_0
    iget v6, p0, Lcom/google/android/material/timepicker/ClockHandView;->h:F

    .line 30
    .line 31
    sub-float v6, v1, v6

    .line 32
    .line 33
    float-to-int v6, v6

    .line 34
    iget v7, p0, Lcom/google/android/material/timepicker/ClockHandView;->i:F

    .line 35
    .line 36
    sub-float v7, p1, v7

    .line 37
    .line 38
    float-to-int v7, v7

    .line 39
    mul-int/2addr v6, v6

    .line 40
    mul-int/2addr v7, v7

    .line 41
    add-int/2addr v7, v6

    .line 42
    iget v6, p0, Lcom/google/android/material/timepicker/ClockHandView;->k:I

    .line 43
    .line 44
    if-le v7, v6, :cond_1

    .line 45
    .line 46
    move v6, v3

    .line 47
    goto :goto_0

    .line 48
    :cond_1
    move v6, v4

    .line 49
    :goto_0
    iput-boolean v6, p0, Lcom/google/android/material/timepicker/ClockHandView;->j:Z

    .line 50
    .line 51
    iget-boolean v6, p0, Lcom/google/android/material/timepicker/ClockHandView;->t:Z

    .line 52
    .line 53
    if-ne v0, v3, :cond_2

    .line 54
    .line 55
    move v0, v3

    .line 56
    goto :goto_1

    .line 57
    :cond_2
    move v0, v4

    .line 58
    :goto_1
    iget-boolean v7, p0, Lcom/google/android/material/timepicker/ClockHandView;->l:Z

    .line 59
    .line 60
    if-eqz v7, :cond_4

    .line 61
    .line 62
    invoke-virtual {p0}, Landroid/view/View;->getWidth()I

    .line 63
    .line 64
    .line 65
    move-result v7

    .line 66
    div-int/2addr v7, v5

    .line 67
    invoke-virtual {p0}, Landroid/view/View;->getHeight()I

    .line 68
    .line 69
    .line 70
    move-result v8

    .line 71
    div-int/2addr v8, v5

    .line 72
    int-to-float v7, v7

    .line 73
    int-to-float v8, v8

    .line 74
    sub-float v7, v1, v7

    .line 75
    .line 76
    sub-float v8, p1, v8

    .line 77
    .line 78
    float-to-double v9, v7

    .line 79
    float-to-double v7, v8

    .line 80
    invoke-static {v9, v10, v7, v8}, Ljava/lang/Math;->hypot(DD)D

    .line 81
    .line 82
    .line 83
    move-result-wide v7

    .line 84
    double-to-float v7, v7

    .line 85
    invoke-virtual {p0, v5}, Lcom/google/android/material/timepicker/ClockHandView;->b(I)I

    .line 86
    .line 87
    .line 88
    move-result v8

    .line 89
    invoke-virtual {p0}, Landroid/view/View;->getContext()Landroid/content/Context;

    .line 90
    .line 91
    .line 92
    move-result-object v9

    .line 93
    invoke-virtual {v9}, Landroid/content/Context;->getResources()Landroid/content/res/Resources;

    .line 94
    .line 95
    .line 96
    move-result-object v9

    .line 97
    int-to-float v10, v2

    .line 98
    invoke-virtual {v9}, Landroid/content/res/Resources;->getDisplayMetrics()Landroid/util/DisplayMetrics;

    .line 99
    .line 100
    .line 101
    move-result-object v9

    .line 102
    invoke-static {v3, v10, v9}, Landroid/util/TypedValue;->applyDimension(IFLandroid/util/DisplayMetrics;)F

    .line 103
    .line 104
    .line 105
    move-result v9

    .line 106
    int-to-float v8, v8

    .line 107
    add-float/2addr v8, v9

    .line 108
    cmpg-float v7, v7, v8

    .line 109
    .line 110
    if-gtz v7, :cond_3

    .line 111
    .line 112
    goto :goto_2

    .line 113
    :cond_3
    move v5, v3

    .line 114
    :goto_2
    iput v5, p0, Lcom/google/android/material/timepicker/ClockHandView;->x:I

    .line 115
    .line 116
    :cond_4
    move v5, v4

    .line 117
    goto :goto_3

    .line 118
    :cond_5
    iput v1, p0, Lcom/google/android/material/timepicker/ClockHandView;->h:F

    .line 119
    .line 120
    iput p1, p0, Lcom/google/android/material/timepicker/ClockHandView;->i:F

    .line 121
    .line 122
    iput-boolean v3, p0, Lcom/google/android/material/timepicker/ClockHandView;->j:Z

    .line 123
    .line 124
    iput-boolean v4, p0, Lcom/google/android/material/timepicker/ClockHandView;->t:Z

    .line 125
    .line 126
    move v5, v3

    .line 127
    move v0, v4

    .line 128
    move v6, v0

    .line 129
    :goto_3
    iget-boolean v7, p0, Lcom/google/android/material/timepicker/ClockHandView;->t:Z

    .line 130
    .line 131
    invoke-virtual {p0, v1, p1}, Lcom/google/android/material/timepicker/ClockHandView;->a(FF)I

    .line 132
    .line 133
    .line 134
    move-result v8

    .line 135
    iget v9, p0, Lcom/google/android/material/timepicker/ClockHandView;->s:F

    .line 136
    .line 137
    int-to-float v8, v8

    .line 138
    cmpl-float v9, v9, v8

    .line 139
    .line 140
    if-eqz v9, :cond_6

    .line 141
    .line 142
    move v9, v3

    .line 143
    goto :goto_4

    .line 144
    :cond_6
    move v9, v4

    .line 145
    :goto_4
    if-eqz v5, :cond_7

    .line 146
    .line 147
    if-eqz v9, :cond_7

    .line 148
    .line 149
    :goto_5
    move v5, v3

    .line 150
    goto :goto_8

    .line 151
    :cond_7
    if-nez v9, :cond_9

    .line 152
    .line 153
    if-eqz v6, :cond_8

    .line 154
    .line 155
    goto :goto_6

    .line 156
    :cond_8
    move v5, v4

    .line 157
    goto :goto_8

    .line 158
    :cond_9
    :goto_6
    if-eqz v0, :cond_a

    .line 159
    .line 160
    iget-boolean v5, p0, Lcom/google/android/material/timepicker/ClockHandView;->g:Z

    .line 161
    .line 162
    if-eqz v5, :cond_a

    .line 163
    .line 164
    move v5, v3

    .line 165
    goto :goto_7

    .line 166
    :cond_a
    move v5, v4

    .line 167
    :goto_7
    invoke-virtual {p0, v8, v5}, Lcom/google/android/material/timepicker/ClockHandView;->c(FZ)V

    .line 168
    .line 169
    .line 170
    goto :goto_5

    .line 171
    :goto_8
    or-int/2addr v5, v7

    .line 172
    iput-boolean v5, p0, Lcom/google/android/material/timepicker/ClockHandView;->t:Z

    .line 173
    .line 174
    if-eqz v5, :cond_f

    .line 175
    .line 176
    if-eqz v0, :cond_f

    .line 177
    .line 178
    iget-object v0, p0, Lcom/google/android/material/timepicker/ClockHandView;->u:Lcom/google/android/material/timepicker/n;

    .line 179
    .line 180
    if-eqz v0, :cond_f

    .line 181
    .line 182
    iget-object v5, v0, Lcom/google/android/material/timepicker/n;->e:Lcom/google/android/material/timepicker/l;

    .line 183
    .line 184
    iget-object v6, v0, Lcom/google/android/material/timepicker/n;->d:Lcom/google/android/material/timepicker/TimePickerView;

    .line 185
    .line 186
    invoke-virtual {p0, v1, p1}, Lcom/google/android/material/timepicker/ClockHandView;->a(FF)I

    .line 187
    .line 188
    .line 189
    move-result p1

    .line 190
    int-to-float p1, p1

    .line 191
    iget-boolean p0, p0, Lcom/google/android/material/timepicker/ClockHandView;->j:Z

    .line 192
    .line 193
    iput-boolean v3, v0, Lcom/google/android/material/timepicker/n;->h:Z

    .line 194
    .line 195
    iget v1, v5, Lcom/google/android/material/timepicker/l;->h:I

    .line 196
    .line 197
    iget v7, v5, Lcom/google/android/material/timepicker/l;->g:I

    .line 198
    .line 199
    iget v8, v5, Lcom/google/android/material/timepicker/l;->i:I

    .line 200
    .line 201
    const/16 v9, 0xa

    .line 202
    .line 203
    if-ne v8, v9, :cond_c

    .line 204
    .line 205
    iget p0, v0, Lcom/google/android/material/timepicker/n;->g:F

    .line 206
    .line 207
    iget-object p1, v6, Lcom/google/android/material/timepicker/TimePickerView;->f:Lcom/google/android/material/timepicker/ClockHandView;

    .line 208
    .line 209
    invoke-virtual {p1, p0, v4}, Lcom/google/android/material/timepicker/ClockHandView;->c(FZ)V

    .line 210
    .line 211
    .line 212
    invoke-virtual {v6}, Landroid/view/View;->getContext()Landroid/content/Context;

    .line 213
    .line 214
    .line 215
    move-result-object p0

    .line 216
    const-class p1, Landroid/view/accessibility/AccessibilityManager;

    .line 217
    .line 218
    invoke-virtual {p0, p1}, Landroid/content/Context;->getSystemService(Ljava/lang/Class;)Ljava/lang/Object;

    .line 219
    .line 220
    .line 221
    move-result-object p0

    .line 222
    check-cast p0, Landroid/view/accessibility/AccessibilityManager;

    .line 223
    .line 224
    if-eqz p0, :cond_b

    .line 225
    .line 226
    invoke-virtual {p0}, Landroid/view/accessibility/AccessibilityManager;->isTouchExplorationEnabled()Z

    .line 227
    .line 228
    .line 229
    move-result p0

    .line 230
    if-eqz p0, :cond_b

    .line 231
    .line 232
    goto :goto_9

    .line 233
    :cond_b
    invoke-virtual {v0, v2, v3}, Lcom/google/android/material/timepicker/n;->d(IZ)V

    .line 234
    .line 235
    .line 236
    goto :goto_9

    .line 237
    :cond_c
    invoke-static {p1}, Ljava/lang/Math;->round(F)I

    .line 238
    .line 239
    .line 240
    move-result p1

    .line 241
    if-nez p0, :cond_d

    .line 242
    .line 243
    add-int/lit8 p1, p1, 0xf

    .line 244
    .line 245
    div-int/lit8 p1, p1, 0x1e

    .line 246
    .line 247
    mul-int/lit8 p1, p1, 0x5

    .line 248
    .line 249
    invoke-virtual {v5, p1}, Lcom/google/android/material/timepicker/l;->j(I)V

    .line 250
    .line 251
    .line 252
    iget p1, v5, Lcom/google/android/material/timepicker/l;->h:I

    .line 253
    .line 254
    mul-int/lit8 p1, p1, 0x6

    .line 255
    .line 256
    int-to-float p1, p1

    .line 257
    iput p1, v0, Lcom/google/android/material/timepicker/n;->f:F

    .line 258
    .line 259
    :cond_d
    iget p1, v0, Lcom/google/android/material/timepicker/n;->f:F

    .line 260
    .line 261
    iget-object v2, v6, Lcom/google/android/material/timepicker/TimePickerView;->f:Lcom/google/android/material/timepicker/ClockHandView;

    .line 262
    .line 263
    invoke-virtual {v2, p1, p0}, Lcom/google/android/material/timepicker/ClockHandView;->c(FZ)V

    .line 264
    .line 265
    .line 266
    :goto_9
    iput-boolean v4, v0, Lcom/google/android/material/timepicker/n;->h:Z

    .line 267
    .line 268
    invoke-virtual {v0}, Lcom/google/android/material/timepicker/n;->e()V

    .line 269
    .line 270
    .line 271
    iget p0, v5, Lcom/google/android/material/timepicker/l;->h:I

    .line 272
    .line 273
    if-ne p0, v1, :cond_e

    .line 274
    .line 275
    iget p0, v5, Lcom/google/android/material/timepicker/l;->g:I

    .line 276
    .line 277
    if-eq p0, v7, :cond_f

    .line 278
    .line 279
    :cond_e
    const/4 p0, 0x4

    .line 280
    invoke-virtual {v6, p0}, Landroid/view/View;->performHapticFeedback(I)Z

    .line 281
    .line 282
    .line 283
    :cond_f
    return v3
.end method
