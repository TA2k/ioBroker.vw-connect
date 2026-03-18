.class public final Lgq/c;
.super Lk6/e;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public c:I

.field public d:I

.field public final synthetic e:Lcom/google/android/material/behavior/SwipeDismissBehavior;


# direct methods
.method public constructor <init>(Lcom/google/android/material/behavior/SwipeDismissBehavior;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lgq/c;->e:Lcom/google/android/material/behavior/SwipeDismissBehavior;

    .line 5
    .line 6
    const/4 p1, -0x1

    .line 7
    iput p1, p0, Lgq/c;->d:I

    .line 8
    .line 9
    return-void
.end method


# virtual methods
.method public final clampViewPositionHorizontal(Landroid/view/View;II)I
    .locals 2

    .line 1
    invoke-virtual {p1}, Landroid/view/View;->getLayoutDirection()I

    .line 2
    .line 3
    .line 4
    move-result p3

    .line 5
    const/4 v0, 0x1

    .line 6
    if-ne p3, v0, :cond_0

    .line 7
    .line 8
    move p3, v0

    .line 9
    goto :goto_0

    .line 10
    :cond_0
    const/4 p3, 0x0

    .line 11
    :goto_0
    iget-object v1, p0, Lgq/c;->e:Lcom/google/android/material/behavior/SwipeDismissBehavior;

    .line 12
    .line 13
    iget v1, v1, Lcom/google/android/material/behavior/SwipeDismissBehavior;->d:I

    .line 14
    .line 15
    if-nez v1, :cond_2

    .line 16
    .line 17
    if-eqz p3, :cond_1

    .line 18
    .line 19
    iget p3, p0, Lgq/c;->c:I

    .line 20
    .line 21
    invoke-virtual {p1}, Landroid/view/View;->getWidth()I

    .line 22
    .line 23
    .line 24
    move-result p1

    .line 25
    sub-int/2addr p3, p1

    .line 26
    iget p0, p0, Lgq/c;->c:I

    .line 27
    .line 28
    goto :goto_2

    .line 29
    :cond_1
    iget p3, p0, Lgq/c;->c:I

    .line 30
    .line 31
    invoke-virtual {p1}, Landroid/view/View;->getWidth()I

    .line 32
    .line 33
    .line 34
    move-result p0

    .line 35
    :goto_1
    add-int/2addr p0, p3

    .line 36
    goto :goto_2

    .line 37
    :cond_2
    if-ne v1, v0, :cond_4

    .line 38
    .line 39
    if-eqz p3, :cond_3

    .line 40
    .line 41
    iget p3, p0, Lgq/c;->c:I

    .line 42
    .line 43
    invoke-virtual {p1}, Landroid/view/View;->getWidth()I

    .line 44
    .line 45
    .line 46
    move-result p0

    .line 47
    goto :goto_1

    .line 48
    :cond_3
    iget p3, p0, Lgq/c;->c:I

    .line 49
    .line 50
    invoke-virtual {p1}, Landroid/view/View;->getWidth()I

    .line 51
    .line 52
    .line 53
    move-result p1

    .line 54
    sub-int/2addr p3, p1

    .line 55
    iget p0, p0, Lgq/c;->c:I

    .line 56
    .line 57
    goto :goto_2

    .line 58
    :cond_4
    iget p3, p0, Lgq/c;->c:I

    .line 59
    .line 60
    invoke-virtual {p1}, Landroid/view/View;->getWidth()I

    .line 61
    .line 62
    .line 63
    move-result v0

    .line 64
    sub-int/2addr p3, v0

    .line 65
    iget p0, p0, Lgq/c;->c:I

    .line 66
    .line 67
    invoke-virtual {p1}, Landroid/view/View;->getWidth()I

    .line 68
    .line 69
    .line 70
    move-result p1

    .line 71
    add-int/2addr p0, p1

    .line 72
    :goto_2
    invoke-static {p3, p2}, Ljava/lang/Math;->max(II)I

    .line 73
    .line 74
    .line 75
    move-result p1

    .line 76
    invoke-static {p1, p0}, Ljava/lang/Math;->min(II)I

    .line 77
    .line 78
    .line 79
    move-result p0

    .line 80
    return p0
.end method

.method public final clampViewPositionVertical(Landroid/view/View;II)I
    .locals 0

    .line 1
    invoke-virtual {p1}, Landroid/view/View;->getTop()I

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    return p0
.end method

.method public final getViewHorizontalDragRange(Landroid/view/View;)I
    .locals 0

    .line 1
    invoke-virtual {p1}, Landroid/view/View;->getWidth()I

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    return p0
.end method

.method public final onViewCaptured(Landroid/view/View;I)V
    .locals 0

    .line 1
    iput p2, p0, Lgq/c;->d:I

    .line 2
    .line 3
    invoke-virtual {p1}, Landroid/view/View;->getLeft()I

    .line 4
    .line 5
    .line 6
    move-result p2

    .line 7
    iput p2, p0, Lgq/c;->c:I

    .line 8
    .line 9
    invoke-virtual {p1}, Landroid/view/View;->getParent()Landroid/view/ViewParent;

    .line 10
    .line 11
    .line 12
    move-result-object p1

    .line 13
    if-eqz p1, :cond_0

    .line 14
    .line 15
    iget-object p0, p0, Lgq/c;->e:Lcom/google/android/material/behavior/SwipeDismissBehavior;

    .line 16
    .line 17
    const/4 p2, 0x1

    .line 18
    iput-boolean p2, p0, Lcom/google/android/material/behavior/SwipeDismissBehavior;->c:Z

    .line 19
    .line 20
    invoke-interface {p1, p2}, Landroid/view/ViewParent;->requestDisallowInterceptTouchEvent(Z)V

    .line 21
    .line 22
    .line 23
    const/4 p1, 0x0

    .line 24
    iput-boolean p1, p0, Lcom/google/android/material/behavior/SwipeDismissBehavior;->c:Z

    .line 25
    .line 26
    :cond_0
    return-void
.end method

.method public final onViewDragStateChanged(I)V
    .locals 0

    .line 1
    return-void
.end method

.method public final onViewPositionChanged(Landroid/view/View;IIII)V
    .locals 1

    .line 1
    invoke-virtual {p1}, Landroid/view/View;->getWidth()I

    .line 2
    .line 3
    .line 4
    move-result p3

    .line 5
    int-to-float p3, p3

    .line 6
    iget-object p4, p0, Lgq/c;->e:Lcom/google/android/material/behavior/SwipeDismissBehavior;

    .line 7
    .line 8
    iget p5, p4, Lcom/google/android/material/behavior/SwipeDismissBehavior;->e:F

    .line 9
    .line 10
    mul-float/2addr p3, p5

    .line 11
    invoke-virtual {p1}, Landroid/view/View;->getWidth()I

    .line 12
    .line 13
    .line 14
    move-result p5

    .line 15
    int-to-float p5, p5

    .line 16
    iget p4, p4, Lcom/google/android/material/behavior/SwipeDismissBehavior;->f:F

    .line 17
    .line 18
    mul-float/2addr p5, p4

    .line 19
    iget p0, p0, Lgq/c;->c:I

    .line 20
    .line 21
    sub-int/2addr p2, p0

    .line 22
    invoke-static {p2}, Ljava/lang/Math;->abs(I)I

    .line 23
    .line 24
    .line 25
    move-result p0

    .line 26
    int-to-float p0, p0

    .line 27
    cmpg-float p2, p0, p3

    .line 28
    .line 29
    const/high16 p4, 0x3f800000    # 1.0f

    .line 30
    .line 31
    if-gtz p2, :cond_0

    .line 32
    .line 33
    invoke-virtual {p1, p4}, Landroid/view/View;->setAlpha(F)V

    .line 34
    .line 35
    .line 36
    return-void

    .line 37
    :cond_0
    cmpl-float p2, p0, p5

    .line 38
    .line 39
    const/4 v0, 0x0

    .line 40
    if-ltz p2, :cond_1

    .line 41
    .line 42
    invoke-virtual {p1, v0}, Landroid/view/View;->setAlpha(F)V

    .line 43
    .line 44
    .line 45
    return-void

    .line 46
    :cond_1
    sub-float/2addr p0, p3

    .line 47
    sub-float/2addr p5, p3

    .line 48
    div-float/2addr p0, p5

    .line 49
    sub-float p0, p4, p0

    .line 50
    .line 51
    invoke-static {v0, p0}, Ljava/lang/Math;->max(FF)F

    .line 52
    .line 53
    .line 54
    move-result p0

    .line 55
    invoke-static {p0, p4}, Ljava/lang/Math;->min(FF)F

    .line 56
    .line 57
    .line 58
    move-result p0

    .line 59
    invoke-virtual {p1, p0}, Landroid/view/View;->setAlpha(F)V

    .line 60
    .line 61
    .line 62
    return-void
.end method

.method public final onViewReleased(Landroid/view/View;FF)V
    .locals 8

    .line 1
    const/4 p3, -0x1

    .line 2
    iput p3, p0, Lgq/c;->d:I

    .line 3
    .line 4
    invoke-virtual {p1}, Landroid/view/View;->getWidth()I

    .line 5
    .line 6
    .line 7
    move-result p3

    .line 8
    const/4 v0, 0x0

    .line 9
    cmpl-float v1, p2, v0

    .line 10
    .line 11
    const/4 v2, 0x0

    .line 12
    iget-object v3, p0, Lgq/c;->e:Lcom/google/android/material/behavior/SwipeDismissBehavior;

    .line 13
    .line 14
    const/4 v4, 0x1

    .line 15
    if-eqz v1, :cond_5

    .line 16
    .line 17
    invoke-virtual {p1}, Landroid/view/View;->getLayoutDirection()I

    .line 18
    .line 19
    .line 20
    move-result v5

    .line 21
    if-ne v5, v4, :cond_0

    .line 22
    .line 23
    move v5, v4

    .line 24
    goto :goto_0

    .line 25
    :cond_0
    move v5, v2

    .line 26
    :goto_0
    iget v6, v3, Lcom/google/android/material/behavior/SwipeDismissBehavior;->d:I

    .line 27
    .line 28
    const/4 v7, 0x2

    .line 29
    if-ne v6, v7, :cond_1

    .line 30
    .line 31
    goto :goto_1

    .line 32
    :cond_1
    if-nez v6, :cond_3

    .line 33
    .line 34
    if-eqz v5, :cond_2

    .line 35
    .line 36
    cmpg-float v1, p2, v0

    .line 37
    .line 38
    if-gez v1, :cond_8

    .line 39
    .line 40
    goto :goto_1

    .line 41
    :cond_2
    if-lez v1, :cond_8

    .line 42
    .line 43
    goto :goto_1

    .line 44
    :cond_3
    if-ne v6, v4, :cond_8

    .line 45
    .line 46
    if-eqz v5, :cond_4

    .line 47
    .line 48
    if-lez v1, :cond_8

    .line 49
    .line 50
    goto :goto_1

    .line 51
    :cond_4
    cmpg-float v1, p2, v0

    .line 52
    .line 53
    if-gez v1, :cond_8

    .line 54
    .line 55
    goto :goto_1

    .line 56
    :cond_5
    invoke-virtual {p1}, Landroid/view/View;->getLeft()I

    .line 57
    .line 58
    .line 59
    move-result v1

    .line 60
    iget v5, p0, Lgq/c;->c:I

    .line 61
    .line 62
    sub-int/2addr v1, v5

    .line 63
    invoke-virtual {p1}, Landroid/view/View;->getWidth()I

    .line 64
    .line 65
    .line 66
    move-result v5

    .line 67
    int-to-float v5, v5

    .line 68
    const/high16 v6, 0x3f000000    # 0.5f

    .line 69
    .line 70
    mul-float/2addr v5, v6

    .line 71
    invoke-static {v5}, Ljava/lang/Math;->round(F)I

    .line 72
    .line 73
    .line 74
    move-result v5

    .line 75
    invoke-static {v1}, Ljava/lang/Math;->abs(I)I

    .line 76
    .line 77
    .line 78
    move-result v1

    .line 79
    if-lt v1, v5, :cond_8

    .line 80
    .line 81
    :goto_1
    cmpg-float p2, p2, v0

    .line 82
    .line 83
    if-ltz p2, :cond_7

    .line 84
    .line 85
    invoke-virtual {p1}, Landroid/view/View;->getLeft()I

    .line 86
    .line 87
    .line 88
    move-result p2

    .line 89
    iget v0, p0, Lgq/c;->c:I

    .line 90
    .line 91
    if-ge p2, v0, :cond_6

    .line 92
    .line 93
    goto :goto_2

    .line 94
    :cond_6
    add-int/2addr v0, p3

    .line 95
    goto :goto_3

    .line 96
    :cond_7
    :goto_2
    iget p0, p0, Lgq/c;->c:I

    .line 97
    .line 98
    sub-int v0, p0, p3

    .line 99
    .line 100
    :goto_3
    move v2, v4

    .line 101
    goto :goto_4

    .line 102
    :cond_8
    iget v0, p0, Lgq/c;->c:I

    .line 103
    .line 104
    :goto_4
    iget-object p0, v3, Lcom/google/android/material/behavior/SwipeDismissBehavior;->a:Lk6/f;

    .line 105
    .line 106
    invoke-virtual {p1}, Landroid/view/View;->getTop()I

    .line 107
    .line 108
    .line 109
    move-result p2

    .line 110
    invoke-virtual {p0, v0, p2}, Lk6/f;->o(II)Z

    .line 111
    .line 112
    .line 113
    move-result p0

    .line 114
    if-eqz p0, :cond_9

    .line 115
    .line 116
    new-instance p0, Lk0/g;

    .line 117
    .line 118
    invoke-direct {p0, v3, p1, v2}, Lk0/g;-><init>(Lcom/google/android/material/behavior/SwipeDismissBehavior;Landroid/view/View;Z)V

    .line 119
    .line 120
    .line 121
    invoke-virtual {p1, p0}, Landroid/view/View;->postOnAnimation(Ljava/lang/Runnable;)V

    .line 122
    .line 123
    .line 124
    :cond_9
    return-void
.end method

.method public final tryCaptureView(Landroid/view/View;I)Z
    .locals 2

    .line 1
    iget v0, p0, Lgq/c;->d:I

    .line 2
    .line 3
    const/4 v1, -0x1

    .line 4
    if-eq v0, v1, :cond_0

    .line 5
    .line 6
    if-ne v0, p2, :cond_1

    .line 7
    .line 8
    :cond_0
    iget-object p0, p0, Lgq/c;->e:Lcom/google/android/material/behavior/SwipeDismissBehavior;

    .line 9
    .line 10
    invoke-virtual {p0, p1}, Lcom/google/android/material/behavior/SwipeDismissBehavior;->r(Landroid/view/View;)Z

    .line 11
    .line 12
    .line 13
    move-result p0

    .line 14
    if-eqz p0, :cond_1

    .line 15
    .line 16
    const/4 p0, 0x1

    .line 17
    return p0

    .line 18
    :cond_1
    const/4 p0, 0x0

    .line 19
    return p0
.end method
