.class public Lcom/google/android/material/internal/BaselineLayout;
.super Landroid/view/ViewGroup;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public d:I

.field public e:Z


# direct methods
.method public constructor <init>(Landroid/content/Context;Landroid/util/AttributeSet;)V
    .locals 1

    .line 1
    const/4 v0, 0x0

    .line 2
    invoke-direct {p0, p1, p2, v0}, Landroid/view/ViewGroup;-><init>(Landroid/content/Context;Landroid/util/AttributeSet;I)V

    .line 3
    .line 4
    .line 5
    const/4 p1, -0x1

    .line 6
    iput p1, p0, Lcom/google/android/material/internal/BaselineLayout;->d:I

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public getBaseline()I
    .locals 0

    .line 1
    iget p0, p0, Lcom/google/android/material/internal/BaselineLayout;->d:I

    .line 2
    .line 3
    return p0
.end method

.method public final onLayout(ZIIII)V
    .locals 6

    .line 1
    invoke-virtual {p0}, Landroid/view/ViewGroup;->getChildCount()I

    .line 2
    .line 3
    .line 4
    move-result p1

    .line 5
    invoke-virtual {p0}, Landroid/view/View;->getPaddingLeft()I

    .line 6
    .line 7
    .line 8
    move-result p3

    .line 9
    sub-int/2addr p4, p2

    .line 10
    invoke-virtual {p0}, Landroid/view/View;->getPaddingRight()I

    .line 11
    .line 12
    .line 13
    move-result p2

    .line 14
    sub-int/2addr p4, p2

    .line 15
    sub-int/2addr p4, p3

    .line 16
    invoke-virtual {p0}, Landroid/view/View;->getPaddingTop()I

    .line 17
    .line 18
    .line 19
    move-result p2

    .line 20
    const/4 p5, 0x0

    .line 21
    :goto_0
    if-ge p5, p1, :cond_2

    .line 22
    .line 23
    invoke-virtual {p0, p5}, Landroid/view/ViewGroup;->getChildAt(I)Landroid/view/View;

    .line 24
    .line 25
    .line 26
    move-result-object v0

    .line 27
    invoke-virtual {v0}, Landroid/view/View;->getVisibility()I

    .line 28
    .line 29
    .line 30
    move-result v1

    .line 31
    const/16 v2, 0x8

    .line 32
    .line 33
    if-ne v1, v2, :cond_0

    .line 34
    .line 35
    goto :goto_2

    .line 36
    :cond_0
    invoke-virtual {v0}, Landroid/view/View;->getMeasuredWidth()I

    .line 37
    .line 38
    .line 39
    move-result v1

    .line 40
    invoke-virtual {v0}, Landroid/view/View;->getMeasuredHeight()I

    .line 41
    .line 42
    .line 43
    move-result v2

    .line 44
    sub-int v3, p4, v1

    .line 45
    .line 46
    div-int/lit8 v3, v3, 0x2

    .line 47
    .line 48
    add-int/2addr v3, p3

    .line 49
    iget v4, p0, Lcom/google/android/material/internal/BaselineLayout;->d:I

    .line 50
    .line 51
    const/4 v5, -0x1

    .line 52
    if-eq v4, v5, :cond_1

    .line 53
    .line 54
    invoke-virtual {v0}, Landroid/view/View;->getBaseline()I

    .line 55
    .line 56
    .line 57
    move-result v4

    .line 58
    if-eq v4, v5, :cond_1

    .line 59
    .line 60
    iget v4, p0, Lcom/google/android/material/internal/BaselineLayout;->d:I

    .line 61
    .line 62
    add-int/2addr v4, p2

    .line 63
    invoke-virtual {v0}, Landroid/view/View;->getBaseline()I

    .line 64
    .line 65
    .line 66
    move-result v5

    .line 67
    sub-int/2addr v4, v5

    .line 68
    goto :goto_1

    .line 69
    :cond_1
    move v4, p2

    .line 70
    :goto_1
    add-int/2addr v1, v3

    .line 71
    add-int/2addr v2, v4

    .line 72
    invoke-virtual {v0, v3, v4, v1, v2}, Landroid/view/View;->layout(IIII)V

    .line 73
    .line 74
    .line 75
    :goto_2
    add-int/lit8 p5, p5, 0x1

    .line 76
    .line 77
    goto :goto_0

    .line 78
    :cond_2
    return-void
.end method

.method public final onMeasure(II)V
    .locals 12

    .line 1
    invoke-virtual {p0}, Landroid/view/ViewGroup;->getChildCount()I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    const/4 v1, 0x0

    .line 6
    const/4 v2, -0x1

    .line 7
    move v3, v1

    .line 8
    move v4, v3

    .line 9
    move v5, v4

    .line 10
    move v6, v5

    .line 11
    move v7, v2

    .line 12
    move v8, v7

    .line 13
    :goto_0
    if-ge v1, v0, :cond_2

    .line 14
    .line 15
    invoke-virtual {p0, v1}, Landroid/view/ViewGroup;->getChildAt(I)Landroid/view/View;

    .line 16
    .line 17
    .line 18
    move-result-object v9

    .line 19
    invoke-virtual {v9}, Landroid/view/View;->getVisibility()I

    .line 20
    .line 21
    .line 22
    move-result v10

    .line 23
    const/16 v11, 0x8

    .line 24
    .line 25
    if-ne v10, v11, :cond_0

    .line 26
    .line 27
    goto :goto_1

    .line 28
    :cond_0
    invoke-virtual {p0, v9, p1, p2}, Landroid/view/ViewGroup;->measureChild(Landroid/view/View;II)V

    .line 29
    .line 30
    .line 31
    invoke-virtual {v9}, Landroid/view/View;->getMeasuredHeight()I

    .line 32
    .line 33
    .line 34
    move-result v10

    .line 35
    invoke-static {v3, v10}, Ljava/lang/Math;->max(II)I

    .line 36
    .line 37
    .line 38
    move-result v3

    .line 39
    invoke-virtual {v9}, Landroid/view/View;->getBaseline()I

    .line 40
    .line 41
    .line 42
    move-result v10

    .line 43
    if-eq v10, v2, :cond_1

    .line 44
    .line 45
    invoke-static {v7, v10}, Ljava/lang/Math;->max(II)I

    .line 46
    .line 47
    .line 48
    move-result v7

    .line 49
    invoke-virtual {v9}, Landroid/view/View;->getMeasuredHeight()I

    .line 50
    .line 51
    .line 52
    move-result v11

    .line 53
    sub-int/2addr v11, v10

    .line 54
    invoke-static {v8, v11}, Ljava/lang/Math;->max(II)I

    .line 55
    .line 56
    .line 57
    move-result v8

    .line 58
    :cond_1
    invoke-virtual {v9}, Landroid/view/View;->getMeasuredWidth()I

    .line 59
    .line 60
    .line 61
    move-result v10

    .line 62
    invoke-static {v5, v10}, Ljava/lang/Math;->max(II)I

    .line 63
    .line 64
    .line 65
    move-result v5

    .line 66
    invoke-virtual {v9}, Landroid/view/View;->getMeasuredHeight()I

    .line 67
    .line 68
    .line 69
    move-result v10

    .line 70
    invoke-static {v4, v10}, Ljava/lang/Math;->max(II)I

    .line 71
    .line 72
    .line 73
    move-result v4

    .line 74
    invoke-virtual {v9}, Landroid/view/View;->getMeasuredState()I

    .line 75
    .line 76
    .line 77
    move-result v9

    .line 78
    invoke-static {v6, v9}, Landroid/view/View;->combineMeasuredStates(II)I

    .line 79
    .line 80
    .line 81
    move-result v6

    .line 82
    :goto_1
    add-int/lit8 v1, v1, 0x1

    .line 83
    .line 84
    goto :goto_0

    .line 85
    :cond_2
    if-eq v7, v2, :cond_4

    .line 86
    .line 87
    iget-boolean v0, p0, Lcom/google/android/material/internal/BaselineLayout;->e:Z

    .line 88
    .line 89
    if-eqz v0, :cond_3

    .line 90
    .line 91
    invoke-virtual {p0}, Landroid/view/View;->getPaddingBottom()I

    .line 92
    .line 93
    .line 94
    move-result v0

    .line 95
    invoke-static {v8, v0}, Ljava/lang/Math;->max(II)I

    .line 96
    .line 97
    .line 98
    move-result v0

    .line 99
    add-int/2addr v0, v7

    .line 100
    invoke-static {v4, v0}, Ljava/lang/Math;->max(II)I

    .line 101
    .line 102
    .line 103
    move-result v4

    .line 104
    :cond_3
    iput v7, p0, Lcom/google/android/material/internal/BaselineLayout;->d:I

    .line 105
    .line 106
    :cond_4
    iget-boolean v0, p0, Lcom/google/android/material/internal/BaselineLayout;->e:Z

    .line 107
    .line 108
    if-eqz v0, :cond_5

    .line 109
    .line 110
    goto :goto_2

    .line 111
    :cond_5
    invoke-virtual {p0}, Landroid/view/View;->getPaddingBottom()I

    .line 112
    .line 113
    .line 114
    move-result v0

    .line 115
    add-int v4, v0, v3

    .line 116
    .line 117
    :goto_2
    invoke-virtual {p0}, Landroid/view/View;->getSuggestedMinimumHeight()I

    .line 118
    .line 119
    .line 120
    move-result v0

    .line 121
    invoke-static {v4, v0}, Ljava/lang/Math;->max(II)I

    .line 122
    .line 123
    .line 124
    move-result v0

    .line 125
    invoke-virtual {p0}, Landroid/view/View;->getSuggestedMinimumWidth()I

    .line 126
    .line 127
    .line 128
    move-result v1

    .line 129
    invoke-static {v5, v1}, Ljava/lang/Math;->max(II)I

    .line 130
    .line 131
    .line 132
    move-result v1

    .line 133
    invoke-static {v1, p1, v6}, Landroid/view/View;->resolveSizeAndState(III)I

    .line 134
    .line 135
    .line 136
    move-result p1

    .line 137
    shl-int/lit8 v1, v6, 0x10

    .line 138
    .line 139
    invoke-static {v0, p2, v1}, Landroid/view/View;->resolveSizeAndState(III)I

    .line 140
    .line 141
    .line 142
    move-result p2

    .line 143
    invoke-virtual {p0, p1, p2}, Landroid/view/View;->setMeasuredDimension(II)V

    .line 144
    .line 145
    .line 146
    return-void
.end method

.method public setMeasurePaddingFromBaseline(Z)V
    .locals 0

    .line 1
    iput-boolean p1, p0, Lcom/google/android/material/internal/BaselineLayout;->e:Z

    .line 2
    .line 3
    return-void
.end method
