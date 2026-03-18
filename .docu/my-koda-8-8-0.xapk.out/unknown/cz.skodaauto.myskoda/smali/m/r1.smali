.class public abstract Lm/r1;
.super Landroid/view/ViewGroup;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public d:Z

.field public e:I

.field public f:I

.field public g:I

.field public h:I

.field public i:I

.field public j:F

.field public k:Z

.field public l:[I

.field public m:[I

.field public n:Landroid/graphics/drawable/Drawable;

.field public o:I

.field public p:I

.field public q:I

.field public r:I


# direct methods
.method public constructor <init>(Landroid/content/Context;Landroid/util/AttributeSet;I)V
    .locals 10

    .line 1
    const/4 v5, 0x0

    .line 2
    invoke-direct {p0, p1, p2, v5}, Landroid/view/ViewGroup;-><init>(Landroid/content/Context;Landroid/util/AttributeSet;I)V

    .line 3
    .line 4
    .line 5
    const/4 p3, 0x1

    .line 6
    iput-boolean p3, p0, Lm/r1;->d:Z

    .line 7
    .line 8
    const/4 v7, -0x1

    .line 9
    iput v7, p0, Lm/r1;->e:I

    .line 10
    .line 11
    const/4 v8, 0x0

    .line 12
    iput v8, p0, Lm/r1;->f:I

    .line 13
    .line 14
    const v0, 0x800033

    .line 15
    .line 16
    .line 17
    iput v0, p0, Lm/r1;->h:I

    .line 18
    .line 19
    sget-object v2, Lg/a;->n:[I

    .line 20
    .line 21
    invoke-static {p1, p2, v2, v5}, Lil/g;->R(Landroid/content/Context;Landroid/util/AttributeSet;[II)Lil/g;

    .line 22
    .line 23
    .line 24
    move-result-object v9

    .line 25
    iget-object v0, v9, Lil/g;->f:Ljava/lang/Object;

    .line 26
    .line 27
    move-object v4, v0

    .line 28
    check-cast v4, Landroid/content/res/TypedArray;

    .line 29
    .line 30
    sget-object v0, Ld6/r0;->a:Ljava/util/WeakHashMap;

    .line 31
    .line 32
    const/4 v6, 0x0

    .line 33
    move-object v0, p0

    .line 34
    move-object v1, p1

    .line 35
    move-object v3, p2

    .line 36
    invoke-static/range {v0 .. v6}, Ld6/o0;->b(Landroid/view/View;Landroid/content/Context;[ILandroid/util/AttributeSet;Landroid/content/res/TypedArray;II)V

    .line 37
    .line 38
    .line 39
    iget-object p0, v9, Lil/g;->f:Ljava/lang/Object;

    .line 40
    .line 41
    check-cast p0, Landroid/content/res/TypedArray;

    .line 42
    .line 43
    invoke-virtual {p0, p3, v7}, Landroid/content/res/TypedArray;->getInt(II)I

    .line 44
    .line 45
    .line 46
    move-result p1

    .line 47
    if-ltz p1, :cond_0

    .line 48
    .line 49
    invoke-virtual {v0, p1}, Lm/r1;->setOrientation(I)V

    .line 50
    .line 51
    .line 52
    :cond_0
    invoke-virtual {p0, v8, v7}, Landroid/content/res/TypedArray;->getInt(II)I

    .line 53
    .line 54
    .line 55
    move-result p1

    .line 56
    if-ltz p1, :cond_1

    .line 57
    .line 58
    invoke-virtual {v0, p1}, Lm/r1;->setGravity(I)V

    .line 59
    .line 60
    .line 61
    :cond_1
    const/4 p1, 0x2

    .line 62
    invoke-virtual {p0, p1, p3}, Landroid/content/res/TypedArray;->getBoolean(IZ)Z

    .line 63
    .line 64
    .line 65
    move-result p1

    .line 66
    if-nez p1, :cond_2

    .line 67
    .line 68
    invoke-virtual {v0, p1}, Lm/r1;->setBaselineAligned(Z)V

    .line 69
    .line 70
    .line 71
    :cond_2
    const/4 p1, 0x4

    .line 72
    const/high16 p2, -0x40800000    # -1.0f

    .line 73
    .line 74
    invoke-virtual {p0, p1, p2}, Landroid/content/res/TypedArray;->getFloat(IF)F

    .line 75
    .line 76
    .line 77
    move-result p1

    .line 78
    iput p1, v0, Lm/r1;->j:F

    .line 79
    .line 80
    const/4 p1, 0x3

    .line 81
    invoke-virtual {p0, p1, v7}, Landroid/content/res/TypedArray;->getInt(II)I

    .line 82
    .line 83
    .line 84
    move-result p1

    .line 85
    iput p1, v0, Lm/r1;->e:I

    .line 86
    .line 87
    const/4 p1, 0x7

    .line 88
    invoke-virtual {p0, p1, v8}, Landroid/content/res/TypedArray;->getBoolean(IZ)Z

    .line 89
    .line 90
    .line 91
    move-result p1

    .line 92
    iput-boolean p1, v0, Lm/r1;->k:Z

    .line 93
    .line 94
    const/4 p1, 0x5

    .line 95
    invoke-virtual {v9, p1}, Lil/g;->B(I)Landroid/graphics/drawable/Drawable;

    .line 96
    .line 97
    .line 98
    move-result-object p1

    .line 99
    invoke-virtual {v0, p1}, Lm/r1;->setDividerDrawable(Landroid/graphics/drawable/Drawable;)V

    .line 100
    .line 101
    .line 102
    const/16 p1, 0x8

    .line 103
    .line 104
    invoke-virtual {p0, p1, v8}, Landroid/content/res/TypedArray;->getInt(II)I

    .line 105
    .line 106
    .line 107
    move-result p1

    .line 108
    iput p1, v0, Lm/r1;->q:I

    .line 109
    .line 110
    const/4 p1, 0x6

    .line 111
    invoke-virtual {p0, p1, v8}, Landroid/content/res/TypedArray;->getDimensionPixelSize(II)I

    .line 112
    .line 113
    .line 114
    move-result p0

    .line 115
    iput p0, v0, Lm/r1;->r:I

    .line 116
    .line 117
    invoke-virtual {v9}, Lil/g;->U()V

    .line 118
    .line 119
    .line 120
    return-void
.end method


# virtual methods
.method public checkLayoutParams(Landroid/view/ViewGroup$LayoutParams;)Z
    .locals 0

    .line 1
    instance-of p0, p1, Lm/q1;

    .line 2
    .line 3
    return p0
.end method

.method public final d(Landroid/graphics/Canvas;I)V
    .locals 4

    .line 1
    iget-object v0, p0, Lm/r1;->n:Landroid/graphics/drawable/Drawable;

    .line 2
    .line 3
    invoke-virtual {p0}, Landroid/view/View;->getPaddingLeft()I

    .line 4
    .line 5
    .line 6
    move-result v1

    .line 7
    iget v2, p0, Lm/r1;->r:I

    .line 8
    .line 9
    add-int/2addr v1, v2

    .line 10
    invoke-virtual {p0}, Landroid/view/View;->getWidth()I

    .line 11
    .line 12
    .line 13
    move-result v2

    .line 14
    invoke-virtual {p0}, Landroid/view/View;->getPaddingRight()I

    .line 15
    .line 16
    .line 17
    move-result v3

    .line 18
    sub-int/2addr v2, v3

    .line 19
    iget v3, p0, Lm/r1;->r:I

    .line 20
    .line 21
    sub-int/2addr v2, v3

    .line 22
    iget v3, p0, Lm/r1;->p:I

    .line 23
    .line 24
    add-int/2addr v3, p2

    .line 25
    invoke-virtual {v0, v1, p2, v2, v3}, Landroid/graphics/drawable/Drawable;->setBounds(IIII)V

    .line 26
    .line 27
    .line 28
    iget-object p0, p0, Lm/r1;->n:Landroid/graphics/drawable/Drawable;

    .line 29
    .line 30
    invoke-virtual {p0, p1}, Landroid/graphics/drawable/Drawable;->draw(Landroid/graphics/Canvas;)V

    .line 31
    .line 32
    .line 33
    return-void
.end method

.method public final e(Landroid/graphics/Canvas;I)V
    .locals 5

    .line 1
    iget-object v0, p0, Lm/r1;->n:Landroid/graphics/drawable/Drawable;

    .line 2
    .line 3
    invoke-virtual {p0}, Landroid/view/View;->getPaddingTop()I

    .line 4
    .line 5
    .line 6
    move-result v1

    .line 7
    iget v2, p0, Lm/r1;->r:I

    .line 8
    .line 9
    add-int/2addr v1, v2

    .line 10
    iget v2, p0, Lm/r1;->o:I

    .line 11
    .line 12
    add-int/2addr v2, p2

    .line 13
    invoke-virtual {p0}, Landroid/view/View;->getHeight()I

    .line 14
    .line 15
    .line 16
    move-result v3

    .line 17
    invoke-virtual {p0}, Landroid/view/View;->getPaddingBottom()I

    .line 18
    .line 19
    .line 20
    move-result v4

    .line 21
    sub-int/2addr v3, v4

    .line 22
    iget v4, p0, Lm/r1;->r:I

    .line 23
    .line 24
    sub-int/2addr v3, v4

    .line 25
    invoke-virtual {v0, p2, v1, v2, v3}, Landroid/graphics/drawable/Drawable;->setBounds(IIII)V

    .line 26
    .line 27
    .line 28
    iget-object p0, p0, Lm/r1;->n:Landroid/graphics/drawable/Drawable;

    .line 29
    .line 30
    invoke-virtual {p0, p1}, Landroid/graphics/drawable/Drawable;->draw(Landroid/graphics/Canvas;)V

    .line 31
    .line 32
    .line 33
    return-void
.end method

.method public f()Lm/q1;
    .locals 2

    .line 1
    iget p0, p0, Lm/r1;->g:I

    .line 2
    .line 3
    const/4 v0, -0x2

    .line 4
    if-nez p0, :cond_0

    .line 5
    .line 6
    new-instance p0, Lm/q1;

    .line 7
    .line 8
    invoke-direct {p0, v0, v0}, Landroid/widget/LinearLayout$LayoutParams;-><init>(II)V

    .line 9
    .line 10
    .line 11
    return-object p0

    .line 12
    :cond_0
    const/4 v1, 0x1

    .line 13
    if-ne p0, v1, :cond_1

    .line 14
    .line 15
    new-instance p0, Lm/q1;

    .line 16
    .line 17
    const/4 v1, -0x1

    .line 18
    invoke-direct {p0, v1, v0}, Landroid/widget/LinearLayout$LayoutParams;-><init>(II)V

    .line 19
    .line 20
    .line 21
    return-object p0

    .line 22
    :cond_1
    const/4 p0, 0x0

    .line 23
    return-object p0
.end method

.method public g(Landroid/util/AttributeSet;)Lm/q1;
    .locals 1

    .line 1
    new-instance v0, Lm/q1;

    .line 2
    .line 3
    invoke-virtual {p0}, Landroid/view/View;->getContext()Landroid/content/Context;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    invoke-direct {v0, p0, p1}, Landroid/widget/LinearLayout$LayoutParams;-><init>(Landroid/content/Context;Landroid/util/AttributeSet;)V

    .line 8
    .line 9
    .line 10
    return-object v0
.end method

.method public bridge synthetic generateDefaultLayoutParams()Landroid/view/ViewGroup$LayoutParams;
    .locals 0

    .line 1
    invoke-virtual {p0}, Lm/r1;->f()Lm/q1;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public bridge synthetic generateLayoutParams(Landroid/util/AttributeSet;)Landroid/view/ViewGroup$LayoutParams;
    .locals 0

    .line 1
    invoke-virtual {p0, p1}, Lm/r1;->g(Landroid/util/AttributeSet;)Lm/q1;

    move-result-object p0

    return-object p0
.end method

.method public bridge synthetic generateLayoutParams(Landroid/view/ViewGroup$LayoutParams;)Landroid/view/ViewGroup$LayoutParams;
    .locals 0

    .line 2
    invoke-virtual {p0, p1}, Lm/r1;->h(Landroid/view/ViewGroup$LayoutParams;)Lm/q1;

    move-result-object p0

    return-object p0
.end method

.method public getBaseline()I
    .locals 5

    .line 1
    iget v0, p0, Lm/r1;->e:I

    .line 2
    .line 3
    if-gez v0, :cond_0

    .line 4
    .line 5
    invoke-super {p0}, Landroid/view/View;->getBaseline()I

    .line 6
    .line 7
    .line 8
    move-result p0

    .line 9
    return p0

    .line 10
    :cond_0
    invoke-virtual {p0}, Landroid/view/ViewGroup;->getChildCount()I

    .line 11
    .line 12
    .line 13
    move-result v0

    .line 14
    iget v1, p0, Lm/r1;->e:I

    .line 15
    .line 16
    if-le v0, v1, :cond_6

    .line 17
    .line 18
    invoke-virtual {p0, v1}, Landroid/view/ViewGroup;->getChildAt(I)Landroid/view/View;

    .line 19
    .line 20
    .line 21
    move-result-object v0

    .line 22
    invoke-virtual {v0}, Landroid/view/View;->getBaseline()I

    .line 23
    .line 24
    .line 25
    move-result v1

    .line 26
    const/4 v2, -0x1

    .line 27
    if-ne v1, v2, :cond_2

    .line 28
    .line 29
    iget p0, p0, Lm/r1;->e:I

    .line 30
    .line 31
    if-nez p0, :cond_1

    .line 32
    .line 33
    return v2

    .line 34
    :cond_1
    new-instance p0, Ljava/lang/RuntimeException;

    .line 35
    .line 36
    const-string v0, "mBaselineAlignedChildIndex of LinearLayout points to a View that doesn\'t know how to get its baseline."

    .line 37
    .line 38
    invoke-direct {p0, v0}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/String;)V

    .line 39
    .line 40
    .line 41
    throw p0

    .line 42
    :cond_2
    iget v2, p0, Lm/r1;->f:I

    .line 43
    .line 44
    iget v3, p0, Lm/r1;->g:I

    .line 45
    .line 46
    const/4 v4, 0x1

    .line 47
    if-ne v3, v4, :cond_5

    .line 48
    .line 49
    iget v3, p0, Lm/r1;->h:I

    .line 50
    .line 51
    and-int/lit8 v3, v3, 0x70

    .line 52
    .line 53
    const/16 v4, 0x30

    .line 54
    .line 55
    if-eq v3, v4, :cond_5

    .line 56
    .line 57
    const/16 v4, 0x10

    .line 58
    .line 59
    if-eq v3, v4, :cond_4

    .line 60
    .line 61
    const/16 v4, 0x50

    .line 62
    .line 63
    if-eq v3, v4, :cond_3

    .line 64
    .line 65
    goto :goto_0

    .line 66
    :cond_3
    invoke-virtual {p0}, Landroid/view/View;->getBottom()I

    .line 67
    .line 68
    .line 69
    move-result v2

    .line 70
    invoke-virtual {p0}, Landroid/view/View;->getTop()I

    .line 71
    .line 72
    .line 73
    move-result v3

    .line 74
    sub-int/2addr v2, v3

    .line 75
    invoke-virtual {p0}, Landroid/view/View;->getPaddingBottom()I

    .line 76
    .line 77
    .line 78
    move-result v3

    .line 79
    sub-int/2addr v2, v3

    .line 80
    iget p0, p0, Lm/r1;->i:I

    .line 81
    .line 82
    sub-int/2addr v2, p0

    .line 83
    goto :goto_0

    .line 84
    :cond_4
    invoke-virtual {p0}, Landroid/view/View;->getBottom()I

    .line 85
    .line 86
    .line 87
    move-result v3

    .line 88
    invoke-virtual {p0}, Landroid/view/View;->getTop()I

    .line 89
    .line 90
    .line 91
    move-result v4

    .line 92
    sub-int/2addr v3, v4

    .line 93
    invoke-virtual {p0}, Landroid/view/View;->getPaddingTop()I

    .line 94
    .line 95
    .line 96
    move-result v4

    .line 97
    sub-int/2addr v3, v4

    .line 98
    invoke-virtual {p0}, Landroid/view/View;->getPaddingBottom()I

    .line 99
    .line 100
    .line 101
    move-result v4

    .line 102
    sub-int/2addr v3, v4

    .line 103
    iget p0, p0, Lm/r1;->i:I

    .line 104
    .line 105
    sub-int/2addr v3, p0

    .line 106
    div-int/lit8 v3, v3, 0x2

    .line 107
    .line 108
    add-int/2addr v2, v3

    .line 109
    :cond_5
    :goto_0
    invoke-virtual {v0}, Landroid/view/View;->getLayoutParams()Landroid/view/ViewGroup$LayoutParams;

    .line 110
    .line 111
    .line 112
    move-result-object p0

    .line 113
    check-cast p0, Lm/q1;

    .line 114
    .line 115
    iget p0, p0, Landroid/widget/LinearLayout$LayoutParams;->topMargin:I

    .line 116
    .line 117
    add-int/2addr v2, p0

    .line 118
    add-int/2addr v2, v1

    .line 119
    return v2

    .line 120
    :cond_6
    new-instance p0, Ljava/lang/RuntimeException;

    .line 121
    .line 122
    const-string v0, "mBaselineAlignedChildIndex of LinearLayout set to an index that is out of bounds."

    .line 123
    .line 124
    invoke-direct {p0, v0}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/String;)V

    .line 125
    .line 126
    .line 127
    throw p0
.end method

.method public getBaselineAlignedChildIndex()I
    .locals 0

    .line 1
    iget p0, p0, Lm/r1;->e:I

    .line 2
    .line 3
    return p0
.end method

.method public getDividerDrawable()Landroid/graphics/drawable/Drawable;
    .locals 0

    .line 1
    iget-object p0, p0, Lm/r1;->n:Landroid/graphics/drawable/Drawable;

    .line 2
    .line 3
    return-object p0
.end method

.method public getDividerPadding()I
    .locals 0

    .line 1
    iget p0, p0, Lm/r1;->r:I

    .line 2
    .line 3
    return p0
.end method

.method public getDividerWidth()I
    .locals 0

    .line 1
    iget p0, p0, Lm/r1;->o:I

    .line 2
    .line 3
    return p0
.end method

.method public getGravity()I
    .locals 0

    .line 1
    iget p0, p0, Lm/r1;->h:I

    .line 2
    .line 3
    return p0
.end method

.method public getOrientation()I
    .locals 0

    .line 1
    iget p0, p0, Lm/r1;->g:I

    .line 2
    .line 3
    return p0
.end method

.method public getShowDividers()I
    .locals 0

    .line 1
    iget p0, p0, Lm/r1;->q:I

    .line 2
    .line 3
    return p0
.end method

.method public getVirtualChildCount()I
    .locals 0

    .line 1
    invoke-virtual {p0}, Landroid/view/ViewGroup;->getChildCount()I

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    return p0
.end method

.method public getWeightSum()F
    .locals 0

    .line 1
    iget p0, p0, Lm/r1;->j:F

    .line 2
    .line 3
    return p0
.end method

.method public h(Landroid/view/ViewGroup$LayoutParams;)Lm/q1;
    .locals 0

    .line 1
    instance-of p0, p1, Lm/q1;

    .line 2
    .line 3
    if-eqz p0, :cond_0

    .line 4
    .line 5
    new-instance p0, Lm/q1;

    .line 6
    .line 7
    check-cast p1, Lm/q1;

    .line 8
    .line 9
    invoke-direct {p0, p1}, Landroid/widget/LinearLayout$LayoutParams;-><init>(Landroid/view/ViewGroup$MarginLayoutParams;)V

    .line 10
    .line 11
    .line 12
    return-object p0

    .line 13
    :cond_0
    instance-of p0, p1, Landroid/view/ViewGroup$MarginLayoutParams;

    .line 14
    .line 15
    if-eqz p0, :cond_1

    .line 16
    .line 17
    new-instance p0, Lm/q1;

    .line 18
    .line 19
    check-cast p1, Landroid/view/ViewGroup$MarginLayoutParams;

    .line 20
    .line 21
    invoke-direct {p0, p1}, Landroid/widget/LinearLayout$LayoutParams;-><init>(Landroid/view/ViewGroup$MarginLayoutParams;)V

    .line 22
    .line 23
    .line 24
    return-object p0

    .line 25
    :cond_1
    new-instance p0, Lm/q1;

    .line 26
    .line 27
    invoke-direct {p0, p1}, Landroid/widget/LinearLayout$LayoutParams;-><init>(Landroid/view/ViewGroup$LayoutParams;)V

    .line 28
    .line 29
    .line 30
    return-object p0
.end method

.method public final i(I)Z
    .locals 4

    .line 1
    const/4 v0, 0x0

    .line 2
    const/4 v1, 0x1

    .line 3
    if-nez p1, :cond_1

    .line 4
    .line 5
    iget p0, p0, Lm/r1;->q:I

    .line 6
    .line 7
    and-int/2addr p0, v1

    .line 8
    if-eqz p0, :cond_0

    .line 9
    .line 10
    return v1

    .line 11
    :cond_0
    return v0

    .line 12
    :cond_1
    invoke-virtual {p0}, Landroid/view/ViewGroup;->getChildCount()I

    .line 13
    .line 14
    .line 15
    move-result v2

    .line 16
    if-ne p1, v2, :cond_3

    .line 17
    .line 18
    iget p0, p0, Lm/r1;->q:I

    .line 19
    .line 20
    and-int/lit8 p0, p0, 0x4

    .line 21
    .line 22
    if-eqz p0, :cond_2

    .line 23
    .line 24
    return v1

    .line 25
    :cond_2
    return v0

    .line 26
    :cond_3
    iget v2, p0, Lm/r1;->q:I

    .line 27
    .line 28
    and-int/lit8 v2, v2, 0x2

    .line 29
    .line 30
    if-eqz v2, :cond_5

    .line 31
    .line 32
    sub-int/2addr p1, v1

    .line 33
    :goto_0
    if-ltz p1, :cond_5

    .line 34
    .line 35
    invoke-virtual {p0, p1}, Landroid/view/ViewGroup;->getChildAt(I)Landroid/view/View;

    .line 36
    .line 37
    .line 38
    move-result-object v2

    .line 39
    invoke-virtual {v2}, Landroid/view/View;->getVisibility()I

    .line 40
    .line 41
    .line 42
    move-result v2

    .line 43
    const/16 v3, 0x8

    .line 44
    .line 45
    if-eq v2, v3, :cond_4

    .line 46
    .line 47
    return v1

    .line 48
    :cond_4
    add-int/lit8 p1, p1, -0x1

    .line 49
    .line 50
    goto :goto_0

    .line 51
    :cond_5
    return v0
.end method

.method public final onDraw(Landroid/graphics/Canvas;)V
    .locals 7

    .line 1
    iget-object v0, p0, Lm/r1;->n:Landroid/graphics/drawable/Drawable;

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    goto/16 :goto_6

    .line 6
    .line 7
    :cond_0
    iget v0, p0, Lm/r1;->g:I

    .line 8
    .line 9
    const/16 v1, 0x8

    .line 10
    .line 11
    const/4 v2, 0x0

    .line 12
    const/4 v3, 0x1

    .line 13
    if-ne v0, v3, :cond_4

    .line 14
    .line 15
    invoke-virtual {p0}, Lm/r1;->getVirtualChildCount()I

    .line 16
    .line 17
    .line 18
    move-result v0

    .line 19
    :goto_0
    if-ge v2, v0, :cond_2

    .line 20
    .line 21
    invoke-virtual {p0, v2}, Landroid/view/ViewGroup;->getChildAt(I)Landroid/view/View;

    .line 22
    .line 23
    .line 24
    move-result-object v4

    .line 25
    if-eqz v4, :cond_1

    .line 26
    .line 27
    invoke-virtual {v4}, Landroid/view/View;->getVisibility()I

    .line 28
    .line 29
    .line 30
    move-result v5

    .line 31
    if-eq v5, v1, :cond_1

    .line 32
    .line 33
    invoke-virtual {p0, v2}, Lm/r1;->i(I)Z

    .line 34
    .line 35
    .line 36
    move-result v5

    .line 37
    if-eqz v5, :cond_1

    .line 38
    .line 39
    invoke-virtual {v4}, Landroid/view/View;->getLayoutParams()Landroid/view/ViewGroup$LayoutParams;

    .line 40
    .line 41
    .line 42
    move-result-object v5

    .line 43
    check-cast v5, Lm/q1;

    .line 44
    .line 45
    invoke-virtual {v4}, Landroid/view/View;->getTop()I

    .line 46
    .line 47
    .line 48
    move-result v4

    .line 49
    iget v5, v5, Landroid/widget/LinearLayout$LayoutParams;->topMargin:I

    .line 50
    .line 51
    sub-int/2addr v4, v5

    .line 52
    iget v5, p0, Lm/r1;->p:I

    .line 53
    .line 54
    sub-int/2addr v4, v5

    .line 55
    invoke-virtual {p0, p1, v4}, Lm/r1;->d(Landroid/graphics/Canvas;I)V

    .line 56
    .line 57
    .line 58
    :cond_1
    add-int/lit8 v2, v2, 0x1

    .line 59
    .line 60
    goto :goto_0

    .line 61
    :cond_2
    invoke-virtual {p0, v0}, Lm/r1;->i(I)Z

    .line 62
    .line 63
    .line 64
    move-result v1

    .line 65
    if-eqz v1, :cond_c

    .line 66
    .line 67
    sub-int/2addr v0, v3

    .line 68
    invoke-virtual {p0, v0}, Landroid/view/ViewGroup;->getChildAt(I)Landroid/view/View;

    .line 69
    .line 70
    .line 71
    move-result-object v0

    .line 72
    if-nez v0, :cond_3

    .line 73
    .line 74
    invoke-virtual {p0}, Landroid/view/View;->getHeight()I

    .line 75
    .line 76
    .line 77
    move-result v0

    .line 78
    invoke-virtual {p0}, Landroid/view/View;->getPaddingBottom()I

    .line 79
    .line 80
    .line 81
    move-result v1

    .line 82
    sub-int/2addr v0, v1

    .line 83
    iget v1, p0, Lm/r1;->p:I

    .line 84
    .line 85
    sub-int/2addr v0, v1

    .line 86
    goto :goto_1

    .line 87
    :cond_3
    invoke-virtual {v0}, Landroid/view/View;->getLayoutParams()Landroid/view/ViewGroup$LayoutParams;

    .line 88
    .line 89
    .line 90
    move-result-object v1

    .line 91
    check-cast v1, Lm/q1;

    .line 92
    .line 93
    invoke-virtual {v0}, Landroid/view/View;->getBottom()I

    .line 94
    .line 95
    .line 96
    move-result v0

    .line 97
    iget v1, v1, Landroid/widget/LinearLayout$LayoutParams;->bottomMargin:I

    .line 98
    .line 99
    add-int/2addr v0, v1

    .line 100
    :goto_1
    invoke-virtual {p0, p1, v0}, Lm/r1;->d(Landroid/graphics/Canvas;I)V

    .line 101
    .line 102
    .line 103
    return-void

    .line 104
    :cond_4
    invoke-virtual {p0}, Lm/r1;->getVirtualChildCount()I

    .line 105
    .line 106
    .line 107
    move-result v0

    .line 108
    invoke-virtual {p0}, Landroid/view/View;->getLayoutDirection()I

    .line 109
    .line 110
    .line 111
    move-result v4

    .line 112
    if-ne v4, v3, :cond_5

    .line 113
    .line 114
    move v4, v3

    .line 115
    goto :goto_2

    .line 116
    :cond_5
    move v4, v2

    .line 117
    :goto_2
    if-ge v2, v0, :cond_8

    .line 118
    .line 119
    invoke-virtual {p0, v2}, Landroid/view/ViewGroup;->getChildAt(I)Landroid/view/View;

    .line 120
    .line 121
    .line 122
    move-result-object v5

    .line 123
    if-eqz v5, :cond_7

    .line 124
    .line 125
    invoke-virtual {v5}, Landroid/view/View;->getVisibility()I

    .line 126
    .line 127
    .line 128
    move-result v6

    .line 129
    if-eq v6, v1, :cond_7

    .line 130
    .line 131
    invoke-virtual {p0, v2}, Lm/r1;->i(I)Z

    .line 132
    .line 133
    .line 134
    move-result v6

    .line 135
    if-eqz v6, :cond_7

    .line 136
    .line 137
    invoke-virtual {v5}, Landroid/view/View;->getLayoutParams()Landroid/view/ViewGroup$LayoutParams;

    .line 138
    .line 139
    .line 140
    move-result-object v6

    .line 141
    check-cast v6, Lm/q1;

    .line 142
    .line 143
    if-eqz v4, :cond_6

    .line 144
    .line 145
    invoke-virtual {v5}, Landroid/view/View;->getRight()I

    .line 146
    .line 147
    .line 148
    move-result v5

    .line 149
    iget v6, v6, Landroid/widget/LinearLayout$LayoutParams;->rightMargin:I

    .line 150
    .line 151
    add-int/2addr v5, v6

    .line 152
    goto :goto_3

    .line 153
    :cond_6
    invoke-virtual {v5}, Landroid/view/View;->getLeft()I

    .line 154
    .line 155
    .line 156
    move-result v5

    .line 157
    iget v6, v6, Landroid/widget/LinearLayout$LayoutParams;->leftMargin:I

    .line 158
    .line 159
    sub-int/2addr v5, v6

    .line 160
    iget v6, p0, Lm/r1;->o:I

    .line 161
    .line 162
    sub-int/2addr v5, v6

    .line 163
    :goto_3
    invoke-virtual {p0, p1, v5}, Lm/r1;->e(Landroid/graphics/Canvas;I)V

    .line 164
    .line 165
    .line 166
    :cond_7
    add-int/lit8 v2, v2, 0x1

    .line 167
    .line 168
    goto :goto_2

    .line 169
    :cond_8
    invoke-virtual {p0, v0}, Lm/r1;->i(I)Z

    .line 170
    .line 171
    .line 172
    move-result v1

    .line 173
    if-eqz v1, :cond_c

    .line 174
    .line 175
    sub-int/2addr v0, v3

    .line 176
    invoke-virtual {p0, v0}, Landroid/view/ViewGroup;->getChildAt(I)Landroid/view/View;

    .line 177
    .line 178
    .line 179
    move-result-object v0

    .line 180
    if-nez v0, :cond_a

    .line 181
    .line 182
    if-eqz v4, :cond_9

    .line 183
    .line 184
    invoke-virtual {p0}, Landroid/view/View;->getPaddingLeft()I

    .line 185
    .line 186
    .line 187
    move-result v0

    .line 188
    goto :goto_5

    .line 189
    :cond_9
    invoke-virtual {p0}, Landroid/view/View;->getWidth()I

    .line 190
    .line 191
    .line 192
    move-result v0

    .line 193
    invoke-virtual {p0}, Landroid/view/View;->getPaddingRight()I

    .line 194
    .line 195
    .line 196
    move-result v1

    .line 197
    sub-int/2addr v0, v1

    .line 198
    iget v1, p0, Lm/r1;->o:I

    .line 199
    .line 200
    :goto_4
    sub-int/2addr v0, v1

    .line 201
    goto :goto_5

    .line 202
    :cond_a
    invoke-virtual {v0}, Landroid/view/View;->getLayoutParams()Landroid/view/ViewGroup$LayoutParams;

    .line 203
    .line 204
    .line 205
    move-result-object v1

    .line 206
    check-cast v1, Lm/q1;

    .line 207
    .line 208
    if-eqz v4, :cond_b

    .line 209
    .line 210
    invoke-virtual {v0}, Landroid/view/View;->getLeft()I

    .line 211
    .line 212
    .line 213
    move-result v0

    .line 214
    iget v1, v1, Landroid/widget/LinearLayout$LayoutParams;->leftMargin:I

    .line 215
    .line 216
    sub-int/2addr v0, v1

    .line 217
    iget v1, p0, Lm/r1;->o:I

    .line 218
    .line 219
    goto :goto_4

    .line 220
    :cond_b
    invoke-virtual {v0}, Landroid/view/View;->getRight()I

    .line 221
    .line 222
    .line 223
    move-result v0

    .line 224
    iget v1, v1, Landroid/widget/LinearLayout$LayoutParams;->rightMargin:I

    .line 225
    .line 226
    add-int/2addr v0, v1

    .line 227
    :goto_5
    invoke-virtual {p0, p1, v0}, Lm/r1;->e(Landroid/graphics/Canvas;I)V

    .line 228
    .line 229
    .line 230
    :cond_c
    :goto_6
    return-void
.end method

.method public final onInitializeAccessibilityEvent(Landroid/view/accessibility/AccessibilityEvent;)V
    .locals 0

    .line 1
    invoke-super {p0, p1}, Landroid/view/View;->onInitializeAccessibilityEvent(Landroid/view/accessibility/AccessibilityEvent;)V

    .line 2
    .line 3
    .line 4
    const-string p0, "androidx.appcompat.widget.LinearLayoutCompat"

    .line 5
    .line 6
    invoke-virtual {p1, p0}, Landroid/view/accessibility/AccessibilityRecord;->setClassName(Ljava/lang/CharSequence;)V

    .line 7
    .line 8
    .line 9
    return-void
.end method

.method public final onInitializeAccessibilityNodeInfo(Landroid/view/accessibility/AccessibilityNodeInfo;)V
    .locals 0

    .line 1
    invoke-super {p0, p1}, Landroid/view/View;->onInitializeAccessibilityNodeInfo(Landroid/view/accessibility/AccessibilityNodeInfo;)V

    .line 2
    .line 3
    .line 4
    const-string p0, "androidx.appcompat.widget.LinearLayoutCompat"

    .line 5
    .line 6
    invoke-virtual {p1, p0}, Landroid/view/accessibility/AccessibilityNodeInfo;->setClassName(Ljava/lang/CharSequence;)V

    .line 7
    .line 8
    .line 9
    return-void
.end method

.method public onLayout(ZIIII)V
    .locals 22

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Lm/r1;->g:I

    .line 4
    .line 5
    const/4 v2, 0x5

    .line 6
    const/16 v3, 0x8

    .line 7
    .line 8
    const/16 v5, 0x50

    .line 9
    .line 10
    const/16 v6, 0x10

    .line 11
    .line 12
    const v7, 0x800007

    .line 13
    .line 14
    .line 15
    const/4 v8, 0x2

    .line 16
    const/4 v9, 0x1

    .line 17
    if-ne v1, v9, :cond_8

    .line 18
    .line 19
    invoke-virtual {v0}, Landroid/view/View;->getPaddingLeft()I

    .line 20
    .line 21
    .line 22
    move-result v1

    .line 23
    sub-int v10, p4, p2

    .line 24
    .line 25
    invoke-virtual {v0}, Landroid/view/View;->getPaddingRight()I

    .line 26
    .line 27
    .line 28
    move-result v11

    .line 29
    sub-int v11, v10, v11

    .line 30
    .line 31
    sub-int/2addr v10, v1

    .line 32
    invoke-virtual {v0}, Landroid/view/View;->getPaddingRight()I

    .line 33
    .line 34
    .line 35
    move-result v12

    .line 36
    sub-int/2addr v10, v12

    .line 37
    invoke-virtual {v0}, Lm/r1;->getVirtualChildCount()I

    .line 38
    .line 39
    .line 40
    move-result v12

    .line 41
    iget v13, v0, Lm/r1;->h:I

    .line 42
    .line 43
    and-int/lit8 v14, v13, 0x70

    .line 44
    .line 45
    and-int/2addr v7, v13

    .line 46
    if-eq v14, v6, :cond_1

    .line 47
    .line 48
    if-eq v14, v5, :cond_0

    .line 49
    .line 50
    invoke-virtual {v0}, Landroid/view/View;->getPaddingTop()I

    .line 51
    .line 52
    .line 53
    move-result v5

    .line 54
    goto :goto_0

    .line 55
    :cond_0
    invoke-virtual {v0}, Landroid/view/View;->getPaddingTop()I

    .line 56
    .line 57
    .line 58
    move-result v5

    .line 59
    add-int v5, v5, p5

    .line 60
    .line 61
    sub-int v5, v5, p3

    .line 62
    .line 63
    iget v6, v0, Lm/r1;->i:I

    .line 64
    .line 65
    sub-int/2addr v5, v6

    .line 66
    goto :goto_0

    .line 67
    :cond_1
    invoke-virtual {v0}, Landroid/view/View;->getPaddingTop()I

    .line 68
    .line 69
    .line 70
    move-result v5

    .line 71
    sub-int v6, p5, p3

    .line 72
    .line 73
    iget v13, v0, Lm/r1;->i:I

    .line 74
    .line 75
    sub-int/2addr v6, v13

    .line 76
    div-int/2addr v6, v8

    .line 77
    add-int/2addr v5, v6

    .line 78
    :goto_0
    const/4 v4, 0x0

    .line 79
    :goto_1
    if-ge v4, v12, :cond_17

    .line 80
    .line 81
    invoke-virtual {v0, v4}, Landroid/view/ViewGroup;->getChildAt(I)Landroid/view/View;

    .line 82
    .line 83
    .line 84
    move-result-object v6

    .line 85
    if-nez v6, :cond_3

    .line 86
    .line 87
    :cond_2
    move/from16 p1, v8

    .line 88
    .line 89
    goto :goto_4

    .line 90
    :cond_3
    invoke-virtual {v6}, Landroid/view/View;->getVisibility()I

    .line 91
    .line 92
    .line 93
    move-result v13

    .line 94
    if-eq v13, v3, :cond_2

    .line 95
    .line 96
    invoke-virtual {v6}, Landroid/view/View;->getMeasuredWidth()I

    .line 97
    .line 98
    .line 99
    move-result v13

    .line 100
    invoke-virtual {v6}, Landroid/view/View;->getMeasuredHeight()I

    .line 101
    .line 102
    .line 103
    move-result v14

    .line 104
    invoke-virtual {v6}, Landroid/view/View;->getLayoutParams()Landroid/view/ViewGroup$LayoutParams;

    .line 105
    .line 106
    .line 107
    move-result-object v15

    .line 108
    check-cast v15, Lm/q1;

    .line 109
    .line 110
    move/from16 p1, v8

    .line 111
    .line 112
    iget v8, v15, Landroid/widget/LinearLayout$LayoutParams;->gravity:I

    .line 113
    .line 114
    if-gez v8, :cond_4

    .line 115
    .line 116
    move v8, v7

    .line 117
    :cond_4
    invoke-virtual {v0}, Landroid/view/View;->getLayoutDirection()I

    .line 118
    .line 119
    .line 120
    move-result v3

    .line 121
    invoke-static {v8, v3}, Landroid/view/Gravity;->getAbsoluteGravity(II)I

    .line 122
    .line 123
    .line 124
    move-result v3

    .line 125
    and-int/lit8 v3, v3, 0x7

    .line 126
    .line 127
    if-eq v3, v9, :cond_6

    .line 128
    .line 129
    if-eq v3, v2, :cond_5

    .line 130
    .line 131
    iget v3, v15, Landroid/widget/LinearLayout$LayoutParams;->leftMargin:I

    .line 132
    .line 133
    add-int/2addr v3, v1

    .line 134
    goto :goto_3

    .line 135
    :cond_5
    sub-int v3, v11, v13

    .line 136
    .line 137
    iget v8, v15, Landroid/widget/LinearLayout$LayoutParams;->rightMargin:I

    .line 138
    .line 139
    :goto_2
    sub-int/2addr v3, v8

    .line 140
    goto :goto_3

    .line 141
    :cond_6
    sub-int v3, v10, v13

    .line 142
    .line 143
    div-int/lit8 v3, v3, 0x2

    .line 144
    .line 145
    add-int/2addr v3, v1

    .line 146
    iget v8, v15, Landroid/widget/LinearLayout$LayoutParams;->leftMargin:I

    .line 147
    .line 148
    add-int/2addr v3, v8

    .line 149
    iget v8, v15, Landroid/widget/LinearLayout$LayoutParams;->rightMargin:I

    .line 150
    .line 151
    goto :goto_2

    .line 152
    :goto_3
    invoke-virtual {v0, v4}, Lm/r1;->i(I)Z

    .line 153
    .line 154
    .line 155
    move-result v8

    .line 156
    if-eqz v8, :cond_7

    .line 157
    .line 158
    iget v8, v0, Lm/r1;->p:I

    .line 159
    .line 160
    add-int/2addr v5, v8

    .line 161
    :cond_7
    iget v8, v15, Landroid/widget/LinearLayout$LayoutParams;->topMargin:I

    .line 162
    .line 163
    add-int/2addr v5, v8

    .line 164
    add-int/2addr v13, v3

    .line 165
    add-int v8, v5, v14

    .line 166
    .line 167
    invoke-virtual {v6, v3, v5, v13, v8}, Landroid/view/View;->layout(IIII)V

    .line 168
    .line 169
    .line 170
    iget v3, v15, Landroid/widget/LinearLayout$LayoutParams;->bottomMargin:I

    .line 171
    .line 172
    add-int/2addr v14, v3

    .line 173
    add-int/2addr v14, v5

    .line 174
    move v5, v14

    .line 175
    :goto_4
    add-int/lit8 v4, v4, 0x1

    .line 176
    .line 177
    move/from16 v8, p1

    .line 178
    .line 179
    const/16 v3, 0x8

    .line 180
    .line 181
    goto :goto_1

    .line 182
    :cond_8
    move/from16 p1, v8

    .line 183
    .line 184
    invoke-virtual {v0}, Landroid/view/View;->getLayoutDirection()I

    .line 185
    .line 186
    .line 187
    move-result v1

    .line 188
    if-ne v1, v9, :cond_9

    .line 189
    .line 190
    move v1, v9

    .line 191
    goto :goto_5

    .line 192
    :cond_9
    const/4 v1, 0x0

    .line 193
    :goto_5
    invoke-virtual {v0}, Landroid/view/View;->getPaddingTop()I

    .line 194
    .line 195
    .line 196
    move-result v3

    .line 197
    sub-int v8, p5, p3

    .line 198
    .line 199
    invoke-virtual {v0}, Landroid/view/View;->getPaddingBottom()I

    .line 200
    .line 201
    .line 202
    move-result v10

    .line 203
    sub-int v10, v8, v10

    .line 204
    .line 205
    sub-int/2addr v8, v3

    .line 206
    invoke-virtual {v0}, Landroid/view/View;->getPaddingBottom()I

    .line 207
    .line 208
    .line 209
    move-result v11

    .line 210
    sub-int/2addr v8, v11

    .line 211
    invoke-virtual {v0}, Lm/r1;->getVirtualChildCount()I

    .line 212
    .line 213
    .line 214
    move-result v11

    .line 215
    iget v12, v0, Lm/r1;->h:I

    .line 216
    .line 217
    and-int/2addr v7, v12

    .line 218
    and-int/lit8 v12, v12, 0x70

    .line 219
    .line 220
    iget-boolean v13, v0, Lm/r1;->d:Z

    .line 221
    .line 222
    iget-object v14, v0, Lm/r1;->l:[I

    .line 223
    .line 224
    iget-object v15, v0, Lm/r1;->m:[I

    .line 225
    .line 226
    invoke-virtual {v0}, Landroid/view/View;->getLayoutDirection()I

    .line 227
    .line 228
    .line 229
    move-result v4

    .line 230
    invoke-static {v7, v4}, Landroid/view/Gravity;->getAbsoluteGravity(II)I

    .line 231
    .line 232
    .line 233
    move-result v4

    .line 234
    if-eq v4, v9, :cond_b

    .line 235
    .line 236
    if-eq v4, v2, :cond_a

    .line 237
    .line 238
    invoke-virtual {v0}, Landroid/view/View;->getPaddingLeft()I

    .line 239
    .line 240
    .line 241
    move-result v2

    .line 242
    goto :goto_6

    .line 243
    :cond_a
    invoke-virtual {v0}, Landroid/view/View;->getPaddingLeft()I

    .line 244
    .line 245
    .line 246
    move-result v2

    .line 247
    add-int v2, v2, p4

    .line 248
    .line 249
    sub-int v2, v2, p2

    .line 250
    .line 251
    iget v4, v0, Lm/r1;->i:I

    .line 252
    .line 253
    sub-int/2addr v2, v4

    .line 254
    goto :goto_6

    .line 255
    :cond_b
    invoke-virtual {v0}, Landroid/view/View;->getPaddingLeft()I

    .line 256
    .line 257
    .line 258
    move-result v2

    .line 259
    sub-int v4, p4, p2

    .line 260
    .line 261
    iget v7, v0, Lm/r1;->i:I

    .line 262
    .line 263
    sub-int/2addr v4, v7

    .line 264
    div-int/lit8 v4, v4, 0x2

    .line 265
    .line 266
    add-int/2addr v2, v4

    .line 267
    :goto_6
    if-eqz v1, :cond_c

    .line 268
    .line 269
    add-int/lit8 v1, v11, -0x1

    .line 270
    .line 271
    const/4 v7, -0x1

    .line 272
    goto :goto_7

    .line 273
    :cond_c
    move v7, v9

    .line 274
    const/4 v1, 0x0

    .line 275
    :goto_7
    move/from16 v17, v9

    .line 276
    .line 277
    const/4 v9, 0x0

    .line 278
    :goto_8
    if-ge v9, v11, :cond_17

    .line 279
    .line 280
    mul-int v18, v7, v9

    .line 281
    .line 282
    add-int v5, v18, v1

    .line 283
    .line 284
    invoke-virtual {v0, v5}, Landroid/view/ViewGroup;->getChildAt(I)Landroid/view/View;

    .line 285
    .line 286
    .line 287
    move-result-object v6

    .line 288
    if-nez v6, :cond_d

    .line 289
    .line 290
    move/from16 p3, v1

    .line 291
    .line 292
    :goto_9
    move/from16 v19, v3

    .line 293
    .line 294
    goto/16 :goto_e

    .line 295
    .line 296
    :cond_d
    invoke-virtual {v6}, Landroid/view/View;->getVisibility()I

    .line 297
    .line 298
    .line 299
    move-result v4

    .line 300
    move/from16 p3, v1

    .line 301
    .line 302
    const/16 v1, 0x8

    .line 303
    .line 304
    if-eq v4, v1, :cond_16

    .line 305
    .line 306
    invoke-virtual {v6}, Landroid/view/View;->getMeasuredWidth()I

    .line 307
    .line 308
    .line 309
    move-result v4

    .line 310
    invoke-virtual {v6}, Landroid/view/View;->getMeasuredHeight()I

    .line 311
    .line 312
    .line 313
    move-result v16

    .line 314
    invoke-virtual {v6}, Landroid/view/View;->getLayoutParams()Landroid/view/ViewGroup$LayoutParams;

    .line 315
    .line 316
    .line 317
    move-result-object v19

    .line 318
    move-object/from16 v1, v19

    .line 319
    .line 320
    check-cast v1, Lm/q1;

    .line 321
    .line 322
    move/from16 p5, v2

    .line 323
    .line 324
    if-eqz v13, :cond_e

    .line 325
    .line 326
    iget v2, v1, Landroid/widget/LinearLayout$LayoutParams;->height:I

    .line 327
    .line 328
    move/from16 v19, v3

    .line 329
    .line 330
    const/4 v3, -0x1

    .line 331
    if-eq v2, v3, :cond_f

    .line 332
    .line 333
    invoke-virtual {v6}, Landroid/view/View;->getBaseline()I

    .line 334
    .line 335
    .line 336
    move-result v3

    .line 337
    goto :goto_a

    .line 338
    :cond_e
    move/from16 v19, v3

    .line 339
    .line 340
    :cond_f
    const/4 v3, -0x1

    .line 341
    :goto_a
    iget v2, v1, Landroid/widget/LinearLayout$LayoutParams;->gravity:I

    .line 342
    .line 343
    if-gez v2, :cond_10

    .line 344
    .line 345
    move v2, v12

    .line 346
    :cond_10
    and-int/lit8 v2, v2, 0x70

    .line 347
    .line 348
    move/from16 v20, v4

    .line 349
    .line 350
    const/16 v4, 0x10

    .line 351
    .line 352
    if-eq v2, v4, :cond_13

    .line 353
    .line 354
    const/16 v4, 0x30

    .line 355
    .line 356
    if-eq v2, v4, :cond_12

    .line 357
    .line 358
    const/16 v4, 0x50

    .line 359
    .line 360
    if-eq v2, v4, :cond_11

    .line 361
    .line 362
    move/from16 v2, v19

    .line 363
    .line 364
    const/4 v4, -0x1

    .line 365
    goto :goto_c

    .line 366
    :cond_11
    sub-int v2, v10, v16

    .line 367
    .line 368
    iget v4, v1, Landroid/widget/LinearLayout$LayoutParams;->bottomMargin:I

    .line 369
    .line 370
    sub-int/2addr v2, v4

    .line 371
    const/4 v4, -0x1

    .line 372
    if-eq v3, v4, :cond_14

    .line 373
    .line 374
    invoke-virtual {v6}, Landroid/view/View;->getMeasuredHeight()I

    .line 375
    .line 376
    .line 377
    move-result v21

    .line 378
    sub-int v21, v21, v3

    .line 379
    .line 380
    aget v3, v15, p1

    .line 381
    .line 382
    sub-int v3, v3, v21

    .line 383
    .line 384
    :goto_b
    sub-int/2addr v2, v3

    .line 385
    goto :goto_c

    .line 386
    :cond_12
    const/4 v4, -0x1

    .line 387
    iget v2, v1, Landroid/widget/LinearLayout$LayoutParams;->topMargin:I

    .line 388
    .line 389
    add-int v2, v19, v2

    .line 390
    .line 391
    if-eq v3, v4, :cond_14

    .line 392
    .line 393
    aget v21, v14, v17

    .line 394
    .line 395
    sub-int v21, v21, v3

    .line 396
    .line 397
    add-int v2, v21, v2

    .line 398
    .line 399
    goto :goto_c

    .line 400
    :cond_13
    const/4 v4, -0x1

    .line 401
    sub-int v2, v8, v16

    .line 402
    .line 403
    div-int/lit8 v2, v2, 0x2

    .line 404
    .line 405
    add-int v2, v2, v19

    .line 406
    .line 407
    iget v3, v1, Landroid/widget/LinearLayout$LayoutParams;->topMargin:I

    .line 408
    .line 409
    add-int/2addr v2, v3

    .line 410
    iget v3, v1, Landroid/widget/LinearLayout$LayoutParams;->bottomMargin:I

    .line 411
    .line 412
    goto :goto_b

    .line 413
    :cond_14
    :goto_c
    invoke-virtual {v0, v5}, Lm/r1;->i(I)Z

    .line 414
    .line 415
    .line 416
    move-result v3

    .line 417
    if-eqz v3, :cond_15

    .line 418
    .line 419
    iget v3, v0, Lm/r1;->o:I

    .line 420
    .line 421
    add-int v3, p5, v3

    .line 422
    .line 423
    goto :goto_d

    .line 424
    :cond_15
    move/from16 v3, p5

    .line 425
    .line 426
    :goto_d
    iget v5, v1, Landroid/widget/LinearLayout$LayoutParams;->leftMargin:I

    .line 427
    .line 428
    add-int/2addr v3, v5

    .line 429
    add-int v5, v3, v20

    .line 430
    .line 431
    add-int v4, v2, v16

    .line 432
    .line 433
    invoke-virtual {v6, v3, v2, v5, v4}, Landroid/view/View;->layout(IIII)V

    .line 434
    .line 435
    .line 436
    iget v1, v1, Landroid/widget/LinearLayout$LayoutParams;->rightMargin:I

    .line 437
    .line 438
    add-int v4, v20, v1

    .line 439
    .line 440
    add-int/2addr v4, v3

    .line 441
    move v2, v4

    .line 442
    goto :goto_e

    .line 443
    :cond_16
    move/from16 p5, v2

    .line 444
    .line 445
    goto/16 :goto_9

    .line 446
    .line 447
    :goto_e
    add-int/lit8 v9, v9, 0x1

    .line 448
    .line 449
    move/from16 v1, p3

    .line 450
    .line 451
    move/from16 v3, v19

    .line 452
    .line 453
    const/16 v5, 0x50

    .line 454
    .line 455
    const/16 v6, 0x10

    .line 456
    .line 457
    goto/16 :goto_8

    .line 458
    .line 459
    :cond_17
    return-void
.end method

.method public onMeasure(II)V
    .locals 38

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Lm/r1;->g:I

    .line 4
    .line 5
    const/4 v7, -0x2

    .line 6
    const/4 v9, 0x0

    .line 7
    const/high16 v10, 0x40000000    # 2.0f

    .line 8
    .line 9
    const/16 v11, 0x8

    .line 10
    .line 11
    const/4 v14, 0x1

    .line 12
    if-ne v1, v14, :cond_29

    .line 13
    .line 14
    iput v9, v0, Lm/r1;->i:I

    .line 15
    .line 16
    invoke-virtual {v0}, Lm/r1;->getVirtualChildCount()I

    .line 17
    .line 18
    .line 19
    move-result v15

    .line 20
    invoke-static/range {p1 .. p1}, Landroid/view/View$MeasureSpec;->getMode(I)I

    .line 21
    .line 22
    .line 23
    move-result v1

    .line 24
    invoke-static/range {p2 .. p2}, Landroid/view/View$MeasureSpec;->getMode(I)I

    .line 25
    .line 26
    .line 27
    move-result v2

    .line 28
    iget v3, v0, Lm/r1;->e:I

    .line 29
    .line 30
    iget-boolean v4, v0, Lm/r1;->k:Z

    .line 31
    .line 32
    move v5, v9

    .line 33
    move v6, v5

    .line 34
    move v8, v6

    .line 35
    move/from16 v19, v8

    .line 36
    .line 37
    move/from16 v22, v19

    .line 38
    .line 39
    move/from16 v23, v22

    .line 40
    .line 41
    move/from16 v20, v14

    .line 42
    .line 43
    move/from16 v24, v20

    .line 44
    .line 45
    const/16 v16, 0x0

    .line 46
    .line 47
    const v17, 0xffffff

    .line 48
    .line 49
    .line 50
    const/16 v18, 0x0

    .line 51
    .line 52
    move/from16 v14, v23

    .line 53
    .line 54
    :goto_0
    if-ge v5, v15, :cond_11

    .line 55
    .line 56
    move/from16 v25, v1

    .line 57
    .line 58
    invoke-virtual {v0, v5}, Landroid/view/ViewGroup;->getChildAt(I)Landroid/view/View;

    .line 59
    .line 60
    .line 61
    move-result-object v1

    .line 62
    if-nez v1, :cond_0

    .line 63
    .line 64
    iget v1, v0, Lm/r1;->i:I

    .line 65
    .line 66
    iput v1, v0, Lm/r1;->i:I

    .line 67
    .line 68
    :goto_1
    move/from16 v29, v2

    .line 69
    .line 70
    move v7, v3

    .line 71
    move/from16 v28, v4

    .line 72
    .line 73
    move v13, v5

    .line 74
    move/from16 v12, v25

    .line 75
    .line 76
    move/from16 v2, p1

    .line 77
    .line 78
    move/from16 v4, p2

    .line 79
    .line 80
    goto/16 :goto_c

    .line 81
    .line 82
    :cond_0
    invoke-virtual {v1}, Landroid/view/View;->getVisibility()I

    .line 83
    .line 84
    .line 85
    move-result v12

    .line 86
    if-ne v12, v11, :cond_1

    .line 87
    .line 88
    goto :goto_1

    .line 89
    :cond_1
    invoke-virtual {v0, v5}, Lm/r1;->i(I)Z

    .line 90
    .line 91
    .line 92
    move-result v12

    .line 93
    if-eqz v12, :cond_2

    .line 94
    .line 95
    iget v12, v0, Lm/r1;->i:I

    .line 96
    .line 97
    iget v11, v0, Lm/r1;->p:I

    .line 98
    .line 99
    add-int/2addr v12, v11

    .line 100
    iput v12, v0, Lm/r1;->i:I

    .line 101
    .line 102
    :cond_2
    invoke-virtual {v1}, Landroid/view/View;->getLayoutParams()Landroid/view/ViewGroup$LayoutParams;

    .line 103
    .line 104
    .line 105
    move-result-object v11

    .line 106
    check-cast v11, Lm/q1;

    .line 107
    .line 108
    iget v12, v11, Landroid/widget/LinearLayout$LayoutParams;->weight:F

    .line 109
    .line 110
    add-float v16, v16, v12

    .line 111
    .line 112
    if-ne v2, v10, :cond_3

    .line 113
    .line 114
    iget v10, v11, Landroid/widget/LinearLayout$LayoutParams;->height:I

    .line 115
    .line 116
    if-nez v10, :cond_3

    .line 117
    .line 118
    cmpl-float v10, v12, v18

    .line 119
    .line 120
    if-lez v10, :cond_3

    .line 121
    .line 122
    iget v10, v0, Lm/r1;->i:I

    .line 123
    .line 124
    iget v12, v11, Landroid/widget/LinearLayout$LayoutParams;->topMargin:I

    .line 125
    .line 126
    add-int/2addr v12, v10

    .line 127
    iget v13, v11, Landroid/widget/LinearLayout$LayoutParams;->bottomMargin:I

    .line 128
    .line 129
    add-int/2addr v12, v13

    .line 130
    invoke-static {v10, v12}, Ljava/lang/Math;->max(II)I

    .line 131
    .line 132
    .line 133
    move-result v10

    .line 134
    iput v10, v0, Lm/r1;->i:I

    .line 135
    .line 136
    move-object/from16 v30, v1

    .line 137
    .line 138
    move/from16 v29, v2

    .line 139
    .line 140
    move v7, v3

    .line 141
    move/from16 v28, v4

    .line 142
    .line 143
    move v13, v5

    .line 144
    move/from16 v19, v20

    .line 145
    .line 146
    move/from16 v12, v25

    .line 147
    .line 148
    move/from16 v2, p1

    .line 149
    .line 150
    move/from16 v4, p2

    .line 151
    .line 152
    goto :goto_5

    .line 153
    :cond_3
    iget v10, v11, Landroid/widget/LinearLayout$LayoutParams;->height:I

    .line 154
    .line 155
    if-nez v10, :cond_4

    .line 156
    .line 157
    cmpl-float v10, v12, v18

    .line 158
    .line 159
    if-lez v10, :cond_4

    .line 160
    .line 161
    iput v7, v11, Landroid/widget/LinearLayout$LayoutParams;->height:I

    .line 162
    .line 163
    const/4 v10, 0x0

    .line 164
    goto :goto_2

    .line 165
    :cond_4
    const/high16 v10, -0x80000000

    .line 166
    .line 167
    :goto_2
    cmpl-float v12, v16, v18

    .line 168
    .line 169
    if-nez v12, :cond_5

    .line 170
    .line 171
    iget v12, v0, Lm/r1;->i:I

    .line 172
    .line 173
    move v13, v12

    .line 174
    move v12, v5

    .line 175
    move v5, v13

    .line 176
    :goto_3
    move v13, v3

    .line 177
    goto :goto_4

    .line 178
    :cond_5
    move v12, v5

    .line 179
    const/4 v5, 0x0

    .line 180
    goto :goto_3

    .line 181
    :goto_4
    const/4 v3, 0x0

    .line 182
    move/from16 v29, v2

    .line 183
    .line 184
    move/from16 v28, v4

    .line 185
    .line 186
    move v7, v13

    .line 187
    move/from16 v2, p1

    .line 188
    .line 189
    move/from16 v4, p2

    .line 190
    .line 191
    move v13, v12

    .line 192
    move/from16 v12, v25

    .line 193
    .line 194
    invoke-virtual/range {v0 .. v5}, Landroid/view/ViewGroup;->measureChildWithMargins(Landroid/view/View;IIII)V

    .line 195
    .line 196
    .line 197
    const/high16 v3, -0x80000000

    .line 198
    .line 199
    if-eq v10, v3, :cond_6

    .line 200
    .line 201
    iput v10, v11, Landroid/widget/LinearLayout$LayoutParams;->height:I

    .line 202
    .line 203
    :cond_6
    invoke-virtual {v1}, Landroid/view/View;->getMeasuredHeight()I

    .line 204
    .line 205
    .line 206
    move-result v3

    .line 207
    iget v5, v0, Lm/r1;->i:I

    .line 208
    .line 209
    add-int v10, v5, v3

    .line 210
    .line 211
    move-object/from16 v30, v1

    .line 212
    .line 213
    iget v1, v11, Landroid/widget/LinearLayout$LayoutParams;->topMargin:I

    .line 214
    .line 215
    add-int/2addr v10, v1

    .line 216
    iget v1, v11, Landroid/widget/LinearLayout$LayoutParams;->bottomMargin:I

    .line 217
    .line 218
    add-int/2addr v10, v1

    .line 219
    invoke-static {v5, v10}, Ljava/lang/Math;->max(II)I

    .line 220
    .line 221
    .line 222
    move-result v1

    .line 223
    iput v1, v0, Lm/r1;->i:I

    .line 224
    .line 225
    if-eqz v28, :cond_7

    .line 226
    .line 227
    invoke-static {v3, v14}, Ljava/lang/Math;->max(II)I

    .line 228
    .line 229
    .line 230
    move-result v14

    .line 231
    :cond_7
    :goto_5
    if-ltz v7, :cond_8

    .line 232
    .line 233
    add-int/lit8 v5, v13, 0x1

    .line 234
    .line 235
    if-ne v7, v5, :cond_8

    .line 236
    .line 237
    iget v1, v0, Lm/r1;->i:I

    .line 238
    .line 239
    iput v1, v0, Lm/r1;->f:I

    .line 240
    .line 241
    :cond_8
    if-ge v13, v7, :cond_9

    .line 242
    .line 243
    iget v1, v11, Landroid/widget/LinearLayout$LayoutParams;->weight:F

    .line 244
    .line 245
    cmpl-float v1, v1, v18

    .line 246
    .line 247
    if-gtz v1, :cond_a

    .line 248
    .line 249
    :cond_9
    const/high16 v1, 0x40000000    # 2.0f

    .line 250
    .line 251
    goto :goto_6

    .line 252
    :cond_a
    new-instance v0, Ljava/lang/RuntimeException;

    .line 253
    .line 254
    const-string v1, "A child of LinearLayout with index less than mBaselineAlignedChildIndex has weight > 0, which won\'t work.  Either remove the weight, or don\'t set mBaselineAlignedChildIndex."

    .line 255
    .line 256
    invoke-direct {v0, v1}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/String;)V

    .line 257
    .line 258
    .line 259
    throw v0

    .line 260
    :goto_6
    if-eq v12, v1, :cond_b

    .line 261
    .line 262
    iget v1, v11, Landroid/widget/LinearLayout$LayoutParams;->width:I

    .line 263
    .line 264
    const/4 v3, -0x1

    .line 265
    if-ne v1, v3, :cond_b

    .line 266
    .line 267
    move/from16 v1, v20

    .line 268
    .line 269
    move/from16 v23, v1

    .line 270
    .line 271
    goto :goto_7

    .line 272
    :cond_b
    const/4 v1, 0x0

    .line 273
    :goto_7
    iget v3, v11, Landroid/widget/LinearLayout$LayoutParams;->leftMargin:I

    .line 274
    .line 275
    iget v5, v11, Landroid/widget/LinearLayout$LayoutParams;->rightMargin:I

    .line 276
    .line 277
    add-int/2addr v3, v5

    .line 278
    invoke-virtual/range {v30 .. v30}, Landroid/view/View;->getMeasuredWidth()I

    .line 279
    .line 280
    .line 281
    move-result v5

    .line 282
    add-int/2addr v5, v3

    .line 283
    invoke-static {v9, v5}, Ljava/lang/Math;->max(II)I

    .line 284
    .line 285
    .line 286
    move-result v9

    .line 287
    invoke-virtual/range {v30 .. v30}, Landroid/view/View;->getMeasuredState()I

    .line 288
    .line 289
    .line 290
    move-result v10

    .line 291
    move/from16 v30, v1

    .line 292
    .line 293
    move/from16 v1, v22

    .line 294
    .line 295
    invoke-static {v1, v10}, Landroid/view/View;->combineMeasuredStates(II)I

    .line 296
    .line 297
    .line 298
    move-result v1

    .line 299
    if-eqz v24, :cond_c

    .line 300
    .line 301
    iget v10, v11, Landroid/widget/LinearLayout$LayoutParams;->width:I

    .line 302
    .line 303
    move/from16 v22, v1

    .line 304
    .line 305
    const/4 v1, -0x1

    .line 306
    if-ne v10, v1, :cond_d

    .line 307
    .line 308
    move/from16 v1, v20

    .line 309
    .line 310
    goto :goto_8

    .line 311
    :cond_c
    move/from16 v22, v1

    .line 312
    .line 313
    :cond_d
    const/4 v1, 0x0

    .line 314
    :goto_8
    iget v10, v11, Landroid/widget/LinearLayout$LayoutParams;->weight:F

    .line 315
    .line 316
    cmpl-float v10, v10, v18

    .line 317
    .line 318
    if-lez v10, :cond_f

    .line 319
    .line 320
    if-eqz v30, :cond_e

    .line 321
    .line 322
    goto :goto_9

    .line 323
    :cond_e
    move v3, v5

    .line 324
    :goto_9
    invoke-static {v8, v3}, Ljava/lang/Math;->max(II)I

    .line 325
    .line 326
    .line 327
    move-result v8

    .line 328
    goto :goto_b

    .line 329
    :cond_f
    if-eqz v30, :cond_10

    .line 330
    .line 331
    goto :goto_a

    .line 332
    :cond_10
    move v3, v5

    .line 333
    :goto_a
    invoke-static {v6, v3}, Ljava/lang/Math;->max(II)I

    .line 334
    .line 335
    .line 336
    move-result v6

    .line 337
    :goto_b
    move/from16 v24, v1

    .line 338
    .line 339
    :goto_c
    add-int/lit8 v5, v13, 0x1

    .line 340
    .line 341
    move v3, v7

    .line 342
    move v1, v12

    .line 343
    move/from16 v4, v28

    .line 344
    .line 345
    move/from16 v2, v29

    .line 346
    .line 347
    const/4 v7, -0x2

    .line 348
    const/high16 v10, 0x40000000    # 2.0f

    .line 349
    .line 350
    const/16 v11, 0x8

    .line 351
    .line 352
    goto/16 :goto_0

    .line 353
    .line 354
    :cond_11
    move v12, v1

    .line 355
    move/from16 v29, v2

    .line 356
    .line 357
    move/from16 v28, v4

    .line 358
    .line 359
    move/from16 v1, v22

    .line 360
    .line 361
    move/from16 v2, p1

    .line 362
    .line 363
    move/from16 v4, p2

    .line 364
    .line 365
    iget v3, v0, Lm/r1;->i:I

    .line 366
    .line 367
    if-lez v3, :cond_12

    .line 368
    .line 369
    invoke-virtual {v0, v15}, Lm/r1;->i(I)Z

    .line 370
    .line 371
    .line 372
    move-result v3

    .line 373
    if-eqz v3, :cond_12

    .line 374
    .line 375
    iget v3, v0, Lm/r1;->i:I

    .line 376
    .line 377
    iget v5, v0, Lm/r1;->p:I

    .line 378
    .line 379
    add-int/2addr v3, v5

    .line 380
    iput v3, v0, Lm/r1;->i:I

    .line 381
    .line 382
    :cond_12
    move/from16 v3, v29

    .line 383
    .line 384
    if-eqz v28, :cond_16

    .line 385
    .line 386
    const/high16 v5, -0x80000000

    .line 387
    .line 388
    if-eq v3, v5, :cond_13

    .line 389
    .line 390
    if-nez v3, :cond_16

    .line 391
    .line 392
    :cond_13
    const/4 v5, 0x0

    .line 393
    iput v5, v0, Lm/r1;->i:I

    .line 394
    .line 395
    const/4 v5, 0x0

    .line 396
    :goto_d
    if-ge v5, v15, :cond_16

    .line 397
    .line 398
    invoke-virtual {v0, v5}, Landroid/view/ViewGroup;->getChildAt(I)Landroid/view/View;

    .line 399
    .line 400
    .line 401
    move-result-object v7

    .line 402
    if-nez v7, :cond_14

    .line 403
    .line 404
    iget v7, v0, Lm/r1;->i:I

    .line 405
    .line 406
    iput v7, v0, Lm/r1;->i:I

    .line 407
    .line 408
    goto :goto_e

    .line 409
    :cond_14
    invoke-virtual {v7}, Landroid/view/View;->getVisibility()I

    .line 410
    .line 411
    .line 412
    move-result v10

    .line 413
    const/16 v11, 0x8

    .line 414
    .line 415
    if-ne v10, v11, :cond_15

    .line 416
    .line 417
    goto :goto_e

    .line 418
    :cond_15
    invoke-virtual {v7}, Landroid/view/View;->getLayoutParams()Landroid/view/ViewGroup$LayoutParams;

    .line 419
    .line 420
    .line 421
    move-result-object v7

    .line 422
    check-cast v7, Lm/q1;

    .line 423
    .line 424
    iget v10, v0, Lm/r1;->i:I

    .line 425
    .line 426
    add-int v11, v10, v14

    .line 427
    .line 428
    iget v13, v7, Landroid/widget/LinearLayout$LayoutParams;->topMargin:I

    .line 429
    .line 430
    add-int/2addr v11, v13

    .line 431
    iget v7, v7, Landroid/widget/LinearLayout$LayoutParams;->bottomMargin:I

    .line 432
    .line 433
    add-int/2addr v11, v7

    .line 434
    invoke-static {v10, v11}, Ljava/lang/Math;->max(II)I

    .line 435
    .line 436
    .line 437
    move-result v7

    .line 438
    iput v7, v0, Lm/r1;->i:I

    .line 439
    .line 440
    :goto_e
    add-int/lit8 v5, v5, 0x1

    .line 441
    .line 442
    goto :goto_d

    .line 443
    :cond_16
    iget v5, v0, Lm/r1;->i:I

    .line 444
    .line 445
    invoke-virtual {v0}, Landroid/view/View;->getPaddingTop()I

    .line 446
    .line 447
    .line 448
    move-result v7

    .line 449
    invoke-virtual {v0}, Landroid/view/View;->getPaddingBottom()I

    .line 450
    .line 451
    .line 452
    move-result v10

    .line 453
    add-int/2addr v10, v7

    .line 454
    add-int/2addr v10, v5

    .line 455
    iput v10, v0, Lm/r1;->i:I

    .line 456
    .line 457
    invoke-virtual {v0}, Landroid/view/View;->getSuggestedMinimumHeight()I

    .line 458
    .line 459
    .line 460
    move-result v5

    .line 461
    invoke-static {v10, v5}, Ljava/lang/Math;->max(II)I

    .line 462
    .line 463
    .line 464
    move-result v5

    .line 465
    const/4 v7, 0x0

    .line 466
    invoke-static {v5, v4, v7}, Landroid/view/View;->resolveSizeAndState(III)I

    .line 467
    .line 468
    .line 469
    move-result v5

    .line 470
    and-int v7, v5, v17

    .line 471
    .line 472
    iget v10, v0, Lm/r1;->i:I

    .line 473
    .line 474
    sub-int/2addr v7, v10

    .line 475
    if-nez v19, :cond_1a

    .line 476
    .line 477
    if-eqz v7, :cond_17

    .line 478
    .line 479
    cmpl-float v10, v16, v18

    .line 480
    .line 481
    if-lez v10, :cond_17

    .line 482
    .line 483
    goto :goto_11

    .line 484
    :cond_17
    invoke-static {v6, v8}, Ljava/lang/Math;->max(II)I

    .line 485
    .line 486
    .line 487
    move-result v6

    .line 488
    if-eqz v28, :cond_26

    .line 489
    .line 490
    const/high16 v7, 0x40000000    # 2.0f

    .line 491
    .line 492
    if-eq v3, v7, :cond_26

    .line 493
    .line 494
    const/4 v3, 0x0

    .line 495
    :goto_f
    if-ge v3, v15, :cond_26

    .line 496
    .line 497
    invoke-virtual {v0, v3}, Landroid/view/ViewGroup;->getChildAt(I)Landroid/view/View;

    .line 498
    .line 499
    .line 500
    move-result-object v7

    .line 501
    if-eqz v7, :cond_19

    .line 502
    .line 503
    invoke-virtual {v7}, Landroid/view/View;->getVisibility()I

    .line 504
    .line 505
    .line 506
    move-result v8

    .line 507
    const/16 v11, 0x8

    .line 508
    .line 509
    if-ne v8, v11, :cond_18

    .line 510
    .line 511
    goto :goto_10

    .line 512
    :cond_18
    invoke-virtual {v7}, Landroid/view/View;->getLayoutParams()Landroid/view/ViewGroup$LayoutParams;

    .line 513
    .line 514
    .line 515
    move-result-object v8

    .line 516
    check-cast v8, Lm/q1;

    .line 517
    .line 518
    iget v8, v8, Landroid/widget/LinearLayout$LayoutParams;->weight:F

    .line 519
    .line 520
    cmpl-float v8, v8, v18

    .line 521
    .line 522
    if-lez v8, :cond_19

    .line 523
    .line 524
    invoke-virtual {v7}, Landroid/view/View;->getMeasuredWidth()I

    .line 525
    .line 526
    .line 527
    move-result v8

    .line 528
    const/high16 v10, 0x40000000    # 2.0f

    .line 529
    .line 530
    invoke-static {v8, v10}, Landroid/view/View$MeasureSpec;->makeMeasureSpec(II)I

    .line 531
    .line 532
    .line 533
    move-result v8

    .line 534
    invoke-static {v14, v10}, Landroid/view/View$MeasureSpec;->makeMeasureSpec(II)I

    .line 535
    .line 536
    .line 537
    move-result v11

    .line 538
    invoke-virtual {v7, v8, v11}, Landroid/view/View;->measure(II)V

    .line 539
    .line 540
    .line 541
    :cond_19
    :goto_10
    add-int/lit8 v3, v3, 0x1

    .line 542
    .line 543
    goto :goto_f

    .line 544
    :cond_1a
    :goto_11
    iget v8, v0, Lm/r1;->j:F

    .line 545
    .line 546
    cmpl-float v10, v8, v18

    .line 547
    .line 548
    if-lez v10, :cond_1b

    .line 549
    .line 550
    move/from16 v16, v8

    .line 551
    .line 552
    :cond_1b
    const/4 v8, 0x0

    .line 553
    iput v8, v0, Lm/r1;->i:I

    .line 554
    .line 555
    move v8, v1

    .line 556
    const/4 v1, 0x0

    .line 557
    :goto_12
    if-ge v1, v15, :cond_25

    .line 558
    .line 559
    invoke-virtual {v0, v1}, Landroid/view/ViewGroup;->getChildAt(I)Landroid/view/View;

    .line 560
    .line 561
    .line 562
    move-result-object v10

    .line 563
    invoke-virtual {v10}, Landroid/view/View;->getVisibility()I

    .line 564
    .line 565
    .line 566
    move-result v11

    .line 567
    const/16 v13, 0x8

    .line 568
    .line 569
    if-ne v11, v13, :cond_1c

    .line 570
    .line 571
    move/from16 v17, v1

    .line 572
    .line 573
    goto/16 :goto_19

    .line 574
    .line 575
    :cond_1c
    invoke-virtual {v10}, Landroid/view/View;->getLayoutParams()Landroid/view/ViewGroup$LayoutParams;

    .line 576
    .line 577
    .line 578
    move-result-object v11

    .line 579
    check-cast v11, Lm/q1;

    .line 580
    .line 581
    iget v13, v11, Landroid/widget/LinearLayout$LayoutParams;->weight:F

    .line 582
    .line 583
    cmpl-float v14, v13, v18

    .line 584
    .line 585
    if-lez v14, :cond_21

    .line 586
    .line 587
    int-to-float v14, v7

    .line 588
    mul-float/2addr v14, v13

    .line 589
    div-float v14, v14, v16

    .line 590
    .line 591
    float-to-int v14, v14

    .line 592
    sub-float v16, v16, v13

    .line 593
    .line 594
    sub-int/2addr v7, v14

    .line 595
    invoke-virtual {v0}, Landroid/view/View;->getPaddingLeft()I

    .line 596
    .line 597
    .line 598
    move-result v13

    .line 599
    invoke-virtual {v0}, Landroid/view/View;->getPaddingRight()I

    .line 600
    .line 601
    .line 602
    move-result v17

    .line 603
    add-int v17, v17, v13

    .line 604
    .line 605
    iget v13, v11, Landroid/widget/LinearLayout$LayoutParams;->leftMargin:I

    .line 606
    .line 607
    add-int v17, v17, v13

    .line 608
    .line 609
    iget v13, v11, Landroid/widget/LinearLayout$LayoutParams;->rightMargin:I

    .line 610
    .line 611
    add-int v13, v17, v13

    .line 612
    .line 613
    move/from16 v17, v1

    .line 614
    .line 615
    iget v1, v11, Landroid/widget/LinearLayout$LayoutParams;->width:I

    .line 616
    .line 617
    invoke-static {v2, v13, v1}, Landroid/view/ViewGroup;->getChildMeasureSpec(III)I

    .line 618
    .line 619
    .line 620
    move-result v1

    .line 621
    iget v13, v11, Landroid/widget/LinearLayout$LayoutParams;->height:I

    .line 622
    .line 623
    if-nez v13, :cond_1f

    .line 624
    .line 625
    const/high16 v13, 0x40000000    # 2.0f

    .line 626
    .line 627
    if-eq v3, v13, :cond_1d

    .line 628
    .line 629
    goto :goto_14

    .line 630
    :cond_1d
    if-lez v14, :cond_1e

    .line 631
    .line 632
    goto :goto_13

    .line 633
    :cond_1e
    const/4 v14, 0x0

    .line 634
    :goto_13
    invoke-static {v14, v13}, Landroid/view/View$MeasureSpec;->makeMeasureSpec(II)I

    .line 635
    .line 636
    .line 637
    move-result v14

    .line 638
    invoke-virtual {v10, v1, v14}, Landroid/view/View;->measure(II)V

    .line 639
    .line 640
    .line 641
    goto :goto_15

    .line 642
    :cond_1f
    const/high16 v13, 0x40000000    # 2.0f

    .line 643
    .line 644
    :goto_14
    invoke-virtual {v10}, Landroid/view/View;->getMeasuredHeight()I

    .line 645
    .line 646
    .line 647
    move-result v19

    .line 648
    add-int v14, v19, v14

    .line 649
    .line 650
    if-gez v14, :cond_20

    .line 651
    .line 652
    const/4 v14, 0x0

    .line 653
    :cond_20
    invoke-static {v14, v13}, Landroid/view/View$MeasureSpec;->makeMeasureSpec(II)I

    .line 654
    .line 655
    .line 656
    move-result v14

    .line 657
    invoke-virtual {v10, v1, v14}, Landroid/view/View;->measure(II)V

    .line 658
    .line 659
    .line 660
    :goto_15
    invoke-virtual {v10}, Landroid/view/View;->getMeasuredState()I

    .line 661
    .line 662
    .line 663
    move-result v1

    .line 664
    and-int/lit16 v1, v1, -0x100

    .line 665
    .line 666
    invoke-static {v8, v1}, Landroid/view/View;->combineMeasuredStates(II)I

    .line 667
    .line 668
    .line 669
    move-result v8

    .line 670
    goto :goto_16

    .line 671
    :cond_21
    move/from16 v17, v1

    .line 672
    .line 673
    :goto_16
    iget v1, v11, Landroid/widget/LinearLayout$LayoutParams;->leftMargin:I

    .line 674
    .line 675
    iget v13, v11, Landroid/widget/LinearLayout$LayoutParams;->rightMargin:I

    .line 676
    .line 677
    add-int/2addr v1, v13

    .line 678
    invoke-virtual {v10}, Landroid/view/View;->getMeasuredWidth()I

    .line 679
    .line 680
    .line 681
    move-result v13

    .line 682
    add-int/2addr v13, v1

    .line 683
    invoke-static {v9, v13}, Ljava/lang/Math;->max(II)I

    .line 684
    .line 685
    .line 686
    move-result v9

    .line 687
    const/high16 v14, 0x40000000    # 2.0f

    .line 688
    .line 689
    if-eq v12, v14, :cond_22

    .line 690
    .line 691
    iget v14, v11, Landroid/widget/LinearLayout$LayoutParams;->width:I

    .line 692
    .line 693
    move/from16 v19, v1

    .line 694
    .line 695
    const/4 v1, -0x1

    .line 696
    if-ne v14, v1, :cond_23

    .line 697
    .line 698
    move/from16 v13, v19

    .line 699
    .line 700
    goto :goto_17

    .line 701
    :cond_22
    const/4 v1, -0x1

    .line 702
    :cond_23
    :goto_17
    invoke-static {v6, v13}, Ljava/lang/Math;->max(II)I

    .line 703
    .line 704
    .line 705
    move-result v6

    .line 706
    if-eqz v24, :cond_24

    .line 707
    .line 708
    iget v13, v11, Landroid/widget/LinearLayout$LayoutParams;->width:I

    .line 709
    .line 710
    if-ne v13, v1, :cond_24

    .line 711
    .line 712
    move/from16 v1, v20

    .line 713
    .line 714
    goto :goto_18

    .line 715
    :cond_24
    const/4 v1, 0x0

    .line 716
    :goto_18
    iget v13, v0, Lm/r1;->i:I

    .line 717
    .line 718
    invoke-virtual {v10}, Landroid/view/View;->getMeasuredHeight()I

    .line 719
    .line 720
    .line 721
    move-result v10

    .line 722
    add-int/2addr v10, v13

    .line 723
    iget v14, v11, Landroid/widget/LinearLayout$LayoutParams;->topMargin:I

    .line 724
    .line 725
    add-int/2addr v10, v14

    .line 726
    iget v11, v11, Landroid/widget/LinearLayout$LayoutParams;->bottomMargin:I

    .line 727
    .line 728
    add-int/2addr v10, v11

    .line 729
    invoke-static {v13, v10}, Ljava/lang/Math;->max(II)I

    .line 730
    .line 731
    .line 732
    move-result v10

    .line 733
    iput v10, v0, Lm/r1;->i:I

    .line 734
    .line 735
    move/from16 v24, v1

    .line 736
    .line 737
    :goto_19
    add-int/lit8 v1, v17, 0x1

    .line 738
    .line 739
    goto/16 :goto_12

    .line 740
    .line 741
    :cond_25
    iget v1, v0, Lm/r1;->i:I

    .line 742
    .line 743
    invoke-virtual {v0}, Landroid/view/View;->getPaddingTop()I

    .line 744
    .line 745
    .line 746
    move-result v3

    .line 747
    invoke-virtual {v0}, Landroid/view/View;->getPaddingBottom()I

    .line 748
    .line 749
    .line 750
    move-result v7

    .line 751
    add-int/2addr v7, v3

    .line 752
    add-int/2addr v7, v1

    .line 753
    iput v7, v0, Lm/r1;->i:I

    .line 754
    .line 755
    move v1, v8

    .line 756
    :cond_26
    if-nez v24, :cond_27

    .line 757
    .line 758
    const/high16 v13, 0x40000000    # 2.0f

    .line 759
    .line 760
    if-eq v12, v13, :cond_27

    .line 761
    .line 762
    goto :goto_1a

    .line 763
    :cond_27
    move v6, v9

    .line 764
    :goto_1a
    invoke-virtual {v0}, Landroid/view/View;->getPaddingLeft()I

    .line 765
    .line 766
    .line 767
    move-result v3

    .line 768
    invoke-virtual {v0}, Landroid/view/View;->getPaddingRight()I

    .line 769
    .line 770
    .line 771
    move-result v7

    .line 772
    add-int/2addr v7, v3

    .line 773
    add-int/2addr v7, v6

    .line 774
    invoke-virtual {v0}, Landroid/view/View;->getSuggestedMinimumWidth()I

    .line 775
    .line 776
    .line 777
    move-result v3

    .line 778
    invoke-static {v7, v3}, Ljava/lang/Math;->max(II)I

    .line 779
    .line 780
    .line 781
    move-result v3

    .line 782
    invoke-static {v3, v2, v1}, Landroid/view/View;->resolveSizeAndState(III)I

    .line 783
    .line 784
    .line 785
    move-result v1

    .line 786
    invoke-virtual {v0, v1, v5}, Landroid/view/View;->setMeasuredDimension(II)V

    .line 787
    .line 788
    .line 789
    if-eqz v23, :cond_63

    .line 790
    .line 791
    invoke-virtual {v0}, Landroid/view/View;->getMeasuredWidth()I

    .line 792
    .line 793
    .line 794
    move-result v1

    .line 795
    const/high16 v13, 0x40000000    # 2.0f

    .line 796
    .line 797
    invoke-static {v1, v13}, Landroid/view/View$MeasureSpec;->makeMeasureSpec(II)I

    .line 798
    .line 799
    .line 800
    move-result v2

    .line 801
    const/4 v9, 0x0

    .line 802
    :goto_1b
    if-ge v9, v15, :cond_63

    .line 803
    .line 804
    invoke-virtual {v0, v9}, Landroid/view/ViewGroup;->getChildAt(I)Landroid/view/View;

    .line 805
    .line 806
    .line 807
    move-result-object v1

    .line 808
    invoke-virtual {v1}, Landroid/view/View;->getVisibility()I

    .line 809
    .line 810
    .line 811
    move-result v3

    .line 812
    const/16 v11, 0x8

    .line 813
    .line 814
    if-eq v3, v11, :cond_28

    .line 815
    .line 816
    invoke-virtual {v1}, Landroid/view/View;->getLayoutParams()Landroid/view/ViewGroup$LayoutParams;

    .line 817
    .line 818
    .line 819
    move-result-object v3

    .line 820
    move-object v6, v3

    .line 821
    check-cast v6, Lm/q1;

    .line 822
    .line 823
    iget v3, v6, Landroid/widget/LinearLayout$LayoutParams;->width:I

    .line 824
    .line 825
    const/4 v5, -0x1

    .line 826
    if-ne v3, v5, :cond_28

    .line 827
    .line 828
    iget v7, v6, Landroid/widget/LinearLayout$LayoutParams;->height:I

    .line 829
    .line 830
    invoke-virtual {v1}, Landroid/view/View;->getMeasuredHeight()I

    .line 831
    .line 832
    .line 833
    move-result v3

    .line 834
    iput v3, v6, Landroid/widget/LinearLayout$LayoutParams;->height:I

    .line 835
    .line 836
    const/4 v3, 0x0

    .line 837
    const/4 v5, 0x0

    .line 838
    invoke-virtual/range {v0 .. v5}, Landroid/view/ViewGroup;->measureChildWithMargins(Landroid/view/View;IIII)V

    .line 839
    .line 840
    .line 841
    iput v7, v6, Landroid/widget/LinearLayout$LayoutParams;->height:I

    .line 842
    .line 843
    :cond_28
    add-int/lit8 v9, v9, 0x1

    .line 844
    .line 845
    move/from16 v4, p2

    .line 846
    .line 847
    goto :goto_1b

    .line 848
    :cond_29
    move/from16 v2, p1

    .line 849
    .line 850
    move v5, v9

    .line 851
    move/from16 v20, v14

    .line 852
    .line 853
    const v17, 0xffffff

    .line 854
    .line 855
    .line 856
    const/16 v18, 0x0

    .line 857
    .line 858
    iput v5, v0, Lm/r1;->i:I

    .line 859
    .line 860
    invoke-virtual {v0}, Lm/r1;->getVirtualChildCount()I

    .line 861
    .line 862
    .line 863
    move-result v6

    .line 864
    invoke-static {v2}, Landroid/view/View$MeasureSpec;->getMode(I)I

    .line 865
    .line 866
    .line 867
    move-result v7

    .line 868
    invoke-static/range {p2 .. p2}, Landroid/view/View$MeasureSpec;->getMode(I)I

    .line 869
    .line 870
    .line 871
    move-result v8

    .line 872
    iget-object v1, v0, Lm/r1;->l:[I

    .line 873
    .line 874
    const/4 v9, 0x4

    .line 875
    if-eqz v1, :cond_2a

    .line 876
    .line 877
    iget-object v1, v0, Lm/r1;->m:[I

    .line 878
    .line 879
    if-nez v1, :cond_2b

    .line 880
    .line 881
    :cond_2a
    new-array v1, v9, [I

    .line 882
    .line 883
    iput-object v1, v0, Lm/r1;->l:[I

    .line 884
    .line 885
    new-array v1, v9, [I

    .line 886
    .line 887
    iput-object v1, v0, Lm/r1;->m:[I

    .line 888
    .line 889
    :cond_2b
    iget-object v10, v0, Lm/r1;->l:[I

    .line 890
    .line 891
    iget-object v11, v0, Lm/r1;->m:[I

    .line 892
    .line 893
    const/4 v12, 0x3

    .line 894
    const/16 v26, -0x1

    .line 895
    .line 896
    aput v26, v10, v12

    .line 897
    .line 898
    const/4 v13, 0x2

    .line 899
    aput v26, v10, v13

    .line 900
    .line 901
    aput v26, v10, v20

    .line 902
    .line 903
    const/16 v21, 0x0

    .line 904
    .line 905
    aput v26, v10, v21

    .line 906
    .line 907
    aput v26, v11, v12

    .line 908
    .line 909
    aput v26, v11, v13

    .line 910
    .line 911
    aput v26, v11, v20

    .line 912
    .line 913
    aput v26, v11, v21

    .line 914
    .line 915
    iget-boolean v14, v0, Lm/r1;->d:Z

    .line 916
    .line 917
    iget-boolean v15, v0, Lm/r1;->k:Z

    .line 918
    .line 919
    const/high16 v1, 0x40000000    # 2.0f

    .line 920
    .line 921
    if-ne v7, v1, :cond_2c

    .line 922
    .line 923
    move/from16 v16, v20

    .line 924
    .line 925
    goto :goto_1c

    .line 926
    :cond_2c
    const/16 v16, 0x0

    .line 927
    .line 928
    :goto_1c
    move/from16 v23, v9

    .line 929
    .line 930
    move/from16 v24, v12

    .line 931
    .line 932
    move/from16 v28, v18

    .line 933
    .line 934
    move/from16 v29, v20

    .line 935
    .line 936
    const/4 v1, 0x0

    .line 937
    const/4 v3, 0x0

    .line 938
    const/4 v4, 0x0

    .line 939
    const/4 v5, 0x0

    .line 940
    const/4 v9, 0x0

    .line 941
    const/4 v12, 0x0

    .line 942
    const/16 v19, 0x0

    .line 943
    .line 944
    const/16 v22, 0x0

    .line 945
    .line 946
    :goto_1d
    if-ge v1, v6, :cond_40

    .line 947
    .line 948
    move/from16 v30, v13

    .line 949
    .line 950
    invoke-virtual {v0, v1}, Landroid/view/ViewGroup;->getChildAt(I)Landroid/view/View;

    .line 951
    .line 952
    .line 953
    move-result-object v13

    .line 954
    if-nez v13, :cond_2d

    .line 955
    .line 956
    iget v13, v0, Lm/r1;->i:I

    .line 957
    .line 958
    iput v13, v0, Lm/r1;->i:I

    .line 959
    .line 960
    move/from16 v33, v1

    .line 961
    .line 962
    move v1, v4

    .line 963
    move-object/from16 v31, v10

    .line 964
    .line 965
    move-object/from16 v32, v11

    .line 966
    .line 967
    move/from16 v34, v14

    .line 968
    .line 969
    move/from16 v35, v15

    .line 970
    .line 971
    move/from16 v4, p2

    .line 972
    .line 973
    goto/16 :goto_2b

    .line 974
    .line 975
    :cond_2d
    invoke-virtual {v13}, Landroid/view/View;->getVisibility()I

    .line 976
    .line 977
    .line 978
    move-result v2

    .line 979
    move/from16 v31, v3

    .line 980
    .line 981
    const/16 v3, 0x8

    .line 982
    .line 983
    if-ne v2, v3, :cond_2e

    .line 984
    .line 985
    move/from16 v2, p1

    .line 986
    .line 987
    move/from16 v33, v1

    .line 988
    .line 989
    move v1, v4

    .line 990
    move-object/from16 v32, v11

    .line 991
    .line 992
    move/from16 v34, v14

    .line 993
    .line 994
    move/from16 v35, v15

    .line 995
    .line 996
    move/from16 v3, v31

    .line 997
    .line 998
    move/from16 v4, p2

    .line 999
    .line 1000
    move-object/from16 v31, v10

    .line 1001
    .line 1002
    goto/16 :goto_2b

    .line 1003
    .line 1004
    :cond_2e
    invoke-virtual {v0, v1}, Lm/r1;->i(I)Z

    .line 1005
    .line 1006
    .line 1007
    move-result v2

    .line 1008
    if-eqz v2, :cond_2f

    .line 1009
    .line 1010
    iget v2, v0, Lm/r1;->i:I

    .line 1011
    .line 1012
    iget v3, v0, Lm/r1;->o:I

    .line 1013
    .line 1014
    add-int/2addr v2, v3

    .line 1015
    iput v2, v0, Lm/r1;->i:I

    .line 1016
    .line 1017
    :cond_2f
    invoke-virtual {v13}, Landroid/view/View;->getLayoutParams()Landroid/view/ViewGroup$LayoutParams;

    .line 1018
    .line 1019
    .line 1020
    move-result-object v2

    .line 1021
    check-cast v2, Lm/q1;

    .line 1022
    .line 1023
    iget v3, v2, Landroid/widget/LinearLayout$LayoutParams;->weight:F

    .line 1024
    .line 1025
    add-float v28, v28, v3

    .line 1026
    .line 1027
    move/from16 v32, v1

    .line 1028
    .line 1029
    const/high16 v1, 0x40000000    # 2.0f

    .line 1030
    .line 1031
    if-ne v7, v1, :cond_32

    .line 1032
    .line 1033
    iget v1, v2, Landroid/widget/LinearLayout$LayoutParams;->width:I

    .line 1034
    .line 1035
    if-nez v1, :cond_32

    .line 1036
    .line 1037
    cmpl-float v1, v3, v18

    .line 1038
    .line 1039
    if-lez v1, :cond_32

    .line 1040
    .line 1041
    if-eqz v16, :cond_30

    .line 1042
    .line 1043
    iget v1, v0, Lm/r1;->i:I

    .line 1044
    .line 1045
    iget v3, v2, Landroid/widget/LinearLayout$LayoutParams;->leftMargin:I

    .line 1046
    .line 1047
    move/from16 v33, v1

    .line 1048
    .line 1049
    iget v1, v2, Landroid/widget/LinearLayout$LayoutParams;->rightMargin:I

    .line 1050
    .line 1051
    add-int/2addr v3, v1

    .line 1052
    add-int v3, v3, v33

    .line 1053
    .line 1054
    iput v3, v0, Lm/r1;->i:I

    .line 1055
    .line 1056
    goto :goto_1e

    .line 1057
    :cond_30
    iget v1, v0, Lm/r1;->i:I

    .line 1058
    .line 1059
    iget v3, v2, Landroid/widget/LinearLayout$LayoutParams;->leftMargin:I

    .line 1060
    .line 1061
    add-int/2addr v3, v1

    .line 1062
    move/from16 v33, v3

    .line 1063
    .line 1064
    iget v3, v2, Landroid/widget/LinearLayout$LayoutParams;->rightMargin:I

    .line 1065
    .line 1066
    add-int v3, v33, v3

    .line 1067
    .line 1068
    invoke-static {v1, v3}, Ljava/lang/Math;->max(II)I

    .line 1069
    .line 1070
    .line 1071
    move-result v1

    .line 1072
    iput v1, v0, Lm/r1;->i:I

    .line 1073
    .line 1074
    :goto_1e
    if-eqz v14, :cond_31

    .line 1075
    .line 1076
    const/4 v1, 0x0

    .line 1077
    invoke-static {v1, v1}, Landroid/view/View$MeasureSpec;->makeMeasureSpec(II)I

    .line 1078
    .line 1079
    .line 1080
    move-result v3

    .line 1081
    invoke-virtual {v13, v3, v3}, Landroid/view/View;->measure(II)V

    .line 1082
    .line 1083
    .line 1084
    move-object/from16 v36, v13

    .line 1085
    .line 1086
    move/from16 v34, v14

    .line 1087
    .line 1088
    move/from16 v35, v15

    .line 1089
    .line 1090
    move/from16 v13, v31

    .line 1091
    .line 1092
    move/from16 v33, v32

    .line 1093
    .line 1094
    move-object v14, v2

    .line 1095
    move-object/from16 v31, v10

    .line 1096
    .line 1097
    move-object/from16 v32, v11

    .line 1098
    .line 1099
    move/from16 v2, p1

    .line 1100
    .line 1101
    move v10, v4

    .line 1102
    move v11, v5

    .line 1103
    move/from16 v4, p2

    .line 1104
    .line 1105
    goto/16 :goto_23

    .line 1106
    .line 1107
    :cond_31
    move-object/from16 v36, v13

    .line 1108
    .line 1109
    move/from16 v34, v14

    .line 1110
    .line 1111
    move/from16 v35, v15

    .line 1112
    .line 1113
    move/from16 v22, v20

    .line 1114
    .line 1115
    move/from16 v13, v31

    .line 1116
    .line 1117
    move/from16 v33, v32

    .line 1118
    .line 1119
    const/high16 v1, 0x40000000    # 2.0f

    .line 1120
    .line 1121
    move-object v14, v2

    .line 1122
    move-object/from16 v31, v10

    .line 1123
    .line 1124
    move-object/from16 v32, v11

    .line 1125
    .line 1126
    move/from16 v2, p1

    .line 1127
    .line 1128
    move v10, v4

    .line 1129
    move v11, v5

    .line 1130
    move/from16 v4, p2

    .line 1131
    .line 1132
    goto/16 :goto_24

    .line 1133
    .line 1134
    :cond_32
    iget v1, v2, Landroid/widget/LinearLayout$LayoutParams;->width:I

    .line 1135
    .line 1136
    if-nez v1, :cond_33

    .line 1137
    .line 1138
    cmpl-float v1, v3, v18

    .line 1139
    .line 1140
    if-lez v1, :cond_33

    .line 1141
    .line 1142
    const/4 v1, -0x2

    .line 1143
    iput v1, v2, Landroid/widget/LinearLayout$LayoutParams;->width:I

    .line 1144
    .line 1145
    const/4 v1, 0x0

    .line 1146
    goto :goto_1f

    .line 1147
    :cond_33
    const/high16 v1, -0x80000000

    .line 1148
    .line 1149
    :goto_1f
    cmpl-float v3, v28, v18

    .line 1150
    .line 1151
    if-nez v3, :cond_34

    .line 1152
    .line 1153
    iget v3, v0, Lm/r1;->i:I

    .line 1154
    .line 1155
    :goto_20
    move/from16 v33, v5

    .line 1156
    .line 1157
    goto :goto_21

    .line 1158
    :cond_34
    const/4 v3, 0x0

    .line 1159
    goto :goto_20

    .line 1160
    :goto_21
    const/4 v5, 0x0

    .line 1161
    move/from16 v34, v32

    .line 1162
    .line 1163
    move-object/from16 v32, v11

    .line 1164
    .line 1165
    move/from16 v11, v33

    .line 1166
    .line 1167
    move/from16 v33, v34

    .line 1168
    .line 1169
    move/from16 v34, v14

    .line 1170
    .line 1171
    move/from16 v35, v15

    .line 1172
    .line 1173
    move v15, v1

    .line 1174
    move-object v14, v2

    .line 1175
    move-object v1, v13

    .line 1176
    move/from16 v13, v31

    .line 1177
    .line 1178
    move/from16 v2, p1

    .line 1179
    .line 1180
    move-object/from16 v31, v10

    .line 1181
    .line 1182
    move v10, v4

    .line 1183
    move/from16 v4, p2

    .line 1184
    .line 1185
    invoke-virtual/range {v0 .. v5}, Landroid/view/ViewGroup;->measureChildWithMargins(Landroid/view/View;IIII)V

    .line 1186
    .line 1187
    .line 1188
    const/high16 v3, -0x80000000

    .line 1189
    .line 1190
    if-eq v15, v3, :cond_35

    .line 1191
    .line 1192
    iput v15, v14, Landroid/widget/LinearLayout$LayoutParams;->width:I

    .line 1193
    .line 1194
    :cond_35
    invoke-virtual {v1}, Landroid/view/View;->getMeasuredWidth()I

    .line 1195
    .line 1196
    .line 1197
    move-result v3

    .line 1198
    if-eqz v16, :cond_36

    .line 1199
    .line 1200
    iget v5, v0, Lm/r1;->i:I

    .line 1201
    .line 1202
    iget v15, v14, Landroid/widget/LinearLayout$LayoutParams;->leftMargin:I

    .line 1203
    .line 1204
    add-int/2addr v15, v3

    .line 1205
    move-object/from16 v36, v1

    .line 1206
    .line 1207
    iget v1, v14, Landroid/widget/LinearLayout$LayoutParams;->rightMargin:I

    .line 1208
    .line 1209
    add-int/2addr v15, v1

    .line 1210
    add-int/2addr v15, v5

    .line 1211
    iput v15, v0, Lm/r1;->i:I

    .line 1212
    .line 1213
    goto :goto_22

    .line 1214
    :cond_36
    move-object/from16 v36, v1

    .line 1215
    .line 1216
    iget v1, v0, Lm/r1;->i:I

    .line 1217
    .line 1218
    add-int v5, v1, v3

    .line 1219
    .line 1220
    iget v15, v14, Landroid/widget/LinearLayout$LayoutParams;->leftMargin:I

    .line 1221
    .line 1222
    add-int/2addr v5, v15

    .line 1223
    iget v15, v14, Landroid/widget/LinearLayout$LayoutParams;->rightMargin:I

    .line 1224
    .line 1225
    add-int/2addr v5, v15

    .line 1226
    invoke-static {v1, v5}, Ljava/lang/Math;->max(II)I

    .line 1227
    .line 1228
    .line 1229
    move-result v1

    .line 1230
    iput v1, v0, Lm/r1;->i:I

    .line 1231
    .line 1232
    :goto_22
    if-eqz v35, :cond_37

    .line 1233
    .line 1234
    invoke-static {v3, v9}, Ljava/lang/Math;->max(II)I

    .line 1235
    .line 1236
    .line 1237
    move-result v9

    .line 1238
    :cond_37
    :goto_23
    const/high16 v1, 0x40000000    # 2.0f

    .line 1239
    .line 1240
    :goto_24
    if-eq v8, v1, :cond_38

    .line 1241
    .line 1242
    iget v1, v14, Landroid/widget/LinearLayout$LayoutParams;->height:I

    .line 1243
    .line 1244
    const/4 v3, -0x1

    .line 1245
    if-ne v1, v3, :cond_38

    .line 1246
    .line 1247
    move/from16 v1, v20

    .line 1248
    .line 1249
    move/from16 v19, v1

    .line 1250
    .line 1251
    goto :goto_25

    .line 1252
    :cond_38
    const/4 v1, 0x0

    .line 1253
    :goto_25
    iget v3, v14, Landroid/widget/LinearLayout$LayoutParams;->topMargin:I

    .line 1254
    .line 1255
    iget v5, v14, Landroid/widget/LinearLayout$LayoutParams;->bottomMargin:I

    .line 1256
    .line 1257
    add-int/2addr v3, v5

    .line 1258
    invoke-virtual/range {v36 .. v36}, Landroid/view/View;->getMeasuredHeight()I

    .line 1259
    .line 1260
    .line 1261
    move-result v5

    .line 1262
    add-int/2addr v5, v3

    .line 1263
    invoke-virtual/range {v36 .. v36}, Landroid/view/View;->getMeasuredState()I

    .line 1264
    .line 1265
    .line 1266
    move-result v15

    .line 1267
    invoke-static {v12, v15}, Landroid/view/View;->combineMeasuredStates(II)I

    .line 1268
    .line 1269
    .line 1270
    move-result v12

    .line 1271
    if-eqz v34, :cond_3a

    .line 1272
    .line 1273
    invoke-virtual/range {v36 .. v36}, Landroid/view/View;->getBaseline()I

    .line 1274
    .line 1275
    .line 1276
    move-result v15

    .line 1277
    move/from16 v36, v1

    .line 1278
    .line 1279
    const/4 v1, -0x1

    .line 1280
    if-eq v15, v1, :cond_3b

    .line 1281
    .line 1282
    iget v1, v14, Landroid/widget/LinearLayout$LayoutParams;->gravity:I

    .line 1283
    .line 1284
    if-gez v1, :cond_39

    .line 1285
    .line 1286
    iget v1, v0, Lm/r1;->h:I

    .line 1287
    .line 1288
    :cond_39
    and-int/lit8 v1, v1, 0x70

    .line 1289
    .line 1290
    shr-int/lit8 v1, v1, 0x4

    .line 1291
    .line 1292
    const/16 v25, -0x2

    .line 1293
    .line 1294
    and-int/lit8 v1, v1, -0x2

    .line 1295
    .line 1296
    shr-int/lit8 v1, v1, 0x1

    .line 1297
    .line 1298
    move/from16 v37, v1

    .line 1299
    .line 1300
    aget v1, v31, v37

    .line 1301
    .line 1302
    invoke-static {v1, v15}, Ljava/lang/Math;->max(II)I

    .line 1303
    .line 1304
    .line 1305
    move-result v1

    .line 1306
    aput v1, v31, v37

    .line 1307
    .line 1308
    aget v1, v32, v37

    .line 1309
    .line 1310
    sub-int v15, v5, v15

    .line 1311
    .line 1312
    invoke-static {v1, v15}, Ljava/lang/Math;->max(II)I

    .line 1313
    .line 1314
    .line 1315
    move-result v1

    .line 1316
    aput v1, v32, v37

    .line 1317
    .line 1318
    goto :goto_26

    .line 1319
    :cond_3a
    move/from16 v36, v1

    .line 1320
    .line 1321
    :cond_3b
    :goto_26
    invoke-static {v13, v5}, Ljava/lang/Math;->max(II)I

    .line 1322
    .line 1323
    .line 1324
    move-result v1

    .line 1325
    if-eqz v29, :cond_3c

    .line 1326
    .line 1327
    iget v13, v14, Landroid/widget/LinearLayout$LayoutParams;->height:I

    .line 1328
    .line 1329
    const/4 v15, -0x1

    .line 1330
    if-ne v13, v15, :cond_3c

    .line 1331
    .line 1332
    move/from16 v13, v20

    .line 1333
    .line 1334
    goto :goto_27

    .line 1335
    :cond_3c
    const/4 v13, 0x0

    .line 1336
    :goto_27
    iget v14, v14, Landroid/widget/LinearLayout$LayoutParams;->weight:F

    .line 1337
    .line 1338
    cmpl-float v14, v14, v18

    .line 1339
    .line 1340
    if-lez v14, :cond_3e

    .line 1341
    .line 1342
    if-eqz v36, :cond_3d

    .line 1343
    .line 1344
    goto :goto_28

    .line 1345
    :cond_3d
    move v3, v5

    .line 1346
    :goto_28
    invoke-static {v11, v3}, Ljava/lang/Math;->max(II)I

    .line 1347
    .line 1348
    .line 1349
    move-result v5

    .line 1350
    move v3, v10

    .line 1351
    goto :goto_2a

    .line 1352
    :cond_3e
    if-eqz v36, :cond_3f

    .line 1353
    .line 1354
    goto :goto_29

    .line 1355
    :cond_3f
    move v3, v5

    .line 1356
    :goto_29
    invoke-static {v10, v3}, Ljava/lang/Math;->max(II)I

    .line 1357
    .line 1358
    .line 1359
    move-result v3

    .line 1360
    move v5, v11

    .line 1361
    :goto_2a
    move/from16 v29, v3

    .line 1362
    .line 1363
    move v3, v1

    .line 1364
    move/from16 v1, v29

    .line 1365
    .line 1366
    move/from16 v29, v13

    .line 1367
    .line 1368
    :goto_2b
    add-int/lit8 v10, v33, 0x1

    .line 1369
    .line 1370
    move v4, v1

    .line 1371
    move v1, v10

    .line 1372
    move/from16 v13, v30

    .line 1373
    .line 1374
    move-object/from16 v10, v31

    .line 1375
    .line 1376
    move-object/from16 v11, v32

    .line 1377
    .line 1378
    move/from16 v14, v34

    .line 1379
    .line 1380
    move/from16 v15, v35

    .line 1381
    .line 1382
    goto/16 :goto_1d

    .line 1383
    .line 1384
    :cond_40
    move-object/from16 v31, v10

    .line 1385
    .line 1386
    move-object/from16 v32, v11

    .line 1387
    .line 1388
    move/from16 v30, v13

    .line 1389
    .line 1390
    move/from16 v34, v14

    .line 1391
    .line 1392
    move/from16 v35, v15

    .line 1393
    .line 1394
    move v13, v3

    .line 1395
    move v10, v4

    .line 1396
    move v11, v5

    .line 1397
    move/from16 v4, p2

    .line 1398
    .line 1399
    iget v1, v0, Lm/r1;->i:I

    .line 1400
    .line 1401
    if-lez v1, :cond_41

    .line 1402
    .line 1403
    invoke-virtual {v0, v6}, Lm/r1;->i(I)Z

    .line 1404
    .line 1405
    .line 1406
    move-result v1

    .line 1407
    if-eqz v1, :cond_41

    .line 1408
    .line 1409
    iget v1, v0, Lm/r1;->i:I

    .line 1410
    .line 1411
    iget v3, v0, Lm/r1;->o:I

    .line 1412
    .line 1413
    add-int/2addr v1, v3

    .line 1414
    iput v1, v0, Lm/r1;->i:I

    .line 1415
    .line 1416
    :cond_41
    aget v1, v31, v20

    .line 1417
    .line 1418
    const/4 v3, -0x1

    .line 1419
    if-ne v1, v3, :cond_43

    .line 1420
    .line 1421
    const/16 v21, 0x0

    .line 1422
    .line 1423
    aget v5, v31, v21

    .line 1424
    .line 1425
    if-ne v5, v3, :cond_43

    .line 1426
    .line 1427
    aget v5, v31, v30

    .line 1428
    .line 1429
    if-ne v5, v3, :cond_43

    .line 1430
    .line 1431
    aget v5, v31, v24

    .line 1432
    .line 1433
    if-eq v5, v3, :cond_42

    .line 1434
    .line 1435
    goto :goto_2c

    .line 1436
    :cond_42
    move v3, v13

    .line 1437
    goto :goto_2d

    .line 1438
    :cond_43
    :goto_2c
    aget v3, v31, v24

    .line 1439
    .line 1440
    const/16 v21, 0x0

    .line 1441
    .line 1442
    aget v5, v31, v21

    .line 1443
    .line 1444
    aget v14, v31, v30

    .line 1445
    .line 1446
    invoke-static {v1, v14}, Ljava/lang/Math;->max(II)I

    .line 1447
    .line 1448
    .line 1449
    move-result v1

    .line 1450
    invoke-static {v5, v1}, Ljava/lang/Math;->max(II)I

    .line 1451
    .line 1452
    .line 1453
    move-result v1

    .line 1454
    invoke-static {v3, v1}, Ljava/lang/Math;->max(II)I

    .line 1455
    .line 1456
    .line 1457
    move-result v1

    .line 1458
    aget v3, v32, v24

    .line 1459
    .line 1460
    aget v5, v32, v21

    .line 1461
    .line 1462
    aget v14, v32, v20

    .line 1463
    .line 1464
    aget v15, v32, v30

    .line 1465
    .line 1466
    invoke-static {v14, v15}, Ljava/lang/Math;->max(II)I

    .line 1467
    .line 1468
    .line 1469
    move-result v14

    .line 1470
    invoke-static {v5, v14}, Ljava/lang/Math;->max(II)I

    .line 1471
    .line 1472
    .line 1473
    move-result v5

    .line 1474
    invoke-static {v3, v5}, Ljava/lang/Math;->max(II)I

    .line 1475
    .line 1476
    .line 1477
    move-result v3

    .line 1478
    add-int/2addr v3, v1

    .line 1479
    invoke-static {v13, v3}, Ljava/lang/Math;->max(II)I

    .line 1480
    .line 1481
    .line 1482
    move-result v3

    .line 1483
    :goto_2d
    if-eqz v35, :cond_48

    .line 1484
    .line 1485
    const/high16 v5, -0x80000000

    .line 1486
    .line 1487
    if-eq v7, v5, :cond_44

    .line 1488
    .line 1489
    if-nez v7, :cond_48

    .line 1490
    .line 1491
    :cond_44
    const/4 v5, 0x0

    .line 1492
    iput v5, v0, Lm/r1;->i:I

    .line 1493
    .line 1494
    const/4 v1, 0x0

    .line 1495
    :goto_2e
    if-ge v1, v6, :cond_48

    .line 1496
    .line 1497
    invoke-virtual {v0, v1}, Landroid/view/ViewGroup;->getChildAt(I)Landroid/view/View;

    .line 1498
    .line 1499
    .line 1500
    move-result-object v5

    .line 1501
    if-nez v5, :cond_45

    .line 1502
    .line 1503
    iget v5, v0, Lm/r1;->i:I

    .line 1504
    .line 1505
    iput v5, v0, Lm/r1;->i:I

    .line 1506
    .line 1507
    goto :goto_2f

    .line 1508
    :cond_45
    invoke-virtual {v5}, Landroid/view/View;->getVisibility()I

    .line 1509
    .line 1510
    .line 1511
    move-result v13

    .line 1512
    const/16 v14, 0x8

    .line 1513
    .line 1514
    if-ne v13, v14, :cond_46

    .line 1515
    .line 1516
    goto :goto_2f

    .line 1517
    :cond_46
    invoke-virtual {v5}, Landroid/view/View;->getLayoutParams()Landroid/view/ViewGroup$LayoutParams;

    .line 1518
    .line 1519
    .line 1520
    move-result-object v5

    .line 1521
    check-cast v5, Lm/q1;

    .line 1522
    .line 1523
    if-eqz v16, :cond_47

    .line 1524
    .line 1525
    iget v13, v0, Lm/r1;->i:I

    .line 1526
    .line 1527
    iget v14, v5, Landroid/widget/LinearLayout$LayoutParams;->leftMargin:I

    .line 1528
    .line 1529
    add-int/2addr v14, v9

    .line 1530
    iget v5, v5, Landroid/widget/LinearLayout$LayoutParams;->rightMargin:I

    .line 1531
    .line 1532
    add-int/2addr v14, v5

    .line 1533
    add-int/2addr v14, v13

    .line 1534
    iput v14, v0, Lm/r1;->i:I

    .line 1535
    .line 1536
    goto :goto_2f

    .line 1537
    :cond_47
    iget v13, v0, Lm/r1;->i:I

    .line 1538
    .line 1539
    add-int v14, v13, v9

    .line 1540
    .line 1541
    iget v15, v5, Landroid/widget/LinearLayout$LayoutParams;->leftMargin:I

    .line 1542
    .line 1543
    add-int/2addr v14, v15

    .line 1544
    iget v5, v5, Landroid/widget/LinearLayout$LayoutParams;->rightMargin:I

    .line 1545
    .line 1546
    add-int/2addr v14, v5

    .line 1547
    invoke-static {v13, v14}, Ljava/lang/Math;->max(II)I

    .line 1548
    .line 1549
    .line 1550
    move-result v5

    .line 1551
    iput v5, v0, Lm/r1;->i:I

    .line 1552
    .line 1553
    :goto_2f
    add-int/lit8 v1, v1, 0x1

    .line 1554
    .line 1555
    goto :goto_2e

    .line 1556
    :cond_48
    iget v1, v0, Lm/r1;->i:I

    .line 1557
    .line 1558
    invoke-virtual {v0}, Landroid/view/View;->getPaddingLeft()I

    .line 1559
    .line 1560
    .line 1561
    move-result v5

    .line 1562
    invoke-virtual {v0}, Landroid/view/View;->getPaddingRight()I

    .line 1563
    .line 1564
    .line 1565
    move-result v13

    .line 1566
    add-int/2addr v13, v5

    .line 1567
    add-int/2addr v13, v1

    .line 1568
    iput v13, v0, Lm/r1;->i:I

    .line 1569
    .line 1570
    invoke-virtual {v0}, Landroid/view/View;->getSuggestedMinimumWidth()I

    .line 1571
    .line 1572
    .line 1573
    move-result v1

    .line 1574
    invoke-static {v13, v1}, Ljava/lang/Math;->max(II)I

    .line 1575
    .line 1576
    .line 1577
    move-result v1

    .line 1578
    const/4 v5, 0x0

    .line 1579
    invoke-static {v1, v2, v5}, Landroid/view/View;->resolveSizeAndState(III)I

    .line 1580
    .line 1581
    .line 1582
    move-result v1

    .line 1583
    and-int v5, v1, v17

    .line 1584
    .line 1585
    iget v13, v0, Lm/r1;->i:I

    .line 1586
    .line 1587
    sub-int/2addr v5, v13

    .line 1588
    if-nez v22, :cond_4d

    .line 1589
    .line 1590
    if-eqz v5, :cond_49

    .line 1591
    .line 1592
    cmpl-float v14, v28, v18

    .line 1593
    .line 1594
    if-lez v14, :cond_49

    .line 1595
    .line 1596
    goto :goto_32

    .line 1597
    :cond_49
    invoke-static {v10, v11}, Ljava/lang/Math;->max(II)I

    .line 1598
    .line 1599
    .line 1600
    move-result v5

    .line 1601
    if-eqz v35, :cond_4c

    .line 1602
    .line 1603
    const/high16 v14, 0x40000000    # 2.0f

    .line 1604
    .line 1605
    if-eq v7, v14, :cond_4c

    .line 1606
    .line 1607
    const/4 v7, 0x0

    .line 1608
    :goto_30
    if-ge v7, v6, :cond_4c

    .line 1609
    .line 1610
    invoke-virtual {v0, v7}, Landroid/view/ViewGroup;->getChildAt(I)Landroid/view/View;

    .line 1611
    .line 1612
    .line 1613
    move-result-object v10

    .line 1614
    if-eqz v10, :cond_4b

    .line 1615
    .line 1616
    invoke-virtual {v10}, Landroid/view/View;->getVisibility()I

    .line 1617
    .line 1618
    .line 1619
    move-result v11

    .line 1620
    const/16 v14, 0x8

    .line 1621
    .line 1622
    if-ne v11, v14, :cond_4a

    .line 1623
    .line 1624
    goto :goto_31

    .line 1625
    :cond_4a
    invoke-virtual {v10}, Landroid/view/View;->getLayoutParams()Landroid/view/ViewGroup$LayoutParams;

    .line 1626
    .line 1627
    .line 1628
    move-result-object v11

    .line 1629
    check-cast v11, Lm/q1;

    .line 1630
    .line 1631
    iget v11, v11, Landroid/widget/LinearLayout$LayoutParams;->weight:F

    .line 1632
    .line 1633
    cmpl-float v11, v11, v18

    .line 1634
    .line 1635
    if-lez v11, :cond_4b

    .line 1636
    .line 1637
    const/high16 v14, 0x40000000    # 2.0f

    .line 1638
    .line 1639
    invoke-static {v9, v14}, Landroid/view/View$MeasureSpec;->makeMeasureSpec(II)I

    .line 1640
    .line 1641
    .line 1642
    move-result v11

    .line 1643
    invoke-virtual {v10}, Landroid/view/View;->getMeasuredHeight()I

    .line 1644
    .line 1645
    .line 1646
    move-result v15

    .line 1647
    invoke-static {v15, v14}, Landroid/view/View$MeasureSpec;->makeMeasureSpec(II)I

    .line 1648
    .line 1649
    .line 1650
    move-result v15

    .line 1651
    invoke-virtual {v10, v11, v15}, Landroid/view/View;->measure(II)V

    .line 1652
    .line 1653
    .line 1654
    :cond_4b
    :goto_31
    add-int/lit8 v7, v7, 0x1

    .line 1655
    .line 1656
    goto :goto_30

    .line 1657
    :cond_4c
    move/from16 v22, v1

    .line 1658
    .line 1659
    const/high16 v17, -0x1000000

    .line 1660
    .line 1661
    const/16 v21, 0x0

    .line 1662
    .line 1663
    goto/16 :goto_41

    .line 1664
    .line 1665
    :cond_4d
    :goto_32
    iget v3, v0, Lm/r1;->j:F

    .line 1666
    .line 1667
    cmpl-float v9, v3, v18

    .line 1668
    .line 1669
    if-lez v9, :cond_4e

    .line 1670
    .line 1671
    move/from16 v28, v3

    .line 1672
    .line 1673
    :cond_4e
    const/16 v26, -0x1

    .line 1674
    .line 1675
    aput v26, v31, v24

    .line 1676
    .line 1677
    aput v26, v31, v30

    .line 1678
    .line 1679
    aput v26, v31, v20

    .line 1680
    .line 1681
    const/4 v3, 0x0

    .line 1682
    aput v26, v31, v3

    .line 1683
    .line 1684
    aput v26, v32, v24

    .line 1685
    .line 1686
    aput v26, v32, v30

    .line 1687
    .line 1688
    aput v26, v32, v20

    .line 1689
    .line 1690
    aput v26, v32, v3

    .line 1691
    .line 1692
    iput v3, v0, Lm/r1;->i:I

    .line 1693
    .line 1694
    const/4 v3, -0x1

    .line 1695
    const/4 v9, 0x0

    .line 1696
    :goto_33
    if-ge v9, v6, :cond_5d

    .line 1697
    .line 1698
    invoke-virtual {v0, v9}, Landroid/view/ViewGroup;->getChildAt(I)Landroid/view/View;

    .line 1699
    .line 1700
    .line 1701
    move-result-object v11

    .line 1702
    if-eqz v11, :cond_4f

    .line 1703
    .line 1704
    invoke-virtual {v11}, Landroid/view/View;->getVisibility()I

    .line 1705
    .line 1706
    .line 1707
    move-result v14

    .line 1708
    const/16 v15, 0x8

    .line 1709
    .line 1710
    if-ne v14, v15, :cond_50

    .line 1711
    .line 1712
    :cond_4f
    move/from16 v22, v1

    .line 1713
    .line 1714
    const/high16 v17, -0x1000000

    .line 1715
    .line 1716
    const/16 v25, -0x2

    .line 1717
    .line 1718
    goto/16 :goto_3e

    .line 1719
    .line 1720
    :cond_50
    invoke-virtual {v11}, Landroid/view/View;->getLayoutParams()Landroid/view/ViewGroup$LayoutParams;

    .line 1721
    .line 1722
    .line 1723
    move-result-object v14

    .line 1724
    check-cast v14, Lm/q1;

    .line 1725
    .line 1726
    iget v15, v14, Landroid/widget/LinearLayout$LayoutParams;->weight:F

    .line 1727
    .line 1728
    cmpl-float v17, v15, v18

    .line 1729
    .line 1730
    if-lez v17, :cond_55

    .line 1731
    .line 1732
    const/high16 v17, -0x1000000

    .line 1733
    .line 1734
    int-to-float v13, v5

    .line 1735
    mul-float/2addr v13, v15

    .line 1736
    div-float v13, v13, v28

    .line 1737
    .line 1738
    float-to-int v13, v13

    .line 1739
    sub-float v28, v28, v15

    .line 1740
    .line 1741
    sub-int/2addr v5, v13

    .line 1742
    invoke-virtual {v0}, Landroid/view/View;->getPaddingTop()I

    .line 1743
    .line 1744
    .line 1745
    move-result v15

    .line 1746
    invoke-virtual {v0}, Landroid/view/View;->getPaddingBottom()I

    .line 1747
    .line 1748
    .line 1749
    move-result v22

    .line 1750
    add-int v22, v22, v15

    .line 1751
    .line 1752
    iget v15, v14, Landroid/widget/LinearLayout$LayoutParams;->topMargin:I

    .line 1753
    .line 1754
    add-int v22, v22, v15

    .line 1755
    .line 1756
    iget v15, v14, Landroid/widget/LinearLayout$LayoutParams;->bottomMargin:I

    .line 1757
    .line 1758
    add-int v15, v22, v15

    .line 1759
    .line 1760
    move/from16 v22, v1

    .line 1761
    .line 1762
    iget v1, v14, Landroid/widget/LinearLayout$LayoutParams;->height:I

    .line 1763
    .line 1764
    invoke-static {v4, v15, v1}, Landroid/view/ViewGroup;->getChildMeasureSpec(III)I

    .line 1765
    .line 1766
    .line 1767
    move-result v1

    .line 1768
    iget v15, v14, Landroid/widget/LinearLayout$LayoutParams;->width:I

    .line 1769
    .line 1770
    if-nez v15, :cond_53

    .line 1771
    .line 1772
    const/high16 v15, 0x40000000    # 2.0f

    .line 1773
    .line 1774
    if-eq v7, v15, :cond_51

    .line 1775
    .line 1776
    goto :goto_35

    .line 1777
    :cond_51
    if-lez v13, :cond_52

    .line 1778
    .line 1779
    goto :goto_34

    .line 1780
    :cond_52
    const/4 v13, 0x0

    .line 1781
    :goto_34
    invoke-static {v13, v15}, Landroid/view/View$MeasureSpec;->makeMeasureSpec(II)I

    .line 1782
    .line 1783
    .line 1784
    move-result v13

    .line 1785
    invoke-virtual {v11, v13, v1}, Landroid/view/View;->measure(II)V

    .line 1786
    .line 1787
    .line 1788
    goto :goto_36

    .line 1789
    :cond_53
    const/high16 v15, 0x40000000    # 2.0f

    .line 1790
    .line 1791
    :goto_35
    invoke-virtual {v11}, Landroid/view/View;->getMeasuredWidth()I

    .line 1792
    .line 1793
    .line 1794
    move-result v27

    .line 1795
    add-int v13, v27, v13

    .line 1796
    .line 1797
    if-gez v13, :cond_54

    .line 1798
    .line 1799
    const/4 v13, 0x0

    .line 1800
    :cond_54
    invoke-static {v13, v15}, Landroid/view/View$MeasureSpec;->makeMeasureSpec(II)I

    .line 1801
    .line 1802
    .line 1803
    move-result v13

    .line 1804
    invoke-virtual {v11, v13, v1}, Landroid/view/View;->measure(II)V

    .line 1805
    .line 1806
    .line 1807
    :goto_36
    invoke-virtual {v11}, Landroid/view/View;->getMeasuredState()I

    .line 1808
    .line 1809
    .line 1810
    move-result v1

    .line 1811
    and-int v1, v1, v17

    .line 1812
    .line 1813
    invoke-static {v12, v1}, Landroid/view/View;->combineMeasuredStates(II)I

    .line 1814
    .line 1815
    .line 1816
    move-result v12

    .line 1817
    goto :goto_37

    .line 1818
    :cond_55
    move/from16 v22, v1

    .line 1819
    .line 1820
    const/high16 v17, -0x1000000

    .line 1821
    .line 1822
    :goto_37
    if-eqz v16, :cond_56

    .line 1823
    .line 1824
    iget v1, v0, Lm/r1;->i:I

    .line 1825
    .line 1826
    invoke-virtual {v11}, Landroid/view/View;->getMeasuredWidth()I

    .line 1827
    .line 1828
    .line 1829
    move-result v13

    .line 1830
    iget v15, v14, Landroid/widget/LinearLayout$LayoutParams;->leftMargin:I

    .line 1831
    .line 1832
    add-int/2addr v13, v15

    .line 1833
    iget v15, v14, Landroid/widget/LinearLayout$LayoutParams;->rightMargin:I

    .line 1834
    .line 1835
    add-int/2addr v13, v15

    .line 1836
    add-int/2addr v13, v1

    .line 1837
    iput v13, v0, Lm/r1;->i:I

    .line 1838
    .line 1839
    :goto_38
    const/high16 v1, 0x40000000    # 2.0f

    .line 1840
    .line 1841
    goto :goto_39

    .line 1842
    :cond_56
    iget v1, v0, Lm/r1;->i:I

    .line 1843
    .line 1844
    invoke-virtual {v11}, Landroid/view/View;->getMeasuredWidth()I

    .line 1845
    .line 1846
    .line 1847
    move-result v13

    .line 1848
    add-int/2addr v13, v1

    .line 1849
    iget v15, v14, Landroid/widget/LinearLayout$LayoutParams;->leftMargin:I

    .line 1850
    .line 1851
    add-int/2addr v13, v15

    .line 1852
    iget v15, v14, Landroid/widget/LinearLayout$LayoutParams;->rightMargin:I

    .line 1853
    .line 1854
    add-int/2addr v13, v15

    .line 1855
    invoke-static {v1, v13}, Ljava/lang/Math;->max(II)I

    .line 1856
    .line 1857
    .line 1858
    move-result v1

    .line 1859
    iput v1, v0, Lm/r1;->i:I

    .line 1860
    .line 1861
    goto :goto_38

    .line 1862
    :goto_39
    if-eq v8, v1, :cond_57

    .line 1863
    .line 1864
    iget v1, v14, Landroid/widget/LinearLayout$LayoutParams;->height:I

    .line 1865
    .line 1866
    const/4 v15, -0x1

    .line 1867
    if-ne v1, v15, :cond_57

    .line 1868
    .line 1869
    move/from16 v1, v20

    .line 1870
    .line 1871
    goto :goto_3a

    .line 1872
    :cond_57
    const/4 v1, 0x0

    .line 1873
    :goto_3a
    iget v13, v14, Landroid/widget/LinearLayout$LayoutParams;->topMargin:I

    .line 1874
    .line 1875
    iget v15, v14, Landroid/widget/LinearLayout$LayoutParams;->bottomMargin:I

    .line 1876
    .line 1877
    add-int/2addr v13, v15

    .line 1878
    invoke-virtual {v11}, Landroid/view/View;->getMeasuredHeight()I

    .line 1879
    .line 1880
    .line 1881
    move-result v15

    .line 1882
    add-int/2addr v15, v13

    .line 1883
    invoke-static {v3, v15}, Ljava/lang/Math;->max(II)I

    .line 1884
    .line 1885
    .line 1886
    move-result v3

    .line 1887
    if-eqz v1, :cond_58

    .line 1888
    .line 1889
    goto :goto_3b

    .line 1890
    :cond_58
    move v13, v15

    .line 1891
    :goto_3b
    invoke-static {v10, v13}, Ljava/lang/Math;->max(II)I

    .line 1892
    .line 1893
    .line 1894
    move-result v1

    .line 1895
    if-eqz v29, :cond_59

    .line 1896
    .line 1897
    iget v10, v14, Landroid/widget/LinearLayout$LayoutParams;->height:I

    .line 1898
    .line 1899
    const/4 v13, -0x1

    .line 1900
    if-ne v10, v13, :cond_5a

    .line 1901
    .line 1902
    move/from16 v10, v20

    .line 1903
    .line 1904
    goto :goto_3c

    .line 1905
    :cond_59
    const/4 v13, -0x1

    .line 1906
    :cond_5a
    const/4 v10, 0x0

    .line 1907
    :goto_3c
    if-eqz v34, :cond_5c

    .line 1908
    .line 1909
    invoke-virtual {v11}, Landroid/view/View;->getBaseline()I

    .line 1910
    .line 1911
    .line 1912
    move-result v11

    .line 1913
    if-eq v11, v13, :cond_5c

    .line 1914
    .line 1915
    iget v13, v14, Landroid/widget/LinearLayout$LayoutParams;->gravity:I

    .line 1916
    .line 1917
    if-gez v13, :cond_5b

    .line 1918
    .line 1919
    iget v13, v0, Lm/r1;->h:I

    .line 1920
    .line 1921
    :cond_5b
    and-int/lit8 v13, v13, 0x70

    .line 1922
    .line 1923
    shr-int/lit8 v13, v13, 0x4

    .line 1924
    .line 1925
    const/16 v25, -0x2

    .line 1926
    .line 1927
    and-int/lit8 v13, v13, -0x2

    .line 1928
    .line 1929
    shr-int/lit8 v13, v13, 0x1

    .line 1930
    .line 1931
    aget v14, v31, v13

    .line 1932
    .line 1933
    invoke-static {v14, v11}, Ljava/lang/Math;->max(II)I

    .line 1934
    .line 1935
    .line 1936
    move-result v14

    .line 1937
    aput v14, v31, v13

    .line 1938
    .line 1939
    aget v14, v32, v13

    .line 1940
    .line 1941
    sub-int/2addr v15, v11

    .line 1942
    invoke-static {v14, v15}, Ljava/lang/Math;->max(II)I

    .line 1943
    .line 1944
    .line 1945
    move-result v11

    .line 1946
    aput v11, v32, v13

    .line 1947
    .line 1948
    goto :goto_3d

    .line 1949
    :cond_5c
    const/16 v25, -0x2

    .line 1950
    .line 1951
    :goto_3d
    move/from16 v29, v10

    .line 1952
    .line 1953
    move v10, v1

    .line 1954
    :goto_3e
    add-int/lit8 v9, v9, 0x1

    .line 1955
    .line 1956
    move/from16 v1, v22

    .line 1957
    .line 1958
    goto/16 :goto_33

    .line 1959
    .line 1960
    :cond_5d
    move/from16 v22, v1

    .line 1961
    .line 1962
    const/high16 v17, -0x1000000

    .line 1963
    .line 1964
    iget v1, v0, Lm/r1;->i:I

    .line 1965
    .line 1966
    invoke-virtual {v0}, Landroid/view/View;->getPaddingLeft()I

    .line 1967
    .line 1968
    .line 1969
    move-result v5

    .line 1970
    invoke-virtual {v0}, Landroid/view/View;->getPaddingRight()I

    .line 1971
    .line 1972
    .line 1973
    move-result v7

    .line 1974
    add-int/2addr v7, v5

    .line 1975
    add-int/2addr v7, v1

    .line 1976
    iput v7, v0, Lm/r1;->i:I

    .line 1977
    .line 1978
    aget v1, v31, v20

    .line 1979
    .line 1980
    const/4 v15, -0x1

    .line 1981
    if-ne v1, v15, :cond_5f

    .line 1982
    .line 1983
    const/16 v21, 0x0

    .line 1984
    .line 1985
    aget v5, v31, v21

    .line 1986
    .line 1987
    if-ne v5, v15, :cond_5f

    .line 1988
    .line 1989
    aget v5, v31, v30

    .line 1990
    .line 1991
    if-ne v5, v15, :cond_5f

    .line 1992
    .line 1993
    aget v5, v31, v24

    .line 1994
    .line 1995
    if-eq v5, v15, :cond_5e

    .line 1996
    .line 1997
    goto :goto_3f

    .line 1998
    :cond_5e
    const/16 v21, 0x0

    .line 1999
    .line 2000
    goto :goto_40

    .line 2001
    :cond_5f
    :goto_3f
    aget v5, v31, v24

    .line 2002
    .line 2003
    const/16 v21, 0x0

    .line 2004
    .line 2005
    aget v7, v31, v21

    .line 2006
    .line 2007
    aget v9, v31, v30

    .line 2008
    .line 2009
    invoke-static {v1, v9}, Ljava/lang/Math;->max(II)I

    .line 2010
    .line 2011
    .line 2012
    move-result v1

    .line 2013
    invoke-static {v7, v1}, Ljava/lang/Math;->max(II)I

    .line 2014
    .line 2015
    .line 2016
    move-result v1

    .line 2017
    invoke-static {v5, v1}, Ljava/lang/Math;->max(II)I

    .line 2018
    .line 2019
    .line 2020
    move-result v1

    .line 2021
    aget v5, v32, v24

    .line 2022
    .line 2023
    aget v7, v32, v21

    .line 2024
    .line 2025
    aget v9, v32, v20

    .line 2026
    .line 2027
    aget v11, v32, v30

    .line 2028
    .line 2029
    invoke-static {v9, v11}, Ljava/lang/Math;->max(II)I

    .line 2030
    .line 2031
    .line 2032
    move-result v9

    .line 2033
    invoke-static {v7, v9}, Ljava/lang/Math;->max(II)I

    .line 2034
    .line 2035
    .line 2036
    move-result v7

    .line 2037
    invoke-static {v5, v7}, Ljava/lang/Math;->max(II)I

    .line 2038
    .line 2039
    .line 2040
    move-result v5

    .line 2041
    add-int/2addr v5, v1

    .line 2042
    invoke-static {v3, v5}, Ljava/lang/Math;->max(II)I

    .line 2043
    .line 2044
    .line 2045
    move-result v1

    .line 2046
    move v3, v1

    .line 2047
    :goto_40
    move v5, v10

    .line 2048
    :goto_41
    if-nez v29, :cond_60

    .line 2049
    .line 2050
    const/high16 v1, 0x40000000    # 2.0f

    .line 2051
    .line 2052
    if-eq v8, v1, :cond_60

    .line 2053
    .line 2054
    move v3, v5

    .line 2055
    :cond_60
    invoke-virtual {v0}, Landroid/view/View;->getPaddingTop()I

    .line 2056
    .line 2057
    .line 2058
    move-result v1

    .line 2059
    invoke-virtual {v0}, Landroid/view/View;->getPaddingBottom()I

    .line 2060
    .line 2061
    .line 2062
    move-result v5

    .line 2063
    add-int/2addr v5, v1

    .line 2064
    add-int/2addr v5, v3

    .line 2065
    invoke-virtual {v0}, Landroid/view/View;->getSuggestedMinimumHeight()I

    .line 2066
    .line 2067
    .line 2068
    move-result v1

    .line 2069
    invoke-static {v5, v1}, Ljava/lang/Math;->max(II)I

    .line 2070
    .line 2071
    .line 2072
    move-result v1

    .line 2073
    and-int v3, v12, v17

    .line 2074
    .line 2075
    or-int v3, v22, v3

    .line 2076
    .line 2077
    shl-int/lit8 v5, v12, 0x10

    .line 2078
    .line 2079
    invoke-static {v1, v4, v5}, Landroid/view/View;->resolveSizeAndState(III)I

    .line 2080
    .line 2081
    .line 2082
    move-result v1

    .line 2083
    invoke-virtual {v0, v3, v1}, Landroid/view/View;->setMeasuredDimension(II)V

    .line 2084
    .line 2085
    .line 2086
    if-eqz v19, :cond_63

    .line 2087
    .line 2088
    invoke-virtual {v0}, Landroid/view/View;->getMeasuredHeight()I

    .line 2089
    .line 2090
    .line 2091
    move-result v1

    .line 2092
    const/high16 v13, 0x40000000    # 2.0f

    .line 2093
    .line 2094
    invoke-static {v1, v13}, Landroid/view/View$MeasureSpec;->makeMeasureSpec(II)I

    .line 2095
    .line 2096
    .line 2097
    move-result v4

    .line 2098
    move/from16 v9, v21

    .line 2099
    .line 2100
    :goto_42
    if-ge v9, v6, :cond_63

    .line 2101
    .line 2102
    invoke-virtual {v0, v9}, Landroid/view/ViewGroup;->getChildAt(I)Landroid/view/View;

    .line 2103
    .line 2104
    .line 2105
    move-result-object v1

    .line 2106
    invoke-virtual {v1}, Landroid/view/View;->getVisibility()I

    .line 2107
    .line 2108
    .line 2109
    move-result v3

    .line 2110
    const/16 v11, 0x8

    .line 2111
    .line 2112
    if-eq v3, v11, :cond_61

    .line 2113
    .line 2114
    invoke-virtual {v1}, Landroid/view/View;->getLayoutParams()Landroid/view/ViewGroup$LayoutParams;

    .line 2115
    .line 2116
    .line 2117
    move-result-object v3

    .line 2118
    move-object v7, v3

    .line 2119
    check-cast v7, Lm/q1;

    .line 2120
    .line 2121
    iget v3, v7, Landroid/widget/LinearLayout$LayoutParams;->height:I

    .line 2122
    .line 2123
    const/4 v15, -0x1

    .line 2124
    if-ne v3, v15, :cond_62

    .line 2125
    .line 2126
    iget v8, v7, Landroid/widget/LinearLayout$LayoutParams;->width:I

    .line 2127
    .line 2128
    invoke-virtual {v1}, Landroid/view/View;->getMeasuredWidth()I

    .line 2129
    .line 2130
    .line 2131
    move-result v3

    .line 2132
    iput v3, v7, Landroid/widget/LinearLayout$LayoutParams;->width:I

    .line 2133
    .line 2134
    const/4 v3, 0x0

    .line 2135
    const/4 v5, 0x0

    .line 2136
    invoke-virtual/range {v0 .. v5}, Landroid/view/ViewGroup;->measureChildWithMargins(Landroid/view/View;IIII)V

    .line 2137
    .line 2138
    .line 2139
    iput v8, v7, Landroid/widget/LinearLayout$LayoutParams;->width:I

    .line 2140
    .line 2141
    goto :goto_43

    .line 2142
    :cond_61
    const/4 v15, -0x1

    .line 2143
    :cond_62
    :goto_43
    add-int/lit8 v9, v9, 0x1

    .line 2144
    .line 2145
    move-object/from16 v0, p0

    .line 2146
    .line 2147
    move/from16 v2, p1

    .line 2148
    .line 2149
    goto :goto_42

    .line 2150
    :cond_63
    return-void
.end method

.method public setBaselineAligned(Z)V
    .locals 0

    .line 1
    iput-boolean p1, p0, Lm/r1;->d:Z

    .line 2
    .line 3
    return-void
.end method

.method public setBaselineAlignedChildIndex(I)V
    .locals 2

    .line 1
    if-ltz p1, :cond_0

    .line 2
    .line 3
    invoke-virtual {p0}, Landroid/view/ViewGroup;->getChildCount()I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    if-ge p1, v0, :cond_0

    .line 8
    .line 9
    iput p1, p0, Lm/r1;->e:I

    .line 10
    .line 11
    return-void

    .line 12
    :cond_0
    new-instance p1, Ljava/lang/IllegalArgumentException;

    .line 13
    .line 14
    new-instance v0, Ljava/lang/StringBuilder;

    .line 15
    .line 16
    const-string v1, "base aligned child index out of range (0, "

    .line 17
    .line 18
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 19
    .line 20
    .line 21
    invoke-virtual {p0}, Landroid/view/ViewGroup;->getChildCount()I

    .line 22
    .line 23
    .line 24
    move-result p0

    .line 25
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 26
    .line 27
    .line 28
    const-string p0, ")"

    .line 29
    .line 30
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 31
    .line 32
    .line 33
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 34
    .line 35
    .line 36
    move-result-object p0

    .line 37
    invoke-direct {p1, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 38
    .line 39
    .line 40
    throw p1
.end method

.method public setDividerDrawable(Landroid/graphics/drawable/Drawable;)V
    .locals 2

    .line 1
    iget-object v0, p0, Lm/r1;->n:Landroid/graphics/drawable/Drawable;

    .line 2
    .line 3
    if-ne p1, v0, :cond_0

    .line 4
    .line 5
    return-void

    .line 6
    :cond_0
    iput-object p1, p0, Lm/r1;->n:Landroid/graphics/drawable/Drawable;

    .line 7
    .line 8
    const/4 v0, 0x0

    .line 9
    if-eqz p1, :cond_1

    .line 10
    .line 11
    invoke-virtual {p1}, Landroid/graphics/drawable/Drawable;->getIntrinsicWidth()I

    .line 12
    .line 13
    .line 14
    move-result v1

    .line 15
    iput v1, p0, Lm/r1;->o:I

    .line 16
    .line 17
    invoke-virtual {p1}, Landroid/graphics/drawable/Drawable;->getIntrinsicHeight()I

    .line 18
    .line 19
    .line 20
    move-result v1

    .line 21
    iput v1, p0, Lm/r1;->p:I

    .line 22
    .line 23
    goto :goto_0

    .line 24
    :cond_1
    iput v0, p0, Lm/r1;->o:I

    .line 25
    .line 26
    iput v0, p0, Lm/r1;->p:I

    .line 27
    .line 28
    :goto_0
    if-nez p1, :cond_2

    .line 29
    .line 30
    const/4 v0, 0x1

    .line 31
    :cond_2
    invoke-virtual {p0, v0}, Landroid/view/View;->setWillNotDraw(Z)V

    .line 32
    .line 33
    .line 34
    invoke-virtual {p0}, Landroid/view/View;->requestLayout()V

    .line 35
    .line 36
    .line 37
    return-void
.end method

.method public setDividerPadding(I)V
    .locals 0

    .line 1
    iput p1, p0, Lm/r1;->r:I

    .line 2
    .line 3
    return-void
.end method

.method public setGravity(I)V
    .locals 1

    .line 1
    iget v0, p0, Lm/r1;->h:I

    .line 2
    .line 3
    if-eq v0, p1, :cond_2

    .line 4
    .line 5
    const v0, 0x800007

    .line 6
    .line 7
    .line 8
    and-int/2addr v0, p1

    .line 9
    if-nez v0, :cond_0

    .line 10
    .line 11
    const v0, 0x800003

    .line 12
    .line 13
    .line 14
    or-int/2addr p1, v0

    .line 15
    :cond_0
    and-int/lit8 v0, p1, 0x70

    .line 16
    .line 17
    if-nez v0, :cond_1

    .line 18
    .line 19
    or-int/lit8 p1, p1, 0x30

    .line 20
    .line 21
    :cond_1
    iput p1, p0, Lm/r1;->h:I

    .line 22
    .line 23
    invoke-virtual {p0}, Landroid/view/View;->requestLayout()V

    .line 24
    .line 25
    .line 26
    :cond_2
    return-void
.end method

.method public setHorizontalGravity(I)V
    .locals 2

    .line 1
    const v0, 0x800007

    .line 2
    .line 3
    .line 4
    and-int/2addr p1, v0

    .line 5
    iget v1, p0, Lm/r1;->h:I

    .line 6
    .line 7
    and-int/2addr v0, v1

    .line 8
    if-eq v0, p1, :cond_0

    .line 9
    .line 10
    const v0, -0x800008

    .line 11
    .line 12
    .line 13
    and-int/2addr v0, v1

    .line 14
    or-int/2addr p1, v0

    .line 15
    iput p1, p0, Lm/r1;->h:I

    .line 16
    .line 17
    invoke-virtual {p0}, Landroid/view/View;->requestLayout()V

    .line 18
    .line 19
    .line 20
    :cond_0
    return-void
.end method

.method public setMeasureWithLargestChildEnabled(Z)V
    .locals 0

    .line 1
    iput-boolean p1, p0, Lm/r1;->k:Z

    .line 2
    .line 3
    return-void
.end method

.method public setOrientation(I)V
    .locals 1

    .line 1
    iget v0, p0, Lm/r1;->g:I

    .line 2
    .line 3
    if-eq v0, p1, :cond_0

    .line 4
    .line 5
    iput p1, p0, Lm/r1;->g:I

    .line 6
    .line 7
    invoke-virtual {p0}, Landroid/view/View;->requestLayout()V

    .line 8
    .line 9
    .line 10
    :cond_0
    return-void
.end method

.method public setShowDividers(I)V
    .locals 1

    .line 1
    iget v0, p0, Lm/r1;->q:I

    .line 2
    .line 3
    if-eq p1, v0, :cond_0

    .line 4
    .line 5
    invoke-virtual {p0}, Landroid/view/View;->requestLayout()V

    .line 6
    .line 7
    .line 8
    :cond_0
    iput p1, p0, Lm/r1;->q:I

    .line 9
    .line 10
    return-void
.end method

.method public setVerticalGravity(I)V
    .locals 2

    .line 1
    and-int/lit8 p1, p1, 0x70

    .line 2
    .line 3
    iget v0, p0, Lm/r1;->h:I

    .line 4
    .line 5
    and-int/lit8 v1, v0, 0x70

    .line 6
    .line 7
    if-eq v1, p1, :cond_0

    .line 8
    .line 9
    and-int/lit8 v0, v0, -0x71

    .line 10
    .line 11
    or-int/2addr p1, v0

    .line 12
    iput p1, p0, Lm/r1;->h:I

    .line 13
    .line 14
    invoke-virtual {p0}, Landroid/view/View;->requestLayout()V

    .line 15
    .line 16
    .line 17
    :cond_0
    return-void
.end method

.method public setWeightSum(F)V
    .locals 1

    .line 1
    const/4 v0, 0x0

    .line 2
    invoke-static {v0, p1}, Ljava/lang/Math;->max(FF)F

    .line 3
    .line 4
    .line 5
    move-result p1

    .line 6
    iput p1, p0, Lm/r1;->j:F

    .line 7
    .line 8
    return-void
.end method

.method public final shouldDelayChildPressedState()Z
    .locals 0

    .line 1
    const/4 p0, 0x0

    .line 2
    return p0
.end method
