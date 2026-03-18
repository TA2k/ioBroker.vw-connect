.class public final Lx4/o;
.super Lw3/a;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lx4/q;
.implements Ld6/s;


# instance fields
.field public final l:Landroid/view/Window;

.field public final m:Ll2/j1;

.field public n:Z

.field public o:Z

.field public p:Z

.field public q:Z


# direct methods
.method public constructor <init>(Landroid/content/Context;Landroid/view/Window;)V
    .locals 0

    .line 1
    invoke-direct {p0, p1}, Lw3/a;-><init>(Landroid/content/Context;)V

    .line 2
    .line 3
    .line 4
    iput-object p2, p0, Lx4/o;->l:Landroid/view/Window;

    .line 5
    .line 6
    sget-object p1, Lx4/m;->a:Lt2/b;

    .line 7
    .line 8
    invoke-static {p1}, Ll2/b;->n(Ljava/lang/Object;)Ll2/j1;

    .line 9
    .line 10
    .line 11
    move-result-object p1

    .line 12
    iput-object p1, p0, Lx4/o;->m:Ll2/j1;

    .line 13
    .line 14
    sget-object p1, Ld6/r0;->a:Ljava/util/WeakHashMap;

    .line 15
    .line 16
    invoke-static {p0, p0}, Ld6/k0;->j(Landroid/view/View;Ld6/s;)V

    .line 17
    .line 18
    .line 19
    new-instance p1, Lw4/a;

    .line 20
    .line 21
    const/4 p2, 0x1

    .line 22
    invoke-direct {p1, p0, p2}, Lw4/a;-><init>(Landroid/view/ViewGroup;I)V

    .line 23
    .line 24
    .line 25
    invoke-static {p0, p1}, Ld6/r0;->k(Landroid/view/View;Landroidx/datastore/preferences/protobuf/k;)V

    .line 26
    .line 27
    .line 28
    return-void
.end method


# virtual methods
.method public final a(Ll2/o;I)V
    .locals 5

    .line 1
    check-cast p1, Ll2/t;

    .line 2
    .line 3
    const v0, 0x6770d814

    .line 4
    .line 5
    .line 6
    invoke-virtual {p1, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 7
    .line 8
    .line 9
    invoke-virtual {p1, p0}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 10
    .line 11
    .line 12
    move-result v0

    .line 13
    const/4 v1, 0x2

    .line 14
    if-eqz v0, :cond_0

    .line 15
    .line 16
    const/4 v0, 0x4

    .line 17
    goto :goto_0

    .line 18
    :cond_0
    move v0, v1

    .line 19
    :goto_0
    or-int/2addr v0, p2

    .line 20
    and-int/lit8 v2, v0, 0x3

    .line 21
    .line 22
    const/4 v3, 0x0

    .line 23
    const/4 v4, 0x1

    .line 24
    if-eq v2, v1, :cond_1

    .line 25
    .line 26
    move v1, v4

    .line 27
    goto :goto_1

    .line 28
    :cond_1
    move v1, v3

    .line 29
    :goto_1
    and-int/2addr v0, v4

    .line 30
    invoke-virtual {p1, v0, v1}, Ll2/t;->O(IZ)Z

    .line 31
    .line 32
    .line 33
    move-result v0

    .line 34
    if-eqz v0, :cond_2

    .line 35
    .line 36
    iget-object v0, p0, Lx4/o;->m:Ll2/j1;

    .line 37
    .line 38
    invoke-virtual {v0}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 39
    .line 40
    .line 41
    move-result-object v0

    .line 42
    check-cast v0, Lay0/n;

    .line 43
    .line 44
    invoke-static {v3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 45
    .line 46
    .line 47
    move-result-object v1

    .line 48
    invoke-interface {v0, p1, v1}, Lay0/n;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 49
    .line 50
    .line 51
    goto :goto_2

    .line 52
    :cond_2
    invoke-virtual {p1}, Ll2/t;->R()V

    .line 53
    .line 54
    .line 55
    :goto_2
    invoke-virtual {p1}, Ll2/t;->s()Ll2/u1;

    .line 56
    .line 57
    .line 58
    move-result-object p1

    .line 59
    if-eqz p1, :cond_3

    .line 60
    .line 61
    new-instance v0, Lb1/g;

    .line 62
    .line 63
    const/16 v1, 0x8

    .line 64
    .line 65
    invoke-direct {v0, p0, p2, v1}, Lb1/g;-><init>(Lw3/a;II)V

    .line 66
    .line 67
    .line 68
    iput-object v0, p1, Ll2/u1;->d:Lay0/n;

    .line 69
    .line 70
    :cond_3
    return-void
.end method

.method public final f(IIIIZ)V
    .locals 3

    .line 1
    const/4 p5, 0x0

    .line 2
    invoke-virtual {p0, p5}, Landroid/view/ViewGroup;->getChildAt(I)Landroid/view/View;

    .line 3
    .line 4
    .line 5
    move-result-object p5

    .line 6
    if-nez p5, :cond_0

    .line 7
    .line 8
    return-void

    .line 9
    :cond_0
    invoke-virtual {p0}, Landroid/view/View;->getPaddingLeft()I

    .line 10
    .line 11
    .line 12
    move-result v0

    .line 13
    invoke-virtual {p0}, Landroid/view/View;->getPaddingRight()I

    .line 14
    .line 15
    .line 16
    move-result v1

    .line 17
    add-int/2addr v1, v0

    .line 18
    invoke-virtual {p0}, Landroid/view/View;->getPaddingTop()I

    .line 19
    .line 20
    .line 21
    move-result v0

    .line 22
    invoke-virtual {p0}, Landroid/view/View;->getPaddingBottom()I

    .line 23
    .line 24
    .line 25
    move-result v2

    .line 26
    add-int/2addr v2, v0

    .line 27
    sub-int/2addr p3, p1

    .line 28
    sub-int/2addr p4, p2

    .line 29
    invoke-virtual {p5}, Landroid/view/View;->getMeasuredWidth()I

    .line 30
    .line 31
    .line 32
    move-result p1

    .line 33
    invoke-virtual {p5}, Landroid/view/View;->getMeasuredHeight()I

    .line 34
    .line 35
    .line 36
    move-result p2

    .line 37
    sub-int/2addr p3, p1

    .line 38
    sub-int/2addr p3, v1

    .line 39
    sub-int/2addr p4, p2

    .line 40
    sub-int/2addr p4, v2

    .line 41
    invoke-virtual {p0}, Landroid/view/View;->getPaddingLeft()I

    .line 42
    .line 43
    .line 44
    move-result v0

    .line 45
    div-int/lit8 p3, p3, 0x2

    .line 46
    .line 47
    add-int/2addr p3, v0

    .line 48
    invoke-virtual {p0}, Landroid/view/View;->getPaddingTop()I

    .line 49
    .line 50
    .line 51
    move-result p0

    .line 52
    div-int/lit8 p4, p4, 0x2

    .line 53
    .line 54
    add-int/2addr p4, p0

    .line 55
    add-int/2addr p1, p3

    .line 56
    add-int/2addr p2, p4

    .line 57
    invoke-virtual {p5, p3, p4, p1, p2}, Landroid/view/View;->layout(IIII)V

    .line 58
    .line 59
    .line 60
    return-void
.end method

.method public final g(II)V
    .locals 12

    .line 1
    const/4 v0, 0x0

    .line 2
    invoke-virtual {p0, v0}, Landroid/view/ViewGroup;->getChildAt(I)Landroid/view/View;

    .line 3
    .line 4
    .line 5
    move-result-object v1

    .line 6
    if-nez v1, :cond_0

    .line 7
    .line 8
    invoke-super {p0, p1, p2}, Lw3/a;->g(II)V

    .line 9
    .line 10
    .line 11
    return-void

    .line 12
    :cond_0
    invoke-static {p1}, Landroid/view/View$MeasureSpec;->getSize(I)I

    .line 13
    .line 14
    .line 15
    move-result v2

    .line 16
    invoke-static {p2}, Landroid/view/View$MeasureSpec;->getSize(I)I

    .line 17
    .line 18
    .line 19
    move-result v3

    .line 20
    invoke-static {p2}, Landroid/view/View$MeasureSpec;->getMode(I)I

    .line 21
    .line 22
    .line 23
    move-result v4

    .line 24
    const/4 v5, -0x2

    .line 25
    iget-object v6, p0, Lx4/o;->l:Landroid/view/Window;

    .line 26
    .line 27
    const/high16 v7, -0x80000000

    .line 28
    .line 29
    if-ne v4, v7, :cond_1

    .line 30
    .line 31
    iget-boolean v8, p0, Lx4/o;->n:Z

    .line 32
    .line 33
    if-nez v8, :cond_1

    .line 34
    .line 35
    iget-boolean v8, p0, Lx4/o;->o:Z

    .line 36
    .line 37
    if-nez v8, :cond_1

    .line 38
    .line 39
    invoke-virtual {v6}, Landroid/view/Window;->getAttributes()Landroid/view/WindowManager$LayoutParams;

    .line 40
    .line 41
    .line 42
    move-result-object v8

    .line 43
    iget v8, v8, Landroid/view/WindowManager$LayoutParams;->height:I

    .line 44
    .line 45
    if-ne v8, v5, :cond_1

    .line 46
    .line 47
    add-int/lit8 v8, v3, 0x1

    .line 48
    .line 49
    goto :goto_0

    .line 50
    :cond_1
    move v8, v3

    .line 51
    :goto_0
    invoke-virtual {p0}, Landroid/view/View;->getPaddingLeft()I

    .line 52
    .line 53
    .line 54
    move-result v9

    .line 55
    invoke-virtual {p0}, Landroid/view/View;->getPaddingRight()I

    .line 56
    .line 57
    .line 58
    move-result v10

    .line 59
    add-int/2addr v10, v9

    .line 60
    invoke-virtual {p0}, Landroid/view/View;->getPaddingTop()I

    .line 61
    .line 62
    .line 63
    move-result v9

    .line 64
    invoke-virtual {p0}, Landroid/view/View;->getPaddingBottom()I

    .line 65
    .line 66
    .line 67
    move-result v11

    .line 68
    add-int/2addr v11, v9

    .line 69
    sub-int v9, v2, v10

    .line 70
    .line 71
    if-gez v9, :cond_2

    .line 72
    .line 73
    move v9, v0

    .line 74
    :cond_2
    sub-int/2addr v8, v11

    .line 75
    if-gez v8, :cond_3

    .line 76
    .line 77
    goto :goto_1

    .line 78
    :cond_3
    move v0, v8

    .line 79
    :goto_1
    invoke-static {p1}, Landroid/view/View$MeasureSpec;->getMode(I)I

    .line 80
    .line 81
    .line 82
    move-result v8

    .line 83
    if-nez v8, :cond_4

    .line 84
    .line 85
    goto :goto_2

    .line 86
    :cond_4
    invoke-static {v9, v7}, Landroid/view/View$MeasureSpec;->makeMeasureSpec(II)I

    .line 87
    .line 88
    .line 89
    move-result p1

    .line 90
    :goto_2
    if-nez v4, :cond_5

    .line 91
    .line 92
    goto :goto_3

    .line 93
    :cond_5
    invoke-static {v0, v7}, Landroid/view/View$MeasureSpec;->makeMeasureSpec(II)I

    .line 94
    .line 95
    .line 96
    move-result p2

    .line 97
    :goto_3
    invoke-virtual {v1, p1, p2}, Landroid/view/View;->measure(II)V

    .line 98
    .line 99
    .line 100
    const/high16 p1, 0x40000000    # 2.0f

    .line 101
    .line 102
    if-eq v8, v7, :cond_6

    .line 103
    .line 104
    if-eq v8, p1, :cond_7

    .line 105
    .line 106
    invoke-virtual {v1}, Landroid/view/View;->getMeasuredWidth()I

    .line 107
    .line 108
    .line 109
    move-result p2

    .line 110
    add-int v2, p2, v10

    .line 111
    .line 112
    goto :goto_4

    .line 113
    :cond_6
    invoke-virtual {v1}, Landroid/view/View;->getMeasuredWidth()I

    .line 114
    .line 115
    .line 116
    move-result p2

    .line 117
    add-int/2addr p2, v10

    .line 118
    invoke-static {v2, p2}, Ljava/lang/Math;->min(II)I

    .line 119
    .line 120
    .line 121
    move-result v2

    .line 122
    :cond_7
    :goto_4
    if-eq v4, v7, :cond_9

    .line 123
    .line 124
    if-eq v4, p1, :cond_8

    .line 125
    .line 126
    invoke-virtual {v1}, Landroid/view/View;->getMeasuredHeight()I

    .line 127
    .line 128
    .line 129
    move-result p1

    .line 130
    add-int/2addr p1, v11

    .line 131
    goto :goto_5

    .line 132
    :cond_8
    move p1, v3

    .line 133
    goto :goto_5

    .line 134
    :cond_9
    invoke-virtual {v1}, Landroid/view/View;->getMeasuredHeight()I

    .line 135
    .line 136
    .line 137
    move-result p1

    .line 138
    add-int/2addr p1, v11

    .line 139
    invoke-static {v3, p1}, Ljava/lang/Math;->min(II)I

    .line 140
    .line 141
    .line 142
    move-result p1

    .line 143
    :goto_5
    invoke-virtual {p0, v2, p1}, Landroid/view/View;->setMeasuredDimension(II)V

    .line 144
    .line 145
    .line 146
    iget-boolean p1, p0, Lx4/o;->o:Z

    .line 147
    .line 148
    if-nez p1, :cond_a

    .line 149
    .line 150
    invoke-virtual {v1}, Landroid/view/View;->getMeasuredHeight()I

    .line 151
    .line 152
    .line 153
    move-result p1

    .line 154
    add-int/2addr p1, v11

    .line 155
    if-le p1, v3, :cond_a

    .line 156
    .line 157
    invoke-virtual {v6}, Landroid/view/Window;->getAttributes()Landroid/view/WindowManager$LayoutParams;

    .line 158
    .line 159
    .line 160
    move-result-object p1

    .line 161
    iget p1, p1, Landroid/view/WindowManager$LayoutParams;->height:I

    .line 162
    .line 163
    if-ne p1, v5, :cond_a

    .line 164
    .line 165
    invoke-virtual {v6, v7}, Landroid/view/Window;->addFlags(I)V

    .line 166
    .line 167
    .line 168
    iget-boolean p0, p0, Lx4/o;->n:Z

    .line 169
    .line 170
    if-nez p0, :cond_a

    .line 171
    .line 172
    const/4 p0, -0x1

    .line 173
    invoke-virtual {v6, p0, p0}, Landroid/view/Window;->setLayout(II)V

    .line 174
    .line 175
    .line 176
    :cond_a
    return-void
.end method

.method public final getShouldCreateCompositionOnAttachedToWindow()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Lx4/o;->q:Z

    .line 2
    .line 3
    return p0
.end method

.method public final getWindow()Landroid/view/Window;
    .locals 0

    .line 1
    iget-object p0, p0, Lx4/o;->l:Landroid/view/Window;

    .line 2
    .line 3
    return-object p0
.end method

.method public final onApplyWindowInsets(Landroid/view/View;Ld6/w1;)Ld6/w1;
    .locals 5

    .line 1
    iget-boolean p1, p0, Lx4/o;->o:Z

    .line 2
    .line 3
    if-eqz p1, :cond_0

    .line 4
    .line 5
    goto :goto_0

    .line 6
    :cond_0
    const/4 p1, 0x0

    .line 7
    invoke-virtual {p0, p1}, Landroid/view/ViewGroup;->getChildAt(I)Landroid/view/View;

    .line 8
    .line 9
    .line 10
    move-result-object v0

    .line 11
    invoke-virtual {v0}, Landroid/view/View;->getLeft()I

    .line 12
    .line 13
    .line 14
    move-result v1

    .line 15
    invoke-static {p1, v1}, Ljava/lang/Math;->max(II)I

    .line 16
    .line 17
    .line 18
    move-result v1

    .line 19
    invoke-virtual {v0}, Landroid/view/View;->getTop()I

    .line 20
    .line 21
    .line 22
    move-result v2

    .line 23
    invoke-static {p1, v2}, Ljava/lang/Math;->max(II)I

    .line 24
    .line 25
    .line 26
    move-result v2

    .line 27
    invoke-virtual {p0}, Landroid/view/View;->getWidth()I

    .line 28
    .line 29
    .line 30
    move-result v3

    .line 31
    invoke-virtual {v0}, Landroid/view/View;->getRight()I

    .line 32
    .line 33
    .line 34
    move-result v4

    .line 35
    sub-int/2addr v3, v4

    .line 36
    invoke-static {p1, v3}, Ljava/lang/Math;->max(II)I

    .line 37
    .line 38
    .line 39
    move-result v3

    .line 40
    invoke-virtual {p0}, Landroid/view/View;->getHeight()I

    .line 41
    .line 42
    .line 43
    move-result p0

    .line 44
    invoke-virtual {v0}, Landroid/view/View;->getBottom()I

    .line 45
    .line 46
    .line 47
    move-result v0

    .line 48
    sub-int/2addr p0, v0

    .line 49
    invoke-static {p1, p0}, Ljava/lang/Math;->max(II)I

    .line 50
    .line 51
    .line 52
    move-result p0

    .line 53
    if-nez v1, :cond_1

    .line 54
    .line 55
    if-nez v2, :cond_1

    .line 56
    .line 57
    if-nez v3, :cond_1

    .line 58
    .line 59
    if-nez p0, :cond_1

    .line 60
    .line 61
    :goto_0
    return-object p2

    .line 62
    :cond_1
    iget-object p1, p2, Ld6/w1;->a:Ld6/s1;

    .line 63
    .line 64
    invoke-virtual {p1, v1, v2, v3, p0}, Ld6/s1;->n(IIII)Ld6/w1;

    .line 65
    .line 66
    .line 67
    move-result-object p0

    .line 68
    return-object p0
.end method
