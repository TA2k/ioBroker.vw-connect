.class public Landroidx/core/widget/NestedScrollView;
.super Landroid/widget/FrameLayout;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ld6/r;


# static fields
.field public static final F:F

.field public static final G:Lcom/google/android/material/datepicker/o;

.field public static final H:[I


# instance fields
.field public A:Lh6/g;

.field public final B:Lb8/i;

.field public final C:Ld6/p;

.field public D:F

.field public final E:Ld6/g;

.field public final d:F

.field public e:J

.field public final f:Landroid/graphics/Rect;

.field public final g:Landroid/widget/OverScroller;

.field public final h:Landroid/widget/EdgeEffect;

.field public final i:Landroid/widget/EdgeEffect;

.field public j:Ld6/x;

.field public k:I

.field public l:Z

.field public m:Z

.field public n:Landroid/view/View;

.field public o:Z

.field public p:Landroid/view/VelocityTracker;

.field public q:Z

.field public r:Z

.field public final s:I

.field public final t:I

.field public final u:I

.field public v:I

.field public final w:[I

.field public final x:[I

.field public y:I

.field public z:I


# direct methods
.method static constructor <clinit>()V
    .locals 4

    .line 1
    const-wide v0, 0x3fe8f5c28f5c28f6L    # 0.78

    .line 2
    .line 3
    .line 4
    .line 5
    .line 6
    invoke-static {v0, v1}, Ljava/lang/Math;->log(D)D

    .line 7
    .line 8
    .line 9
    move-result-wide v0

    .line 10
    const-wide v2, 0x3feccccccccccccdL    # 0.9

    .line 11
    .line 12
    .line 13
    .line 14
    .line 15
    invoke-static {v2, v3}, Ljava/lang/Math;->log(D)D

    .line 16
    .line 17
    .line 18
    move-result-wide v2

    .line 19
    div-double/2addr v0, v2

    .line 20
    double-to-float v0, v0

    .line 21
    sput v0, Landroidx/core/widget/NestedScrollView;->F:F

    .line 22
    .line 23
    new-instance v0, Lcom/google/android/material/datepicker/o;

    .line 24
    .line 25
    const/4 v1, 0x3

    .line 26
    invoke-direct {v0, v1}, Lcom/google/android/material/datepicker/o;-><init>(I)V

    .line 27
    .line 28
    .line 29
    sput-object v0, Landroidx/core/widget/NestedScrollView;->G:Lcom/google/android/material/datepicker/o;

    .line 30
    .line 31
    const v0, 0x101017a

    .line 32
    .line 33
    .line 34
    filled-new-array {v0}, [I

    .line 35
    .line 36
    .line 37
    move-result-object v0

    .line 38
    sput-object v0, Landroidx/core/widget/NestedScrollView;->H:[I

    .line 39
    .line 40
    return-void
.end method

.method public constructor <init>(Landroid/content/Context;Landroid/util/AttributeSet;)V
    .locals 6

    .line 1
    const v0, 0x7f040418

    .line 2
    .line 3
    .line 4
    invoke-direct {p0, p1, p2, v0}, Landroid/widget/FrameLayout;-><init>(Landroid/content/Context;Landroid/util/AttributeSet;I)V

    .line 5
    .line 6
    .line 7
    new-instance v1, Landroid/graphics/Rect;

    .line 8
    .line 9
    invoke-direct {v1}, Landroid/graphics/Rect;-><init>()V

    .line 10
    .line 11
    .line 12
    iput-object v1, p0, Landroidx/core/widget/NestedScrollView;->f:Landroid/graphics/Rect;

    .line 13
    .line 14
    const/4 v1, 0x1

    .line 15
    iput-boolean v1, p0, Landroidx/core/widget/NestedScrollView;->l:Z

    .line 16
    .line 17
    const/4 v2, 0x0

    .line 18
    iput-boolean v2, p0, Landroidx/core/widget/NestedScrollView;->m:Z

    .line 19
    .line 20
    const/4 v3, 0x0

    .line 21
    iput-object v3, p0, Landroidx/core/widget/NestedScrollView;->n:Landroid/view/View;

    .line 22
    .line 23
    iput-boolean v2, p0, Landroidx/core/widget/NestedScrollView;->o:Z

    .line 24
    .line 25
    iput-boolean v1, p0, Landroidx/core/widget/NestedScrollView;->r:Z

    .line 26
    .line 27
    const/4 v3, -0x1

    .line 28
    iput v3, p0, Landroidx/core/widget/NestedScrollView;->v:I

    .line 29
    .line 30
    const/4 v3, 0x2

    .line 31
    new-array v4, v3, [I

    .line 32
    .line 33
    iput-object v4, p0, Landroidx/core/widget/NestedScrollView;->w:[I

    .line 34
    .line 35
    new-array v3, v3, [I

    .line 36
    .line 37
    iput-object v3, p0, Landroidx/core/widget/NestedScrollView;->x:[I

    .line 38
    .line 39
    new-instance v3, Lh6/e;

    .line 40
    .line 41
    const/4 v4, 0x0

    .line 42
    invoke-direct {v3, p0, v4}, Lh6/e;-><init>(Ljava/lang/Object;I)V

    .line 43
    .line 44
    .line 45
    new-instance v4, Ld6/g;

    .line 46
    .line 47
    invoke-virtual {p0}, Landroid/view/View;->getContext()Landroid/content/Context;

    .line 48
    .line 49
    .line 50
    move-result-object v5

    .line 51
    invoke-direct {v4, v5, v3}, Ld6/g;-><init>(Landroid/content/Context;Lh6/e;)V

    .line 52
    .line 53
    .line 54
    iput-object v4, p0, Landroidx/core/widget/NestedScrollView;->E:Ld6/g;

    .line 55
    .line 56
    sget v3, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 57
    .line 58
    const/16 v4, 0x1f

    .line 59
    .line 60
    if-lt v3, v4, :cond_0

    .line 61
    .line 62
    invoke-static {p1, p2}, Lh6/c;->a(Landroid/content/Context;Landroid/util/AttributeSet;)Landroid/widget/EdgeEffect;

    .line 63
    .line 64
    .line 65
    move-result-object v5

    .line 66
    goto :goto_0

    .line 67
    :cond_0
    new-instance v5, Landroid/widget/EdgeEffect;

    .line 68
    .line 69
    invoke-direct {v5, p1}, Landroid/widget/EdgeEffect;-><init>(Landroid/content/Context;)V

    .line 70
    .line 71
    .line 72
    :goto_0
    iput-object v5, p0, Landroidx/core/widget/NestedScrollView;->h:Landroid/widget/EdgeEffect;

    .line 73
    .line 74
    if-lt v3, v4, :cond_1

    .line 75
    .line 76
    invoke-static {p1, p2}, Lh6/c;->a(Landroid/content/Context;Landroid/util/AttributeSet;)Landroid/widget/EdgeEffect;

    .line 77
    .line 78
    .line 79
    move-result-object v3

    .line 80
    goto :goto_1

    .line 81
    :cond_1
    new-instance v3, Landroid/widget/EdgeEffect;

    .line 82
    .line 83
    invoke-direct {v3, p1}, Landroid/widget/EdgeEffect;-><init>(Landroid/content/Context;)V

    .line 84
    .line 85
    .line 86
    :goto_1
    iput-object v3, p0, Landroidx/core/widget/NestedScrollView;->i:Landroid/widget/EdgeEffect;

    .line 87
    .line 88
    invoke-virtual {p1}, Landroid/content/Context;->getResources()Landroid/content/res/Resources;

    .line 89
    .line 90
    .line 91
    move-result-object v3

    .line 92
    invoke-virtual {v3}, Landroid/content/res/Resources;->getDisplayMetrics()Landroid/util/DisplayMetrics;

    .line 93
    .line 94
    .line 95
    move-result-object v3

    .line 96
    iget v3, v3, Landroid/util/DisplayMetrics;->density:F

    .line 97
    .line 98
    const/high16 v4, 0x43200000    # 160.0f

    .line 99
    .line 100
    mul-float/2addr v3, v4

    .line 101
    const v4, 0x43c10b3d

    .line 102
    .line 103
    .line 104
    mul-float/2addr v3, v4

    .line 105
    const v4, 0x3f570a3d    # 0.84f

    .line 106
    .line 107
    .line 108
    mul-float/2addr v3, v4

    .line 109
    iput v3, p0, Landroidx/core/widget/NestedScrollView;->d:F

    .line 110
    .line 111
    new-instance v3, Landroid/widget/OverScroller;

    .line 112
    .line 113
    invoke-virtual {p0}, Landroid/view/View;->getContext()Landroid/content/Context;

    .line 114
    .line 115
    .line 116
    move-result-object v4

    .line 117
    invoke-direct {v3, v4}, Landroid/widget/OverScroller;-><init>(Landroid/content/Context;)V

    .line 118
    .line 119
    .line 120
    iput-object v3, p0, Landroidx/core/widget/NestedScrollView;->g:Landroid/widget/OverScroller;

    .line 121
    .line 122
    invoke-virtual {p0, v1}, Landroid/view/View;->setFocusable(Z)V

    .line 123
    .line 124
    .line 125
    const/high16 v3, 0x40000

    .line 126
    .line 127
    invoke-virtual {p0, v3}, Landroid/view/ViewGroup;->setDescendantFocusability(I)V

    .line 128
    .line 129
    .line 130
    invoke-virtual {p0, v2}, Landroid/view/View;->setWillNotDraw(Z)V

    .line 131
    .line 132
    .line 133
    invoke-virtual {p0}, Landroid/view/View;->getContext()Landroid/content/Context;

    .line 134
    .line 135
    .line 136
    move-result-object v3

    .line 137
    invoke-static {v3}, Landroid/view/ViewConfiguration;->get(Landroid/content/Context;)Landroid/view/ViewConfiguration;

    .line 138
    .line 139
    .line 140
    move-result-object v3

    .line 141
    invoke-virtual {v3}, Landroid/view/ViewConfiguration;->getScaledTouchSlop()I

    .line 142
    .line 143
    .line 144
    move-result v4

    .line 145
    iput v4, p0, Landroidx/core/widget/NestedScrollView;->s:I

    .line 146
    .line 147
    invoke-virtual {v3}, Landroid/view/ViewConfiguration;->getScaledMinimumFlingVelocity()I

    .line 148
    .line 149
    .line 150
    move-result v4

    .line 151
    iput v4, p0, Landroidx/core/widget/NestedScrollView;->t:I

    .line 152
    .line 153
    invoke-virtual {v3}, Landroid/view/ViewConfiguration;->getScaledMaximumFlingVelocity()I

    .line 154
    .line 155
    .line 156
    move-result v3

    .line 157
    iput v3, p0, Landroidx/core/widget/NestedScrollView;->u:I

    .line 158
    .line 159
    sget-object v3, Landroidx/core/widget/NestedScrollView;->H:[I

    .line 160
    .line 161
    invoke-virtual {p1, p2, v3, v0, v2}, Landroid/content/Context;->obtainStyledAttributes(Landroid/util/AttributeSet;[III)Landroid/content/res/TypedArray;

    .line 162
    .line 163
    .line 164
    move-result-object p1

    .line 165
    invoke-virtual {p1, v2, v2}, Landroid/content/res/TypedArray;->getBoolean(IZ)Z

    .line 166
    .line 167
    .line 168
    move-result p2

    .line 169
    invoke-virtual {p0, p2}, Landroidx/core/widget/NestedScrollView;->setFillViewport(Z)V

    .line 170
    .line 171
    .line 172
    invoke-virtual {p1}, Landroid/content/res/TypedArray;->recycle()V

    .line 173
    .line 174
    .line 175
    new-instance p1, Lb8/i;

    .line 176
    .line 177
    const/4 p2, 0x1

    .line 178
    invoke-direct {p1, p2}, Lb8/i;-><init>(I)V

    .line 179
    .line 180
    .line 181
    iput-object p1, p0, Landroidx/core/widget/NestedScrollView;->B:Lb8/i;

    .line 182
    .line 183
    new-instance p1, Ld6/p;

    .line 184
    .line 185
    invoke-direct {p1, p0}, Ld6/p;-><init>(Landroid/view/ViewGroup;)V

    .line 186
    .line 187
    .line 188
    iput-object p1, p0, Landroidx/core/widget/NestedScrollView;->C:Ld6/p;

    .line 189
    .line 190
    invoke-virtual {p0, v1}, Landroidx/core/widget/NestedScrollView;->setNestedScrollingEnabled(Z)V

    .line 191
    .line 192
    .line 193
    sget-object p1, Landroidx/core/widget/NestedScrollView;->G:Lcom/google/android/material/datepicker/o;

    .line 194
    .line 195
    invoke-static {p0, p1}, Ld6/r0;->i(Landroid/view/View;Ld6/b;)V

    .line 196
    .line 197
    .line 198
    return-void
.end method

.method private getScrollFeedbackProvider()Ld6/x;
    .locals 1

    .line 1
    iget-object v0, p0, Landroidx/core/widget/NestedScrollView;->j:Ld6/x;

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    new-instance v0, Ld6/x;

    .line 6
    .line 7
    invoke-direct {v0, p0}, Ld6/x;-><init>(Landroidx/core/widget/NestedScrollView;)V

    .line 8
    .line 9
    .line 10
    iput-object v0, p0, Landroidx/core/widget/NestedScrollView;->j:Ld6/x;

    .line 11
    .line 12
    :cond_0
    iget-object p0, p0, Landroidx/core/widget/NestedScrollView;->j:Ld6/x;

    .line 13
    .line 14
    return-object p0
.end method

.method public static m(Landroid/view/View;Landroidx/core/widget/NestedScrollView;)Z
    .locals 1

    .line 1
    if-ne p0, p1, :cond_0

    .line 2
    .line 3
    goto :goto_0

    .line 4
    :cond_0
    invoke-virtual {p0}, Landroid/view/View;->getParent()Landroid/view/ViewParent;

    .line 5
    .line 6
    .line 7
    move-result-object p0

    .line 8
    instance-of v0, p0, Landroid/view/ViewGroup;

    .line 9
    .line 10
    if-eqz v0, :cond_1

    .line 11
    .line 12
    check-cast p0, Landroid/view/View;

    .line 13
    .line 14
    invoke-static {p0, p1}, Landroidx/core/widget/NestedScrollView;->m(Landroid/view/View;Landroidx/core/widget/NestedScrollView;)Z

    .line 15
    .line 16
    .line 17
    move-result p0

    .line 18
    if-eqz p0, :cond_1

    .line 19
    .line 20
    :goto_0
    const/4 p0, 0x1

    .line 21
    return p0

    .line 22
    :cond_1
    const/4 p0, 0x0

    .line 23
    return p0
.end method


# virtual methods
.method public final a(I)Z
    .locals 10

    .line 1
    invoke-virtual {p0}, Landroid/view/View;->findFocus()Landroid/view/View;

    .line 2
    .line 3
    .line 4
    move-result-object v1

    .line 5
    if-ne v1, p0, :cond_0

    .line 6
    .line 7
    const/4 v1, 0x0

    .line 8
    :cond_0
    move-object v7, v1

    .line 9
    invoke-static {}, Landroid/view/FocusFinder;->getInstance()Landroid/view/FocusFinder;

    .line 10
    .line 11
    .line 12
    move-result-object v1

    .line 13
    invoke-virtual {v1, p0, v7, p1}, Landroid/view/FocusFinder;->findNextFocus(Landroid/view/ViewGroup;Landroid/view/View;I)Landroid/view/View;

    .line 14
    .line 15
    .line 16
    move-result-object v8

    .line 17
    invoke-virtual {p0}, Landroidx/core/widget/NestedScrollView;->getMaxScrollAmount()I

    .line 18
    .line 19
    .line 20
    move-result v1

    .line 21
    const/4 v9, 0x0

    .line 22
    if-eqz v8, :cond_1

    .line 23
    .line 24
    invoke-virtual {p0}, Landroid/view/View;->getHeight()I

    .line 25
    .line 26
    .line 27
    move-result v2

    .line 28
    invoke-virtual {p0, v8, v1, v2}, Landroidx/core/widget/NestedScrollView;->n(Landroid/view/View;II)Z

    .line 29
    .line 30
    .line 31
    move-result v2

    .line 32
    if-eqz v2, :cond_1

    .line 33
    .line 34
    iget-object v1, p0, Landroidx/core/widget/NestedScrollView;->f:Landroid/graphics/Rect;

    .line 35
    .line 36
    invoke-virtual {v8, v1}, Landroid/view/View;->getDrawingRect(Landroid/graphics/Rect;)V

    .line 37
    .line 38
    .line 39
    invoke-virtual {p0, v8, v1}, Landroid/view/ViewGroup;->offsetDescendantRectToMyCoords(Landroid/view/View;Landroid/graphics/Rect;)V

    .line 40
    .line 41
    .line 42
    invoke-virtual {p0, v1}, Landroidx/core/widget/NestedScrollView;->e(Landroid/graphics/Rect;)I

    .line 43
    .line 44
    .line 45
    move-result v1

    .line 46
    const/4 v2, -0x1

    .line 47
    const/4 v3, 0x0

    .line 48
    const/4 v4, 0x0

    .line 49
    const/4 v5, 0x1

    .line 50
    const/4 v6, 0x1

    .line 51
    move-object v0, p0

    .line 52
    invoke-virtual/range {v0 .. v6}, Landroidx/core/widget/NestedScrollView;->t(IILandroid/view/MotionEvent;IIZ)I

    .line 53
    .line 54
    .line 55
    invoke-virtual {v8, p1}, Landroid/view/View;->requestFocus(I)Z

    .line 56
    .line 57
    .line 58
    goto :goto_2

    .line 59
    :cond_1
    const/16 v2, 0x21

    .line 60
    .line 61
    const/16 v3, 0x82

    .line 62
    .line 63
    if-ne p1, v2, :cond_2

    .line 64
    .line 65
    invoke-virtual {p0}, Landroid/view/View;->getScrollY()I

    .line 66
    .line 67
    .line 68
    move-result v2

    .line 69
    if-ge v2, v1, :cond_2

    .line 70
    .line 71
    invoke-virtual {p0}, Landroid/view/View;->getScrollY()I

    .line 72
    .line 73
    .line 74
    move-result v1

    .line 75
    goto :goto_0

    .line 76
    :cond_2
    if-ne p1, v3, :cond_3

    .line 77
    .line 78
    invoke-virtual {p0}, Landroid/view/ViewGroup;->getChildCount()I

    .line 79
    .line 80
    .line 81
    move-result v2

    .line 82
    if-lez v2, :cond_3

    .line 83
    .line 84
    invoke-virtual {p0, v9}, Landroid/view/ViewGroup;->getChildAt(I)Landroid/view/View;

    .line 85
    .line 86
    .line 87
    move-result-object v2

    .line 88
    invoke-virtual {v2}, Landroid/view/View;->getLayoutParams()Landroid/view/ViewGroup$LayoutParams;

    .line 89
    .line 90
    .line 91
    move-result-object v4

    .line 92
    check-cast v4, Landroid/widget/FrameLayout$LayoutParams;

    .line 93
    .line 94
    invoke-virtual {v2}, Landroid/view/View;->getBottom()I

    .line 95
    .line 96
    .line 97
    move-result v2

    .line 98
    iget v4, v4, Landroid/widget/FrameLayout$LayoutParams;->bottomMargin:I

    .line 99
    .line 100
    add-int/2addr v2, v4

    .line 101
    invoke-virtual {p0}, Landroid/view/View;->getScrollY()I

    .line 102
    .line 103
    .line 104
    move-result v4

    .line 105
    invoke-virtual {p0}, Landroid/view/View;->getHeight()I

    .line 106
    .line 107
    .line 108
    move-result v5

    .line 109
    add-int/2addr v5, v4

    .line 110
    invoke-virtual {p0}, Landroid/view/View;->getPaddingBottom()I

    .line 111
    .line 112
    .line 113
    move-result v4

    .line 114
    sub-int/2addr v5, v4

    .line 115
    sub-int/2addr v2, v5

    .line 116
    invoke-static {v2, v1}, Ljava/lang/Math;->min(II)I

    .line 117
    .line 118
    .line 119
    move-result v1

    .line 120
    :cond_3
    :goto_0
    if-nez v1, :cond_4

    .line 121
    .line 122
    return v9

    .line 123
    :cond_4
    if-ne p1, v3, :cond_5

    .line 124
    .line 125
    goto :goto_1

    .line 126
    :cond_5
    neg-int v1, v1

    .line 127
    :goto_1
    const/4 v2, -0x1

    .line 128
    const/4 v3, 0x0

    .line 129
    const/4 v4, 0x0

    .line 130
    const/4 v5, 0x1

    .line 131
    const/4 v6, 0x1

    .line 132
    move-object v0, p0

    .line 133
    invoke-virtual/range {v0 .. v6}, Landroidx/core/widget/NestedScrollView;->t(IILandroid/view/MotionEvent;IIZ)I

    .line 134
    .line 135
    .line 136
    :goto_2
    const/4 v1, 0x1

    .line 137
    if-eqz v7, :cond_6

    .line 138
    .line 139
    invoke-virtual {v7}, Landroid/view/View;->isFocused()Z

    .line 140
    .line 141
    .line 142
    move-result v2

    .line 143
    if-eqz v2, :cond_6

    .line 144
    .line 145
    invoke-virtual {p0}, Landroid/view/View;->getHeight()I

    .line 146
    .line 147
    .line 148
    move-result v2

    .line 149
    invoke-virtual {p0, v7, v9, v2}, Landroidx/core/widget/NestedScrollView;->n(Landroid/view/View;II)Z

    .line 150
    .line 151
    .line 152
    move-result v2

    .line 153
    if-nez v2, :cond_6

    .line 154
    .line 155
    invoke-virtual {p0}, Landroid/view/ViewGroup;->getDescendantFocusability()I

    .line 156
    .line 157
    .line 158
    move-result v2

    .line 159
    const/high16 v3, 0x20000

    .line 160
    .line 161
    invoke-virtual {p0, v3}, Landroid/view/ViewGroup;->setDescendantFocusability(I)V

    .line 162
    .line 163
    .line 164
    invoke-virtual {p0}, Landroid/view/View;->requestFocus()Z

    .line 165
    .line 166
    .line 167
    invoke-virtual {p0, v2}, Landroid/view/ViewGroup;->setDescendantFocusability(I)V

    .line 168
    .line 169
    .line 170
    :cond_6
    return v1
.end method

.method public final addView(Landroid/view/View;)V
    .locals 1

    .line 1
    invoke-virtual {p0}, Landroid/view/ViewGroup;->getChildCount()I

    move-result v0

    if-gtz v0, :cond_0

    .line 2
    invoke-super {p0, p1}, Landroid/view/ViewGroup;->addView(Landroid/view/View;)V

    return-void

    .line 3
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    const-string p1, "ScrollView can host only one direct child"

    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p0
.end method

.method public final addView(Landroid/view/View;I)V
    .locals 1

    .line 4
    invoke-virtual {p0}, Landroid/view/ViewGroup;->getChildCount()I

    move-result v0

    if-gtz v0, :cond_0

    .line 5
    invoke-super {p0, p1, p2}, Landroid/view/ViewGroup;->addView(Landroid/view/View;I)V

    return-void

    .line 6
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    const-string p1, "ScrollView can host only one direct child"

    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p0
.end method

.method public final addView(Landroid/view/View;ILandroid/view/ViewGroup$LayoutParams;)V
    .locals 1

    .line 10
    invoke-virtual {p0}, Landroid/view/ViewGroup;->getChildCount()I

    move-result v0

    if-gtz v0, :cond_0

    .line 11
    invoke-super {p0, p1, p2, p3}, Landroid/view/ViewGroup;->addView(Landroid/view/View;ILandroid/view/ViewGroup$LayoutParams;)V

    return-void

    .line 12
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    const-string p1, "ScrollView can host only one direct child"

    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p0
.end method

.method public final addView(Landroid/view/View;Landroid/view/ViewGroup$LayoutParams;)V
    .locals 1

    .line 7
    invoke-virtual {p0}, Landroid/view/ViewGroup;->getChildCount()I

    move-result v0

    if-gtz v0, :cond_0

    .line 8
    invoke-super {p0, p1, p2}, Landroid/view/ViewGroup;->addView(Landroid/view/View;Landroid/view/ViewGroup$LayoutParams;)V

    return-void

    .line 9
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    const-string p1, "ScrollView can host only one direct child"

    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p0
.end method

.method public final b(Landroid/view/View;Landroid/view/View;II)V
    .locals 0

    .line 1
    const/4 p1, 0x1

    .line 2
    iget-object p2, p0, Landroidx/core/widget/NestedScrollView;->B:Lb8/i;

    .line 3
    .line 4
    if-ne p4, p1, :cond_0

    .line 5
    .line 6
    iput p3, p2, Lb8/i;->c:I

    .line 7
    .line 8
    goto :goto_0

    .line 9
    :cond_0
    iput p3, p2, Lb8/i;->b:I

    .line 10
    .line 11
    :goto_0
    const/4 p1, 0x2

    .line 12
    invoke-virtual {p0, p1, p4}, Landroidx/core/widget/NestedScrollView;->w(II)V

    .line 13
    .line 14
    .line 15
    return-void
.end method

.method public final c(Landroid/view/View;I)V
    .locals 2

    .line 1
    const/4 p1, 0x1

    .line 2
    iget-object v0, p0, Landroidx/core/widget/NestedScrollView;->B:Lb8/i;

    .line 3
    .line 4
    const/4 v1, 0x0

    .line 5
    if-ne p2, p1, :cond_0

    .line 6
    .line 7
    iput v1, v0, Lb8/i;->c:I

    .line 8
    .line 9
    goto :goto_0

    .line 10
    :cond_0
    iput v1, v0, Lb8/i;->b:I

    .line 11
    .line 12
    :goto_0
    invoke-virtual {p0, p2}, Landroidx/core/widget/NestedScrollView;->y(I)V

    .line 13
    .line 14
    .line 15
    return-void
.end method

.method public final computeHorizontalScrollExtent()I
    .locals 0

    .line 1
    invoke-super {p0}, Landroid/view/View;->computeHorizontalScrollExtent()I

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    return p0
.end method

.method public final computeHorizontalScrollOffset()I
    .locals 0

    .line 1
    invoke-super {p0}, Landroid/view/View;->computeHorizontalScrollOffset()I

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    return p0
.end method

.method public final computeHorizontalScrollRange()I
    .locals 0

    .line 1
    invoke-super {p0}, Landroid/view/View;->computeHorizontalScrollRange()I

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    return p0
.end method

.method public final computeScroll()V
    .locals 16

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget-object v1, v0, Landroidx/core/widget/NestedScrollView;->g:Landroid/widget/OverScroller;

    .line 4
    .line 5
    invoke-virtual {v1}, Landroid/widget/OverScroller;->isFinished()Z

    .line 6
    .line 7
    .line 8
    move-result v1

    .line 9
    if-eqz v1, :cond_0

    .line 10
    .line 11
    return-void

    .line 12
    :cond_0
    iget-object v1, v0, Landroidx/core/widget/NestedScrollView;->g:Landroid/widget/OverScroller;

    .line 13
    .line 14
    invoke-virtual {v1}, Landroid/widget/OverScroller;->computeScrollOffset()Z

    .line 15
    .line 16
    .line 17
    iget-object v1, v0, Landroidx/core/widget/NestedScrollView;->g:Landroid/widget/OverScroller;

    .line 18
    .line 19
    invoke-virtual {v1}, Landroid/widget/OverScroller;->getCurrY()I

    .line 20
    .line 21
    .line 22
    move-result v1

    .line 23
    iget v2, v0, Landroidx/core/widget/NestedScrollView;->z:I

    .line 24
    .line 25
    sub-int v2, v1, v2

    .line 26
    .line 27
    invoke-virtual {v0}, Landroid/view/View;->getHeight()I

    .line 28
    .line 29
    .line 30
    move-result v3

    .line 31
    iget-object v6, v0, Landroidx/core/widget/NestedScrollView;->h:Landroid/widget/EdgeEffect;

    .line 32
    .line 33
    iget-object v7, v0, Landroidx/core/widget/NestedScrollView;->i:Landroid/widget/EdgeEffect;

    .line 34
    .line 35
    const/high16 v4, 0x3f000000    # 0.5f

    .line 36
    .line 37
    const/4 v5, 0x0

    .line 38
    const/high16 v8, 0x40800000    # 4.0f

    .line 39
    .line 40
    if-lez v2, :cond_2

    .line 41
    .line 42
    invoke-static {v6}, Llp/l0;->b(Landroid/widget/EdgeEffect;)F

    .line 43
    .line 44
    .line 45
    move-result v9

    .line 46
    cmpl-float v9, v9, v5

    .line 47
    .line 48
    if-eqz v9, :cond_2

    .line 49
    .line 50
    neg-int v5, v2

    .line 51
    int-to-float v5, v5

    .line 52
    mul-float/2addr v5, v8

    .line 53
    int-to-float v9, v3

    .line 54
    div-float/2addr v5, v9

    .line 55
    neg-int v3, v3

    .line 56
    int-to-float v3, v3

    .line 57
    div-float/2addr v3, v8

    .line 58
    invoke-static {v6, v5, v4}, Llp/l0;->c(Landroid/widget/EdgeEffect;FF)F

    .line 59
    .line 60
    .line 61
    move-result v4

    .line 62
    mul-float/2addr v4, v3

    .line 63
    invoke-static {v4}, Ljava/lang/Math;->round(F)I

    .line 64
    .line 65
    .line 66
    move-result v3

    .line 67
    if-eq v3, v2, :cond_1

    .line 68
    .line 69
    invoke-virtual {v6}, Landroid/widget/EdgeEffect;->finish()V

    .line 70
    .line 71
    .line 72
    :cond_1
    :goto_0
    sub-int/2addr v2, v3

    .line 73
    goto :goto_1

    .line 74
    :cond_2
    if-gez v2, :cond_3

    .line 75
    .line 76
    invoke-static {v7}, Llp/l0;->b(Landroid/widget/EdgeEffect;)F

    .line 77
    .line 78
    .line 79
    move-result v9

    .line 80
    cmpl-float v5, v9, v5

    .line 81
    .line 82
    if-eqz v5, :cond_3

    .line 83
    .line 84
    int-to-float v5, v2

    .line 85
    mul-float/2addr v5, v8

    .line 86
    int-to-float v3, v3

    .line 87
    div-float/2addr v5, v3

    .line 88
    div-float/2addr v3, v8

    .line 89
    invoke-static {v7, v5, v4}, Llp/l0;->c(Landroid/widget/EdgeEffect;FF)F

    .line 90
    .line 91
    .line 92
    move-result v4

    .line 93
    mul-float/2addr v4, v3

    .line 94
    invoke-static {v4}, Ljava/lang/Math;->round(F)I

    .line 95
    .line 96
    .line 97
    move-result v3

    .line 98
    if-eq v3, v2, :cond_1

    .line 99
    .line 100
    invoke-virtual {v7}, Landroid/widget/EdgeEffect;->finish()V

    .line 101
    .line 102
    .line 103
    goto :goto_0

    .line 104
    :cond_3
    :goto_1
    iput v1, v0, Landroidx/core/widget/NestedScrollView;->z:I

    .line 105
    .line 106
    iget-object v15, v0, Landroidx/core/widget/NestedScrollView;->x:[I

    .line 107
    .line 108
    const/4 v8, 0x1

    .line 109
    const/4 v9, 0x0

    .line 110
    aput v9, v15, v8

    .line 111
    .line 112
    const/4 v5, 0x0

    .line 113
    const/4 v3, 0x1

    .line 114
    const/4 v1, 0x0

    .line 115
    move-object v4, v15

    .line 116
    invoke-virtual/range {v0 .. v5}, Landroidx/core/widget/NestedScrollView;->f(III[I[I)Z

    .line 117
    .line 118
    .line 119
    aget v1, v15, v8

    .line 120
    .line 121
    sub-int/2addr v2, v1

    .line 122
    invoke-virtual {v0}, Landroidx/core/widget/NestedScrollView;->getScrollRange()I

    .line 123
    .line 124
    .line 125
    move-result v1

    .line 126
    sget v3, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 127
    .line 128
    const/16 v4, 0x23

    .line 129
    .line 130
    if-lt v3, v4, :cond_4

    .line 131
    .line 132
    iget-object v3, v0, Landroidx/core/widget/NestedScrollView;->g:Landroid/widget/OverScroller;

    .line 133
    .line 134
    invoke-virtual {v3}, Landroid/widget/OverScroller;->getCurrVelocity()F

    .line 135
    .line 136
    .line 137
    move-result v3

    .line 138
    invoke-static {v3}, Ljava/lang/Math;->abs(F)F

    .line 139
    .line 140
    .line 141
    move-result v3

    .line 142
    invoke-static {v0, v3}, Lf6/a;->a(Landroidx/core/widget/NestedScrollView;F)V

    .line 143
    .line 144
    .line 145
    :cond_4
    if-eqz v2, :cond_5

    .line 146
    .line 147
    invoke-virtual {v0}, Landroid/view/View;->getScrollY()I

    .line 148
    .line 149
    .line 150
    move-result v3

    .line 151
    invoke-virtual {v0}, Landroid/view/View;->getScrollX()I

    .line 152
    .line 153
    .line 154
    move-result v4

    .line 155
    invoke-virtual {v0, v2, v4, v3, v1}, Landroidx/core/widget/NestedScrollView;->q(IIII)Z

    .line 156
    .line 157
    .line 158
    invoke-virtual {v0}, Landroid/view/View;->getScrollY()I

    .line 159
    .line 160
    .line 161
    move-result v4

    .line 162
    sub-int v10, v4, v3

    .line 163
    .line 164
    sub-int v12, v2, v10

    .line 165
    .line 166
    aput v9, v15, v8

    .line 167
    .line 168
    const/4 v11, 0x0

    .line 169
    move v2, v8

    .line 170
    iget-object v8, v0, Landroidx/core/widget/NestedScrollView;->C:Ld6/p;

    .line 171
    .line 172
    const/4 v9, 0x0

    .line 173
    iget-object v13, v0, Landroidx/core/widget/NestedScrollView;->w:[I

    .line 174
    .line 175
    const/4 v14, 0x1

    .line 176
    move v3, v2

    .line 177
    invoke-virtual/range {v8 .. v15}, Ld6/p;->d(IIII[II[I)Z

    .line 178
    .line 179
    .line 180
    aget v2, v15, v3

    .line 181
    .line 182
    sub-int v2, v12, v2

    .line 183
    .line 184
    goto :goto_2

    .line 185
    :cond_5
    move v3, v8

    .line 186
    :goto_2
    if-eqz v2, :cond_9

    .line 187
    .line 188
    invoke-virtual {v0}, Landroid/view/View;->getOverScrollMode()I

    .line 189
    .line 190
    .line 191
    move-result v4

    .line 192
    if-eqz v4, :cond_6

    .line 193
    .line 194
    if-ne v4, v3, :cond_8

    .line 195
    .line 196
    if-lez v1, :cond_8

    .line 197
    .line 198
    :cond_6
    if-gez v2, :cond_7

    .line 199
    .line 200
    invoke-virtual {v6}, Landroid/widget/EdgeEffect;->isFinished()Z

    .line 201
    .line 202
    .line 203
    move-result v1

    .line 204
    if-eqz v1, :cond_8

    .line 205
    .line 206
    iget-object v1, v0, Landroidx/core/widget/NestedScrollView;->g:Landroid/widget/OverScroller;

    .line 207
    .line 208
    invoke-virtual {v1}, Landroid/widget/OverScroller;->getCurrVelocity()F

    .line 209
    .line 210
    .line 211
    move-result v1

    .line 212
    float-to-int v1, v1

    .line 213
    invoke-virtual {v6, v1}, Landroid/widget/EdgeEffect;->onAbsorb(I)V

    .line 214
    .line 215
    .line 216
    goto :goto_3

    .line 217
    :cond_7
    invoke-virtual {v7}, Landroid/widget/EdgeEffect;->isFinished()Z

    .line 218
    .line 219
    .line 220
    move-result v1

    .line 221
    if-eqz v1, :cond_8

    .line 222
    .line 223
    iget-object v1, v0, Landroidx/core/widget/NestedScrollView;->g:Landroid/widget/OverScroller;

    .line 224
    .line 225
    invoke-virtual {v1}, Landroid/widget/OverScroller;->getCurrVelocity()F

    .line 226
    .line 227
    .line 228
    move-result v1

    .line 229
    float-to-int v1, v1

    .line 230
    invoke-virtual {v7, v1}, Landroid/widget/EdgeEffect;->onAbsorb(I)V

    .line 231
    .line 232
    .line 233
    :cond_8
    :goto_3
    iget-object v1, v0, Landroidx/core/widget/NestedScrollView;->g:Landroid/widget/OverScroller;

    .line 234
    .line 235
    invoke-virtual {v1}, Landroid/widget/OverScroller;->abortAnimation()V

    .line 236
    .line 237
    .line 238
    invoke-virtual {v0, v3}, Landroidx/core/widget/NestedScrollView;->y(I)V

    .line 239
    .line 240
    .line 241
    :cond_9
    iget-object v1, v0, Landroidx/core/widget/NestedScrollView;->g:Landroid/widget/OverScroller;

    .line 242
    .line 243
    invoke-virtual {v1}, Landroid/widget/OverScroller;->isFinished()Z

    .line 244
    .line 245
    .line 246
    move-result v1

    .line 247
    if-nez v1, :cond_a

    .line 248
    .line 249
    invoke-virtual {v0}, Landroid/view/View;->postInvalidateOnAnimation()V

    .line 250
    .line 251
    .line 252
    return-void

    .line 253
    :cond_a
    invoke-virtual {v0, v3}, Landroidx/core/widget/NestedScrollView;->y(I)V

    .line 254
    .line 255
    .line 256
    return-void
.end method

.method public final computeVerticalScrollExtent()I
    .locals 0

    .line 1
    invoke-super {p0}, Landroid/view/View;->computeVerticalScrollExtent()I

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    return p0
.end method

.method public final computeVerticalScrollOffset()I
    .locals 1

    .line 1
    const/4 v0, 0x0

    .line 2
    invoke-super {p0}, Landroid/view/View;->computeVerticalScrollOffset()I

    .line 3
    .line 4
    .line 5
    move-result p0

    .line 6
    invoke-static {v0, p0}, Ljava/lang/Math;->max(II)I

    .line 7
    .line 8
    .line 9
    move-result p0

    .line 10
    return p0
.end method

.method public final computeVerticalScrollRange()I
    .locals 4

    .line 1
    invoke-virtual {p0}, Landroid/view/ViewGroup;->getChildCount()I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    invoke-virtual {p0}, Landroid/view/View;->getHeight()I

    .line 6
    .line 7
    .line 8
    move-result v1

    .line 9
    invoke-virtual {p0}, Landroid/view/View;->getPaddingBottom()I

    .line 10
    .line 11
    .line 12
    move-result v2

    .line 13
    sub-int/2addr v1, v2

    .line 14
    invoke-virtual {p0}, Landroid/view/View;->getPaddingTop()I

    .line 15
    .line 16
    .line 17
    move-result v2

    .line 18
    sub-int/2addr v1, v2

    .line 19
    if-nez v0, :cond_0

    .line 20
    .line 21
    return v1

    .line 22
    :cond_0
    const/4 v0, 0x0

    .line 23
    invoke-virtual {p0, v0}, Landroid/view/ViewGroup;->getChildAt(I)Landroid/view/View;

    .line 24
    .line 25
    .line 26
    move-result-object v2

    .line 27
    invoke-virtual {v2}, Landroid/view/View;->getLayoutParams()Landroid/view/ViewGroup$LayoutParams;

    .line 28
    .line 29
    .line 30
    move-result-object v3

    .line 31
    check-cast v3, Landroid/widget/FrameLayout$LayoutParams;

    .line 32
    .line 33
    invoke-virtual {v2}, Landroid/view/View;->getBottom()I

    .line 34
    .line 35
    .line 36
    move-result v2

    .line 37
    iget v3, v3, Landroid/widget/FrameLayout$LayoutParams;->bottomMargin:I

    .line 38
    .line 39
    add-int/2addr v2, v3

    .line 40
    invoke-virtual {p0}, Landroid/view/View;->getScrollY()I

    .line 41
    .line 42
    .line 43
    move-result p0

    .line 44
    sub-int v1, v2, v1

    .line 45
    .line 46
    invoke-static {v0, v1}, Ljava/lang/Math;->max(II)I

    .line 47
    .line 48
    .line 49
    move-result v0

    .line 50
    if-gez p0, :cond_1

    .line 51
    .line 52
    sub-int/2addr v2, p0

    .line 53
    return v2

    .line 54
    :cond_1
    if-le p0, v0, :cond_2

    .line 55
    .line 56
    sub-int/2addr p0, v0

    .line 57
    add-int/2addr p0, v2

    .line 58
    return p0

    .line 59
    :cond_2
    return v2
.end method

.method public final d(Landroid/view/View;II[II)V
    .locals 0

    .line 1
    move p1, p2

    .line 2
    move p2, p3

    .line 3
    move p3, p5

    .line 4
    const/4 p5, 0x0

    .line 5
    invoke-virtual/range {p0 .. p5}, Landroidx/core/widget/NestedScrollView;->f(III[I[I)Z

    .line 6
    .line 7
    .line 8
    return-void
.end method

.method public final dispatchKeyEvent(Landroid/view/KeyEvent;)Z
    .locals 1

    .line 1
    invoke-super {p0, p1}, Landroid/view/View;->dispatchKeyEvent(Landroid/view/KeyEvent;)Z

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    if-nez v0, :cond_1

    .line 6
    .line 7
    invoke-virtual {p0, p1}, Landroidx/core/widget/NestedScrollView;->j(Landroid/view/KeyEvent;)Z

    .line 8
    .line 9
    .line 10
    move-result p0

    .line 11
    if-eqz p0, :cond_0

    .line 12
    .line 13
    goto :goto_0

    .line 14
    :cond_0
    const/4 p0, 0x0

    .line 15
    return p0

    .line 16
    :cond_1
    :goto_0
    const/4 p0, 0x1

    .line 17
    return p0
.end method

.method public final dispatchNestedFling(FFZ)Z
    .locals 0

    .line 1
    iget-object p0, p0, Landroidx/core/widget/NestedScrollView;->C:Ld6/p;

    .line 2
    .line 3
    invoke-virtual {p0, p1, p2, p3}, Ld6/p;->a(FFZ)Z

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method

.method public final dispatchNestedPreFling(FF)Z
    .locals 0

    .line 1
    iget-object p0, p0, Landroidx/core/widget/NestedScrollView;->C:Ld6/p;

    .line 2
    .line 3
    invoke-virtual {p0, p1, p2}, Ld6/p;->b(FF)Z

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method

.method public final dispatchNestedPreScroll(II[I[I)Z
    .locals 6

    .line 1
    const/4 v3, 0x0

    .line 2
    iget-object v0, p0, Landroidx/core/widget/NestedScrollView;->C:Ld6/p;

    .line 3
    .line 4
    move v1, p1

    .line 5
    move v2, p2

    .line 6
    move-object v4, p3

    .line 7
    move-object v5, p4

    .line 8
    invoke-virtual/range {v0 .. v5}, Ld6/p;->c(III[I[I)Z

    .line 9
    .line 10
    .line 11
    move-result p0

    .line 12
    return p0
.end method

.method public final dispatchNestedScroll(IIII[I)Z
    .locals 8

    .line 1
    const/4 v6, 0x0

    .line 2
    const/4 v7, 0x0

    .line 3
    iget-object v0, p0, Landroidx/core/widget/NestedScrollView;->C:Ld6/p;

    .line 4
    .line 5
    move v1, p1

    .line 6
    move v2, p2

    .line 7
    move v3, p3

    .line 8
    move v4, p4

    .line 9
    move-object v5, p5

    .line 10
    invoke-virtual/range {v0 .. v7}, Ld6/p;->d(IIII[II[I)Z

    .line 11
    .line 12
    .line 13
    move-result p0

    .line 14
    return p0
.end method

.method public final draw(Landroid/graphics/Canvas;)V
    .locals 10

    .line 1
    invoke-super {p0, p1}, Landroid/view/View;->draw(Landroid/graphics/Canvas;)V

    .line 2
    .line 3
    .line 4
    invoke-virtual {p0}, Landroid/view/View;->getScrollY()I

    .line 5
    .line 6
    .line 7
    move-result v0

    .line 8
    iget-object v1, p0, Landroidx/core/widget/NestedScrollView;->h:Landroid/widget/EdgeEffect;

    .line 9
    .line 10
    invoke-virtual {v1}, Landroid/widget/EdgeEffect;->isFinished()Z

    .line 11
    .line 12
    .line 13
    move-result v2

    .line 14
    const/4 v3, 0x0

    .line 15
    if-nez v2, :cond_3

    .line 16
    .line 17
    invoke-virtual {p1}, Landroid/graphics/Canvas;->save()I

    .line 18
    .line 19
    .line 20
    move-result v2

    .line 21
    invoke-virtual {p0}, Landroid/view/View;->getWidth()I

    .line 22
    .line 23
    .line 24
    move-result v4

    .line 25
    invoke-virtual {p0}, Landroid/view/View;->getHeight()I

    .line 26
    .line 27
    .line 28
    move-result v5

    .line 29
    invoke-static {v3, v0}, Ljava/lang/Math;->min(II)I

    .line 30
    .line 31
    .line 32
    move-result v6

    .line 33
    invoke-virtual {p0}, Landroid/view/ViewGroup;->getClipToPadding()Z

    .line 34
    .line 35
    .line 36
    move-result v7

    .line 37
    if-eqz v7, :cond_0

    .line 38
    .line 39
    invoke-virtual {p0}, Landroid/view/View;->getPaddingLeft()I

    .line 40
    .line 41
    .line 42
    move-result v7

    .line 43
    invoke-virtual {p0}, Landroid/view/View;->getPaddingRight()I

    .line 44
    .line 45
    .line 46
    move-result v8

    .line 47
    add-int/2addr v8, v7

    .line 48
    sub-int/2addr v4, v8

    .line 49
    invoke-virtual {p0}, Landroid/view/View;->getPaddingLeft()I

    .line 50
    .line 51
    .line 52
    move-result v7

    .line 53
    goto :goto_0

    .line 54
    :cond_0
    move v7, v3

    .line 55
    :goto_0
    invoke-virtual {p0}, Landroid/view/ViewGroup;->getClipToPadding()Z

    .line 56
    .line 57
    .line 58
    move-result v8

    .line 59
    if-eqz v8, :cond_1

    .line 60
    .line 61
    invoke-virtual {p0}, Landroid/view/View;->getPaddingTop()I

    .line 62
    .line 63
    .line 64
    move-result v8

    .line 65
    invoke-virtual {p0}, Landroid/view/View;->getPaddingBottom()I

    .line 66
    .line 67
    .line 68
    move-result v9

    .line 69
    add-int/2addr v9, v8

    .line 70
    sub-int/2addr v5, v9

    .line 71
    invoke-virtual {p0}, Landroid/view/View;->getPaddingTop()I

    .line 72
    .line 73
    .line 74
    move-result v8

    .line 75
    add-int/2addr v6, v8

    .line 76
    :cond_1
    int-to-float v7, v7

    .line 77
    int-to-float v6, v6

    .line 78
    invoke-virtual {p1, v7, v6}, Landroid/graphics/Canvas;->translate(FF)V

    .line 79
    .line 80
    .line 81
    invoke-virtual {v1, v4, v5}, Landroid/widget/EdgeEffect;->setSize(II)V

    .line 82
    .line 83
    .line 84
    invoke-virtual {v1, p1}, Landroid/widget/EdgeEffect;->draw(Landroid/graphics/Canvas;)Z

    .line 85
    .line 86
    .line 87
    move-result v1

    .line 88
    if-eqz v1, :cond_2

    .line 89
    .line 90
    invoke-virtual {p0}, Landroid/view/View;->postInvalidateOnAnimation()V

    .line 91
    .line 92
    .line 93
    :cond_2
    invoke-virtual {p1, v2}, Landroid/graphics/Canvas;->restoreToCount(I)V

    .line 94
    .line 95
    .line 96
    :cond_3
    iget-object v1, p0, Landroidx/core/widget/NestedScrollView;->i:Landroid/widget/EdgeEffect;

    .line 97
    .line 98
    invoke-virtual {v1}, Landroid/widget/EdgeEffect;->isFinished()Z

    .line 99
    .line 100
    .line 101
    move-result v2

    .line 102
    if-nez v2, :cond_7

    .line 103
    .line 104
    invoke-virtual {p1}, Landroid/graphics/Canvas;->save()I

    .line 105
    .line 106
    .line 107
    move-result v2

    .line 108
    invoke-virtual {p0}, Landroid/view/View;->getWidth()I

    .line 109
    .line 110
    .line 111
    move-result v4

    .line 112
    invoke-virtual {p0}, Landroid/view/View;->getHeight()I

    .line 113
    .line 114
    .line 115
    move-result v5

    .line 116
    invoke-virtual {p0}, Landroidx/core/widget/NestedScrollView;->getScrollRange()I

    .line 117
    .line 118
    .line 119
    move-result v6

    .line 120
    invoke-static {v6, v0}, Ljava/lang/Math;->max(II)I

    .line 121
    .line 122
    .line 123
    move-result v0

    .line 124
    add-int/2addr v0, v5

    .line 125
    invoke-virtual {p0}, Landroid/view/ViewGroup;->getClipToPadding()Z

    .line 126
    .line 127
    .line 128
    move-result v6

    .line 129
    if-eqz v6, :cond_4

    .line 130
    .line 131
    invoke-virtual {p0}, Landroid/view/View;->getPaddingLeft()I

    .line 132
    .line 133
    .line 134
    move-result v3

    .line 135
    invoke-virtual {p0}, Landroid/view/View;->getPaddingRight()I

    .line 136
    .line 137
    .line 138
    move-result v6

    .line 139
    add-int/2addr v6, v3

    .line 140
    sub-int/2addr v4, v6

    .line 141
    invoke-virtual {p0}, Landroid/view/View;->getPaddingLeft()I

    .line 142
    .line 143
    .line 144
    move-result v3

    .line 145
    :cond_4
    invoke-virtual {p0}, Landroid/view/ViewGroup;->getClipToPadding()Z

    .line 146
    .line 147
    .line 148
    move-result v6

    .line 149
    if-eqz v6, :cond_5

    .line 150
    .line 151
    invoke-virtual {p0}, Landroid/view/View;->getPaddingTop()I

    .line 152
    .line 153
    .line 154
    move-result v6

    .line 155
    invoke-virtual {p0}, Landroid/view/View;->getPaddingBottom()I

    .line 156
    .line 157
    .line 158
    move-result v7

    .line 159
    add-int/2addr v7, v6

    .line 160
    sub-int/2addr v5, v7

    .line 161
    invoke-virtual {p0}, Landroid/view/View;->getPaddingBottom()I

    .line 162
    .line 163
    .line 164
    move-result v6

    .line 165
    sub-int/2addr v0, v6

    .line 166
    :cond_5
    sub-int/2addr v3, v4

    .line 167
    int-to-float v3, v3

    .line 168
    int-to-float v0, v0

    .line 169
    invoke-virtual {p1, v3, v0}, Landroid/graphics/Canvas;->translate(FF)V

    .line 170
    .line 171
    .line 172
    int-to-float v0, v4

    .line 173
    const/4 v3, 0x0

    .line 174
    const/high16 v6, 0x43340000    # 180.0f

    .line 175
    .line 176
    invoke-virtual {p1, v6, v0, v3}, Landroid/graphics/Canvas;->rotate(FFF)V

    .line 177
    .line 178
    .line 179
    invoke-virtual {v1, v4, v5}, Landroid/widget/EdgeEffect;->setSize(II)V

    .line 180
    .line 181
    .line 182
    invoke-virtual {v1, p1}, Landroid/widget/EdgeEffect;->draw(Landroid/graphics/Canvas;)Z

    .line 183
    .line 184
    .line 185
    move-result v0

    .line 186
    if-eqz v0, :cond_6

    .line 187
    .line 188
    invoke-virtual {p0}, Landroid/view/View;->postInvalidateOnAnimation()V

    .line 189
    .line 190
    .line 191
    :cond_6
    invoke-virtual {p1, v2}, Landroid/graphics/Canvas;->restoreToCount(I)V

    .line 192
    .line 193
    .line 194
    :cond_7
    return-void
.end method

.method public final e(Landroid/graphics/Rect;)I
    .locals 10

    .line 1
    invoke-virtual {p0}, Landroid/view/ViewGroup;->getChildCount()I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    const/4 v1, 0x0

    .line 6
    if-nez v0, :cond_0

    .line 7
    .line 8
    return v1

    .line 9
    :cond_0
    invoke-virtual {p0}, Landroid/view/View;->getHeight()I

    .line 10
    .line 11
    .line 12
    move-result v0

    .line 13
    invoke-virtual {p0}, Landroid/view/View;->getScrollY()I

    .line 14
    .line 15
    .line 16
    move-result v2

    .line 17
    add-int v3, v2, v0

    .line 18
    .line 19
    invoke-virtual {p0}, Landroid/view/View;->getVerticalFadingEdgeLength()I

    .line 20
    .line 21
    .line 22
    move-result v4

    .line 23
    iget v5, p1, Landroid/graphics/Rect;->top:I

    .line 24
    .line 25
    if-lez v5, :cond_1

    .line 26
    .line 27
    add-int/2addr v2, v4

    .line 28
    :cond_1
    invoke-virtual {p0, v1}, Landroid/view/ViewGroup;->getChildAt(I)Landroid/view/View;

    .line 29
    .line 30
    .line 31
    move-result-object v5

    .line 32
    invoke-virtual {v5}, Landroid/view/View;->getLayoutParams()Landroid/view/ViewGroup$LayoutParams;

    .line 33
    .line 34
    .line 35
    move-result-object v6

    .line 36
    check-cast v6, Landroid/widget/FrameLayout$LayoutParams;

    .line 37
    .line 38
    iget v7, p1, Landroid/graphics/Rect;->bottom:I

    .line 39
    .line 40
    invoke-virtual {v5}, Landroid/view/View;->getHeight()I

    .line 41
    .line 42
    .line 43
    move-result v8

    .line 44
    iget v9, v6, Landroid/widget/FrameLayout$LayoutParams;->topMargin:I

    .line 45
    .line 46
    add-int/2addr v8, v9

    .line 47
    iget v9, v6, Landroid/widget/FrameLayout$LayoutParams;->bottomMargin:I

    .line 48
    .line 49
    add-int/2addr v8, v9

    .line 50
    if-ge v7, v8, :cond_2

    .line 51
    .line 52
    sub-int v4, v3, v4

    .line 53
    .line 54
    goto :goto_0

    .line 55
    :cond_2
    move v4, v3

    .line 56
    :goto_0
    iget v7, p1, Landroid/graphics/Rect;->bottom:I

    .line 57
    .line 58
    if-le v7, v4, :cond_4

    .line 59
    .line 60
    iget v8, p1, Landroid/graphics/Rect;->top:I

    .line 61
    .line 62
    if-le v8, v2, :cond_4

    .line 63
    .line 64
    invoke-virtual {p1}, Landroid/graphics/Rect;->height()I

    .line 65
    .line 66
    .line 67
    move-result p0

    .line 68
    if-le p0, v0, :cond_3

    .line 69
    .line 70
    iget p0, p1, Landroid/graphics/Rect;->top:I

    .line 71
    .line 72
    sub-int/2addr p0, v2

    .line 73
    goto :goto_1

    .line 74
    :cond_3
    iget p0, p1, Landroid/graphics/Rect;->bottom:I

    .line 75
    .line 76
    sub-int/2addr p0, v4

    .line 77
    :goto_1
    invoke-virtual {v5}, Landroid/view/View;->getBottom()I

    .line 78
    .line 79
    .line 80
    move-result p1

    .line 81
    iget v0, v6, Landroid/widget/FrameLayout$LayoutParams;->bottomMargin:I

    .line 82
    .line 83
    add-int/2addr p1, v0

    .line 84
    sub-int/2addr p1, v3

    .line 85
    invoke-static {p0, p1}, Ljava/lang/Math;->min(II)I

    .line 86
    .line 87
    .line 88
    move-result p0

    .line 89
    return p0

    .line 90
    :cond_4
    iget v3, p1, Landroid/graphics/Rect;->top:I

    .line 91
    .line 92
    if-ge v3, v2, :cond_6

    .line 93
    .line 94
    if-ge v7, v4, :cond_6

    .line 95
    .line 96
    invoke-virtual {p1}, Landroid/graphics/Rect;->height()I

    .line 97
    .line 98
    .line 99
    move-result v3

    .line 100
    if-le v3, v0, :cond_5

    .line 101
    .line 102
    iget p1, p1, Landroid/graphics/Rect;->bottom:I

    .line 103
    .line 104
    sub-int/2addr v4, p1

    .line 105
    sub-int/2addr v1, v4

    .line 106
    goto :goto_2

    .line 107
    :cond_5
    iget p1, p1, Landroid/graphics/Rect;->top:I

    .line 108
    .line 109
    sub-int/2addr v2, p1

    .line 110
    sub-int/2addr v1, v2

    .line 111
    :goto_2
    invoke-virtual {p0}, Landroid/view/View;->getScrollY()I

    .line 112
    .line 113
    .line 114
    move-result p0

    .line 115
    neg-int p0, p0

    .line 116
    invoke-static {v1, p0}, Ljava/lang/Math;->max(II)I

    .line 117
    .line 118
    .line 119
    move-result p0

    .line 120
    return p0

    .line 121
    :cond_6
    return v1
.end method

.method public final f(III[I[I)Z
    .locals 0

    .line 1
    const/4 p5, 0x0

    .line 2
    iget-object p0, p0, Landroidx/core/widget/NestedScrollView;->C:Ld6/p;

    .line 3
    .line 4
    invoke-virtual/range {p0 .. p5}, Ld6/p;->c(III[I[I)Z

    .line 5
    .line 6
    .line 7
    move-result p0

    .line 8
    return p0
.end method

.method public final g(Landroid/view/View;IIIII[I)V
    .locals 0

    .line 1
    invoke-virtual {p0, p5, p6, p7}, Landroidx/core/widget/NestedScrollView;->o(II[I)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public getBottomFadingEdgeStrength()F
    .locals 5

    .line 1
    invoke-virtual {p0}, Landroid/view/ViewGroup;->getChildCount()I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    if-nez v0, :cond_0

    .line 6
    .line 7
    const/4 p0, 0x0

    .line 8
    return p0

    .line 9
    :cond_0
    const/4 v0, 0x0

    .line 10
    invoke-virtual {p0, v0}, Landroid/view/ViewGroup;->getChildAt(I)Landroid/view/View;

    .line 11
    .line 12
    .line 13
    move-result-object v0

    .line 14
    invoke-virtual {v0}, Landroid/view/View;->getLayoutParams()Landroid/view/ViewGroup$LayoutParams;

    .line 15
    .line 16
    .line 17
    move-result-object v1

    .line 18
    check-cast v1, Landroid/widget/FrameLayout$LayoutParams;

    .line 19
    .line 20
    invoke-virtual {p0}, Landroid/view/View;->getVerticalFadingEdgeLength()I

    .line 21
    .line 22
    .line 23
    move-result v2

    .line 24
    invoke-virtual {p0}, Landroid/view/View;->getHeight()I

    .line 25
    .line 26
    .line 27
    move-result v3

    .line 28
    invoke-virtual {p0}, Landroid/view/View;->getPaddingBottom()I

    .line 29
    .line 30
    .line 31
    move-result v4

    .line 32
    sub-int/2addr v3, v4

    .line 33
    invoke-virtual {v0}, Landroid/view/View;->getBottom()I

    .line 34
    .line 35
    .line 36
    move-result v0

    .line 37
    iget v1, v1, Landroid/widget/FrameLayout$LayoutParams;->bottomMargin:I

    .line 38
    .line 39
    add-int/2addr v0, v1

    .line 40
    invoke-virtual {p0}, Landroid/view/View;->getScrollY()I

    .line 41
    .line 42
    .line 43
    move-result p0

    .line 44
    sub-int/2addr v0, p0

    .line 45
    sub-int/2addr v0, v3

    .line 46
    if-ge v0, v2, :cond_1

    .line 47
    .line 48
    int-to-float p0, v0

    .line 49
    int-to-float v0, v2

    .line 50
    div-float/2addr p0, v0

    .line 51
    return p0

    .line 52
    :cond_1
    const/high16 p0, 0x3f800000    # 1.0f

    .line 53
    .line 54
    return p0
.end method

.method public getMaxScrollAmount()I
    .locals 1

    .line 1
    invoke-virtual {p0}, Landroid/view/View;->getHeight()I

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    int-to-float p0, p0

    .line 6
    const/high16 v0, 0x3f000000    # 0.5f

    .line 7
    .line 8
    mul-float/2addr p0, v0

    .line 9
    float-to-int p0, p0

    .line 10
    return p0
.end method

.method public getNestedScrollAxes()I
    .locals 1

    .line 1
    iget-object p0, p0, Landroidx/core/widget/NestedScrollView;->B:Lb8/i;

    .line 2
    .line 3
    iget v0, p0, Lb8/i;->b:I

    .line 4
    .line 5
    iget p0, p0, Lb8/i;->c:I

    .line 6
    .line 7
    or-int/2addr p0, v0

    .line 8
    return p0
.end method

.method public getScrollRange()I
    .locals 4

    .line 1
    invoke-virtual {p0}, Landroid/view/ViewGroup;->getChildCount()I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    const/4 v1, 0x0

    .line 6
    if-lez v0, :cond_0

    .line 7
    .line 8
    invoke-virtual {p0, v1}, Landroid/view/ViewGroup;->getChildAt(I)Landroid/view/View;

    .line 9
    .line 10
    .line 11
    move-result-object v0

    .line 12
    invoke-virtual {v0}, Landroid/view/View;->getLayoutParams()Landroid/view/ViewGroup$LayoutParams;

    .line 13
    .line 14
    .line 15
    move-result-object v2

    .line 16
    check-cast v2, Landroid/widget/FrameLayout$LayoutParams;

    .line 17
    .line 18
    invoke-virtual {v0}, Landroid/view/View;->getHeight()I

    .line 19
    .line 20
    .line 21
    move-result v0

    .line 22
    iget v3, v2, Landroid/widget/FrameLayout$LayoutParams;->topMargin:I

    .line 23
    .line 24
    add-int/2addr v0, v3

    .line 25
    iget v2, v2, Landroid/widget/FrameLayout$LayoutParams;->bottomMargin:I

    .line 26
    .line 27
    add-int/2addr v0, v2

    .line 28
    invoke-virtual {p0}, Landroid/view/View;->getHeight()I

    .line 29
    .line 30
    .line 31
    move-result v2

    .line 32
    invoke-virtual {p0}, Landroid/view/View;->getPaddingTop()I

    .line 33
    .line 34
    .line 35
    move-result v3

    .line 36
    sub-int/2addr v2, v3

    .line 37
    invoke-virtual {p0}, Landroid/view/View;->getPaddingBottom()I

    .line 38
    .line 39
    .line 40
    move-result p0

    .line 41
    sub-int/2addr v2, p0

    .line 42
    sub-int/2addr v0, v2

    .line 43
    invoke-static {v1, v0}, Ljava/lang/Math;->max(II)I

    .line 44
    .line 45
    .line 46
    move-result p0

    .line 47
    return p0

    .line 48
    :cond_0
    return v1
.end method

.method public getTopFadingEdgeStrength()F
    .locals 1

    .line 1
    invoke-virtual {p0}, Landroid/view/ViewGroup;->getChildCount()I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    if-nez v0, :cond_0

    .line 6
    .line 7
    const/4 p0, 0x0

    .line 8
    return p0

    .line 9
    :cond_0
    invoke-virtual {p0}, Landroid/view/View;->getVerticalFadingEdgeLength()I

    .line 10
    .line 11
    .line 12
    move-result v0

    .line 13
    invoke-virtual {p0}, Landroid/view/View;->getScrollY()I

    .line 14
    .line 15
    .line 16
    move-result p0

    .line 17
    if-ge p0, v0, :cond_1

    .line 18
    .line 19
    int-to-float p0, p0

    .line 20
    int-to-float v0, v0

    .line 21
    div-float/2addr p0, v0

    .line 22
    return p0

    .line 23
    :cond_1
    const/high16 p0, 0x3f800000    # 1.0f

    .line 24
    .line 25
    return p0
.end method

.method public getVerticalScrollFactorCompat()F
    .locals 5

    .line 1
    iget v0, p0, Landroidx/core/widget/NestedScrollView;->D:F

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    cmpl-float v0, v0, v1

    .line 5
    .line 6
    if-nez v0, :cond_1

    .line 7
    .line 8
    new-instance v0, Landroid/util/TypedValue;

    .line 9
    .line 10
    invoke-direct {v0}, Landroid/util/TypedValue;-><init>()V

    .line 11
    .line 12
    .line 13
    invoke-virtual {p0}, Landroid/view/View;->getContext()Landroid/content/Context;

    .line 14
    .line 15
    .line 16
    move-result-object v1

    .line 17
    invoke-virtual {v1}, Landroid/content/Context;->getTheme()Landroid/content/res/Resources$Theme;

    .line 18
    .line 19
    .line 20
    move-result-object v2

    .line 21
    const v3, 0x101004d

    .line 22
    .line 23
    .line 24
    const/4 v4, 0x1

    .line 25
    invoke-virtual {v2, v3, v0, v4}, Landroid/content/res/Resources$Theme;->resolveAttribute(ILandroid/util/TypedValue;Z)Z

    .line 26
    .line 27
    .line 28
    move-result v2

    .line 29
    if-eqz v2, :cond_0

    .line 30
    .line 31
    invoke-virtual {v1}, Landroid/content/Context;->getResources()Landroid/content/res/Resources;

    .line 32
    .line 33
    .line 34
    move-result-object v1

    .line 35
    invoke-virtual {v1}, Landroid/content/res/Resources;->getDisplayMetrics()Landroid/util/DisplayMetrics;

    .line 36
    .line 37
    .line 38
    move-result-object v1

    .line 39
    invoke-virtual {v0, v1}, Landroid/util/TypedValue;->getDimension(Landroid/util/DisplayMetrics;)F

    .line 40
    .line 41
    .line 42
    move-result v0

    .line 43
    iput v0, p0, Landroidx/core/widget/NestedScrollView;->D:F

    .line 44
    .line 45
    goto :goto_0

    .line 46
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 47
    .line 48
    const-string v0, "Expected theme to define listPreferredItemHeight."

    .line 49
    .line 50
    invoke-direct {p0, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 51
    .line 52
    .line 53
    throw p0

    .line 54
    :cond_1
    :goto_0
    iget p0, p0, Landroidx/core/widget/NestedScrollView;->D:F

    .line 55
    .line 56
    return p0
.end method

.method public final h(Landroid/view/View;IIIII)V
    .locals 0

    .line 1
    const/4 p1, 0x0

    .line 2
    invoke-virtual {p0, p5, p6, p1}, Landroidx/core/widget/NestedScrollView;->o(II[I)V

    .line 3
    .line 4
    .line 5
    return-void
.end method

.method public final hasNestedScrollingParent()Z
    .locals 1

    .line 1
    const/4 v0, 0x0

    .line 2
    iget-object p0, p0, Landroidx/core/widget/NestedScrollView;->C:Ld6/p;

    .line 3
    .line 4
    invoke-virtual {p0, v0}, Ld6/p;->f(I)Z

    .line 5
    .line 6
    .line 7
    move-result p0

    .line 8
    return p0
.end method

.method public final i(Landroid/view/View;Landroid/view/View;II)Z
    .locals 0

    .line 1
    and-int/lit8 p0, p3, 0x2

    .line 2
    .line 3
    if-eqz p0, :cond_0

    .line 4
    .line 5
    const/4 p0, 0x1

    .line 6
    return p0

    .line 7
    :cond_0
    const/4 p0, 0x0

    .line 8
    return p0
.end method

.method public final isNestedScrollingEnabled()Z
    .locals 0

    .line 1
    iget-object p0, p0, Landroidx/core/widget/NestedScrollView;->C:Ld6/p;

    .line 2
    .line 3
    iget-boolean p0, p0, Ld6/p;->d:Z

    .line 4
    .line 5
    return p0
.end method

.method public final j(Landroid/view/KeyEvent;)Z
    .locals 5

    .line 1
    iget-object v0, p0, Landroidx/core/widget/NestedScrollView;->f:Landroid/graphics/Rect;

    .line 2
    .line 3
    invoke-virtual {v0}, Landroid/graphics/Rect;->setEmpty()V

    .line 4
    .line 5
    .line 6
    invoke-virtual {p0}, Landroid/view/ViewGroup;->getChildCount()I

    .line 7
    .line 8
    .line 9
    move-result v0

    .line 10
    const/16 v1, 0x82

    .line 11
    .line 12
    const/4 v2, 0x0

    .line 13
    if-lez v0, :cond_a

    .line 14
    .line 15
    invoke-virtual {p0, v2}, Landroid/view/ViewGroup;->getChildAt(I)Landroid/view/View;

    .line 16
    .line 17
    .line 18
    move-result-object v0

    .line 19
    invoke-virtual {v0}, Landroid/view/View;->getLayoutParams()Landroid/view/ViewGroup$LayoutParams;

    .line 20
    .line 21
    .line 22
    move-result-object v3

    .line 23
    check-cast v3, Landroid/widget/FrameLayout$LayoutParams;

    .line 24
    .line 25
    invoke-virtual {v0}, Landroid/view/View;->getHeight()I

    .line 26
    .line 27
    .line 28
    move-result v0

    .line 29
    iget v4, v3, Landroid/widget/FrameLayout$LayoutParams;->topMargin:I

    .line 30
    .line 31
    add-int/2addr v0, v4

    .line 32
    iget v3, v3, Landroid/widget/FrameLayout$LayoutParams;->bottomMargin:I

    .line 33
    .line 34
    add-int/2addr v0, v3

    .line 35
    invoke-virtual {p0}, Landroid/view/View;->getHeight()I

    .line 36
    .line 37
    .line 38
    move-result v3

    .line 39
    invoke-virtual {p0}, Landroid/view/View;->getPaddingTop()I

    .line 40
    .line 41
    .line 42
    move-result v4

    .line 43
    sub-int/2addr v3, v4

    .line 44
    invoke-virtual {p0}, Landroid/view/View;->getPaddingBottom()I

    .line 45
    .line 46
    .line 47
    move-result v4

    .line 48
    sub-int/2addr v3, v4

    .line 49
    if-le v0, v3, :cond_a

    .line 50
    .line 51
    invoke-virtual {p1}, Landroid/view/KeyEvent;->getAction()I

    .line 52
    .line 53
    .line 54
    move-result v0

    .line 55
    if-nez v0, :cond_c

    .line 56
    .line 57
    invoke-virtual {p1}, Landroid/view/KeyEvent;->getKeyCode()I

    .line 58
    .line 59
    .line 60
    move-result v0

    .line 61
    const/16 v3, 0x13

    .line 62
    .line 63
    const/16 v4, 0x21

    .line 64
    .line 65
    if-eq v0, v3, :cond_8

    .line 66
    .line 67
    const/16 v3, 0x14

    .line 68
    .line 69
    if-eq v0, v3, :cond_6

    .line 70
    .line 71
    const/16 v3, 0x3e

    .line 72
    .line 73
    if-eq v0, v3, :cond_4

    .line 74
    .line 75
    const/16 p1, 0x5c

    .line 76
    .line 77
    if-eq v0, p1, :cond_3

    .line 78
    .line 79
    const/16 p1, 0x5d

    .line 80
    .line 81
    if-eq v0, p1, :cond_2

    .line 82
    .line 83
    const/16 p1, 0x7a

    .line 84
    .line 85
    if-eq v0, p1, :cond_1

    .line 86
    .line 87
    const/16 p1, 0x7b

    .line 88
    .line 89
    if-eq v0, p1, :cond_0

    .line 90
    .line 91
    goto :goto_0

    .line 92
    :cond_0
    invoke-virtual {p0, v1}, Landroidx/core/widget/NestedScrollView;->r(I)V

    .line 93
    .line 94
    .line 95
    return v2

    .line 96
    :cond_1
    invoke-virtual {p0, v4}, Landroidx/core/widget/NestedScrollView;->r(I)V

    .line 97
    .line 98
    .line 99
    return v2

    .line 100
    :cond_2
    invoke-virtual {p0, v1}, Landroidx/core/widget/NestedScrollView;->l(I)Z

    .line 101
    .line 102
    .line 103
    move-result p0

    .line 104
    return p0

    .line 105
    :cond_3
    invoke-virtual {p0, v4}, Landroidx/core/widget/NestedScrollView;->l(I)Z

    .line 106
    .line 107
    .line 108
    move-result p0

    .line 109
    return p0

    .line 110
    :cond_4
    invoke-virtual {p1}, Landroid/view/KeyEvent;->isShiftPressed()Z

    .line 111
    .line 112
    .line 113
    move-result p1

    .line 114
    if-eqz p1, :cond_5

    .line 115
    .line 116
    move v1, v4

    .line 117
    :cond_5
    invoke-virtual {p0, v1}, Landroidx/core/widget/NestedScrollView;->r(I)V

    .line 118
    .line 119
    .line 120
    return v2

    .line 121
    :cond_6
    invoke-virtual {p1}, Landroid/view/KeyEvent;->isAltPressed()Z

    .line 122
    .line 123
    .line 124
    move-result p1

    .line 125
    if-eqz p1, :cond_7

    .line 126
    .line 127
    invoke-virtual {p0, v1}, Landroidx/core/widget/NestedScrollView;->l(I)Z

    .line 128
    .line 129
    .line 130
    move-result p0

    .line 131
    return p0

    .line 132
    :cond_7
    invoke-virtual {p0, v1}, Landroidx/core/widget/NestedScrollView;->a(I)Z

    .line 133
    .line 134
    .line 135
    move-result p0

    .line 136
    return p0

    .line 137
    :cond_8
    invoke-virtual {p1}, Landroid/view/KeyEvent;->isAltPressed()Z

    .line 138
    .line 139
    .line 140
    move-result p1

    .line 141
    if-eqz p1, :cond_9

    .line 142
    .line 143
    invoke-virtual {p0, v4}, Landroidx/core/widget/NestedScrollView;->l(I)Z

    .line 144
    .line 145
    .line 146
    move-result p0

    .line 147
    return p0

    .line 148
    :cond_9
    invoke-virtual {p0, v4}, Landroidx/core/widget/NestedScrollView;->a(I)Z

    .line 149
    .line 150
    .line 151
    move-result p0

    .line 152
    return p0

    .line 153
    :cond_a
    invoke-virtual {p0}, Landroid/view/View;->isFocused()Z

    .line 154
    .line 155
    .line 156
    move-result v0

    .line 157
    if-eqz v0, :cond_c

    .line 158
    .line 159
    invoke-virtual {p1}, Landroid/view/KeyEvent;->getKeyCode()I

    .line 160
    .line 161
    .line 162
    move-result p1

    .line 163
    const/4 v0, 0x4

    .line 164
    if-eq p1, v0, :cond_c

    .line 165
    .line 166
    invoke-virtual {p0}, Landroid/view/View;->findFocus()Landroid/view/View;

    .line 167
    .line 168
    .line 169
    move-result-object p1

    .line 170
    if-ne p1, p0, :cond_b

    .line 171
    .line 172
    const/4 p1, 0x0

    .line 173
    :cond_b
    invoke-static {}, Landroid/view/FocusFinder;->getInstance()Landroid/view/FocusFinder;

    .line 174
    .line 175
    .line 176
    move-result-object v0

    .line 177
    invoke-virtual {v0, p0, p1, v1}, Landroid/view/FocusFinder;->findNextFocus(Landroid/view/ViewGroup;Landroid/view/View;I)Landroid/view/View;

    .line 178
    .line 179
    .line 180
    move-result-object p1

    .line 181
    if-eqz p1, :cond_c

    .line 182
    .line 183
    if-eq p1, p0, :cond_c

    .line 184
    .line 185
    invoke-virtual {p1, v1}, Landroid/view/View;->requestFocus(I)Z

    .line 186
    .line 187
    .line 188
    move-result p0

    .line 189
    if-eqz p0, :cond_c

    .line 190
    .line 191
    const/4 p0, 0x1

    .line 192
    return p0

    .line 193
    :cond_c
    :goto_0
    return v2
.end method

.method public final k(I)V
    .locals 12

    .line 1
    invoke-virtual {p0}, Landroid/view/ViewGroup;->getChildCount()I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    if-lez v0, :cond_0

    .line 6
    .line 7
    invoke-virtual {p0}, Landroid/view/View;->getScrollX()I

    .line 8
    .line 9
    .line 10
    move-result v2

    .line 11
    invoke-virtual {p0}, Landroid/view/View;->getScrollY()I

    .line 12
    .line 13
    .line 14
    move-result v3

    .line 15
    const/4 v10, 0x0

    .line 16
    const/4 v11, 0x0

    .line 17
    iget-object v1, p0, Landroidx/core/widget/NestedScrollView;->g:Landroid/widget/OverScroller;

    .line 18
    .line 19
    const/4 v4, 0x0

    .line 20
    const/4 v6, 0x0

    .line 21
    const/4 v7, 0x0

    .line 22
    const/high16 v8, -0x80000000

    .line 23
    .line 24
    const v9, 0x7fffffff

    .line 25
    .line 26
    .line 27
    move v5, p1

    .line 28
    invoke-virtual/range {v1 .. v11}, Landroid/widget/OverScroller;->fling(IIIIIIIIII)V

    .line 29
    .line 30
    .line 31
    const/4 p1, 0x1

    .line 32
    const/4 v0, 0x2

    .line 33
    invoke-virtual {p0, v0, p1}, Landroidx/core/widget/NestedScrollView;->w(II)V

    .line 34
    .line 35
    .line 36
    invoke-virtual {p0}, Landroid/view/View;->getScrollY()I

    .line 37
    .line 38
    .line 39
    move-result p1

    .line 40
    iput p1, p0, Landroidx/core/widget/NestedScrollView;->z:I

    .line 41
    .line 42
    invoke-virtual {p0}, Landroid/view/View;->postInvalidateOnAnimation()V

    .line 43
    .line 44
    .line 45
    sget p1, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 46
    .line 47
    const/16 v0, 0x23

    .line 48
    .line 49
    if-lt p1, v0, :cond_0

    .line 50
    .line 51
    iget-object p1, p0, Landroidx/core/widget/NestedScrollView;->g:Landroid/widget/OverScroller;

    .line 52
    .line 53
    invoke-virtual {p1}, Landroid/widget/OverScroller;->getCurrVelocity()F

    .line 54
    .line 55
    .line 56
    move-result p1

    .line 57
    invoke-static {p1}, Ljava/lang/Math;->abs(F)F

    .line 58
    .line 59
    .line 60
    move-result p1

    .line 61
    invoke-static {p0, p1}, Lf6/a;->a(Landroidx/core/widget/NestedScrollView;F)V

    .line 62
    .line 63
    .line 64
    :cond_0
    return-void
.end method

.method public final l(I)Z
    .locals 5

    .line 1
    const/16 v0, 0x82

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    const/4 v2, 0x1

    .line 5
    if-ne p1, v0, :cond_0

    .line 6
    .line 7
    move v0, v2

    .line 8
    goto :goto_0

    .line 9
    :cond_0
    move v0, v1

    .line 10
    :goto_0
    invoke-virtual {p0}, Landroid/view/View;->getHeight()I

    .line 11
    .line 12
    .line 13
    move-result v3

    .line 14
    iget-object v4, p0, Landroidx/core/widget/NestedScrollView;->f:Landroid/graphics/Rect;

    .line 15
    .line 16
    iput v1, v4, Landroid/graphics/Rect;->top:I

    .line 17
    .line 18
    iput v3, v4, Landroid/graphics/Rect;->bottom:I

    .line 19
    .line 20
    if-eqz v0, :cond_1

    .line 21
    .line 22
    invoke-virtual {p0}, Landroid/view/ViewGroup;->getChildCount()I

    .line 23
    .line 24
    .line 25
    move-result v0

    .line 26
    if-lez v0, :cond_1

    .line 27
    .line 28
    sub-int/2addr v0, v2

    .line 29
    invoke-virtual {p0, v0}, Landroid/view/ViewGroup;->getChildAt(I)Landroid/view/View;

    .line 30
    .line 31
    .line 32
    move-result-object v0

    .line 33
    invoke-virtual {v0}, Landroid/view/View;->getLayoutParams()Landroid/view/ViewGroup$LayoutParams;

    .line 34
    .line 35
    .line 36
    move-result-object v1

    .line 37
    check-cast v1, Landroid/widget/FrameLayout$LayoutParams;

    .line 38
    .line 39
    invoke-virtual {v0}, Landroid/view/View;->getBottom()I

    .line 40
    .line 41
    .line 42
    move-result v0

    .line 43
    iget v1, v1, Landroid/widget/FrameLayout$LayoutParams;->bottomMargin:I

    .line 44
    .line 45
    add-int/2addr v0, v1

    .line 46
    invoke-virtual {p0}, Landroid/view/View;->getPaddingBottom()I

    .line 47
    .line 48
    .line 49
    move-result v1

    .line 50
    add-int/2addr v1, v0

    .line 51
    iput v1, v4, Landroid/graphics/Rect;->bottom:I

    .line 52
    .line 53
    sub-int/2addr v1, v3

    .line 54
    iput v1, v4, Landroid/graphics/Rect;->top:I

    .line 55
    .line 56
    :cond_1
    iget v0, v4, Landroid/graphics/Rect;->top:I

    .line 57
    .line 58
    iget v1, v4, Landroid/graphics/Rect;->bottom:I

    .line 59
    .line 60
    invoke-virtual {p0, p1, v0, v1}, Landroidx/core/widget/NestedScrollView;->s(III)Z

    .line 61
    .line 62
    .line 63
    move-result p0

    .line 64
    return p0
.end method

.method public final measureChild(Landroid/view/View;II)V
    .locals 1

    .line 1
    invoke-virtual {p1}, Landroid/view/View;->getLayoutParams()Landroid/view/ViewGroup$LayoutParams;

    .line 2
    .line 3
    .line 4
    move-result-object p3

    .line 5
    invoke-virtual {p0}, Landroid/view/View;->getPaddingLeft()I

    .line 6
    .line 7
    .line 8
    move-result v0

    .line 9
    invoke-virtual {p0}, Landroid/view/View;->getPaddingRight()I

    .line 10
    .line 11
    .line 12
    move-result p0

    .line 13
    add-int/2addr p0, v0

    .line 14
    iget p3, p3, Landroid/view/ViewGroup$LayoutParams;->width:I

    .line 15
    .line 16
    invoke-static {p2, p0, p3}, Landroid/view/ViewGroup;->getChildMeasureSpec(III)I

    .line 17
    .line 18
    .line 19
    move-result p0

    .line 20
    const/4 p2, 0x0

    .line 21
    invoke-static {p2, p2}, Landroid/view/View$MeasureSpec;->makeMeasureSpec(II)I

    .line 22
    .line 23
    .line 24
    move-result p2

    .line 25
    invoke-virtual {p1, p0, p2}, Landroid/view/View;->measure(II)V

    .line 26
    .line 27
    .line 28
    return-void
.end method

.method public final measureChildWithMargins(Landroid/view/View;IIII)V
    .locals 0

    .line 1
    invoke-virtual {p1}, Landroid/view/View;->getLayoutParams()Landroid/view/ViewGroup$LayoutParams;

    .line 2
    .line 3
    .line 4
    move-result-object p4

    .line 5
    check-cast p4, Landroid/view/ViewGroup$MarginLayoutParams;

    .line 6
    .line 7
    invoke-virtual {p0}, Landroid/view/View;->getPaddingLeft()I

    .line 8
    .line 9
    .line 10
    move-result p5

    .line 11
    invoke-virtual {p0}, Landroid/view/View;->getPaddingRight()I

    .line 12
    .line 13
    .line 14
    move-result p0

    .line 15
    add-int/2addr p0, p5

    .line 16
    iget p5, p4, Landroid/view/ViewGroup$MarginLayoutParams;->leftMargin:I

    .line 17
    .line 18
    add-int/2addr p0, p5

    .line 19
    iget p5, p4, Landroid/view/ViewGroup$MarginLayoutParams;->rightMargin:I

    .line 20
    .line 21
    add-int/2addr p0, p5

    .line 22
    add-int/2addr p0, p3

    .line 23
    iget p3, p4, Landroid/view/ViewGroup$MarginLayoutParams;->width:I

    .line 24
    .line 25
    invoke-static {p2, p0, p3}, Landroid/view/ViewGroup;->getChildMeasureSpec(III)I

    .line 26
    .line 27
    .line 28
    move-result p0

    .line 29
    iget p2, p4, Landroid/view/ViewGroup$MarginLayoutParams;->topMargin:I

    .line 30
    .line 31
    iget p3, p4, Landroid/view/ViewGroup$MarginLayoutParams;->bottomMargin:I

    .line 32
    .line 33
    add-int/2addr p2, p3

    .line 34
    const/4 p3, 0x0

    .line 35
    invoke-static {p2, p3}, Landroid/view/View$MeasureSpec;->makeMeasureSpec(II)I

    .line 36
    .line 37
    .line 38
    move-result p2

    .line 39
    invoke-virtual {p1, p0, p2}, Landroid/view/View;->measure(II)V

    .line 40
    .line 41
    .line 42
    return-void
.end method

.method public final n(Landroid/view/View;II)Z
    .locals 2

    .line 1
    iget-object v0, p0, Landroidx/core/widget/NestedScrollView;->f:Landroid/graphics/Rect;

    .line 2
    .line 3
    invoke-virtual {p1, v0}, Landroid/view/View;->getDrawingRect(Landroid/graphics/Rect;)V

    .line 4
    .line 5
    .line 6
    invoke-virtual {p0, p1, v0}, Landroid/view/ViewGroup;->offsetDescendantRectToMyCoords(Landroid/view/View;Landroid/graphics/Rect;)V

    .line 7
    .line 8
    .line 9
    iget p1, v0, Landroid/graphics/Rect;->bottom:I

    .line 10
    .line 11
    add-int/2addr p1, p2

    .line 12
    invoke-virtual {p0}, Landroid/view/View;->getScrollY()I

    .line 13
    .line 14
    .line 15
    move-result v1

    .line 16
    if-lt p1, v1, :cond_0

    .line 17
    .line 18
    iget p1, v0, Landroid/graphics/Rect;->top:I

    .line 19
    .line 20
    sub-int/2addr p1, p2

    .line 21
    invoke-virtual {p0}, Landroid/view/View;->getScrollY()I

    .line 22
    .line 23
    .line 24
    move-result p0

    .line 25
    add-int/2addr p0, p3

    .line 26
    if-gt p1, p0, :cond_0

    .line 27
    .line 28
    const/4 p0, 0x1

    .line 29
    return p0

    .line 30
    :cond_0
    const/4 p0, 0x0

    .line 31
    return p0
.end method

.method public final o(II[I)V
    .locals 10

    .line 1
    invoke-virtual {p0}, Landroid/view/View;->getScrollY()I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    const/4 v1, 0x0

    .line 6
    invoke-virtual {p0, v1, p1}, Landroid/view/View;->scrollBy(II)V

    .line 7
    .line 8
    .line 9
    invoke-virtual {p0}, Landroid/view/View;->getScrollY()I

    .line 10
    .line 11
    .line 12
    move-result v1

    .line 13
    sub-int v4, v1, v0

    .line 14
    .line 15
    if-eqz p3, :cond_0

    .line 16
    .line 17
    const/4 v0, 0x1

    .line 18
    aget v1, p3, v0

    .line 19
    .line 20
    add-int/2addr v1, v4

    .line 21
    aput v1, p3, v0

    .line 22
    .line 23
    :cond_0
    sub-int v6, p1, v4

    .line 24
    .line 25
    const/4 v5, 0x0

    .line 26
    const/4 v7, 0x0

    .line 27
    iget-object v2, p0, Landroidx/core/widget/NestedScrollView;->C:Ld6/p;

    .line 28
    .line 29
    const/4 v3, 0x0

    .line 30
    move v8, p2

    .line 31
    move-object v9, p3

    .line 32
    invoke-virtual/range {v2 .. v9}, Ld6/p;->d(IIII[II[I)Z

    .line 33
    .line 34
    .line 35
    return-void
.end method

.method public final onAttachedToWindow()V
    .locals 1

    .line 1
    invoke-super {p0}, Landroid/view/View;->onAttachedToWindow()V

    .line 2
    .line 3
    .line 4
    const/4 v0, 0x0

    .line 5
    iput-boolean v0, p0, Landroidx/core/widget/NestedScrollView;->m:Z

    .line 6
    .line 7
    return-void
.end method

.method public final onGenericMotionEvent(Landroid/view/MotionEvent;)Z
    .locals 29

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v3, p1

    .line 4
    .line 5
    invoke-virtual {v3}, Landroid/view/MotionEvent;->getAction()I

    .line 6
    .line 7
    .line 8
    move-result v1

    .line 9
    const/16 v2, 0x8

    .line 10
    .line 11
    if-ne v1, v2, :cond_2e

    .line 12
    .line 13
    iget-boolean v1, v0, Landroidx/core/widget/NestedScrollView;->o:Z

    .line 14
    .line 15
    if-nez v1, :cond_2e

    .line 16
    .line 17
    invoke-virtual {v3}, Landroid/view/MotionEvent;->getSource()I

    .line 18
    .line 19
    .line 20
    move-result v1

    .line 21
    const/4 v8, 0x2

    .line 22
    and-int/2addr v1, v8

    .line 23
    const/high16 v9, 0x400000

    .line 24
    .line 25
    const/4 v10, 0x0

    .line 26
    const/16 v11, 0x1a

    .line 27
    .line 28
    if-ne v1, v8, :cond_0

    .line 29
    .line 30
    const/16 v1, 0x9

    .line 31
    .line 32
    invoke-virtual {v3, v1}, Landroid/view/MotionEvent;->getAxisValue(I)F

    .line 33
    .line 34
    .line 35
    move-result v2

    .line 36
    invoke-virtual {v3}, Landroid/view/MotionEvent;->getX()F

    .line 37
    .line 38
    .line 39
    move-result v4

    .line 40
    float-to-int v4, v4

    .line 41
    move/from16 v28, v2

    .line 42
    .line 43
    move v2, v1

    .line 44
    move/from16 v1, v28

    .line 45
    .line 46
    goto :goto_0

    .line 47
    :cond_0
    invoke-virtual {v3}, Landroid/view/MotionEvent;->getSource()I

    .line 48
    .line 49
    .line 50
    move-result v1

    .line 51
    and-int/2addr v1, v9

    .line 52
    if-ne v1, v9, :cond_1

    .line 53
    .line 54
    invoke-virtual {v3, v11}, Landroid/view/MotionEvent;->getAxisValue(I)F

    .line 55
    .line 56
    .line 57
    move-result v2

    .line 58
    invoke-virtual {v0}, Landroid/view/View;->getWidth()I

    .line 59
    .line 60
    .line 61
    move-result v1

    .line 62
    div-int/lit8 v4, v1, 0x2

    .line 63
    .line 64
    move v1, v2

    .line 65
    move v2, v11

    .line 66
    goto :goto_0

    .line 67
    :cond_1
    move v1, v10

    .line 68
    const/4 v2, 0x0

    .line 69
    const/4 v4, 0x0

    .line 70
    :goto_0
    cmpl-float v5, v1, v10

    .line 71
    .line 72
    if-eqz v5, :cond_2e

    .line 73
    .line 74
    invoke-virtual {v0}, Landroidx/core/widget/NestedScrollView;->getVerticalScrollFactorCompat()F

    .line 75
    .line 76
    .line 77
    move-result v5

    .line 78
    mul-float/2addr v5, v1

    .line 79
    float-to-int v1, v5

    .line 80
    invoke-virtual {v3}, Landroid/view/MotionEvent;->getSource()I

    .line 81
    .line 82
    .line 83
    move-result v5

    .line 84
    const/16 v6, 0x2002

    .line 85
    .line 86
    and-int/2addr v5, v6

    .line 87
    if-ne v5, v6, :cond_2

    .line 88
    .line 89
    const/4 v6, 0x1

    .line 90
    goto :goto_1

    .line 91
    :cond_2
    const/4 v6, 0x0

    .line 92
    :goto_1
    neg-int v1, v1

    .line 93
    const/4 v5, 0x1

    .line 94
    invoke-virtual/range {v0 .. v6}, Landroidx/core/widget/NestedScrollView;->t(IILandroid/view/MotionEvent;IIZ)I

    .line 95
    .line 96
    .line 97
    if-eqz v2, :cond_2a

    .line 98
    .line 99
    iget-object v0, v0, Landroidx/core/widget/NestedScrollView;->E:Ld6/g;

    .line 100
    .line 101
    iget-object v1, v0, Ld6/g;->b:Lh6/e;

    .line 102
    .line 103
    iget-object v1, v1, Lh6/e;->e:Ljava/lang/Object;

    .line 104
    .line 105
    check-cast v1, Landroidx/core/widget/NestedScrollView;

    .line 106
    .line 107
    iget-object v4, v0, Ld6/g;->h:[I

    .line 108
    .line 109
    invoke-virtual {v3}, Landroid/view/MotionEvent;->getSource()I

    .line 110
    .line 111
    .line 112
    move-result v5

    .line 113
    invoke-virtual {v3}, Landroid/view/MotionEvent;->getDeviceId()I

    .line 114
    .line 115
    .line 116
    move-result v6

    .line 117
    iget v13, v0, Ld6/g;->f:I

    .line 118
    .line 119
    const/16 v14, 0x22

    .line 120
    .line 121
    if-ne v13, v5, :cond_4

    .line 122
    .line 123
    iget v13, v0, Ld6/g;->g:I

    .line 124
    .line 125
    if-ne v13, v6, :cond_4

    .line 126
    .line 127
    iget v13, v0, Ld6/g;->e:I

    .line 128
    .line 129
    if-eq v13, v2, :cond_3

    .line 130
    .line 131
    goto :goto_2

    .line 132
    :cond_3
    const/4 v7, 0x0

    .line 133
    const/16 v16, 0x1

    .line 134
    .line 135
    const/16 v19, 0x0

    .line 136
    .line 137
    goto/16 :goto_9

    .line 138
    .line 139
    :cond_4
    :goto_2
    iget-object v13, v0, Ld6/g;->a:Landroid/content/Context;

    .line 140
    .line 141
    const/16 v16, 0x1

    .line 142
    .line 143
    invoke-static {v13}, Landroid/view/ViewConfiguration;->get(Landroid/content/Context;)Landroid/view/ViewConfiguration;

    .line 144
    .line 145
    .line 146
    move-result-object v12

    .line 147
    invoke-virtual {v3}, Landroid/view/MotionEvent;->getDeviceId()I

    .line 148
    .line 149
    .line 150
    move-result v8

    .line 151
    invoke-virtual {v3}, Landroid/view/MotionEvent;->getSource()I

    .line 152
    .line 153
    .line 154
    move-result v10

    .line 155
    const/16 v19, 0x0

    .line 156
    .line 157
    sget v7, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 158
    .line 159
    const-string v15, "android"

    .line 160
    .line 161
    const-string v11, "dimen"

    .line 162
    .line 163
    const/4 v9, -0x1

    .line 164
    if-lt v7, v14, :cond_5

    .line 165
    .line 166
    invoke-static {v12, v8, v2, v10}, Lb/a;->i(Landroid/view/ViewConfiguration;III)I

    .line 167
    .line 168
    .line 169
    move-result v8

    .line 170
    goto :goto_5

    .line 171
    :cond_5
    invoke-static {v8}, Landroid/view/InputDevice;->getDevice(I)Landroid/view/InputDevice;

    .line 172
    .line 173
    .line 174
    move-result-object v8

    .line 175
    if-eqz v8, :cond_8

    .line 176
    .line 177
    invoke-virtual {v8, v2, v10}, Landroid/view/InputDevice;->getMotionRange(II)Landroid/view/InputDevice$MotionRange;

    .line 178
    .line 179
    .line 180
    move-result-object v8

    .line 181
    if-eqz v8, :cond_8

    .line 182
    .line 183
    invoke-virtual {v13}, Landroid/content/Context;->getResources()Landroid/content/res/Resources;

    .line 184
    .line 185
    .line 186
    move-result-object v8

    .line 187
    const/high16 v14, 0x400000

    .line 188
    .line 189
    if-ne v10, v14, :cond_6

    .line 190
    .line 191
    const/16 v10, 0x1a

    .line 192
    .line 193
    if-ne v2, v10, :cond_6

    .line 194
    .line 195
    const-string v10, "config_viewMinRotaryEncoderFlingVelocity"

    .line 196
    .line 197
    invoke-virtual {v8, v10, v11, v15}, Landroid/content/res/Resources;->getIdentifier(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)I

    .line 198
    .line 199
    .line 200
    move-result v10

    .line 201
    goto :goto_3

    .line 202
    :cond_6
    move v10, v9

    .line 203
    :goto_3
    invoke-static {v12}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;)Ljava/lang/Object;

    .line 204
    .line 205
    .line 206
    if-eq v10, v9, :cond_7

    .line 207
    .line 208
    if-eqz v10, :cond_8

    .line 209
    .line 210
    invoke-virtual {v8, v10}, Landroid/content/res/Resources;->getDimensionPixelSize(I)I

    .line 211
    .line 212
    .line 213
    move-result v8

    .line 214
    if-gez v8, :cond_9

    .line 215
    .line 216
    goto :goto_4

    .line 217
    :cond_7
    invoke-virtual {v12}, Landroid/view/ViewConfiguration;->getScaledMinimumFlingVelocity()I

    .line 218
    .line 219
    .line 220
    move-result v8

    .line 221
    goto :goto_5

    .line 222
    :cond_8
    :goto_4
    const v8, 0x7fffffff

    .line 223
    .line 224
    .line 225
    :cond_9
    :goto_5
    aput v8, v4, v19

    .line 226
    .line 227
    invoke-virtual {v3}, Landroid/view/MotionEvent;->getDeviceId()I

    .line 228
    .line 229
    .line 230
    move-result v8

    .line 231
    invoke-virtual {v3}, Landroid/view/MotionEvent;->getSource()I

    .line 232
    .line 233
    .line 234
    move-result v10

    .line 235
    const/16 v14, 0x22

    .line 236
    .line 237
    if-lt v7, v14, :cond_a

    .line 238
    .line 239
    invoke-static {v12, v8, v2, v10}, Lb/a;->h(Landroid/view/ViewConfiguration;III)I

    .line 240
    .line 241
    .line 242
    move-result v7

    .line 243
    goto :goto_8

    .line 244
    :cond_a
    invoke-static {v8}, Landroid/view/InputDevice;->getDevice(I)Landroid/view/InputDevice;

    .line 245
    .line 246
    .line 247
    move-result-object v7

    .line 248
    const/high16 v8, -0x80000000

    .line 249
    .line 250
    if-eqz v7, :cond_d

    .line 251
    .line 252
    invoke-virtual {v7, v2, v10}, Landroid/view/InputDevice;->getMotionRange(II)Landroid/view/InputDevice$MotionRange;

    .line 253
    .line 254
    .line 255
    move-result-object v7

    .line 256
    if-eqz v7, :cond_d

    .line 257
    .line 258
    invoke-virtual {v13}, Landroid/content/Context;->getResources()Landroid/content/res/Resources;

    .line 259
    .line 260
    .line 261
    move-result-object v7

    .line 262
    const/high16 v14, 0x400000

    .line 263
    .line 264
    if-ne v10, v14, :cond_b

    .line 265
    .line 266
    const/16 v10, 0x1a

    .line 267
    .line 268
    if-ne v2, v10, :cond_b

    .line 269
    .line 270
    const-string v10, "config_viewMaxRotaryEncoderFlingVelocity"

    .line 271
    .line 272
    invoke-virtual {v7, v10, v11, v15}, Landroid/content/res/Resources;->getIdentifier(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)I

    .line 273
    .line 274
    .line 275
    move-result v10

    .line 276
    goto :goto_6

    .line 277
    :cond_b
    move v10, v9

    .line 278
    :goto_6
    invoke-static {v12}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;)Ljava/lang/Object;

    .line 279
    .line 280
    .line 281
    if-eq v10, v9, :cond_c

    .line 282
    .line 283
    if-eqz v10, :cond_d

    .line 284
    .line 285
    invoke-virtual {v7, v10}, Landroid/content/res/Resources;->getDimensionPixelSize(I)I

    .line 286
    .line 287
    .line 288
    move-result v7

    .line 289
    if-gez v7, :cond_e

    .line 290
    .line 291
    goto :goto_7

    .line 292
    :cond_c
    invoke-virtual {v12}, Landroid/view/ViewConfiguration;->getScaledMaximumFlingVelocity()I

    .line 293
    .line 294
    .line 295
    move-result v7

    .line 296
    goto :goto_8

    .line 297
    :cond_d
    :goto_7
    move v7, v8

    .line 298
    :cond_e
    :goto_8
    aput v7, v4, v16

    .line 299
    .line 300
    iput v5, v0, Ld6/g;->f:I

    .line 301
    .line 302
    iput v6, v0, Ld6/g;->g:I

    .line 303
    .line 304
    iput v2, v0, Ld6/g;->e:I

    .line 305
    .line 306
    move/from16 v7, v16

    .line 307
    .line 308
    :goto_9
    aget v5, v4, v19

    .line 309
    .line 310
    const v6, 0x7fffffff

    .line 311
    .line 312
    .line 313
    if-ne v5, v6, :cond_f

    .line 314
    .line 315
    iget-object v1, v0, Ld6/g;->c:Landroid/view/VelocityTracker;

    .line 316
    .line 317
    if-eqz v1, :cond_2d

    .line 318
    .line 319
    invoke-virtual {v1}, Landroid/view/VelocityTracker;->recycle()V

    .line 320
    .line 321
    .line 322
    const/4 v1, 0x0

    .line 323
    iput-object v1, v0, Ld6/g;->c:Landroid/view/VelocityTracker;

    .line 324
    .line 325
    return v16

    .line 326
    :cond_f
    iget-object v5, v0, Ld6/g;->c:Landroid/view/VelocityTracker;

    .line 327
    .line 328
    if-nez v5, :cond_10

    .line 329
    .line 330
    invoke-static {}, Landroid/view/VelocityTracker;->obtain()Landroid/view/VelocityTracker;

    .line 331
    .line 332
    .line 333
    move-result-object v5

    .line 334
    iput-object v5, v0, Ld6/g;->c:Landroid/view/VelocityTracker;

    .line 335
    .line 336
    :cond_10
    iget-object v5, v0, Ld6/g;->c:Landroid/view/VelocityTracker;

    .line 337
    .line 338
    sget-object v6, Ld6/c0;->a:Ljava/util/Map;

    .line 339
    .line 340
    invoke-virtual {v5, v3}, Landroid/view/VelocityTracker;->addMovement(Landroid/view/MotionEvent;)V

    .line 341
    .line 342
    .line 343
    sget v6, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 344
    .line 345
    const/16 v8, 0x14

    .line 346
    .line 347
    const/16 v14, 0x22

    .line 348
    .line 349
    if-lt v6, v14, :cond_11

    .line 350
    .line 351
    goto :goto_a

    .line 352
    :cond_11
    invoke-virtual {v3}, Landroid/view/MotionEvent;->getSource()I

    .line 353
    .line 354
    .line 355
    move-result v6

    .line 356
    const/high16 v14, 0x400000

    .line 357
    .line 358
    if-ne v6, v14, :cond_15

    .line 359
    .line 360
    sget-object v6, Ld6/c0;->a:Ljava/util/Map;

    .line 361
    .line 362
    invoke-interface {v6, v5}, Ljava/util/Map;->containsKey(Ljava/lang/Object;)Z

    .line 363
    .line 364
    .line 365
    move-result v9

    .line 366
    if-nez v9, :cond_12

    .line 367
    .line 368
    new-instance v9, Ld6/d0;

    .line 369
    .line 370
    invoke-direct {v9}, Ld6/d0;-><init>()V

    .line 371
    .line 372
    .line 373
    invoke-interface {v6, v5, v9}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 374
    .line 375
    .line 376
    :cond_12
    invoke-interface {v6, v5}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 377
    .line 378
    .line 379
    move-result-object v6

    .line 380
    check-cast v6, Ld6/d0;

    .line 381
    .line 382
    iget-object v9, v6, Ld6/d0;->b:[J

    .line 383
    .line 384
    invoke-virtual {v3}, Landroid/view/MotionEvent;->getEventTime()J

    .line 385
    .line 386
    .line 387
    move-result-wide v10

    .line 388
    iget v12, v6, Ld6/d0;->d:I

    .line 389
    .line 390
    if-eqz v12, :cond_13

    .line 391
    .line 392
    iget v12, v6, Ld6/d0;->e:I

    .line 393
    .line 394
    aget-wide v12, v9, v12

    .line 395
    .line 396
    sub-long v12, v10, v12

    .line 397
    .line 398
    const-wide/16 v14, 0x28

    .line 399
    .line 400
    cmp-long v12, v12, v14

    .line 401
    .line 402
    if-lez v12, :cond_13

    .line 403
    .line 404
    move/from16 v12, v19

    .line 405
    .line 406
    iput v12, v6, Ld6/d0;->d:I

    .line 407
    .line 408
    const/4 v12, 0x0

    .line 409
    iput v12, v6, Ld6/d0;->c:F

    .line 410
    .line 411
    :cond_13
    iget v12, v6, Ld6/d0;->e:I

    .line 412
    .line 413
    add-int/lit8 v12, v12, 0x1

    .line 414
    .line 415
    rem-int/2addr v12, v8

    .line 416
    iput v12, v6, Ld6/d0;->e:I

    .line 417
    .line 418
    iget v13, v6, Ld6/d0;->d:I

    .line 419
    .line 420
    if-eq v13, v8, :cond_14

    .line 421
    .line 422
    add-int/lit8 v13, v13, 0x1

    .line 423
    .line 424
    iput v13, v6, Ld6/d0;->d:I

    .line 425
    .line 426
    :cond_14
    iget-object v13, v6, Ld6/d0;->a:[F

    .line 427
    .line 428
    const/16 v14, 0x1a

    .line 429
    .line 430
    invoke-virtual {v3, v14}, Landroid/view/MotionEvent;->getAxisValue(I)F

    .line 431
    .line 432
    .line 433
    move-result v3

    .line 434
    aput v3, v13, v12

    .line 435
    .line 436
    iget v3, v6, Ld6/d0;->e:I

    .line 437
    .line 438
    aput-wide v10, v9, v3

    .line 439
    .line 440
    :cond_15
    :goto_a
    const/16 v3, 0x3e8

    .line 441
    .line 442
    const v6, 0x7f7fffff    # Float.MAX_VALUE

    .line 443
    .line 444
    .line 445
    invoke-virtual {v5, v3, v6}, Landroid/view/VelocityTracker;->computeCurrentVelocity(IF)V

    .line 446
    .line 447
    .line 448
    sget-object v9, Ld6/c0;->a:Ljava/util/Map;

    .line 449
    .line 450
    invoke-interface {v9, v5}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 451
    .line 452
    .line 453
    move-result-object v9

    .line 454
    check-cast v9, Ld6/d0;

    .line 455
    .line 456
    if-eqz v9, :cond_21

    .line 457
    .line 458
    iget-object v10, v9, Ld6/d0;->a:[F

    .line 459
    .line 460
    iget-object v11, v9, Ld6/d0;->b:[J

    .line 461
    .line 462
    iget v12, v9, Ld6/d0;->d:I

    .line 463
    .line 464
    const/4 v13, 0x2

    .line 465
    if-ge v12, v13, :cond_16

    .line 466
    .line 467
    :goto_b
    move-object/from16 v25, v4

    .line 468
    .line 469
    move/from16 p0, v6

    .line 470
    .line 471
    move v4, v3

    .line 472
    const/4 v3, 0x0

    .line 473
    goto/16 :goto_f

    .line 474
    .line 475
    :cond_16
    iget v13, v9, Ld6/d0;->e:I

    .line 476
    .line 477
    add-int/lit8 v14, v13, 0x14

    .line 478
    .line 479
    add-int/lit8 v12, v12, -0x1

    .line 480
    .line 481
    sub-int/2addr v14, v12

    .line 482
    rem-int/2addr v14, v8

    .line 483
    aget-wide v12, v11, v13

    .line 484
    .line 485
    :goto_c
    aget-wide v21, v11, v14

    .line 486
    .line 487
    sub-long v23, v12, v21

    .line 488
    .line 489
    const-wide/16 v25, 0x64

    .line 490
    .line 491
    cmp-long v15, v23, v25

    .line 492
    .line 493
    if-lez v15, :cond_17

    .line 494
    .line 495
    iget v15, v9, Ld6/d0;->d:I

    .line 496
    .line 497
    add-int/lit8 v15, v15, -0x1

    .line 498
    .line 499
    iput v15, v9, Ld6/d0;->d:I

    .line 500
    .line 501
    add-int/lit8 v14, v14, 0x1

    .line 502
    .line 503
    rem-int/2addr v14, v8

    .line 504
    goto :goto_c

    .line 505
    :cond_17
    iget v12, v9, Ld6/d0;->d:I

    .line 506
    .line 507
    const/4 v13, 0x2

    .line 508
    if-ge v12, v13, :cond_18

    .line 509
    .line 510
    goto :goto_b

    .line 511
    :cond_18
    if-ne v12, v13, :cond_1a

    .line 512
    .line 513
    add-int/lit8 v14, v14, 0x1

    .line 514
    .line 515
    rem-int/2addr v14, v8

    .line 516
    aget-wide v11, v11, v14

    .line 517
    .line 518
    cmp-long v8, v21, v11

    .line 519
    .line 520
    if-nez v8, :cond_19

    .line 521
    .line 522
    goto :goto_b

    .line 523
    :cond_19
    aget v8, v10, v14

    .line 524
    .line 525
    sub-long v11, v11, v21

    .line 526
    .line 527
    long-to-float v10, v11

    .line 528
    div-float/2addr v8, v10

    .line 529
    move-object/from16 v25, v4

    .line 530
    .line 531
    move/from16 p0, v6

    .line 532
    .line 533
    move v4, v3

    .line 534
    move v3, v8

    .line 535
    goto/16 :goto_f

    .line 536
    .line 537
    :cond_1a
    move/from16 p0, v6

    .line 538
    .line 539
    const/4 v12, 0x0

    .line 540
    const/4 v13, 0x0

    .line 541
    const/4 v15, 0x0

    .line 542
    :goto_d
    iget v6, v9, Ld6/d0;->d:I

    .line 543
    .line 544
    add-int/lit8 v6, v6, -0x1

    .line 545
    .line 546
    const/high16 v17, 0x40000000    # 2.0f

    .line 547
    .line 548
    const/high16 v20, 0x3f800000    # 1.0f

    .line 549
    .line 550
    const/high16 v21, -0x40800000    # -1.0f

    .line 551
    .line 552
    if-ge v13, v6, :cond_1e

    .line 553
    .line 554
    add-int v6, v13, v14

    .line 555
    .line 556
    rem-int/lit8 v22, v6, 0x14

    .line 557
    .line 558
    aget-wide v22, v11, v22

    .line 559
    .line 560
    add-int/lit8 v6, v6, 0x1

    .line 561
    .line 562
    rem-int/2addr v6, v8

    .line 563
    aget-wide v24, v11, v6

    .line 564
    .line 565
    cmp-long v24, v24, v22

    .line 566
    .line 567
    if-nez v24, :cond_1b

    .line 568
    .line 569
    move-object/from16 v25, v4

    .line 570
    .line 571
    goto :goto_e

    .line 572
    :cond_1b
    add-int/lit8 v15, v15, 0x1

    .line 573
    .line 574
    const/16 v18, 0x0

    .line 575
    .line 576
    cmpg-float v24, v12, v18

    .line 577
    .line 578
    if-gez v24, :cond_1c

    .line 579
    .line 580
    move/from16 v20, v21

    .line 581
    .line 582
    :cond_1c
    invoke-static {v12}, Ljava/lang/Math;->abs(F)F

    .line 583
    .line 584
    .line 585
    move-result v21

    .line 586
    mul-float v8, v21, v17

    .line 587
    .line 588
    move-object/from16 v25, v4

    .line 589
    .line 590
    float-to-double v3, v8

    .line 591
    invoke-static {v3, v4}, Ljava/lang/Math;->sqrt(D)D

    .line 592
    .line 593
    .line 594
    move-result-wide v3

    .line 595
    double-to-float v3, v3

    .line 596
    mul-float v20, v20, v3

    .line 597
    .line 598
    aget v3, v10, v6

    .line 599
    .line 600
    aget-wide v26, v11, v6

    .line 601
    .line 602
    move v6, v3

    .line 603
    sub-long v3, v26, v22

    .line 604
    .line 605
    long-to-float v3, v3

    .line 606
    div-float v3, v6, v3

    .line 607
    .line 608
    sub-float v4, v3, v20

    .line 609
    .line 610
    invoke-static {v3}, Ljava/lang/Math;->abs(F)F

    .line 611
    .line 612
    .line 613
    move-result v3

    .line 614
    mul-float/2addr v3, v4

    .line 615
    add-float/2addr v3, v12

    .line 616
    move/from16 v4, v16

    .line 617
    .line 618
    if-ne v15, v4, :cond_1d

    .line 619
    .line 620
    const/high16 v4, 0x3f000000    # 0.5f

    .line 621
    .line 622
    mul-float/2addr v3, v4

    .line 623
    :cond_1d
    move v12, v3

    .line 624
    :goto_e
    add-int/lit8 v13, v13, 0x1

    .line 625
    .line 626
    move-object/from16 v4, v25

    .line 627
    .line 628
    const/16 v3, 0x3e8

    .line 629
    .line 630
    const/16 v8, 0x14

    .line 631
    .line 632
    const/16 v16, 0x1

    .line 633
    .line 634
    goto :goto_d

    .line 635
    :cond_1e
    move-object/from16 v25, v4

    .line 636
    .line 637
    const/16 v18, 0x0

    .line 638
    .line 639
    cmpg-float v3, v12, v18

    .line 640
    .line 641
    if-gez v3, :cond_1f

    .line 642
    .line 643
    move/from16 v20, v21

    .line 644
    .line 645
    :cond_1f
    invoke-static {v12}, Ljava/lang/Math;->abs(F)F

    .line 646
    .line 647
    .line 648
    move-result v3

    .line 649
    mul-float v3, v3, v17

    .line 650
    .line 651
    float-to-double v3, v3

    .line 652
    invoke-static {v3, v4}, Ljava/lang/Math;->sqrt(D)D

    .line 653
    .line 654
    .line 655
    move-result-wide v3

    .line 656
    double-to-float v3, v3

    .line 657
    mul-float v3, v3, v20

    .line 658
    .line 659
    const/16 v4, 0x3e8

    .line 660
    .line 661
    :goto_f
    int-to-float v4, v4

    .line 662
    mul-float/2addr v3, v4

    .line 663
    iput v3, v9, Ld6/d0;->c:F

    .line 664
    .line 665
    invoke-static/range {p0 .. p0}, Ljava/lang/Math;->abs(F)F

    .line 666
    .line 667
    .line 668
    move-result v4

    .line 669
    neg-float v4, v4

    .line 670
    cmpg-float v3, v3, v4

    .line 671
    .line 672
    if-gez v3, :cond_20

    .line 673
    .line 674
    invoke-static/range {p0 .. p0}, Ljava/lang/Math;->abs(F)F

    .line 675
    .line 676
    .line 677
    move-result v3

    .line 678
    neg-float v3, v3

    .line 679
    iput v3, v9, Ld6/d0;->c:F

    .line 680
    .line 681
    goto :goto_10

    .line 682
    :cond_20
    iget v3, v9, Ld6/d0;->c:F

    .line 683
    .line 684
    invoke-static/range {p0 .. p0}, Ljava/lang/Math;->abs(F)F

    .line 685
    .line 686
    .line 687
    move-result v4

    .line 688
    cmpl-float v3, v3, v4

    .line 689
    .line 690
    if-lez v3, :cond_22

    .line 691
    .line 692
    invoke-static/range {p0 .. p0}, Ljava/lang/Math;->abs(F)F

    .line 693
    .line 694
    .line 695
    move-result v3

    .line 696
    iput v3, v9, Ld6/d0;->c:F

    .line 697
    .line 698
    goto :goto_10

    .line 699
    :cond_21
    move-object/from16 v25, v4

    .line 700
    .line 701
    :cond_22
    :goto_10
    sget v3, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 702
    .line 703
    const/16 v14, 0x22

    .line 704
    .line 705
    if-lt v3, v14, :cond_23

    .line 706
    .line 707
    invoke-static {v5, v2}, Lb/a;->c(Landroid/view/VelocityTracker;I)F

    .line 708
    .line 709
    .line 710
    move-result v2

    .line 711
    goto :goto_12

    .line 712
    :cond_23
    if-nez v2, :cond_24

    .line 713
    .line 714
    invoke-virtual {v5}, Landroid/view/VelocityTracker;->getXVelocity()F

    .line 715
    .line 716
    .line 717
    move-result v2

    .line 718
    goto :goto_12

    .line 719
    :cond_24
    const/4 v4, 0x1

    .line 720
    if-ne v2, v4, :cond_25

    .line 721
    .line 722
    invoke-virtual {v5}, Landroid/view/VelocityTracker;->getYVelocity()F

    .line 723
    .line 724
    .line 725
    move-result v2

    .line 726
    goto :goto_12

    .line 727
    :cond_25
    sget-object v3, Ld6/c0;->a:Ljava/util/Map;

    .line 728
    .line 729
    invoke-interface {v3, v5}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 730
    .line 731
    .line 732
    move-result-object v3

    .line 733
    check-cast v3, Ld6/d0;

    .line 734
    .line 735
    if-eqz v3, :cond_27

    .line 736
    .line 737
    const/16 v10, 0x1a

    .line 738
    .line 739
    if-eq v2, v10, :cond_26

    .line 740
    .line 741
    goto :goto_11

    .line 742
    :cond_26
    iget v2, v3, Ld6/d0;->c:F

    .line 743
    .line 744
    goto :goto_12

    .line 745
    :cond_27
    :goto_11
    const/4 v2, 0x0

    .line 746
    :goto_12
    invoke-virtual {v1}, Landroidx/core/widget/NestedScrollView;->getVerticalScrollFactorCompat()F

    .line 747
    .line 748
    .line 749
    move-result v3

    .line 750
    neg-float v3, v3

    .line 751
    mul-float/2addr v2, v3

    .line 752
    invoke-static {v2}, Ljava/lang/Math;->signum(F)F

    .line 753
    .line 754
    .line 755
    move-result v3

    .line 756
    if-nez v7, :cond_28

    .line 757
    .line 758
    iget v4, v0, Ld6/g;->d:F

    .line 759
    .line 760
    invoke-static {v4}, Ljava/lang/Math;->signum(F)F

    .line 761
    .line 762
    .line 763
    move-result v4

    .line 764
    cmpl-float v4, v3, v4

    .line 765
    .line 766
    if-eqz v4, :cond_29

    .line 767
    .line 768
    const/16 v18, 0x0

    .line 769
    .line 770
    cmpl-float v3, v3, v18

    .line 771
    .line 772
    if-eqz v3, :cond_29

    .line 773
    .line 774
    :cond_28
    iget-object v3, v1, Landroidx/core/widget/NestedScrollView;->g:Landroid/widget/OverScroller;

    .line 775
    .line 776
    invoke-virtual {v3}, Landroid/widget/OverScroller;->abortAnimation()V

    .line 777
    .line 778
    .line 779
    :cond_29
    invoke-static {v2}, Ljava/lang/Math;->abs(F)F

    .line 780
    .line 781
    .line 782
    move-result v3

    .line 783
    const/16 v19, 0x0

    .line 784
    .line 785
    aget v4, v25, v19

    .line 786
    .line 787
    int-to-float v4, v4

    .line 788
    cmpg-float v3, v3, v4

    .line 789
    .line 790
    if-gez v3, :cond_2b

    .line 791
    .line 792
    :cond_2a
    const/16 v16, 0x1

    .line 793
    .line 794
    goto :goto_14

    .line 795
    :cond_2b
    const/16 v16, 0x1

    .line 796
    .line 797
    aget v3, v25, v16

    .line 798
    .line 799
    neg-int v4, v3

    .line 800
    int-to-float v4, v4

    .line 801
    int-to-float v3, v3

    .line 802
    invoke-static {v2, v3}, Ljava/lang/Math;->min(FF)F

    .line 803
    .line 804
    .line 805
    move-result v2

    .line 806
    invoke-static {v4, v2}, Ljava/lang/Math;->max(FF)F

    .line 807
    .line 808
    .line 809
    move-result v2

    .line 810
    const/16 v18, 0x0

    .line 811
    .line 812
    cmpl-float v3, v2, v18

    .line 813
    .line 814
    if-nez v3, :cond_2c

    .line 815
    .line 816
    move/from16 v10, v18

    .line 817
    .line 818
    goto :goto_13

    .line 819
    :cond_2c
    iget-object v3, v1, Landroidx/core/widget/NestedScrollView;->g:Landroid/widget/OverScroller;

    .line 820
    .line 821
    invoke-virtual {v3}, Landroid/widget/OverScroller;->abortAnimation()V

    .line 822
    .line 823
    .line 824
    float-to-int v3, v2

    .line 825
    invoke-virtual {v1, v3}, Landroidx/core/widget/NestedScrollView;->k(I)V

    .line 826
    .line 827
    .line 828
    move v10, v2

    .line 829
    :goto_13
    iput v10, v0, Ld6/g;->d:F

    .line 830
    .line 831
    const/16 v16, 0x1

    .line 832
    .line 833
    :cond_2d
    :goto_14
    return v16

    .line 834
    :cond_2e
    const/16 v19, 0x0

    .line 835
    .line 836
    return v19
.end method

.method public final onInterceptTouchEvent(Landroid/view/MotionEvent;)Z
    .locals 12

    .line 1
    invoke-virtual {p1}, Landroid/view/MotionEvent;->getAction()I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    const/4 v1, 0x1

    .line 6
    const/4 v2, 0x2

    .line 7
    if-ne v0, v2, :cond_0

    .line 8
    .line 9
    iget-boolean v3, p0, Landroidx/core/widget/NestedScrollView;->o:Z

    .line 10
    .line 11
    if-eqz v3, :cond_0

    .line 12
    .line 13
    return v1

    .line 14
    :cond_0
    and-int/lit16 v0, v0, 0xff

    .line 15
    .line 16
    const/4 v3, 0x0

    .line 17
    const/4 v4, 0x0

    .line 18
    if-eqz v0, :cond_9

    .line 19
    .line 20
    const/4 v5, -0x1

    .line 21
    if-eq v0, v1, :cond_6

    .line 22
    .line 23
    if-eq v0, v2, :cond_2

    .line 24
    .line 25
    const/4 v1, 0x3

    .line 26
    if-eq v0, v1, :cond_6

    .line 27
    .line 28
    const/4 v1, 0x6

    .line 29
    if-eq v0, v1, :cond_1

    .line 30
    .line 31
    goto/16 :goto_3

    .line 32
    .line 33
    :cond_1
    invoke-virtual {p0, p1}, Landroidx/core/widget/NestedScrollView;->p(Landroid/view/MotionEvent;)V

    .line 34
    .line 35
    .line 36
    goto/16 :goto_3

    .line 37
    .line 38
    :cond_2
    iget v0, p0, Landroidx/core/widget/NestedScrollView;->v:I

    .line 39
    .line 40
    if-ne v0, v5, :cond_3

    .line 41
    .line 42
    goto/16 :goto_3

    .line 43
    .line 44
    :cond_3
    invoke-virtual {p1, v0}, Landroid/view/MotionEvent;->findPointerIndex(I)I

    .line 45
    .line 46
    .line 47
    move-result v3

    .line 48
    if-ne v3, v5, :cond_4

    .line 49
    .line 50
    new-instance p1, Ljava/lang/StringBuilder;

    .line 51
    .line 52
    const-string v1, "Invalid pointerId="

    .line 53
    .line 54
    invoke-direct {p1, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 55
    .line 56
    .line 57
    invoke-virtual {p1, v0}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 58
    .line 59
    .line 60
    const-string v0, " in onInterceptTouchEvent"

    .line 61
    .line 62
    invoke-virtual {p1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 63
    .line 64
    .line 65
    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 66
    .line 67
    .line 68
    move-result-object p1

    .line 69
    const-string v0, "NestedScrollView"

    .line 70
    .line 71
    invoke-static {v0, p1}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I

    .line 72
    .line 73
    .line 74
    goto/16 :goto_3

    .line 75
    .line 76
    :cond_4
    invoke-virtual {p1, v3}, Landroid/view/MotionEvent;->getY(I)F

    .line 77
    .line 78
    .line 79
    move-result v0

    .line 80
    float-to-int v0, v0

    .line 81
    iget v3, p0, Landroidx/core/widget/NestedScrollView;->k:I

    .line 82
    .line 83
    sub-int v3, v0, v3

    .line 84
    .line 85
    invoke-static {v3}, Ljava/lang/Math;->abs(I)I

    .line 86
    .line 87
    .line 88
    move-result v3

    .line 89
    iget v5, p0, Landroidx/core/widget/NestedScrollView;->s:I

    .line 90
    .line 91
    if-le v3, v5, :cond_10

    .line 92
    .line 93
    invoke-virtual {p0}, Landroidx/core/widget/NestedScrollView;->getNestedScrollAxes()I

    .line 94
    .line 95
    .line 96
    move-result v3

    .line 97
    and-int/2addr v2, v3

    .line 98
    if-nez v2, :cond_10

    .line 99
    .line 100
    iput-boolean v1, p0, Landroidx/core/widget/NestedScrollView;->o:Z

    .line 101
    .line 102
    iput v0, p0, Landroidx/core/widget/NestedScrollView;->k:I

    .line 103
    .line 104
    iget-object v0, p0, Landroidx/core/widget/NestedScrollView;->p:Landroid/view/VelocityTracker;

    .line 105
    .line 106
    if-nez v0, :cond_5

    .line 107
    .line 108
    invoke-static {}, Landroid/view/VelocityTracker;->obtain()Landroid/view/VelocityTracker;

    .line 109
    .line 110
    .line 111
    move-result-object v0

    .line 112
    iput-object v0, p0, Landroidx/core/widget/NestedScrollView;->p:Landroid/view/VelocityTracker;

    .line 113
    .line 114
    :cond_5
    iget-object v0, p0, Landroidx/core/widget/NestedScrollView;->p:Landroid/view/VelocityTracker;

    .line 115
    .line 116
    invoke-virtual {v0, p1}, Landroid/view/VelocityTracker;->addMovement(Landroid/view/MotionEvent;)V

    .line 117
    .line 118
    .line 119
    iput v4, p0, Landroidx/core/widget/NestedScrollView;->y:I

    .line 120
    .line 121
    invoke-virtual {p0}, Landroid/view/View;->getParent()Landroid/view/ViewParent;

    .line 122
    .line 123
    .line 124
    move-result-object p1

    .line 125
    if-eqz p1, :cond_10

    .line 126
    .line 127
    invoke-interface {p1, v1}, Landroid/view/ViewParent;->requestDisallowInterceptTouchEvent(Z)V

    .line 128
    .line 129
    .line 130
    goto/16 :goto_3

    .line 131
    .line 132
    :cond_6
    iput-boolean v4, p0, Landroidx/core/widget/NestedScrollView;->o:Z

    .line 133
    .line 134
    iput v5, p0, Landroidx/core/widget/NestedScrollView;->v:I

    .line 135
    .line 136
    iget-object p1, p0, Landroidx/core/widget/NestedScrollView;->p:Landroid/view/VelocityTracker;

    .line 137
    .line 138
    if-eqz p1, :cond_7

    .line 139
    .line 140
    invoke-virtual {p1}, Landroid/view/VelocityTracker;->recycle()V

    .line 141
    .line 142
    .line 143
    iput-object v3, p0, Landroidx/core/widget/NestedScrollView;->p:Landroid/view/VelocityTracker;

    .line 144
    .line 145
    :cond_7
    invoke-virtual {p0}, Landroid/view/View;->getScrollX()I

    .line 146
    .line 147
    .line 148
    move-result v6

    .line 149
    invoke-virtual {p0}, Landroid/view/View;->getScrollY()I

    .line 150
    .line 151
    .line 152
    move-result v7

    .line 153
    const/4 v10, 0x0

    .line 154
    invoke-virtual {p0}, Landroidx/core/widget/NestedScrollView;->getScrollRange()I

    .line 155
    .line 156
    .line 157
    move-result v11

    .line 158
    iget-object v5, p0, Landroidx/core/widget/NestedScrollView;->g:Landroid/widget/OverScroller;

    .line 159
    .line 160
    const/4 v8, 0x0

    .line 161
    const/4 v9, 0x0

    .line 162
    invoke-virtual/range {v5 .. v11}, Landroid/widget/OverScroller;->springBack(IIIIII)Z

    .line 163
    .line 164
    .line 165
    move-result p1

    .line 166
    if-eqz p1, :cond_8

    .line 167
    .line 168
    invoke-virtual {p0}, Landroid/view/View;->postInvalidateOnAnimation()V

    .line 169
    .line 170
    .line 171
    :cond_8
    invoke-virtual {p0, v4}, Landroidx/core/widget/NestedScrollView;->y(I)V

    .line 172
    .line 173
    .line 174
    goto/16 :goto_3

    .line 175
    .line 176
    :cond_9
    invoke-virtual {p1}, Landroid/view/MotionEvent;->getY()F

    .line 177
    .line 178
    .line 179
    move-result v0

    .line 180
    float-to-int v0, v0

    .line 181
    invoke-virtual {p1}, Landroid/view/MotionEvent;->getX()F

    .line 182
    .line 183
    .line 184
    move-result v5

    .line 185
    float-to-int v5, v5

    .line 186
    invoke-virtual {p0}, Landroid/view/ViewGroup;->getChildCount()I

    .line 187
    .line 188
    .line 189
    move-result v6

    .line 190
    if-lez v6, :cond_d

    .line 191
    .line 192
    invoke-virtual {p0}, Landroid/view/View;->getScrollY()I

    .line 193
    .line 194
    .line 195
    move-result v6

    .line 196
    invoke-virtual {p0, v4}, Landroid/view/ViewGroup;->getChildAt(I)Landroid/view/View;

    .line 197
    .line 198
    .line 199
    move-result-object v7

    .line 200
    invoke-virtual {v7}, Landroid/view/View;->getTop()I

    .line 201
    .line 202
    .line 203
    move-result v8

    .line 204
    sub-int/2addr v8, v6

    .line 205
    if-lt v0, v8, :cond_d

    .line 206
    .line 207
    invoke-virtual {v7}, Landroid/view/View;->getBottom()I

    .line 208
    .line 209
    .line 210
    move-result v8

    .line 211
    sub-int/2addr v8, v6

    .line 212
    if-ge v0, v8, :cond_d

    .line 213
    .line 214
    invoke-virtual {v7}, Landroid/view/View;->getLeft()I

    .line 215
    .line 216
    .line 217
    move-result v6

    .line 218
    if-lt v5, v6, :cond_d

    .line 219
    .line 220
    invoke-virtual {v7}, Landroid/view/View;->getRight()I

    .line 221
    .line 222
    .line 223
    move-result v6

    .line 224
    if-ge v5, v6, :cond_d

    .line 225
    .line 226
    iput v0, p0, Landroidx/core/widget/NestedScrollView;->k:I

    .line 227
    .line 228
    invoke-virtual {p1, v4}, Landroid/view/MotionEvent;->getPointerId(I)I

    .line 229
    .line 230
    .line 231
    move-result v0

    .line 232
    iput v0, p0, Landroidx/core/widget/NestedScrollView;->v:I

    .line 233
    .line 234
    iget-object v0, p0, Landroidx/core/widget/NestedScrollView;->p:Landroid/view/VelocityTracker;

    .line 235
    .line 236
    if-nez v0, :cond_a

    .line 237
    .line 238
    invoke-static {}, Landroid/view/VelocityTracker;->obtain()Landroid/view/VelocityTracker;

    .line 239
    .line 240
    .line 241
    move-result-object v0

    .line 242
    iput-object v0, p0, Landroidx/core/widget/NestedScrollView;->p:Landroid/view/VelocityTracker;

    .line 243
    .line 244
    goto :goto_0

    .line 245
    :cond_a
    invoke-virtual {v0}, Landroid/view/VelocityTracker;->clear()V

    .line 246
    .line 247
    .line 248
    :goto_0
    iget-object v0, p0, Landroidx/core/widget/NestedScrollView;->p:Landroid/view/VelocityTracker;

    .line 249
    .line 250
    invoke-virtual {v0, p1}, Landroid/view/VelocityTracker;->addMovement(Landroid/view/MotionEvent;)V

    .line 251
    .line 252
    .line 253
    iget-object v0, p0, Landroidx/core/widget/NestedScrollView;->g:Landroid/widget/OverScroller;

    .line 254
    .line 255
    invoke-virtual {v0}, Landroid/widget/OverScroller;->computeScrollOffset()Z

    .line 256
    .line 257
    .line 258
    invoke-virtual {p0, p1}, Landroidx/core/widget/NestedScrollView;->x(Landroid/view/MotionEvent;)Z

    .line 259
    .line 260
    .line 261
    move-result p1

    .line 262
    if-nez p1, :cond_c

    .line 263
    .line 264
    iget-object p1, p0, Landroidx/core/widget/NestedScrollView;->g:Landroid/widget/OverScroller;

    .line 265
    .line 266
    invoke-virtual {p1}, Landroid/widget/OverScroller;->isFinished()Z

    .line 267
    .line 268
    .line 269
    move-result p1

    .line 270
    if-nez p1, :cond_b

    .line 271
    .line 272
    goto :goto_1

    .line 273
    :cond_b
    move v1, v4

    .line 274
    :cond_c
    :goto_1
    iput-boolean v1, p0, Landroidx/core/widget/NestedScrollView;->o:Z

    .line 275
    .line 276
    invoke-virtual {p0, v2, v4}, Landroidx/core/widget/NestedScrollView;->w(II)V

    .line 277
    .line 278
    .line 279
    goto :goto_3

    .line 280
    :cond_d
    invoke-virtual {p0, p1}, Landroidx/core/widget/NestedScrollView;->x(Landroid/view/MotionEvent;)Z

    .line 281
    .line 282
    .line 283
    move-result p1

    .line 284
    if-nez p1, :cond_f

    .line 285
    .line 286
    iget-object p1, p0, Landroidx/core/widget/NestedScrollView;->g:Landroid/widget/OverScroller;

    .line 287
    .line 288
    invoke-virtual {p1}, Landroid/widget/OverScroller;->isFinished()Z

    .line 289
    .line 290
    .line 291
    move-result p1

    .line 292
    if-nez p1, :cond_e

    .line 293
    .line 294
    goto :goto_2

    .line 295
    :cond_e
    move v1, v4

    .line 296
    :cond_f
    :goto_2
    iput-boolean v1, p0, Landroidx/core/widget/NestedScrollView;->o:Z

    .line 297
    .line 298
    iget-object p1, p0, Landroidx/core/widget/NestedScrollView;->p:Landroid/view/VelocityTracker;

    .line 299
    .line 300
    if-eqz p1, :cond_10

    .line 301
    .line 302
    invoke-virtual {p1}, Landroid/view/VelocityTracker;->recycle()V

    .line 303
    .line 304
    .line 305
    iput-object v3, p0, Landroidx/core/widget/NestedScrollView;->p:Landroid/view/VelocityTracker;

    .line 306
    .line 307
    :cond_10
    :goto_3
    iget-boolean p0, p0, Landroidx/core/widget/NestedScrollView;->o:Z

    .line 308
    .line 309
    return p0
.end method

.method public final onLayout(ZIIII)V
    .locals 1

    .line 1
    invoke-super/range {p0 .. p5}, Landroid/widget/FrameLayout;->onLayout(ZIIII)V

    .line 2
    .line 3
    .line 4
    const/4 p1, 0x0

    .line 5
    iput-boolean p1, p0, Landroidx/core/widget/NestedScrollView;->l:Z

    .line 6
    .line 7
    iget-object p2, p0, Landroidx/core/widget/NestedScrollView;->n:Landroid/view/View;

    .line 8
    .line 9
    if-eqz p2, :cond_0

    .line 10
    .line 11
    invoke-static {p2, p0}, Landroidx/core/widget/NestedScrollView;->m(Landroid/view/View;Landroidx/core/widget/NestedScrollView;)Z

    .line 12
    .line 13
    .line 14
    move-result p2

    .line 15
    if-eqz p2, :cond_0

    .line 16
    .line 17
    iget-object p2, p0, Landroidx/core/widget/NestedScrollView;->n:Landroid/view/View;

    .line 18
    .line 19
    iget-object p4, p0, Landroidx/core/widget/NestedScrollView;->f:Landroid/graphics/Rect;

    .line 20
    .line 21
    invoke-virtual {p2, p4}, Landroid/view/View;->getDrawingRect(Landroid/graphics/Rect;)V

    .line 22
    .line 23
    .line 24
    invoke-virtual {p0, p2, p4}, Landroid/view/ViewGroup;->offsetDescendantRectToMyCoords(Landroid/view/View;Landroid/graphics/Rect;)V

    .line 25
    .line 26
    .line 27
    invoke-virtual {p0, p4}, Landroidx/core/widget/NestedScrollView;->e(Landroid/graphics/Rect;)I

    .line 28
    .line 29
    .line 30
    move-result p2

    .line 31
    if-eqz p2, :cond_0

    .line 32
    .line 33
    invoke-virtual {p0, p1, p2}, Landroid/view/View;->scrollBy(II)V

    .line 34
    .line 35
    .line 36
    :cond_0
    const/4 p2, 0x0

    .line 37
    iput-object p2, p0, Landroidx/core/widget/NestedScrollView;->n:Landroid/view/View;

    .line 38
    .line 39
    iget-boolean p4, p0, Landroidx/core/widget/NestedScrollView;->m:Z

    .line 40
    .line 41
    if-nez p4, :cond_6

    .line 42
    .line 43
    iget-object p4, p0, Landroidx/core/widget/NestedScrollView;->A:Lh6/g;

    .line 44
    .line 45
    if-eqz p4, :cond_1

    .line 46
    .line 47
    invoke-virtual {p0}, Landroid/view/View;->getScrollX()I

    .line 48
    .line 49
    .line 50
    move-result p4

    .line 51
    iget-object v0, p0, Landroidx/core/widget/NestedScrollView;->A:Lh6/g;

    .line 52
    .line 53
    iget v0, v0, Lh6/g;->d:I

    .line 54
    .line 55
    invoke-virtual {p0, p4, v0}, Landroidx/core/widget/NestedScrollView;->scrollTo(II)V

    .line 56
    .line 57
    .line 58
    iput-object p2, p0, Landroidx/core/widget/NestedScrollView;->A:Lh6/g;

    .line 59
    .line 60
    :cond_1
    invoke-virtual {p0}, Landroid/view/ViewGroup;->getChildCount()I

    .line 61
    .line 62
    .line 63
    move-result p2

    .line 64
    if-lez p2, :cond_2

    .line 65
    .line 66
    invoke-virtual {p0, p1}, Landroid/view/ViewGroup;->getChildAt(I)Landroid/view/View;

    .line 67
    .line 68
    .line 69
    move-result-object p2

    .line 70
    invoke-virtual {p2}, Landroid/view/View;->getLayoutParams()Landroid/view/ViewGroup$LayoutParams;

    .line 71
    .line 72
    .line 73
    move-result-object p4

    .line 74
    check-cast p4, Landroid/widget/FrameLayout$LayoutParams;

    .line 75
    .line 76
    invoke-virtual {p2}, Landroid/view/View;->getMeasuredHeight()I

    .line 77
    .line 78
    .line 79
    move-result p2

    .line 80
    iget v0, p4, Landroid/widget/FrameLayout$LayoutParams;->topMargin:I

    .line 81
    .line 82
    add-int/2addr p2, v0

    .line 83
    iget p4, p4, Landroid/widget/FrameLayout$LayoutParams;->bottomMargin:I

    .line 84
    .line 85
    add-int/2addr p2, p4

    .line 86
    goto :goto_0

    .line 87
    :cond_2
    move p2, p1

    .line 88
    :goto_0
    sub-int/2addr p5, p3

    .line 89
    invoke-virtual {p0}, Landroid/view/View;->getPaddingTop()I

    .line 90
    .line 91
    .line 92
    move-result p3

    .line 93
    sub-int/2addr p5, p3

    .line 94
    invoke-virtual {p0}, Landroid/view/View;->getPaddingBottom()I

    .line 95
    .line 96
    .line 97
    move-result p3

    .line 98
    sub-int/2addr p5, p3

    .line 99
    invoke-virtual {p0}, Landroid/view/View;->getScrollY()I

    .line 100
    .line 101
    .line 102
    move-result p3

    .line 103
    if-ge p5, p2, :cond_5

    .line 104
    .line 105
    if-gez p3, :cond_3

    .line 106
    .line 107
    goto :goto_1

    .line 108
    :cond_3
    add-int p1, p5, p3

    .line 109
    .line 110
    if-le p1, p2, :cond_4

    .line 111
    .line 112
    sub-int p1, p2, p5

    .line 113
    .line 114
    goto :goto_1

    .line 115
    :cond_4
    move p1, p3

    .line 116
    :cond_5
    :goto_1
    if-eq p1, p3, :cond_6

    .line 117
    .line 118
    invoke-virtual {p0}, Landroid/view/View;->getScrollX()I

    .line 119
    .line 120
    .line 121
    move-result p2

    .line 122
    invoke-virtual {p0, p2, p1}, Landroidx/core/widget/NestedScrollView;->scrollTo(II)V

    .line 123
    .line 124
    .line 125
    :cond_6
    invoke-virtual {p0}, Landroid/view/View;->getScrollX()I

    .line 126
    .line 127
    .line 128
    move-result p1

    .line 129
    invoke-virtual {p0}, Landroid/view/View;->getScrollY()I

    .line 130
    .line 131
    .line 132
    move-result p2

    .line 133
    invoke-virtual {p0, p1, p2}, Landroidx/core/widget/NestedScrollView;->scrollTo(II)V

    .line 134
    .line 135
    .line 136
    const/4 p1, 0x1

    .line 137
    iput-boolean p1, p0, Landroidx/core/widget/NestedScrollView;->m:Z

    .line 138
    .line 139
    return-void
.end method

.method public final onMeasure(II)V
    .locals 4

    .line 1
    invoke-super {p0, p1, p2}, Landroid/widget/FrameLayout;->onMeasure(II)V

    .line 2
    .line 3
    .line 4
    iget-boolean v0, p0, Landroidx/core/widget/NestedScrollView;->q:Z

    .line 5
    .line 6
    if-nez v0, :cond_0

    .line 7
    .line 8
    goto :goto_0

    .line 9
    :cond_0
    invoke-static {p2}, Landroid/view/View$MeasureSpec;->getMode(I)I

    .line 10
    .line 11
    .line 12
    move-result p2

    .line 13
    if-nez p2, :cond_1

    .line 14
    .line 15
    goto :goto_0

    .line 16
    :cond_1
    invoke-virtual {p0}, Landroid/view/ViewGroup;->getChildCount()I

    .line 17
    .line 18
    .line 19
    move-result p2

    .line 20
    if-lez p2, :cond_2

    .line 21
    .line 22
    const/4 p2, 0x0

    .line 23
    invoke-virtual {p0, p2}, Landroid/view/ViewGroup;->getChildAt(I)Landroid/view/View;

    .line 24
    .line 25
    .line 26
    move-result-object p2

    .line 27
    invoke-virtual {p2}, Landroid/view/View;->getLayoutParams()Landroid/view/ViewGroup$LayoutParams;

    .line 28
    .line 29
    .line 30
    move-result-object v0

    .line 31
    check-cast v0, Landroid/widget/FrameLayout$LayoutParams;

    .line 32
    .line 33
    invoke-virtual {p2}, Landroid/view/View;->getMeasuredHeight()I

    .line 34
    .line 35
    .line 36
    move-result v1

    .line 37
    invoke-virtual {p0}, Landroid/view/View;->getMeasuredHeight()I

    .line 38
    .line 39
    .line 40
    move-result v2

    .line 41
    invoke-virtual {p0}, Landroid/view/View;->getPaddingTop()I

    .line 42
    .line 43
    .line 44
    move-result v3

    .line 45
    sub-int/2addr v2, v3

    .line 46
    invoke-virtual {p0}, Landroid/view/View;->getPaddingBottom()I

    .line 47
    .line 48
    .line 49
    move-result v3

    .line 50
    sub-int/2addr v2, v3

    .line 51
    iget v3, v0, Landroid/widget/FrameLayout$LayoutParams;->topMargin:I

    .line 52
    .line 53
    sub-int/2addr v2, v3

    .line 54
    iget v3, v0, Landroid/widget/FrameLayout$LayoutParams;->bottomMargin:I

    .line 55
    .line 56
    sub-int/2addr v2, v3

    .line 57
    if-ge v1, v2, :cond_2

    .line 58
    .line 59
    invoke-virtual {p0}, Landroid/view/View;->getPaddingLeft()I

    .line 60
    .line 61
    .line 62
    move-result v1

    .line 63
    invoke-virtual {p0}, Landroid/view/View;->getPaddingRight()I

    .line 64
    .line 65
    .line 66
    move-result p0

    .line 67
    add-int/2addr p0, v1

    .line 68
    iget v1, v0, Landroid/widget/FrameLayout$LayoutParams;->leftMargin:I

    .line 69
    .line 70
    add-int/2addr p0, v1

    .line 71
    iget v1, v0, Landroid/widget/FrameLayout$LayoutParams;->rightMargin:I

    .line 72
    .line 73
    add-int/2addr p0, v1

    .line 74
    iget v0, v0, Landroid/widget/FrameLayout$LayoutParams;->width:I

    .line 75
    .line 76
    invoke-static {p1, p0, v0}, Landroid/view/ViewGroup;->getChildMeasureSpec(III)I

    .line 77
    .line 78
    .line 79
    move-result p0

    .line 80
    const/high16 p1, 0x40000000    # 2.0f

    .line 81
    .line 82
    invoke-static {v2, p1}, Landroid/view/View$MeasureSpec;->makeMeasureSpec(II)I

    .line 83
    .line 84
    .line 85
    move-result p1

    .line 86
    invoke-virtual {p2, p0, p1}, Landroid/view/View;->measure(II)V

    .line 87
    .line 88
    .line 89
    :cond_2
    :goto_0
    return-void
.end method

.method public final onNestedFling(Landroid/view/View;FFZ)Z
    .locals 0

    .line 1
    if-nez p4, :cond_0

    .line 2
    .line 3
    const/4 p1, 0x0

    .line 4
    const/4 p2, 0x1

    .line 5
    invoke-virtual {p0, p1, p3, p2}, Landroidx/core/widget/NestedScrollView;->dispatchNestedFling(FFZ)Z

    .line 6
    .line 7
    .line 8
    float-to-int p1, p3

    .line 9
    invoke-virtual {p0, p1}, Landroidx/core/widget/NestedScrollView;->k(I)V

    .line 10
    .line 11
    .line 12
    return p2

    .line 13
    :cond_0
    const/4 p0, 0x0

    .line 14
    return p0
.end method

.method public final onNestedPreFling(Landroid/view/View;FF)Z
    .locals 0

    .line 1
    iget-object p0, p0, Landroidx/core/widget/NestedScrollView;->C:Ld6/p;

    .line 2
    .line 3
    invoke-virtual {p0, p2, p3}, Ld6/p;->b(FF)Z

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method

.method public final onNestedPreScroll(Landroid/view/View;II[I)V
    .locals 6

    .line 1
    const/4 v3, 0x0

    .line 2
    const/4 v5, 0x0

    .line 3
    move-object v0, p0

    .line 4
    move v1, p2

    .line 5
    move v2, p3

    .line 6
    move-object v4, p4

    .line 7
    invoke-virtual/range {v0 .. v5}, Landroidx/core/widget/NestedScrollView;->f(III[I[I)Z

    .line 8
    .line 9
    .line 10
    return-void
.end method

.method public final onNestedScroll(Landroid/view/View;IIII)V
    .locals 0

    .line 1
    const/4 p1, 0x0

    .line 2
    const/4 p2, 0x0

    .line 3
    invoke-virtual {p0, p5, p1, p2}, Landroidx/core/widget/NestedScrollView;->o(II[I)V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public final onNestedScrollAccepted(Landroid/view/View;Landroid/view/View;I)V
    .locals 1

    .line 1
    const/4 v0, 0x0

    .line 2
    invoke-virtual {p0, p1, p2, p3, v0}, Landroidx/core/widget/NestedScrollView;->b(Landroid/view/View;Landroid/view/View;II)V

    .line 3
    .line 4
    .line 5
    return-void
.end method

.method public final onOverScrolled(IIZZ)V
    .locals 0

    .line 1
    invoke-super {p0, p1, p2}, Landroid/view/View;->scrollTo(II)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public final onRequestFocusInDescendants(ILandroid/graphics/Rect;)Z
    .locals 3

    .line 1
    const/4 v0, 0x2

    .line 2
    if-ne p1, v0, :cond_0

    .line 3
    .line 4
    const/16 p1, 0x82

    .line 5
    .line 6
    goto :goto_0

    .line 7
    :cond_0
    const/4 v0, 0x1

    .line 8
    if-ne p1, v0, :cond_1

    .line 9
    .line 10
    const/16 p1, 0x21

    .line 11
    .line 12
    :cond_1
    :goto_0
    if-nez p2, :cond_2

    .line 13
    .line 14
    invoke-static {}, Landroid/view/FocusFinder;->getInstance()Landroid/view/FocusFinder;

    .line 15
    .line 16
    .line 17
    move-result-object v0

    .line 18
    const/4 v1, 0x0

    .line 19
    invoke-virtual {v0, p0, v1, p1}, Landroid/view/FocusFinder;->findNextFocus(Landroid/view/ViewGroup;Landroid/view/View;I)Landroid/view/View;

    .line 20
    .line 21
    .line 22
    move-result-object v0

    .line 23
    goto :goto_1

    .line 24
    :cond_2
    invoke-static {}, Landroid/view/FocusFinder;->getInstance()Landroid/view/FocusFinder;

    .line 25
    .line 26
    .line 27
    move-result-object v0

    .line 28
    invoke-virtual {v0, p0, p2, p1}, Landroid/view/FocusFinder;->findNextFocusFromRect(Landroid/view/ViewGroup;Landroid/graphics/Rect;I)Landroid/view/View;

    .line 29
    .line 30
    .line 31
    move-result-object v0

    .line 32
    :goto_1
    const/4 v1, 0x0

    .line 33
    if-nez v0, :cond_3

    .line 34
    .line 35
    goto :goto_2

    .line 36
    :cond_3
    invoke-virtual {p0}, Landroid/view/View;->getHeight()I

    .line 37
    .line 38
    .line 39
    move-result v2

    .line 40
    invoke-virtual {p0, v0, v1, v2}, Landroidx/core/widget/NestedScrollView;->n(Landroid/view/View;II)Z

    .line 41
    .line 42
    .line 43
    move-result p0

    .line 44
    if-nez p0, :cond_4

    .line 45
    .line 46
    :goto_2
    return v1

    .line 47
    :cond_4
    invoke-virtual {v0, p1, p2}, Landroid/view/View;->requestFocus(ILandroid/graphics/Rect;)Z

    .line 48
    .line 49
    .line 50
    move-result p0

    .line 51
    return p0
.end method

.method public final onRestoreInstanceState(Landroid/os/Parcelable;)V
    .locals 1

    .line 1
    instance-of v0, p1, Lh6/g;

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    invoke-super {p0, p1}, Landroid/view/View;->onRestoreInstanceState(Landroid/os/Parcelable;)V

    .line 6
    .line 7
    .line 8
    return-void

    .line 9
    :cond_0
    check-cast p1, Lh6/g;

    .line 10
    .line 11
    invoke-virtual {p1}, Landroid/view/AbsSavedState;->getSuperState()Landroid/os/Parcelable;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    invoke-super {p0, v0}, Landroid/view/View;->onRestoreInstanceState(Landroid/os/Parcelable;)V

    .line 16
    .line 17
    .line 18
    iput-object p1, p0, Landroidx/core/widget/NestedScrollView;->A:Lh6/g;

    .line 19
    .line 20
    invoke-virtual {p0}, Landroidx/core/widget/NestedScrollView;->requestLayout()V

    .line 21
    .line 22
    .line 23
    return-void
.end method

.method public final onSaveInstanceState()Landroid/os/Parcelable;
    .locals 2

    .line 1
    invoke-super {p0}, Landroid/view/View;->onSaveInstanceState()Landroid/os/Parcelable;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    new-instance v1, Lh6/g;

    .line 6
    .line 7
    invoke-direct {v1, v0}, Landroid/view/View$BaseSavedState;-><init>(Landroid/os/Parcelable;)V

    .line 8
    .line 9
    .line 10
    invoke-virtual {p0}, Landroid/view/View;->getScrollY()I

    .line 11
    .line 12
    .line 13
    move-result p0

    .line 14
    iput p0, v1, Lh6/g;->d:I

    .line 15
    .line 16
    return-object v1
.end method

.method public final onScrollChanged(IIII)V
    .locals 0

    .line 1
    invoke-super {p0, p1, p2, p3, p4}, Landroid/view/View;->onScrollChanged(IIII)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public final onSizeChanged(IIII)V
    .locals 0

    .line 1
    invoke-super {p0, p1, p2, p3, p4}, Landroid/view/View;->onSizeChanged(IIII)V

    .line 2
    .line 3
    .line 4
    invoke-virtual {p0}, Landroid/view/View;->findFocus()Landroid/view/View;

    .line 5
    .line 6
    .line 7
    move-result-object p1

    .line 8
    if-eqz p1, :cond_2

    .line 9
    .line 10
    if-ne p0, p1, :cond_0

    .line 11
    .line 12
    goto :goto_0

    .line 13
    :cond_0
    const/4 p2, 0x0

    .line 14
    invoke-virtual {p0, p1, p2, p4}, Landroidx/core/widget/NestedScrollView;->n(Landroid/view/View;II)Z

    .line 15
    .line 16
    .line 17
    move-result p3

    .line 18
    if-eqz p3, :cond_2

    .line 19
    .line 20
    iget-object p3, p0, Landroidx/core/widget/NestedScrollView;->f:Landroid/graphics/Rect;

    .line 21
    .line 22
    invoke-virtual {p1, p3}, Landroid/view/View;->getDrawingRect(Landroid/graphics/Rect;)V

    .line 23
    .line 24
    .line 25
    invoke-virtual {p0, p1, p3}, Landroid/view/ViewGroup;->offsetDescendantRectToMyCoords(Landroid/view/View;Landroid/graphics/Rect;)V

    .line 26
    .line 27
    .line 28
    invoke-virtual {p0, p3}, Landroidx/core/widget/NestedScrollView;->e(Landroid/graphics/Rect;)I

    .line 29
    .line 30
    .line 31
    move-result p1

    .line 32
    if-eqz p1, :cond_2

    .line 33
    .line 34
    iget-boolean p3, p0, Landroidx/core/widget/NestedScrollView;->r:Z

    .line 35
    .line 36
    if-eqz p3, :cond_1

    .line 37
    .line 38
    invoke-virtual {p0, p2, p1, p2}, Landroidx/core/widget/NestedScrollView;->v(IIZ)V

    .line 39
    .line 40
    .line 41
    return-void

    .line 42
    :cond_1
    invoke-virtual {p0, p2, p1}, Landroid/view/View;->scrollBy(II)V

    .line 43
    .line 44
    .line 45
    :cond_2
    :goto_0
    return-void
.end method

.method public final onStartNestedScroll(Landroid/view/View;Landroid/view/View;I)Z
    .locals 1

    .line 1
    const/4 v0, 0x0

    .line 2
    invoke-virtual {p0, p1, p2, p3, v0}, Landroidx/core/widget/NestedScrollView;->i(Landroid/view/View;Landroid/view/View;II)Z

    .line 3
    .line 4
    .line 5
    move-result p0

    .line 6
    return p0
.end method

.method public final onStopNestedScroll(Landroid/view/View;)V
    .locals 1

    .line 1
    const/4 v0, 0x0

    .line 2
    invoke-virtual {p0, p1, v0}, Landroidx/core/widget/NestedScrollView;->c(Landroid/view/View;I)V

    .line 3
    .line 4
    .line 5
    return-void
.end method

.method public final onTouchEvent(Landroid/view/MotionEvent;)Z
    .locals 19

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v3, p1

    .line 4
    .line 5
    iget-object v1, v0, Landroidx/core/widget/NestedScrollView;->p:Landroid/view/VelocityTracker;

    .line 6
    .line 7
    if-nez v1, :cond_0

    .line 8
    .line 9
    invoke-static {}, Landroid/view/VelocityTracker;->obtain()Landroid/view/VelocityTracker;

    .line 10
    .line 11
    .line 12
    move-result-object v1

    .line 13
    iput-object v1, v0, Landroidx/core/widget/NestedScrollView;->p:Landroid/view/VelocityTracker;

    .line 14
    .line 15
    :cond_0
    invoke-virtual {v3}, Landroid/view/MotionEvent;->getActionMasked()I

    .line 16
    .line 17
    .line 18
    move-result v1

    .line 19
    const/4 v2, 0x0

    .line 20
    if-nez v1, :cond_1

    .line 21
    .line 22
    iput v2, v0, Landroidx/core/widget/NestedScrollView;->y:I

    .line 23
    .line 24
    :cond_1
    invoke-static {v3}, Landroid/view/MotionEvent;->obtain(Landroid/view/MotionEvent;)Landroid/view/MotionEvent;

    .line 25
    .line 26
    .line 27
    move-result-object v7

    .line 28
    iget v4, v0, Landroidx/core/widget/NestedScrollView;->y:I

    .line 29
    .line 30
    int-to-float v4, v4

    .line 31
    const/4 v5, 0x0

    .line 32
    invoke-virtual {v7, v5, v4}, Landroid/view/MotionEvent;->offsetLocation(FF)V

    .line 33
    .line 34
    .line 35
    const/4 v4, 0x2

    .line 36
    const/4 v8, 0x1

    .line 37
    if-eqz v1, :cond_18

    .line 38
    .line 39
    const/4 v6, 0x0

    .line 40
    const/4 v9, -0x1

    .line 41
    iget-object v10, v0, Landroidx/core/widget/NestedScrollView;->h:Landroid/widget/EdgeEffect;

    .line 42
    .line 43
    iget-object v11, v0, Landroidx/core/widget/NestedScrollView;->i:Landroid/widget/EdgeEffect;

    .line 44
    .line 45
    if-eq v1, v8, :cond_10

    .line 46
    .line 47
    if-eq v1, v4, :cond_7

    .line 48
    .line 49
    const/4 v4, 0x3

    .line 50
    if-eq v1, v4, :cond_4

    .line 51
    .line 52
    const/4 v2, 0x5

    .line 53
    if-eq v1, v2, :cond_3

    .line 54
    .line 55
    const/4 v2, 0x6

    .line 56
    if-eq v1, v2, :cond_2

    .line 57
    .line 58
    goto/16 :goto_4

    .line 59
    .line 60
    :cond_2
    invoke-virtual/range {p0 .. p1}, Landroidx/core/widget/NestedScrollView;->p(Landroid/view/MotionEvent;)V

    .line 61
    .line 62
    .line 63
    iget v1, v0, Landroidx/core/widget/NestedScrollView;->v:I

    .line 64
    .line 65
    invoke-virtual {v3, v1}, Landroid/view/MotionEvent;->findPointerIndex(I)I

    .line 66
    .line 67
    .line 68
    move-result v1

    .line 69
    invoke-virtual {v3, v1}, Landroid/view/MotionEvent;->getY(I)F

    .line 70
    .line 71
    .line 72
    move-result v1

    .line 73
    float-to-int v1, v1

    .line 74
    iput v1, v0, Landroidx/core/widget/NestedScrollView;->k:I

    .line 75
    .line 76
    goto/16 :goto_4

    .line 77
    .line 78
    :cond_3
    invoke-virtual {v3}, Landroid/view/MotionEvent;->getActionIndex()I

    .line 79
    .line 80
    .line 81
    move-result v1

    .line 82
    invoke-virtual {v3, v1}, Landroid/view/MotionEvent;->getY(I)F

    .line 83
    .line 84
    .line 85
    move-result v2

    .line 86
    float-to-int v2, v2

    .line 87
    iput v2, v0, Landroidx/core/widget/NestedScrollView;->k:I

    .line 88
    .line 89
    invoke-virtual {v3, v1}, Landroid/view/MotionEvent;->getPointerId(I)I

    .line 90
    .line 91
    .line 92
    move-result v1

    .line 93
    iput v1, v0, Landroidx/core/widget/NestedScrollView;->v:I

    .line 94
    .line 95
    goto/16 :goto_4

    .line 96
    .line 97
    :cond_4
    iget-boolean v1, v0, Landroidx/core/widget/NestedScrollView;->o:Z

    .line 98
    .line 99
    if-eqz v1, :cond_5

    .line 100
    .line 101
    invoke-virtual {v0}, Landroid/view/ViewGroup;->getChildCount()I

    .line 102
    .line 103
    .line 104
    move-result v1

    .line 105
    if-lez v1, :cond_5

    .line 106
    .line 107
    invoke-virtual {v0}, Landroid/view/View;->getScrollX()I

    .line 108
    .line 109
    .line 110
    move-result v13

    .line 111
    invoke-virtual {v0}, Landroid/view/View;->getScrollY()I

    .line 112
    .line 113
    .line 114
    move-result v14

    .line 115
    const/16 v17, 0x0

    .line 116
    .line 117
    invoke-virtual {v0}, Landroidx/core/widget/NestedScrollView;->getScrollRange()I

    .line 118
    .line 119
    .line 120
    move-result v18

    .line 121
    iget-object v12, v0, Landroidx/core/widget/NestedScrollView;->g:Landroid/widget/OverScroller;

    .line 122
    .line 123
    const/4 v15, 0x0

    .line 124
    const/16 v16, 0x0

    .line 125
    .line 126
    invoke-virtual/range {v12 .. v18}, Landroid/widget/OverScroller;->springBack(IIIIII)Z

    .line 127
    .line 128
    .line 129
    move-result v1

    .line 130
    if-eqz v1, :cond_5

    .line 131
    .line 132
    invoke-virtual {v0}, Landroid/view/View;->postInvalidateOnAnimation()V

    .line 133
    .line 134
    .line 135
    :cond_5
    iput v9, v0, Landroidx/core/widget/NestedScrollView;->v:I

    .line 136
    .line 137
    iput-boolean v2, v0, Landroidx/core/widget/NestedScrollView;->o:Z

    .line 138
    .line 139
    iget-object v1, v0, Landroidx/core/widget/NestedScrollView;->p:Landroid/view/VelocityTracker;

    .line 140
    .line 141
    if-eqz v1, :cond_6

    .line 142
    .line 143
    invoke-virtual {v1}, Landroid/view/VelocityTracker;->recycle()V

    .line 144
    .line 145
    .line 146
    iput-object v6, v0, Landroidx/core/widget/NestedScrollView;->p:Landroid/view/VelocityTracker;

    .line 147
    .line 148
    :cond_6
    invoke-virtual {v0, v2}, Landroidx/core/widget/NestedScrollView;->y(I)V

    .line 149
    .line 150
    .line 151
    invoke-virtual {v10}, Landroid/widget/EdgeEffect;->onRelease()V

    .line 152
    .line 153
    .line 154
    invoke-virtual {v11}, Landroid/widget/EdgeEffect;->onRelease()V

    .line 155
    .line 156
    .line 157
    goto/16 :goto_4

    .line 158
    .line 159
    :cond_7
    iget v1, v0, Landroidx/core/widget/NestedScrollView;->v:I

    .line 160
    .line 161
    invoke-virtual {v3, v1}, Landroid/view/MotionEvent;->findPointerIndex(I)I

    .line 162
    .line 163
    .line 164
    move-result v1

    .line 165
    if-ne v1, v9, :cond_8

    .line 166
    .line 167
    new-instance v1, Ljava/lang/StringBuilder;

    .line 168
    .line 169
    const-string v2, "Invalid pointerId="

    .line 170
    .line 171
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 172
    .line 173
    .line 174
    iget v2, v0, Landroidx/core/widget/NestedScrollView;->v:I

    .line 175
    .line 176
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 177
    .line 178
    .line 179
    const-string v2, " in onTouchEvent"

    .line 180
    .line 181
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 182
    .line 183
    .line 184
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 185
    .line 186
    .line 187
    move-result-object v1

    .line 188
    const-string v2, "NestedScrollView"

    .line 189
    .line 190
    invoke-static {v2, v1}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I

    .line 191
    .line 192
    .line 193
    goto/16 :goto_4

    .line 194
    .line 195
    :cond_8
    invoke-virtual {v3, v1}, Landroid/view/MotionEvent;->getY(I)F

    .line 196
    .line 197
    .line 198
    move-result v2

    .line 199
    float-to-int v9, v2

    .line 200
    iget v2, v0, Landroidx/core/widget/NestedScrollView;->k:I

    .line 201
    .line 202
    sub-int/2addr v2, v9

    .line 203
    invoke-virtual {v3, v1}, Landroid/view/MotionEvent;->getX(I)F

    .line 204
    .line 205
    .line 206
    move-result v4

    .line 207
    invoke-virtual {v0}, Landroid/view/View;->getWidth()I

    .line 208
    .line 209
    .line 210
    move-result v6

    .line 211
    int-to-float v6, v6

    .line 212
    div-float/2addr v4, v6

    .line 213
    int-to-float v6, v2

    .line 214
    invoke-virtual {v0}, Landroid/view/View;->getHeight()I

    .line 215
    .line 216
    .line 217
    move-result v12

    .line 218
    int-to-float v12, v12

    .line 219
    div-float/2addr v6, v12

    .line 220
    invoke-static {v10}, Llp/l0;->b(Landroid/widget/EdgeEffect;)F

    .line 221
    .line 222
    .line 223
    move-result v12

    .line 224
    cmpl-float v12, v12, v5

    .line 225
    .line 226
    if-eqz v12, :cond_a

    .line 227
    .line 228
    neg-float v6, v6

    .line 229
    invoke-static {v10, v6, v4}, Llp/l0;->c(Landroid/widget/EdgeEffect;FF)F

    .line 230
    .line 231
    .line 232
    move-result v4

    .line 233
    neg-float v4, v4

    .line 234
    invoke-static {v10}, Llp/l0;->b(Landroid/widget/EdgeEffect;)F

    .line 235
    .line 236
    .line 237
    move-result v6

    .line 238
    cmpl-float v5, v6, v5

    .line 239
    .line 240
    if-nez v5, :cond_9

    .line 241
    .line 242
    invoke-virtual {v10}, Landroid/widget/EdgeEffect;->onRelease()V

    .line 243
    .line 244
    .line 245
    :cond_9
    :goto_0
    move v5, v4

    .line 246
    goto :goto_1

    .line 247
    :cond_a
    invoke-static {v11}, Llp/l0;->b(Landroid/widget/EdgeEffect;)F

    .line 248
    .line 249
    .line 250
    move-result v10

    .line 251
    cmpl-float v10, v10, v5

    .line 252
    .line 253
    if-eqz v10, :cond_b

    .line 254
    .line 255
    const/high16 v10, 0x3f800000    # 1.0f

    .line 256
    .line 257
    sub-float/2addr v10, v4

    .line 258
    invoke-static {v11, v6, v10}, Llp/l0;->c(Landroid/widget/EdgeEffect;FF)F

    .line 259
    .line 260
    .line 261
    move-result v4

    .line 262
    invoke-static {v11}, Llp/l0;->b(Landroid/widget/EdgeEffect;)F

    .line 263
    .line 264
    .line 265
    move-result v6

    .line 266
    cmpl-float v5, v6, v5

    .line 267
    .line 268
    if-nez v5, :cond_9

    .line 269
    .line 270
    invoke-virtual {v11}, Landroid/widget/EdgeEffect;->onRelease()V

    .line 271
    .line 272
    .line 273
    goto :goto_0

    .line 274
    :cond_b
    :goto_1
    invoke-virtual {v0}, Landroid/view/View;->getHeight()I

    .line 275
    .line 276
    .line 277
    move-result v4

    .line 278
    int-to-float v4, v4

    .line 279
    mul-float/2addr v5, v4

    .line 280
    invoke-static {v5}, Ljava/lang/Math;->round(F)I

    .line 281
    .line 282
    .line 283
    move-result v4

    .line 284
    if-eqz v4, :cond_c

    .line 285
    .line 286
    invoke-virtual {v0}, Landroid/view/View;->invalidate()V

    .line 287
    .line 288
    .line 289
    :cond_c
    sub-int/2addr v2, v4

    .line 290
    iget-boolean v4, v0, Landroidx/core/widget/NestedScrollView;->o:Z

    .line 291
    .line 292
    if-nez v4, :cond_f

    .line 293
    .line 294
    invoke-static {v2}, Ljava/lang/Math;->abs(I)I

    .line 295
    .line 296
    .line 297
    move-result v4

    .line 298
    iget v5, v0, Landroidx/core/widget/NestedScrollView;->s:I

    .line 299
    .line 300
    if-le v4, v5, :cond_f

    .line 301
    .line 302
    invoke-virtual {v0}, Landroid/view/View;->getParent()Landroid/view/ViewParent;

    .line 303
    .line 304
    .line 305
    move-result-object v4

    .line 306
    if-eqz v4, :cond_d

    .line 307
    .line 308
    invoke-interface {v4, v8}, Landroid/view/ViewParent;->requestDisallowInterceptTouchEvent(Z)V

    .line 309
    .line 310
    .line 311
    :cond_d
    iput-boolean v8, v0, Landroidx/core/widget/NestedScrollView;->o:Z

    .line 312
    .line 313
    if-lez v2, :cond_e

    .line 314
    .line 315
    iget v4, v0, Landroidx/core/widget/NestedScrollView;->s:I

    .line 316
    .line 317
    sub-int/2addr v2, v4

    .line 318
    goto :goto_2

    .line 319
    :cond_e
    iget v4, v0, Landroidx/core/widget/NestedScrollView;->s:I

    .line 320
    .line 321
    add-int/2addr v2, v4

    .line 322
    :cond_f
    :goto_2
    iget-boolean v4, v0, Landroidx/core/widget/NestedScrollView;->o:Z

    .line 323
    .line 324
    if-eqz v4, :cond_1c

    .line 325
    .line 326
    invoke-virtual {v3, v1}, Landroid/view/MotionEvent;->getX(I)F

    .line 327
    .line 328
    .line 329
    move-result v1

    .line 330
    float-to-int v4, v1

    .line 331
    const/4 v5, 0x0

    .line 332
    const/4 v6, 0x0

    .line 333
    move v1, v2

    .line 334
    const/4 v2, 0x1

    .line 335
    invoke-virtual/range {v0 .. v6}, Landroidx/core/widget/NestedScrollView;->t(IILandroid/view/MotionEvent;IIZ)I

    .line 336
    .line 337
    .line 338
    move-result v1

    .line 339
    sub-int/2addr v9, v1

    .line 340
    iput v9, v0, Landroidx/core/widget/NestedScrollView;->k:I

    .line 341
    .line 342
    iget v2, v0, Landroidx/core/widget/NestedScrollView;->y:I

    .line 343
    .line 344
    add-int/2addr v2, v1

    .line 345
    iput v2, v0, Landroidx/core/widget/NestedScrollView;->y:I

    .line 346
    .line 347
    goto/16 :goto_4

    .line 348
    .line 349
    :cond_10
    iget-object v1, v0, Landroidx/core/widget/NestedScrollView;->p:Landroid/view/VelocityTracker;

    .line 350
    .line 351
    iget v3, v0, Landroidx/core/widget/NestedScrollView;->u:I

    .line 352
    .line 353
    int-to-float v3, v3

    .line 354
    const/16 v4, 0x3e8

    .line 355
    .line 356
    invoke-virtual {v1, v4, v3}, Landroid/view/VelocityTracker;->computeCurrentVelocity(IF)V

    .line 357
    .line 358
    .line 359
    iget v3, v0, Landroidx/core/widget/NestedScrollView;->v:I

    .line 360
    .line 361
    invoke-virtual {v1, v3}, Landroid/view/VelocityTracker;->getYVelocity(I)F

    .line 362
    .line 363
    .line 364
    move-result v1

    .line 365
    float-to-int v1, v1

    .line 366
    invoke-static {v1}, Ljava/lang/Math;->abs(I)I

    .line 367
    .line 368
    .line 369
    move-result v3

    .line 370
    iget v4, v0, Landroidx/core/widget/NestedScrollView;->t:I

    .line 371
    .line 372
    if-lt v3, v4, :cond_15

    .line 373
    .line 374
    invoke-static {v10}, Llp/l0;->b(Landroid/widget/EdgeEffect;)F

    .line 375
    .line 376
    .line 377
    move-result v3

    .line 378
    cmpl-float v3, v3, v5

    .line 379
    .line 380
    if-eqz v3, :cond_12

    .line 381
    .line 382
    invoke-virtual {v0, v10, v1}, Landroidx/core/widget/NestedScrollView;->u(Landroid/widget/EdgeEffect;I)Z

    .line 383
    .line 384
    .line 385
    move-result v3

    .line 386
    if-eqz v3, :cond_11

    .line 387
    .line 388
    invoke-virtual {v10, v1}, Landroid/widget/EdgeEffect;->onAbsorb(I)V

    .line 389
    .line 390
    .line 391
    goto :goto_3

    .line 392
    :cond_11
    neg-int v1, v1

    .line 393
    invoke-virtual {v0, v1}, Landroidx/core/widget/NestedScrollView;->k(I)V

    .line 394
    .line 395
    .line 396
    goto :goto_3

    .line 397
    :cond_12
    invoke-static {v11}, Llp/l0;->b(Landroid/widget/EdgeEffect;)F

    .line 398
    .line 399
    .line 400
    move-result v3

    .line 401
    cmpl-float v3, v3, v5

    .line 402
    .line 403
    if-eqz v3, :cond_14

    .line 404
    .line 405
    neg-int v1, v1

    .line 406
    invoke-virtual {v0, v11, v1}, Landroidx/core/widget/NestedScrollView;->u(Landroid/widget/EdgeEffect;I)Z

    .line 407
    .line 408
    .line 409
    move-result v3

    .line 410
    if-eqz v3, :cond_13

    .line 411
    .line 412
    invoke-virtual {v11, v1}, Landroid/widget/EdgeEffect;->onAbsorb(I)V

    .line 413
    .line 414
    .line 415
    goto :goto_3

    .line 416
    :cond_13
    invoke-virtual {v0, v1}, Landroidx/core/widget/NestedScrollView;->k(I)V

    .line 417
    .line 418
    .line 419
    goto :goto_3

    .line 420
    :cond_14
    neg-int v1, v1

    .line 421
    int-to-float v3, v1

    .line 422
    iget-object v4, v0, Landroidx/core/widget/NestedScrollView;->C:Ld6/p;

    .line 423
    .line 424
    invoke-virtual {v4, v5, v3}, Ld6/p;->b(FF)Z

    .line 425
    .line 426
    .line 427
    move-result v4

    .line 428
    if-nez v4, :cond_16

    .line 429
    .line 430
    invoke-virtual {v0, v5, v3, v8}, Landroidx/core/widget/NestedScrollView;->dispatchNestedFling(FFZ)Z

    .line 431
    .line 432
    .line 433
    invoke-virtual {v0, v1}, Landroidx/core/widget/NestedScrollView;->k(I)V

    .line 434
    .line 435
    .line 436
    goto :goto_3

    .line 437
    :cond_15
    invoke-virtual {v0}, Landroid/view/View;->getScrollX()I

    .line 438
    .line 439
    .line 440
    move-result v13

    .line 441
    invoke-virtual {v0}, Landroid/view/View;->getScrollY()I

    .line 442
    .line 443
    .line 444
    move-result v14

    .line 445
    const/16 v17, 0x0

    .line 446
    .line 447
    invoke-virtual {v0}, Landroidx/core/widget/NestedScrollView;->getScrollRange()I

    .line 448
    .line 449
    .line 450
    move-result v18

    .line 451
    iget-object v12, v0, Landroidx/core/widget/NestedScrollView;->g:Landroid/widget/OverScroller;

    .line 452
    .line 453
    const/4 v15, 0x0

    .line 454
    const/16 v16, 0x0

    .line 455
    .line 456
    invoke-virtual/range {v12 .. v18}, Landroid/widget/OverScroller;->springBack(IIIIII)Z

    .line 457
    .line 458
    .line 459
    move-result v1

    .line 460
    if-eqz v1, :cond_16

    .line 461
    .line 462
    invoke-virtual {v0}, Landroid/view/View;->postInvalidateOnAnimation()V

    .line 463
    .line 464
    .line 465
    :cond_16
    :goto_3
    iput v9, v0, Landroidx/core/widget/NestedScrollView;->v:I

    .line 466
    .line 467
    iput-boolean v2, v0, Landroidx/core/widget/NestedScrollView;->o:Z

    .line 468
    .line 469
    iget-object v1, v0, Landroidx/core/widget/NestedScrollView;->p:Landroid/view/VelocityTracker;

    .line 470
    .line 471
    if-eqz v1, :cond_17

    .line 472
    .line 473
    invoke-virtual {v1}, Landroid/view/VelocityTracker;->recycle()V

    .line 474
    .line 475
    .line 476
    iput-object v6, v0, Landroidx/core/widget/NestedScrollView;->p:Landroid/view/VelocityTracker;

    .line 477
    .line 478
    :cond_17
    invoke-virtual {v0, v2}, Landroidx/core/widget/NestedScrollView;->y(I)V

    .line 479
    .line 480
    .line 481
    invoke-virtual {v10}, Landroid/widget/EdgeEffect;->onRelease()V

    .line 482
    .line 483
    .line 484
    invoke-virtual {v11}, Landroid/widget/EdgeEffect;->onRelease()V

    .line 485
    .line 486
    .line 487
    goto :goto_4

    .line 488
    :cond_18
    invoke-virtual {v0}, Landroid/view/ViewGroup;->getChildCount()I

    .line 489
    .line 490
    .line 491
    move-result v1

    .line 492
    if-nez v1, :cond_19

    .line 493
    .line 494
    return v2

    .line 495
    :cond_19
    iget-boolean v1, v0, Landroidx/core/widget/NestedScrollView;->o:Z

    .line 496
    .line 497
    if-eqz v1, :cond_1a

    .line 498
    .line 499
    invoke-virtual {v0}, Landroid/view/View;->getParent()Landroid/view/ViewParent;

    .line 500
    .line 501
    .line 502
    move-result-object v1

    .line 503
    if-eqz v1, :cond_1a

    .line 504
    .line 505
    invoke-interface {v1, v8}, Landroid/view/ViewParent;->requestDisallowInterceptTouchEvent(Z)V

    .line 506
    .line 507
    .line 508
    :cond_1a
    iget-object v1, v0, Landroidx/core/widget/NestedScrollView;->g:Landroid/widget/OverScroller;

    .line 509
    .line 510
    invoke-virtual {v1}, Landroid/widget/OverScroller;->isFinished()Z

    .line 511
    .line 512
    .line 513
    move-result v1

    .line 514
    if-nez v1, :cond_1b

    .line 515
    .line 516
    iget-object v1, v0, Landroidx/core/widget/NestedScrollView;->g:Landroid/widget/OverScroller;

    .line 517
    .line 518
    invoke-virtual {v1}, Landroid/widget/OverScroller;->abortAnimation()V

    .line 519
    .line 520
    .line 521
    invoke-virtual {v0, v8}, Landroidx/core/widget/NestedScrollView;->y(I)V

    .line 522
    .line 523
    .line 524
    :cond_1b
    invoke-virtual {v3}, Landroid/view/MotionEvent;->getY()F

    .line 525
    .line 526
    .line 527
    move-result v1

    .line 528
    float-to-int v1, v1

    .line 529
    invoke-virtual {v3, v2}, Landroid/view/MotionEvent;->getPointerId(I)I

    .line 530
    .line 531
    .line 532
    move-result v3

    .line 533
    iput v1, v0, Landroidx/core/widget/NestedScrollView;->k:I

    .line 534
    .line 535
    iput v3, v0, Landroidx/core/widget/NestedScrollView;->v:I

    .line 536
    .line 537
    invoke-virtual {v0, v4, v2}, Landroidx/core/widget/NestedScrollView;->w(II)V

    .line 538
    .line 539
    .line 540
    :cond_1c
    :goto_4
    iget-object v0, v0, Landroidx/core/widget/NestedScrollView;->p:Landroid/view/VelocityTracker;

    .line 541
    .line 542
    if-eqz v0, :cond_1d

    .line 543
    .line 544
    invoke-virtual {v0, v7}, Landroid/view/VelocityTracker;->addMovement(Landroid/view/MotionEvent;)V

    .line 545
    .line 546
    .line 547
    :cond_1d
    invoke-virtual {v7}, Landroid/view/MotionEvent;->recycle()V

    .line 548
    .line 549
    .line 550
    return v8
.end method

.method public final p(Landroid/view/MotionEvent;)V
    .locals 3

    .line 1
    invoke-virtual {p1}, Landroid/view/MotionEvent;->getActionIndex()I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    invoke-virtual {p1, v0}, Landroid/view/MotionEvent;->getPointerId(I)I

    .line 6
    .line 7
    .line 8
    move-result v1

    .line 9
    iget v2, p0, Landroidx/core/widget/NestedScrollView;->v:I

    .line 10
    .line 11
    if-ne v1, v2, :cond_1

    .line 12
    .line 13
    if-nez v0, :cond_0

    .line 14
    .line 15
    const/4 v0, 0x1

    .line 16
    goto :goto_0

    .line 17
    :cond_0
    const/4 v0, 0x0

    .line 18
    :goto_0
    invoke-virtual {p1, v0}, Landroid/view/MotionEvent;->getY(I)F

    .line 19
    .line 20
    .line 21
    move-result v1

    .line 22
    float-to-int v1, v1

    .line 23
    iput v1, p0, Landroidx/core/widget/NestedScrollView;->k:I

    .line 24
    .line 25
    invoke-virtual {p1, v0}, Landroid/view/MotionEvent;->getPointerId(I)I

    .line 26
    .line 27
    .line 28
    move-result p1

    .line 29
    iput p1, p0, Landroidx/core/widget/NestedScrollView;->v:I

    .line 30
    .line 31
    iget-object p0, p0, Landroidx/core/widget/NestedScrollView;->p:Landroid/view/VelocityTracker;

    .line 32
    .line 33
    if-eqz p0, :cond_1

    .line 34
    .line 35
    invoke-virtual {p0}, Landroid/view/VelocityTracker;->clear()V

    .line 36
    .line 37
    .line 38
    :cond_1
    return-void
.end method

.method public final q(IIII)Z
    .locals 9

    .line 1
    invoke-virtual {p0}, Landroid/view/View;->getOverScrollMode()I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    invoke-super {p0}, Landroid/view/View;->computeHorizontalScrollRange()I

    .line 6
    .line 7
    .line 8
    invoke-super {p0}, Landroid/view/View;->computeHorizontalScrollExtent()I

    .line 9
    .line 10
    .line 11
    invoke-virtual {p0}, Landroidx/core/widget/NestedScrollView;->computeVerticalScrollRange()I

    .line 12
    .line 13
    .line 14
    invoke-super {p0}, Landroid/view/View;->computeVerticalScrollExtent()I

    .line 15
    .line 16
    .line 17
    const/4 v1, 0x1

    .line 18
    add-int/2addr p3, p1

    .line 19
    const/4 p1, 0x0

    .line 20
    if-lez p2, :cond_0

    .line 21
    .line 22
    :goto_0
    move v3, p1

    .line 23
    move p2, v1

    .line 24
    goto :goto_1

    .line 25
    :cond_0
    if-gez p2, :cond_1

    .line 26
    .line 27
    goto :goto_0

    .line 28
    :cond_1
    move v3, p2

    .line 29
    move p2, p1

    .line 30
    :goto_1
    if-le p3, p4, :cond_2

    .line 31
    .line 32
    move v4, p4

    .line 33
    :goto_2
    move p3, v1

    .line 34
    goto :goto_3

    .line 35
    :cond_2
    if-gez p3, :cond_3

    .line 36
    .line 37
    move v4, p1

    .line 38
    goto :goto_2

    .line 39
    :cond_3
    move v4, p3

    .line 40
    move p3, p1

    .line 41
    :goto_3
    if-eqz p3, :cond_4

    .line 42
    .line 43
    iget-object p4, p0, Landroidx/core/widget/NestedScrollView;->C:Ld6/p;

    .line 44
    .line 45
    invoke-virtual {p4, v1}, Ld6/p;->f(I)Z

    .line 46
    .line 47
    .line 48
    move-result p4

    .line 49
    if-nez p4, :cond_4

    .line 50
    .line 51
    const/4 v7, 0x0

    .line 52
    invoke-virtual {p0}, Landroidx/core/widget/NestedScrollView;->getScrollRange()I

    .line 53
    .line 54
    .line 55
    move-result v8

    .line 56
    iget-object v2, p0, Landroidx/core/widget/NestedScrollView;->g:Landroid/widget/OverScroller;

    .line 57
    .line 58
    const/4 v5, 0x0

    .line 59
    const/4 v6, 0x0

    .line 60
    invoke-virtual/range {v2 .. v8}, Landroid/widget/OverScroller;->springBack(IIIIII)Z

    .line 61
    .line 62
    .line 63
    :cond_4
    invoke-super {p0, v3, v4}, Landroid/view/View;->scrollTo(II)V

    .line 64
    .line 65
    .line 66
    if-nez p2, :cond_6

    .line 67
    .line 68
    if-eqz p3, :cond_5

    .line 69
    .line 70
    goto :goto_4

    .line 71
    :cond_5
    return p1

    .line 72
    :cond_6
    :goto_4
    return v1
.end method

.method public final r(I)V
    .locals 5

    .line 1
    const/16 v0, 0x82

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    const/4 v2, 0x1

    .line 5
    if-ne p1, v0, :cond_0

    .line 6
    .line 7
    move v0, v2

    .line 8
    goto :goto_0

    .line 9
    :cond_0
    move v0, v1

    .line 10
    :goto_0
    invoke-virtual {p0}, Landroid/view/View;->getHeight()I

    .line 11
    .line 12
    .line 13
    move-result v3

    .line 14
    iget-object v4, p0, Landroidx/core/widget/NestedScrollView;->f:Landroid/graphics/Rect;

    .line 15
    .line 16
    if-eqz v0, :cond_1

    .line 17
    .line 18
    invoke-virtual {p0}, Landroid/view/View;->getScrollY()I

    .line 19
    .line 20
    .line 21
    move-result v0

    .line 22
    add-int/2addr v0, v3

    .line 23
    iput v0, v4, Landroid/graphics/Rect;->top:I

    .line 24
    .line 25
    invoke-virtual {p0}, Landroid/view/ViewGroup;->getChildCount()I

    .line 26
    .line 27
    .line 28
    move-result v0

    .line 29
    if-lez v0, :cond_2

    .line 30
    .line 31
    sub-int/2addr v0, v2

    .line 32
    invoke-virtual {p0, v0}, Landroid/view/ViewGroup;->getChildAt(I)Landroid/view/View;

    .line 33
    .line 34
    .line 35
    move-result-object v0

    .line 36
    invoke-virtual {v0}, Landroid/view/View;->getLayoutParams()Landroid/view/ViewGroup$LayoutParams;

    .line 37
    .line 38
    .line 39
    move-result-object v1

    .line 40
    check-cast v1, Landroid/widget/FrameLayout$LayoutParams;

    .line 41
    .line 42
    invoke-virtual {v0}, Landroid/view/View;->getBottom()I

    .line 43
    .line 44
    .line 45
    move-result v0

    .line 46
    iget v1, v1, Landroid/widget/FrameLayout$LayoutParams;->bottomMargin:I

    .line 47
    .line 48
    add-int/2addr v0, v1

    .line 49
    invoke-virtual {p0}, Landroid/view/View;->getPaddingBottom()I

    .line 50
    .line 51
    .line 52
    move-result v1

    .line 53
    add-int/2addr v1, v0

    .line 54
    iget v0, v4, Landroid/graphics/Rect;->top:I

    .line 55
    .line 56
    add-int/2addr v0, v3

    .line 57
    if-le v0, v1, :cond_2

    .line 58
    .line 59
    sub-int/2addr v1, v3

    .line 60
    iput v1, v4, Landroid/graphics/Rect;->top:I

    .line 61
    .line 62
    goto :goto_1

    .line 63
    :cond_1
    invoke-virtual {p0}, Landroid/view/View;->getScrollY()I

    .line 64
    .line 65
    .line 66
    move-result v0

    .line 67
    sub-int/2addr v0, v3

    .line 68
    iput v0, v4, Landroid/graphics/Rect;->top:I

    .line 69
    .line 70
    if-gez v0, :cond_2

    .line 71
    .line 72
    iput v1, v4, Landroid/graphics/Rect;->top:I

    .line 73
    .line 74
    :cond_2
    :goto_1
    iget v0, v4, Landroid/graphics/Rect;->top:I

    .line 75
    .line 76
    add-int/2addr v3, v0

    .line 77
    iput v3, v4, Landroid/graphics/Rect;->bottom:I

    .line 78
    .line 79
    invoke-virtual {p0, p1, v0, v3}, Landroidx/core/widget/NestedScrollView;->s(III)Z

    .line 80
    .line 81
    .line 82
    return-void
.end method

.method public final requestChildFocus(Landroid/view/View;Landroid/view/View;)V
    .locals 2

    .line 1
    iget-boolean v0, p0, Landroidx/core/widget/NestedScrollView;->l:Z

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    iget-object v0, p0, Landroidx/core/widget/NestedScrollView;->f:Landroid/graphics/Rect;

    .line 6
    .line 7
    invoke-virtual {p2, v0}, Landroid/view/View;->getDrawingRect(Landroid/graphics/Rect;)V

    .line 8
    .line 9
    .line 10
    invoke-virtual {p0, p2, v0}, Landroid/view/ViewGroup;->offsetDescendantRectToMyCoords(Landroid/view/View;Landroid/graphics/Rect;)V

    .line 11
    .line 12
    .line 13
    invoke-virtual {p0, v0}, Landroidx/core/widget/NestedScrollView;->e(Landroid/graphics/Rect;)I

    .line 14
    .line 15
    .line 16
    move-result v0

    .line 17
    if-eqz v0, :cond_1

    .line 18
    .line 19
    const/4 v1, 0x0

    .line 20
    invoke-virtual {p0, v1, v0}, Landroid/view/View;->scrollBy(II)V

    .line 21
    .line 22
    .line 23
    goto :goto_0

    .line 24
    :cond_0
    iput-object p2, p0, Landroidx/core/widget/NestedScrollView;->n:Landroid/view/View;

    .line 25
    .line 26
    :cond_1
    :goto_0
    invoke-super {p0, p1, p2}, Landroid/view/ViewGroup;->requestChildFocus(Landroid/view/View;Landroid/view/View;)V

    .line 27
    .line 28
    .line 29
    return-void
.end method

.method public final requestChildRectangleOnScreen(Landroid/view/View;Landroid/graphics/Rect;Z)Z
    .locals 2

    .line 1
    invoke-virtual {p1}, Landroid/view/View;->getLeft()I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    invoke-virtual {p1}, Landroid/view/View;->getScrollX()I

    .line 6
    .line 7
    .line 8
    move-result v1

    .line 9
    sub-int/2addr v0, v1

    .line 10
    invoke-virtual {p1}, Landroid/view/View;->getTop()I

    .line 11
    .line 12
    .line 13
    move-result v1

    .line 14
    invoke-virtual {p1}, Landroid/view/View;->getScrollY()I

    .line 15
    .line 16
    .line 17
    move-result p1

    .line 18
    sub-int/2addr v1, p1

    .line 19
    invoke-virtual {p2, v0, v1}, Landroid/graphics/Rect;->offset(II)V

    .line 20
    .line 21
    .line 22
    invoke-virtual {p0, p2}, Landroidx/core/widget/NestedScrollView;->e(Landroid/graphics/Rect;)I

    .line 23
    .line 24
    .line 25
    move-result p1

    .line 26
    const/4 p2, 0x0

    .line 27
    if-eqz p1, :cond_0

    .line 28
    .line 29
    const/4 v0, 0x1

    .line 30
    goto :goto_0

    .line 31
    :cond_0
    move v0, p2

    .line 32
    :goto_0
    if-eqz v0, :cond_2

    .line 33
    .line 34
    if-eqz p3, :cond_1

    .line 35
    .line 36
    invoke-virtual {p0, p2, p1}, Landroid/view/View;->scrollBy(II)V

    .line 37
    .line 38
    .line 39
    return v0

    .line 40
    :cond_1
    invoke-virtual {p0, p2, p1, p2}, Landroidx/core/widget/NestedScrollView;->v(IIZ)V

    .line 41
    .line 42
    .line 43
    :cond_2
    return v0
.end method

.method public final requestDisallowInterceptTouchEvent(Z)V
    .locals 1

    .line 1
    if-eqz p1, :cond_0

    .line 2
    .line 3
    iget-object v0, p0, Landroidx/core/widget/NestedScrollView;->p:Landroid/view/VelocityTracker;

    .line 4
    .line 5
    if-eqz v0, :cond_0

    .line 6
    .line 7
    invoke-virtual {v0}, Landroid/view/VelocityTracker;->recycle()V

    .line 8
    .line 9
    .line 10
    const/4 v0, 0x0

    .line 11
    iput-object v0, p0, Landroidx/core/widget/NestedScrollView;->p:Landroid/view/VelocityTracker;

    .line 12
    .line 13
    :cond_0
    invoke-super {p0, p1}, Landroid/view/ViewGroup;->requestDisallowInterceptTouchEvent(Z)V

    .line 14
    .line 15
    .line 16
    return-void
.end method

.method public final requestLayout()V
    .locals 1

    .line 1
    const/4 v0, 0x1

    .line 2
    iput-boolean v0, p0, Landroidx/core/widget/NestedScrollView;->l:Z

    .line 3
    .line 4
    invoke-super {p0}, Landroid/view/View;->requestLayout()V

    .line 5
    .line 6
    .line 7
    return-void
.end method

.method public final s(III)Z
    .locals 18

    .line 1
    move/from16 v0, p1

    .line 2
    .line 3
    move/from16 v1, p2

    .line 4
    .line 5
    move/from16 v2, p3

    .line 6
    .line 7
    invoke-virtual/range {p0 .. p0}, Landroid/view/View;->getHeight()I

    .line 8
    .line 9
    .line 10
    move-result v3

    .line 11
    invoke-virtual/range {p0 .. p0}, Landroid/view/View;->getScrollY()I

    .line 12
    .line 13
    .line 14
    move-result v4

    .line 15
    add-int/2addr v3, v4

    .line 16
    const/16 v5, 0x21

    .line 17
    .line 18
    if-ne v0, v5, :cond_0

    .line 19
    .line 20
    const/4 v5, 0x1

    .line 21
    goto :goto_0

    .line 22
    :cond_0
    const/4 v5, 0x0

    .line 23
    :goto_0
    const/4 v8, 0x2

    .line 24
    move-object/from16 v9, p0

    .line 25
    .line 26
    invoke-virtual {v9, v8}, Landroid/view/View;->getFocusables(I)Ljava/util/ArrayList;

    .line 27
    .line 28
    .line 29
    move-result-object v8

    .line 30
    invoke-interface {v8}, Ljava/util/List;->size()I

    .line 31
    .line 32
    .line 33
    move-result v10

    .line 34
    const/4 v11, 0x0

    .line 35
    const/4 v12, 0x0

    .line 36
    const/4 v13, 0x0

    .line 37
    :goto_1
    if-ge v12, v10, :cond_9

    .line 38
    .line 39
    invoke-interface {v8, v12}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 40
    .line 41
    .line 42
    move-result-object v14

    .line 43
    check-cast v14, Landroid/view/View;

    .line 44
    .line 45
    invoke-virtual {v14}, Landroid/view/View;->getTop()I

    .line 46
    .line 47
    .line 48
    move-result v15

    .line 49
    invoke-virtual {v14}, Landroid/view/View;->getBottom()I

    .line 50
    .line 51
    .line 52
    move-result v6

    .line 53
    if-ge v1, v6, :cond_8

    .line 54
    .line 55
    if-ge v15, v2, :cond_8

    .line 56
    .line 57
    if-ge v1, v15, :cond_1

    .line 58
    .line 59
    if-ge v6, v2, :cond_1

    .line 60
    .line 61
    const/16 v17, 0x1

    .line 62
    .line 63
    goto :goto_2

    .line 64
    :cond_1
    const/16 v17, 0x0

    .line 65
    .line 66
    :goto_2
    if-nez v11, :cond_2

    .line 67
    .line 68
    move-object v11, v14

    .line 69
    move/from16 v13, v17

    .line 70
    .line 71
    goto :goto_5

    .line 72
    :cond_2
    if-eqz v5, :cond_3

    .line 73
    .line 74
    invoke-virtual {v11}, Landroid/view/View;->getTop()I

    .line 75
    .line 76
    .line 77
    move-result v7

    .line 78
    if-lt v15, v7, :cond_4

    .line 79
    .line 80
    :cond_3
    if-nez v5, :cond_5

    .line 81
    .line 82
    invoke-virtual {v11}, Landroid/view/View;->getBottom()I

    .line 83
    .line 84
    .line 85
    move-result v7

    .line 86
    if-le v6, v7, :cond_5

    .line 87
    .line 88
    :cond_4
    const/4 v6, 0x1

    .line 89
    goto :goto_3

    .line 90
    :cond_5
    const/4 v6, 0x0

    .line 91
    :goto_3
    if-eqz v13, :cond_6

    .line 92
    .line 93
    if-eqz v17, :cond_8

    .line 94
    .line 95
    if-eqz v6, :cond_8

    .line 96
    .line 97
    goto :goto_4

    .line 98
    :cond_6
    if-eqz v17, :cond_7

    .line 99
    .line 100
    move-object v11, v14

    .line 101
    const/4 v13, 0x1

    .line 102
    goto :goto_5

    .line 103
    :cond_7
    if-eqz v6, :cond_8

    .line 104
    .line 105
    :goto_4
    move-object v11, v14

    .line 106
    :cond_8
    :goto_5
    add-int/lit8 v12, v12, 0x1

    .line 107
    .line 108
    goto :goto_1

    .line 109
    :cond_9
    if-nez v11, :cond_a

    .line 110
    .line 111
    move-object v6, v9

    .line 112
    goto :goto_6

    .line 113
    :cond_a
    move-object v6, v11

    .line 114
    :goto_6
    if-lt v1, v4, :cond_b

    .line 115
    .line 116
    if-gt v2, v3, :cond_b

    .line 117
    .line 118
    const/16 v16, 0x0

    .line 119
    .line 120
    goto :goto_9

    .line 121
    :cond_b
    if-eqz v5, :cond_c

    .line 122
    .line 123
    sub-int/2addr v1, v4

    .line 124
    :goto_7
    move v10, v1

    .line 125
    goto :goto_8

    .line 126
    :cond_c
    sub-int v1, v2, v3

    .line 127
    .line 128
    goto :goto_7

    .line 129
    :goto_8
    const/4 v11, -0x1

    .line 130
    const/4 v12, 0x0

    .line 131
    const/4 v13, 0x0

    .line 132
    const/4 v14, 0x1

    .line 133
    const/4 v15, 0x1

    .line 134
    invoke-virtual/range {v9 .. v15}, Landroidx/core/widget/NestedScrollView;->t(IILandroid/view/MotionEvent;IIZ)I

    .line 135
    .line 136
    .line 137
    const/16 v16, 0x1

    .line 138
    .line 139
    :goto_9
    invoke-virtual/range {p0 .. p0}, Landroid/view/View;->findFocus()Landroid/view/View;

    .line 140
    .line 141
    .line 142
    move-result-object v1

    .line 143
    if-eq v6, v1, :cond_d

    .line 144
    .line 145
    invoke-virtual {v6, v0}, Landroid/view/View;->requestFocus(I)Z

    .line 146
    .line 147
    .line 148
    :cond_d
    return v16
.end method

.method public final scrollTo(II)V
    .locals 7

    .line 1
    invoke-virtual {p0}, Landroid/view/ViewGroup;->getChildCount()I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    if-lez v0, :cond_7

    .line 6
    .line 7
    const/4 v0, 0x0

    .line 8
    invoke-virtual {p0, v0}, Landroid/view/ViewGroup;->getChildAt(I)Landroid/view/View;

    .line 9
    .line 10
    .line 11
    move-result-object v1

    .line 12
    invoke-virtual {v1}, Landroid/view/View;->getLayoutParams()Landroid/view/ViewGroup$LayoutParams;

    .line 13
    .line 14
    .line 15
    move-result-object v2

    .line 16
    check-cast v2, Landroid/widget/FrameLayout$LayoutParams;

    .line 17
    .line 18
    invoke-virtual {p0}, Landroid/view/View;->getWidth()I

    .line 19
    .line 20
    .line 21
    move-result v3

    .line 22
    invoke-virtual {p0}, Landroid/view/View;->getPaddingLeft()I

    .line 23
    .line 24
    .line 25
    move-result v4

    .line 26
    sub-int/2addr v3, v4

    .line 27
    invoke-virtual {p0}, Landroid/view/View;->getPaddingRight()I

    .line 28
    .line 29
    .line 30
    move-result v4

    .line 31
    sub-int/2addr v3, v4

    .line 32
    invoke-virtual {v1}, Landroid/view/View;->getWidth()I

    .line 33
    .line 34
    .line 35
    move-result v4

    .line 36
    iget v5, v2, Landroid/widget/FrameLayout$LayoutParams;->leftMargin:I

    .line 37
    .line 38
    add-int/2addr v4, v5

    .line 39
    iget v5, v2, Landroid/widget/FrameLayout$LayoutParams;->rightMargin:I

    .line 40
    .line 41
    add-int/2addr v4, v5

    .line 42
    invoke-virtual {p0}, Landroid/view/View;->getHeight()I

    .line 43
    .line 44
    .line 45
    move-result v5

    .line 46
    invoke-virtual {p0}, Landroid/view/View;->getPaddingTop()I

    .line 47
    .line 48
    .line 49
    move-result v6

    .line 50
    sub-int/2addr v5, v6

    .line 51
    invoke-virtual {p0}, Landroid/view/View;->getPaddingBottom()I

    .line 52
    .line 53
    .line 54
    move-result v6

    .line 55
    sub-int/2addr v5, v6

    .line 56
    invoke-virtual {v1}, Landroid/view/View;->getHeight()I

    .line 57
    .line 58
    .line 59
    move-result v1

    .line 60
    iget v6, v2, Landroid/widget/FrameLayout$LayoutParams;->topMargin:I

    .line 61
    .line 62
    add-int/2addr v1, v6

    .line 63
    iget v2, v2, Landroid/widget/FrameLayout$LayoutParams;->bottomMargin:I

    .line 64
    .line 65
    add-int/2addr v1, v2

    .line 66
    if-ge v3, v4, :cond_1

    .line 67
    .line 68
    if-gez p1, :cond_0

    .line 69
    .line 70
    goto :goto_0

    .line 71
    :cond_0
    add-int v2, v3, p1

    .line 72
    .line 73
    if-le v2, v4, :cond_2

    .line 74
    .line 75
    sub-int p1, v4, v3

    .line 76
    .line 77
    goto :goto_1

    .line 78
    :cond_1
    :goto_0
    move p1, v0

    .line 79
    :cond_2
    :goto_1
    if-ge v5, v1, :cond_4

    .line 80
    .line 81
    if-gez p2, :cond_3

    .line 82
    .line 83
    goto :goto_2

    .line 84
    :cond_3
    add-int v0, v5, p2

    .line 85
    .line 86
    if-le v0, v1, :cond_5

    .line 87
    .line 88
    sub-int p2, v1, v5

    .line 89
    .line 90
    goto :goto_3

    .line 91
    :cond_4
    :goto_2
    move p2, v0

    .line 92
    :cond_5
    :goto_3
    invoke-virtual {p0}, Landroid/view/View;->getScrollX()I

    .line 93
    .line 94
    .line 95
    move-result v0

    .line 96
    if-ne p1, v0, :cond_6

    .line 97
    .line 98
    invoke-virtual {p0}, Landroid/view/View;->getScrollY()I

    .line 99
    .line 100
    .line 101
    move-result v0

    .line 102
    if-eq p2, v0, :cond_7

    .line 103
    .line 104
    :cond_6
    invoke-super {p0, p1, p2}, Landroid/view/View;->scrollTo(II)V

    .line 105
    .line 106
    .line 107
    :cond_7
    return-void
.end method

.method public setFillViewport(Z)V
    .locals 1

    .line 1
    iget-boolean v0, p0, Landroidx/core/widget/NestedScrollView;->q:Z

    .line 2
    .line 3
    if-eq p1, v0, :cond_0

    .line 4
    .line 5
    iput-boolean p1, p0, Landroidx/core/widget/NestedScrollView;->q:Z

    .line 6
    .line 7
    invoke-virtual {p0}, Landroidx/core/widget/NestedScrollView;->requestLayout()V

    .line 8
    .line 9
    .line 10
    :cond_0
    return-void
.end method

.method public setNestedScrollingEnabled(Z)V
    .locals 2

    .line 1
    iget-object p0, p0, Landroidx/core/widget/NestedScrollView;->C:Ld6/p;

    .line 2
    .line 3
    iget-boolean v0, p0, Ld6/p;->d:Z

    .line 4
    .line 5
    if-eqz v0, :cond_0

    .line 6
    .line 7
    iget-object v0, p0, Ld6/p;->c:Landroid/view/ViewGroup;

    .line 8
    .line 9
    sget-object v1, Ld6/r0;->a:Ljava/util/WeakHashMap;

    .line 10
    .line 11
    invoke-static {v0}, Ld6/k0;->m(Landroid/view/View;)V

    .line 12
    .line 13
    .line 14
    :cond_0
    iput-boolean p1, p0, Ld6/p;->d:Z

    .line 15
    .line 16
    return-void
.end method

.method public setOnScrollChangeListener(Lh6/f;)V
    .locals 0

    .line 1
    return-void
.end method

.method public setSmoothScrollingEnabled(Z)V
    .locals 0

    .line 1
    iput-boolean p1, p0, Landroidx/core/widget/NestedScrollView;->r:Z

    .line 2
    .line 3
    return-void
.end method

.method public final shouldDelayChildPressedState()Z
    .locals 0

    .line 1
    const/4 p0, 0x1

    .line 2
    return p0
.end method

.method public final startNestedScroll(I)Z
    .locals 1

    .line 1
    const/4 v0, 0x0

    .line 2
    iget-object p0, p0, Landroidx/core/widget/NestedScrollView;->C:Ld6/p;

    .line 3
    .line 4
    invoke-virtual {p0, p1, v0}, Ld6/p;->g(II)Z

    .line 5
    .line 6
    .line 7
    move-result p0

    .line 8
    return p0
.end method

.method public final stopNestedScroll()V
    .locals 1

    .line 1
    const/4 v0, 0x0

    .line 2
    invoke-virtual {p0, v0}, Landroidx/core/widget/NestedScrollView;->y(I)V

    .line 3
    .line 4
    .line 5
    return-void
.end method

.method public final t(IILandroid/view/MotionEvent;IIZ)I
    .locals 20

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move/from16 v1, p2

    .line 4
    .line 5
    move/from16 v2, p4

    .line 6
    .line 7
    move/from16 v9, p5

    .line 8
    .line 9
    const/4 v11, 0x1

    .line 10
    if-ne v9, v11, :cond_0

    .line 11
    .line 12
    const/4 v3, 0x2

    .line 13
    invoke-virtual {v0, v3, v9}, Landroidx/core/widget/NestedScrollView;->w(II)V

    .line 14
    .line 15
    .line 16
    :cond_0
    iget-object v8, v0, Landroidx/core/widget/NestedScrollView;->w:[I

    .line 17
    .line 18
    iget-object v3, v0, Landroidx/core/widget/NestedScrollView;->C:Ld6/p;

    .line 19
    .line 20
    const/4 v4, 0x0

    .line 21
    iget-object v7, v0, Landroidx/core/widget/NestedScrollView;->x:[I

    .line 22
    .line 23
    move/from16 v5, p1

    .line 24
    .line 25
    move v6, v9

    .line 26
    invoke-virtual/range {v3 .. v8}, Ld6/p;->c(III[I[I)Z

    .line 27
    .line 28
    .line 29
    move-result v3

    .line 30
    iget-object v12, v0, Landroidx/core/widget/NestedScrollView;->w:[I

    .line 31
    .line 32
    iget-object v10, v0, Landroidx/core/widget/NestedScrollView;->x:[I

    .line 33
    .line 34
    const/4 v13, 0x0

    .line 35
    if-eqz v3, :cond_1

    .line 36
    .line 37
    aget v3, v10, v11

    .line 38
    .line 39
    sub-int v3, p1, v3

    .line 40
    .line 41
    aget v4, v12, v11

    .line 42
    .line 43
    move v14, v3

    .line 44
    move v15, v4

    .line 45
    goto :goto_0

    .line 46
    :cond_1
    move/from16 v14, p1

    .line 47
    .line 48
    move v15, v13

    .line 49
    :goto_0
    invoke-virtual {v0}, Landroid/view/View;->getScrollY()I

    .line 50
    .line 51
    .line 52
    move-result v3

    .line 53
    invoke-virtual {v0}, Landroidx/core/widget/NestedScrollView;->getScrollRange()I

    .line 54
    .line 55
    .line 56
    move-result v4

    .line 57
    invoke-virtual {v0}, Landroid/view/View;->getOverScrollMode()I

    .line 58
    .line 59
    .line 60
    move-result v5

    .line 61
    if-eqz v5, :cond_2

    .line 62
    .line 63
    if-ne v5, v11, :cond_3

    .line 64
    .line 65
    invoke-virtual {v0}, Landroidx/core/widget/NestedScrollView;->getScrollRange()I

    .line 66
    .line 67
    .line 68
    move-result v5

    .line 69
    if-lez v5, :cond_3

    .line 70
    .line 71
    :cond_2
    if-nez p6, :cond_3

    .line 72
    .line 73
    move/from16 v16, v11

    .line 74
    .line 75
    goto :goto_1

    .line 76
    :cond_3
    move/from16 v16, v13

    .line 77
    .line 78
    :goto_1
    invoke-virtual {v0, v14, v13, v3, v4}, Landroidx/core/widget/NestedScrollView;->q(IIII)Z

    .line 79
    .line 80
    .line 81
    move-result v5

    .line 82
    if-eqz v5, :cond_4

    .line 83
    .line 84
    iget-object v5, v0, Landroidx/core/widget/NestedScrollView;->C:Ld6/p;

    .line 85
    .line 86
    invoke-virtual {v5, v9}, Ld6/p;->f(I)Z

    .line 87
    .line 88
    .line 89
    move-result v5

    .line 90
    if-nez v5, :cond_4

    .line 91
    .line 92
    move/from16 v17, v11

    .line 93
    .line 94
    goto :goto_2

    .line 95
    :cond_4
    move/from16 v17, v13

    .line 96
    .line 97
    :goto_2
    invoke-virtual {v0}, Landroid/view/View;->getScrollY()I

    .line 98
    .line 99
    .line 100
    move-result v5

    .line 101
    sub-int/2addr v5, v3

    .line 102
    if-eqz p3, :cond_5

    .line 103
    .line 104
    if-eqz v5, :cond_5

    .line 105
    .line 106
    invoke-direct {v0}, Landroidx/core/widget/NestedScrollView;->getScrollFeedbackProvider()Ld6/x;

    .line 107
    .line 108
    .line 109
    move-result-object v6

    .line 110
    invoke-virtual/range {p3 .. p3}, Landroid/view/MotionEvent;->getDeviceId()I

    .line 111
    .line 112
    .line 113
    move-result v7

    .line 114
    invoke-virtual/range {p3 .. p3}, Landroid/view/MotionEvent;->getSource()I

    .line 115
    .line 116
    .line 117
    move-result v8

    .line 118
    iget-object v6, v6, Ld6/x;->a:Ld6/w;

    .line 119
    .line 120
    invoke-interface {v6, v7, v8, v1, v5}, Ld6/w;->onScrollProgress(IIII)V

    .line 121
    .line 122
    .line 123
    :cond_5
    sub-int v7, v14, v5

    .line 124
    .line 125
    aput v13, v10, v11

    .line 126
    .line 127
    const/4 v6, 0x0

    .line 128
    move v8, v3

    .line 129
    iget-object v3, v0, Landroidx/core/widget/NestedScrollView;->C:Ld6/p;

    .line 130
    .line 131
    move/from16 v18, v4

    .line 132
    .line 133
    const/4 v4, 0x0

    .line 134
    move/from16 v19, v8

    .line 135
    .line 136
    iget-object v8, v0, Landroidx/core/widget/NestedScrollView;->w:[I

    .line 137
    .line 138
    move/from16 v13, v18

    .line 139
    .line 140
    invoke-virtual/range {v3 .. v10}, Ld6/p;->d(IIII[II[I)Z

    .line 141
    .line 142
    .line 143
    aget v3, v12, v11

    .line 144
    .line 145
    add-int/2addr v15, v3

    .line 146
    aget v3, v10, v11

    .line 147
    .line 148
    sub-int/2addr v14, v3

    .line 149
    add-int v3, v19, v14

    .line 150
    .line 151
    iget-object v4, v0, Landroidx/core/widget/NestedScrollView;->i:Landroid/widget/EdgeEffect;

    .line 152
    .line 153
    iget-object v5, v0, Landroidx/core/widget/NestedScrollView;->h:Landroid/widget/EdgeEffect;

    .line 154
    .line 155
    if-gez v3, :cond_8

    .line 156
    .line 157
    if-eqz v16, :cond_7

    .line 158
    .line 159
    neg-int v3, v14

    .line 160
    int-to-float v3, v3

    .line 161
    invoke-virtual {v0}, Landroid/view/View;->getHeight()I

    .line 162
    .line 163
    .line 164
    move-result v6

    .line 165
    int-to-float v6, v6

    .line 166
    div-float/2addr v3, v6

    .line 167
    int-to-float v2, v2

    .line 168
    invoke-virtual {v0}, Landroid/view/View;->getWidth()I

    .line 169
    .line 170
    .line 171
    move-result v6

    .line 172
    int-to-float v6, v6

    .line 173
    div-float/2addr v2, v6

    .line 174
    invoke-static {v5, v3, v2}, Llp/l0;->c(Landroid/widget/EdgeEffect;FF)F

    .line 175
    .line 176
    .line 177
    if-eqz p3, :cond_6

    .line 178
    .line 179
    invoke-direct {v0}, Landroidx/core/widget/NestedScrollView;->getScrollFeedbackProvider()Ld6/x;

    .line 180
    .line 181
    .line 182
    move-result-object v2

    .line 183
    invoke-virtual/range {p3 .. p3}, Landroid/view/MotionEvent;->getDeviceId()I

    .line 184
    .line 185
    .line 186
    move-result v3

    .line 187
    invoke-virtual/range {p3 .. p3}, Landroid/view/MotionEvent;->getSource()I

    .line 188
    .line 189
    .line 190
    move-result v6

    .line 191
    iget-object v2, v2, Ld6/x;->a:Ld6/w;

    .line 192
    .line 193
    invoke-interface {v2, v3, v6, v1, v11}, Ld6/w;->onScrollLimit(IIIZ)V

    .line 194
    .line 195
    .line 196
    :cond_6
    invoke-virtual {v4}, Landroid/widget/EdgeEffect;->isFinished()Z

    .line 197
    .line 198
    .line 199
    move-result v1

    .line 200
    if-nez v1, :cond_7

    .line 201
    .line 202
    invoke-virtual {v4}, Landroid/widget/EdgeEffect;->onRelease()V

    .line 203
    .line 204
    .line 205
    :cond_7
    const/4 v7, 0x0

    .line 206
    goto :goto_4

    .line 207
    :cond_8
    if-le v3, v13, :cond_7

    .line 208
    .line 209
    if-eqz v16, :cond_7

    .line 210
    .line 211
    int-to-float v3, v14

    .line 212
    invoke-virtual {v0}, Landroid/view/View;->getHeight()I

    .line 213
    .line 214
    .line 215
    move-result v6

    .line 216
    int-to-float v6, v6

    .line 217
    div-float/2addr v3, v6

    .line 218
    int-to-float v2, v2

    .line 219
    invoke-virtual {v0}, Landroid/view/View;->getWidth()I

    .line 220
    .line 221
    .line 222
    move-result v6

    .line 223
    int-to-float v6, v6

    .line 224
    div-float/2addr v2, v6

    .line 225
    const/high16 v6, 0x3f800000    # 1.0f

    .line 226
    .line 227
    sub-float/2addr v6, v2

    .line 228
    invoke-static {v4, v3, v6}, Llp/l0;->c(Landroid/widget/EdgeEffect;FF)F

    .line 229
    .line 230
    .line 231
    if-eqz p3, :cond_9

    .line 232
    .line 233
    invoke-direct {v0}, Landroidx/core/widget/NestedScrollView;->getScrollFeedbackProvider()Ld6/x;

    .line 234
    .line 235
    .line 236
    move-result-object v2

    .line 237
    invoke-virtual/range {p3 .. p3}, Landroid/view/MotionEvent;->getDeviceId()I

    .line 238
    .line 239
    .line 240
    move-result v3

    .line 241
    invoke-virtual/range {p3 .. p3}, Landroid/view/MotionEvent;->getSource()I

    .line 242
    .line 243
    .line 244
    move-result v6

    .line 245
    iget-object v2, v2, Ld6/x;->a:Ld6/w;

    .line 246
    .line 247
    const/4 v7, 0x0

    .line 248
    invoke-interface {v2, v3, v6, v1, v7}, Ld6/w;->onScrollLimit(IIIZ)V

    .line 249
    .line 250
    .line 251
    goto :goto_3

    .line 252
    :cond_9
    const/4 v7, 0x0

    .line 253
    :goto_3
    invoke-virtual {v5}, Landroid/widget/EdgeEffect;->isFinished()Z

    .line 254
    .line 255
    .line 256
    move-result v1

    .line 257
    if-nez v1, :cond_a

    .line 258
    .line 259
    invoke-virtual {v5}, Landroid/widget/EdgeEffect;->onRelease()V

    .line 260
    .line 261
    .line 262
    :cond_a
    :goto_4
    invoke-virtual {v5}, Landroid/widget/EdgeEffect;->isFinished()Z

    .line 263
    .line 264
    .line 265
    move-result v1

    .line 266
    if-eqz v1, :cond_c

    .line 267
    .line 268
    invoke-virtual {v4}, Landroid/widget/EdgeEffect;->isFinished()Z

    .line 269
    .line 270
    .line 271
    move-result v1

    .line 272
    if-nez v1, :cond_b

    .line 273
    .line 274
    goto :goto_5

    .line 275
    :cond_b
    move/from16 v13, v17

    .line 276
    .line 277
    goto :goto_6

    .line 278
    :cond_c
    :goto_5
    invoke-virtual {v0}, Landroid/view/View;->postInvalidateOnAnimation()V

    .line 279
    .line 280
    .line 281
    move v13, v7

    .line 282
    :goto_6
    if-eqz v13, :cond_d

    .line 283
    .line 284
    if-nez v9, :cond_d

    .line 285
    .line 286
    iget-object v1, v0, Landroidx/core/widget/NestedScrollView;->p:Landroid/view/VelocityTracker;

    .line 287
    .line 288
    if-eqz v1, :cond_d

    .line 289
    .line 290
    invoke-virtual {v1}, Landroid/view/VelocityTracker;->clear()V

    .line 291
    .line 292
    .line 293
    :cond_d
    if-ne v9, v11, :cond_e

    .line 294
    .line 295
    invoke-virtual {v0, v9}, Landroidx/core/widget/NestedScrollView;->y(I)V

    .line 296
    .line 297
    .line 298
    invoke-virtual {v5}, Landroid/widget/EdgeEffect;->onRelease()V

    .line 299
    .line 300
    .line 301
    invoke-virtual {v4}, Landroid/widget/EdgeEffect;->onRelease()V

    .line 302
    .line 303
    .line 304
    :cond_e
    return v15
.end method

.method public final u(Landroid/widget/EdgeEffect;I)Z
    .locals 9

    .line 1
    const/4 v0, 0x1

    .line 2
    if-lez p2, :cond_0

    .line 3
    .line 4
    return v0

    .line 5
    :cond_0
    invoke-static {p1}, Llp/l0;->b(Landroid/widget/EdgeEffect;)F

    .line 6
    .line 7
    .line 8
    move-result p1

    .line 9
    invoke-virtual {p0}, Landroid/view/View;->getHeight()I

    .line 10
    .line 11
    .line 12
    move-result v1

    .line 13
    int-to-float v1, v1

    .line 14
    mul-float/2addr p1, v1

    .line 15
    neg-int p2, p2

    .line 16
    invoke-static {p2}, Ljava/lang/Math;->abs(I)I

    .line 17
    .line 18
    .line 19
    move-result p2

    .line 20
    int-to-float p2, p2

    .line 21
    const v1, 0x3eb33333    # 0.35f

    .line 22
    .line 23
    .line 24
    mul-float/2addr p2, v1

    .line 25
    const v1, 0x3c75c28f    # 0.015f

    .line 26
    .line 27
    .line 28
    iget p0, p0, Landroidx/core/widget/NestedScrollView;->d:F

    .line 29
    .line 30
    mul-float/2addr p0, v1

    .line 31
    div-float/2addr p2, p0

    .line 32
    float-to-double v1, p2

    .line 33
    invoke-static {v1, v2}, Ljava/lang/Math;->log(D)D

    .line 34
    .line 35
    .line 36
    move-result-wide v1

    .line 37
    sget p2, Landroidx/core/widget/NestedScrollView;->F:F

    .line 38
    .line 39
    float-to-double v3, p2

    .line 40
    const-wide/high16 v5, 0x3ff0000000000000L    # 1.0

    .line 41
    .line 42
    sub-double v5, v3, v5

    .line 43
    .line 44
    float-to-double v7, p0

    .line 45
    div-double/2addr v3, v5

    .line 46
    mul-double/2addr v3, v1

    .line 47
    invoke-static {v3, v4}, Ljava/lang/Math;->exp(D)D

    .line 48
    .line 49
    .line 50
    move-result-wide v1

    .line 51
    mul-double/2addr v1, v7

    .line 52
    double-to-float p0, v1

    .line 53
    cmpg-float p0, p0, p1

    .line 54
    .line 55
    if-gez p0, :cond_1

    .line 56
    .line 57
    return v0

    .line 58
    :cond_1
    const/4 p0, 0x0

    .line 59
    return p0
.end method

.method public final v(IIZ)V
    .locals 9

    .line 1
    invoke-virtual {p0}, Landroid/view/ViewGroup;->getChildCount()I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    if-nez v0, :cond_0

    .line 6
    .line 7
    return-void

    .line 8
    :cond_0
    invoke-static {}, Landroid/view/animation/AnimationUtils;->currentAnimationTimeMillis()J

    .line 9
    .line 10
    .line 11
    move-result-wide v0

    .line 12
    iget-wide v2, p0, Landroidx/core/widget/NestedScrollView;->e:J

    .line 13
    .line 14
    sub-long/2addr v0, v2

    .line 15
    const-wide/16 v2, 0xfa

    .line 16
    .line 17
    cmp-long v0, v0, v2

    .line 18
    .line 19
    const/4 v1, 0x1

    .line 20
    if-lez v0, :cond_2

    .line 21
    .line 22
    const/4 p1, 0x0

    .line 23
    invoke-virtual {p0, p1}, Landroid/view/ViewGroup;->getChildAt(I)Landroid/view/View;

    .line 24
    .line 25
    .line 26
    move-result-object v0

    .line 27
    invoke-virtual {v0}, Landroid/view/View;->getLayoutParams()Landroid/view/ViewGroup$LayoutParams;

    .line 28
    .line 29
    .line 30
    move-result-object v2

    .line 31
    check-cast v2, Landroid/widget/FrameLayout$LayoutParams;

    .line 32
    .line 33
    invoke-virtual {v0}, Landroid/view/View;->getHeight()I

    .line 34
    .line 35
    .line 36
    move-result v0

    .line 37
    iget v3, v2, Landroid/widget/FrameLayout$LayoutParams;->topMargin:I

    .line 38
    .line 39
    add-int/2addr v0, v3

    .line 40
    iget v2, v2, Landroid/widget/FrameLayout$LayoutParams;->bottomMargin:I

    .line 41
    .line 42
    add-int/2addr v0, v2

    .line 43
    invoke-virtual {p0}, Landroid/view/View;->getHeight()I

    .line 44
    .line 45
    .line 46
    move-result v2

    .line 47
    invoke-virtual {p0}, Landroid/view/View;->getPaddingTop()I

    .line 48
    .line 49
    .line 50
    move-result v3

    .line 51
    sub-int/2addr v2, v3

    .line 52
    invoke-virtual {p0}, Landroid/view/View;->getPaddingBottom()I

    .line 53
    .line 54
    .line 55
    move-result v3

    .line 56
    sub-int/2addr v2, v3

    .line 57
    invoke-virtual {p0}, Landroid/view/View;->getScrollY()I

    .line 58
    .line 59
    .line 60
    move-result v5

    .line 61
    sub-int/2addr v0, v2

    .line 62
    invoke-static {p1, v0}, Ljava/lang/Math;->max(II)I

    .line 63
    .line 64
    .line 65
    move-result v0

    .line 66
    add-int/2addr p2, v5

    .line 67
    invoke-static {p2, v0}, Ljava/lang/Math;->min(II)I

    .line 68
    .line 69
    .line 70
    move-result p2

    .line 71
    invoke-static {p1, p2}, Ljava/lang/Math;->max(II)I

    .line 72
    .line 73
    .line 74
    move-result p1

    .line 75
    sub-int v7, p1, v5

    .line 76
    .line 77
    invoke-virtual {p0}, Landroid/view/View;->getScrollX()I

    .line 78
    .line 79
    .line 80
    move-result v4

    .line 81
    const/4 v6, 0x0

    .line 82
    iget-object v3, p0, Landroidx/core/widget/NestedScrollView;->g:Landroid/widget/OverScroller;

    .line 83
    .line 84
    const/16 v8, 0xfa

    .line 85
    .line 86
    invoke-virtual/range {v3 .. v8}, Landroid/widget/OverScroller;->startScroll(IIIII)V

    .line 87
    .line 88
    .line 89
    if-eqz p3, :cond_1

    .line 90
    .line 91
    const/4 p1, 0x2

    .line 92
    invoke-virtual {p0, p1, v1}, Landroidx/core/widget/NestedScrollView;->w(II)V

    .line 93
    .line 94
    .line 95
    goto :goto_0

    .line 96
    :cond_1
    invoke-virtual {p0, v1}, Landroidx/core/widget/NestedScrollView;->y(I)V

    .line 97
    .line 98
    .line 99
    :goto_0
    invoke-virtual {p0}, Landroid/view/View;->getScrollY()I

    .line 100
    .line 101
    .line 102
    move-result p1

    .line 103
    iput p1, p0, Landroidx/core/widget/NestedScrollView;->z:I

    .line 104
    .line 105
    invoke-virtual {p0}, Landroid/view/View;->postInvalidateOnAnimation()V

    .line 106
    .line 107
    .line 108
    goto :goto_1

    .line 109
    :cond_2
    iget-object p3, p0, Landroidx/core/widget/NestedScrollView;->g:Landroid/widget/OverScroller;

    .line 110
    .line 111
    invoke-virtual {p3}, Landroid/widget/OverScroller;->isFinished()Z

    .line 112
    .line 113
    .line 114
    move-result p3

    .line 115
    if-nez p3, :cond_3

    .line 116
    .line 117
    iget-object p3, p0, Landroidx/core/widget/NestedScrollView;->g:Landroid/widget/OverScroller;

    .line 118
    .line 119
    invoke-virtual {p3}, Landroid/widget/OverScroller;->abortAnimation()V

    .line 120
    .line 121
    .line 122
    invoke-virtual {p0, v1}, Landroidx/core/widget/NestedScrollView;->y(I)V

    .line 123
    .line 124
    .line 125
    :cond_3
    invoke-virtual {p0, p1, p2}, Landroid/view/View;->scrollBy(II)V

    .line 126
    .line 127
    .line 128
    :goto_1
    invoke-static {}, Landroid/view/animation/AnimationUtils;->currentAnimationTimeMillis()J

    .line 129
    .line 130
    .line 131
    move-result-wide p1

    .line 132
    iput-wide p1, p0, Landroidx/core/widget/NestedScrollView;->e:J

    .line 133
    .line 134
    return-void
.end method

.method public final w(II)V
    .locals 0

    .line 1
    const/4 p1, 0x2

    .line 2
    iget-object p0, p0, Landroidx/core/widget/NestedScrollView;->C:Ld6/p;

    .line 3
    .line 4
    invoke-virtual {p0, p1, p2}, Ld6/p;->g(II)Z

    .line 5
    .line 6
    .line 7
    return-void
.end method

.method public final x(Landroid/view/MotionEvent;)Z
    .locals 5

    .line 1
    iget-object v0, p0, Landroidx/core/widget/NestedScrollView;->h:Landroid/widget/EdgeEffect;

    .line 2
    .line 3
    invoke-static {v0}, Llp/l0;->b(Landroid/widget/EdgeEffect;)F

    .line 4
    .line 5
    .line 6
    move-result v1

    .line 7
    const/4 v2, 0x0

    .line 8
    cmpl-float v1, v1, v2

    .line 9
    .line 10
    const/4 v3, 0x1

    .line 11
    if-eqz v1, :cond_0

    .line 12
    .line 13
    invoke-virtual {p1}, Landroid/view/MotionEvent;->getX()F

    .line 14
    .line 15
    .line 16
    move-result v1

    .line 17
    invoke-virtual {p0}, Landroid/view/View;->getWidth()I

    .line 18
    .line 19
    .line 20
    move-result v4

    .line 21
    int-to-float v4, v4

    .line 22
    div-float/2addr v1, v4

    .line 23
    invoke-static {v0, v2, v1}, Llp/l0;->c(Landroid/widget/EdgeEffect;FF)F

    .line 24
    .line 25
    .line 26
    move v0, v3

    .line 27
    goto :goto_0

    .line 28
    :cond_0
    const/4 v0, 0x0

    .line 29
    :goto_0
    iget-object v1, p0, Landroidx/core/widget/NestedScrollView;->i:Landroid/widget/EdgeEffect;

    .line 30
    .line 31
    invoke-static {v1}, Llp/l0;->b(Landroid/widget/EdgeEffect;)F

    .line 32
    .line 33
    .line 34
    move-result v4

    .line 35
    cmpl-float v4, v4, v2

    .line 36
    .line 37
    if-eqz v4, :cond_1

    .line 38
    .line 39
    invoke-virtual {p1}, Landroid/view/MotionEvent;->getX()F

    .line 40
    .line 41
    .line 42
    move-result p1

    .line 43
    invoke-virtual {p0}, Landroid/view/View;->getWidth()I

    .line 44
    .line 45
    .line 46
    move-result p0

    .line 47
    int-to-float p0, p0

    .line 48
    div-float/2addr p1, p0

    .line 49
    const/high16 p0, 0x3f800000    # 1.0f

    .line 50
    .line 51
    sub-float/2addr p0, p1

    .line 52
    invoke-static {v1, v2, p0}, Llp/l0;->c(Landroid/widget/EdgeEffect;FF)F

    .line 53
    .line 54
    .line 55
    return v3

    .line 56
    :cond_1
    return v0
.end method

.method public final y(I)V
    .locals 0

    .line 1
    iget-object p0, p0, Landroidx/core/widget/NestedScrollView;->C:Ld6/p;

    .line 2
    .line 3
    invoke-virtual {p0, p1}, Ld6/p;->h(I)V

    .line 4
    .line 5
    .line 6
    return-void
.end method
