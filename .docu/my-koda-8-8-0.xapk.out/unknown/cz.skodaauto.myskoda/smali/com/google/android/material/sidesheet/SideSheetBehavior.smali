.class public Lcom/google/android/material/sidesheet/SideSheetBehavior;
.super Ll5/a;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/Signature;
    value = {
        "<V:",
        "Landroid/view/View;",
        ">",
        "Ll5/a;"
    }
.end annotation


# instance fields
.field public a:Llp/df;

.field public final b:Lwq/i;

.field public final c:Landroid/content/res/ColorStateList;

.field public final d:Lwq/m;

.field public final e:Lh6/i;

.field public final f:F

.field public final g:Z

.field public h:I

.field public i:Lk6/f;

.field public j:Z

.field public final k:F

.field public l:I

.field public m:I

.field public n:I

.field public o:I

.field public p:Ljava/lang/ref/WeakReference;

.field public q:Ljava/lang/ref/WeakReference;

.field public final r:I

.field public s:Landroid/view/VelocityTracker;

.field public t:I

.field public final u:Ljava/util/LinkedHashSet;

.field public final v:Liq/c;


# direct methods
.method public constructor <init>()V
    .locals 2

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    new-instance v0, Lh6/i;

    invoke-direct {v0, p0}, Lh6/i;-><init>(Lcom/google/android/material/sidesheet/SideSheetBehavior;)V

    iput-object v0, p0, Lcom/google/android/material/sidesheet/SideSheetBehavior;->e:Lh6/i;

    const/4 v0, 0x1

    .line 3
    iput-boolean v0, p0, Lcom/google/android/material/sidesheet/SideSheetBehavior;->g:Z

    const/4 v0, 0x5

    .line 4
    iput v0, p0, Lcom/google/android/material/sidesheet/SideSheetBehavior;->h:I

    const v0, 0x3dcccccd    # 0.1f

    .line 5
    iput v0, p0, Lcom/google/android/material/sidesheet/SideSheetBehavior;->k:F

    const/4 v0, -0x1

    .line 6
    iput v0, p0, Lcom/google/android/material/sidesheet/SideSheetBehavior;->r:I

    .line 7
    new-instance v0, Ljava/util/LinkedHashSet;

    invoke-direct {v0}, Ljava/util/LinkedHashSet;-><init>()V

    iput-object v0, p0, Lcom/google/android/material/sidesheet/SideSheetBehavior;->u:Ljava/util/LinkedHashSet;

    .line 8
    new-instance v0, Liq/c;

    const/4 v1, 0x1

    invoke-direct {v0, p0, v1}, Liq/c;-><init>(Ll5/a;I)V

    iput-object v0, p0, Lcom/google/android/material/sidesheet/SideSheetBehavior;->v:Liq/c;

    return-void
.end method

.method public constructor <init>(Landroid/content/Context;Landroid/util/AttributeSet;)V
    .locals 6

    .line 9
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 10
    new-instance v0, Lh6/i;

    invoke-direct {v0, p0}, Lh6/i;-><init>(Lcom/google/android/material/sidesheet/SideSheetBehavior;)V

    iput-object v0, p0, Lcom/google/android/material/sidesheet/SideSheetBehavior;->e:Lh6/i;

    const/4 v0, 0x1

    .line 11
    iput-boolean v0, p0, Lcom/google/android/material/sidesheet/SideSheetBehavior;->g:Z

    const/4 v1, 0x5

    .line 12
    iput v1, p0, Lcom/google/android/material/sidesheet/SideSheetBehavior;->h:I

    const v2, 0x3dcccccd    # 0.1f

    .line 13
    iput v2, p0, Lcom/google/android/material/sidesheet/SideSheetBehavior;->k:F

    const/4 v2, -0x1

    .line 14
    iput v2, p0, Lcom/google/android/material/sidesheet/SideSheetBehavior;->r:I

    .line 15
    new-instance v3, Ljava/util/LinkedHashSet;

    invoke-direct {v3}, Ljava/util/LinkedHashSet;-><init>()V

    iput-object v3, p0, Lcom/google/android/material/sidesheet/SideSheetBehavior;->u:Ljava/util/LinkedHashSet;

    .line 16
    new-instance v3, Liq/c;

    const/4 v4, 0x1

    invoke-direct {v3, p0, v4}, Liq/c;-><init>(Ll5/a;I)V

    iput-object v3, p0, Lcom/google/android/material/sidesheet/SideSheetBehavior;->v:Liq/c;

    .line 17
    sget-object v3, Ldq/a;->A:[I

    invoke-virtual {p1, p2, v3}, Landroid/content/Context;->obtainStyledAttributes(Landroid/util/AttributeSet;[I)Landroid/content/res/TypedArray;

    move-result-object v3

    const/4 v4, 0x3

    .line 18
    invoke-virtual {v3, v4}, Landroid/content/res/TypedArray;->hasValue(I)Z

    move-result v5

    if-eqz v5, :cond_0

    .line 19
    invoke-static {p1, v3, v4}, Llp/x9;->b(Landroid/content/Context;Landroid/content/res/TypedArray;I)Landroid/content/res/ColorStateList;

    move-result-object v4

    iput-object v4, p0, Lcom/google/android/material/sidesheet/SideSheetBehavior;->c:Landroid/content/res/ColorStateList;

    :cond_0
    const/4 v4, 0x6

    .line 20
    invoke-virtual {v3, v4}, Landroid/content/res/TypedArray;->hasValue(I)Z

    move-result v4

    if-eqz v4, :cond_1

    const/4 v4, 0x0

    const v5, 0x7f1304d0

    .line 21
    invoke-static {p1, p2, v4, v5}, Lwq/m;->b(Landroid/content/Context;Landroid/util/AttributeSet;II)Lwq/l;

    move-result-object p2

    invoke-virtual {p2}, Lwq/l;->a()Lwq/m;

    move-result-object p2

    iput-object p2, p0, Lcom/google/android/material/sidesheet/SideSheetBehavior;->d:Lwq/m;

    .line 22
    :cond_1
    invoke-virtual {v3, v1}, Landroid/content/res/TypedArray;->hasValue(I)Z

    move-result p2

    if-eqz p2, :cond_3

    .line 23
    invoke-virtual {v3, v1, v2}, Landroid/content/res/TypedArray;->getResourceId(II)I

    move-result p2

    .line 24
    iput p2, p0, Lcom/google/android/material/sidesheet/SideSheetBehavior;->r:I

    .line 25
    iget-object v1, p0, Lcom/google/android/material/sidesheet/SideSheetBehavior;->q:Ljava/lang/ref/WeakReference;

    if-eqz v1, :cond_2

    .line 26
    invoke-virtual {v1}, Ljava/lang/ref/Reference;->clear()V

    :cond_2
    const/4 v1, 0x0

    .line 27
    iput-object v1, p0, Lcom/google/android/material/sidesheet/SideSheetBehavior;->q:Ljava/lang/ref/WeakReference;

    .line 28
    iget-object v1, p0, Lcom/google/android/material/sidesheet/SideSheetBehavior;->p:Ljava/lang/ref/WeakReference;

    if-eqz v1, :cond_3

    .line 29
    invoke-virtual {v1}, Ljava/lang/ref/Reference;->get()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Landroid/view/View;

    if-eq p2, v2, :cond_3

    .line 30
    invoke-virtual {v1}, Landroid/view/View;->isLaidOut()Z

    move-result p2

    if-eqz p2, :cond_3

    .line 31
    invoke-virtual {v1}, Landroid/view/View;->requestLayout()V

    .line 32
    :cond_3
    iget-object p2, p0, Lcom/google/android/material/sidesheet/SideSheetBehavior;->d:Lwq/m;

    if-nez p2, :cond_4

    goto :goto_0

    .line 33
    :cond_4
    new-instance v1, Lwq/i;

    invoke-direct {v1, p2}, Lwq/i;-><init>(Lwq/m;)V

    iput-object v1, p0, Lcom/google/android/material/sidesheet/SideSheetBehavior;->b:Lwq/i;

    .line 34
    invoke-virtual {v1, p1}, Lwq/i;->j(Landroid/content/Context;)V

    .line 35
    iget-object p2, p0, Lcom/google/android/material/sidesheet/SideSheetBehavior;->c:Landroid/content/res/ColorStateList;

    if-eqz p2, :cond_5

    .line 36
    iget-object v1, p0, Lcom/google/android/material/sidesheet/SideSheetBehavior;->b:Lwq/i;

    invoke-virtual {v1, p2}, Lwq/i;->m(Landroid/content/res/ColorStateList;)V

    goto :goto_0

    .line 37
    :cond_5
    new-instance p2, Landroid/util/TypedValue;

    invoke-direct {p2}, Landroid/util/TypedValue;-><init>()V

    .line 38
    invoke-virtual {p1}, Landroid/content/Context;->getTheme()Landroid/content/res/Resources$Theme;

    move-result-object v1

    const v2, 0x1010031

    invoke-virtual {v1, v2, p2, v0}, Landroid/content/res/Resources$Theme;->resolveAttribute(ILandroid/util/TypedValue;Z)Z

    .line 39
    iget-object v1, p0, Lcom/google/android/material/sidesheet/SideSheetBehavior;->b:Lwq/i;

    iget p2, p2, Landroid/util/TypedValue;->data:I

    invoke-virtual {v1, p2}, Lwq/i;->setTint(I)V

    :goto_0
    const/4 p2, 0x2

    const/high16 v1, -0x40800000    # -1.0f

    .line 40
    invoke-virtual {v3, p2, v1}, Landroid/content/res/TypedArray;->getDimension(IF)F

    move-result p2

    iput p2, p0, Lcom/google/android/material/sidesheet/SideSheetBehavior;->f:F

    const/4 p2, 0x4

    .line 41
    invoke-virtual {v3, p2, v0}, Landroid/content/res/TypedArray;->getBoolean(IZ)Z

    move-result p2

    .line 42
    iput-boolean p2, p0, Lcom/google/android/material/sidesheet/SideSheetBehavior;->g:Z

    .line 43
    invoke-virtual {v3}, Landroid/content/res/TypedArray;->recycle()V

    .line 44
    invoke-static {p1}, Landroid/view/ViewConfiguration;->get(Landroid/content/Context;)Landroid/view/ViewConfiguration;

    move-result-object p0

    .line 45
    invoke-virtual {p0}, Landroid/view/ViewConfiguration;->getScaledMaximumFlingVelocity()I

    return-void
.end method


# virtual methods
.method public final c(Ll5/c;)V
    .locals 0

    .line 1
    const/4 p1, 0x0

    .line 2
    iput-object p1, p0, Lcom/google/android/material/sidesheet/SideSheetBehavior;->p:Ljava/lang/ref/WeakReference;

    .line 3
    .line 4
    iput-object p1, p0, Lcom/google/android/material/sidesheet/SideSheetBehavior;->i:Lk6/f;

    .line 5
    .line 6
    return-void
.end method

.method public final e()V
    .locals 1

    .line 1
    const/4 v0, 0x0

    .line 2
    iput-object v0, p0, Lcom/google/android/material/sidesheet/SideSheetBehavior;->p:Ljava/lang/ref/WeakReference;

    .line 3
    .line 4
    iput-object v0, p0, Lcom/google/android/material/sidesheet/SideSheetBehavior;->i:Lk6/f;

    .line 5
    .line 6
    return-void
.end method

.method public final f(Landroidx/coordinatorlayout/widget/CoordinatorLayout;Landroid/view/View;Landroid/view/MotionEvent;)Z
    .locals 2

    .line 1
    invoke-virtual {p2}, Landroid/view/View;->isShown()Z

    .line 2
    .line 3
    .line 4
    move-result p1

    .line 5
    const/4 v0, 0x1

    .line 6
    const/4 v1, 0x0

    .line 7
    if-nez p1, :cond_0

    .line 8
    .line 9
    sget-object p1, Ld6/r0;->a:Ljava/util/WeakHashMap;

    .line 10
    .line 11
    invoke-static {p2}, Ld6/n0;->a(Landroid/view/View;)Ljava/lang/CharSequence;

    .line 12
    .line 13
    .line 14
    move-result-object p1

    .line 15
    check-cast p1, Ljava/lang/CharSequence;

    .line 16
    .line 17
    if-eqz p1, :cond_7

    .line 18
    .line 19
    :cond_0
    iget-boolean p1, p0, Lcom/google/android/material/sidesheet/SideSheetBehavior;->g:Z

    .line 20
    .line 21
    if-eqz p1, :cond_7

    .line 22
    .line 23
    invoke-virtual {p3}, Landroid/view/MotionEvent;->getActionMasked()I

    .line 24
    .line 25
    .line 26
    move-result p1

    .line 27
    if-nez p1, :cond_1

    .line 28
    .line 29
    iget-object p2, p0, Lcom/google/android/material/sidesheet/SideSheetBehavior;->s:Landroid/view/VelocityTracker;

    .line 30
    .line 31
    if-eqz p2, :cond_1

    .line 32
    .line 33
    invoke-virtual {p2}, Landroid/view/VelocityTracker;->recycle()V

    .line 34
    .line 35
    .line 36
    const/4 p2, 0x0

    .line 37
    iput-object p2, p0, Lcom/google/android/material/sidesheet/SideSheetBehavior;->s:Landroid/view/VelocityTracker;

    .line 38
    .line 39
    :cond_1
    iget-object p2, p0, Lcom/google/android/material/sidesheet/SideSheetBehavior;->s:Landroid/view/VelocityTracker;

    .line 40
    .line 41
    if-nez p2, :cond_2

    .line 42
    .line 43
    invoke-static {}, Landroid/view/VelocityTracker;->obtain()Landroid/view/VelocityTracker;

    .line 44
    .line 45
    .line 46
    move-result-object p2

    .line 47
    iput-object p2, p0, Lcom/google/android/material/sidesheet/SideSheetBehavior;->s:Landroid/view/VelocityTracker;

    .line 48
    .line 49
    :cond_2
    iget-object p2, p0, Lcom/google/android/material/sidesheet/SideSheetBehavior;->s:Landroid/view/VelocityTracker;

    .line 50
    .line 51
    invoke-virtual {p2, p3}, Landroid/view/VelocityTracker;->addMovement(Landroid/view/MotionEvent;)V

    .line 52
    .line 53
    .line 54
    if-eqz p1, :cond_4

    .line 55
    .line 56
    if-eq p1, v0, :cond_3

    .line 57
    .line 58
    const/4 p2, 0x3

    .line 59
    if-eq p1, p2, :cond_3

    .line 60
    .line 61
    goto :goto_0

    .line 62
    :cond_3
    iget-boolean p1, p0, Lcom/google/android/material/sidesheet/SideSheetBehavior;->j:Z

    .line 63
    .line 64
    if-eqz p1, :cond_5

    .line 65
    .line 66
    iput-boolean v1, p0, Lcom/google/android/material/sidesheet/SideSheetBehavior;->j:Z

    .line 67
    .line 68
    return v1

    .line 69
    :cond_4
    invoke-virtual {p3}, Landroid/view/MotionEvent;->getX()F

    .line 70
    .line 71
    .line 72
    move-result p1

    .line 73
    float-to-int p1, p1

    .line 74
    iput p1, p0, Lcom/google/android/material/sidesheet/SideSheetBehavior;->t:I

    .line 75
    .line 76
    :cond_5
    :goto_0
    iget-boolean p1, p0, Lcom/google/android/material/sidesheet/SideSheetBehavior;->j:Z

    .line 77
    .line 78
    if-nez p1, :cond_6

    .line 79
    .line 80
    iget-object p0, p0, Lcom/google/android/material/sidesheet/SideSheetBehavior;->i:Lk6/f;

    .line 81
    .line 82
    if-eqz p0, :cond_6

    .line 83
    .line 84
    invoke-virtual {p0, p3}, Lk6/f;->p(Landroid/view/MotionEvent;)Z

    .line 85
    .line 86
    .line 87
    move-result p0

    .line 88
    if-eqz p0, :cond_6

    .line 89
    .line 90
    return v0

    .line 91
    :cond_6
    return v1

    .line 92
    :cond_7
    iput-boolean v0, p0, Lcom/google/android/material/sidesheet/SideSheetBehavior;->j:Z

    .line 93
    .line 94
    return v1
.end method

.method public final g(Landroidx/coordinatorlayout/widget/CoordinatorLayout;Landroid/view/View;I)Z
    .locals 10

    .line 1
    invoke-virtual {p1}, Landroid/view/View;->getFitsSystemWindows()Z

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    const/4 v1, 0x1

    .line 6
    if-eqz v0, :cond_0

    .line 7
    .line 8
    invoke-virtual {p2}, Landroid/view/View;->getFitsSystemWindows()Z

    .line 9
    .line 10
    .line 11
    move-result v0

    .line 12
    if-nez v0, :cond_0

    .line 13
    .line 14
    invoke-virtual {p2, v1}, Landroid/view/View;->setFitsSystemWindows(Z)V

    .line 15
    .line 16
    .line 17
    :cond_0
    iget-object v0, p0, Lcom/google/android/material/sidesheet/SideSheetBehavior;->p:Ljava/lang/ref/WeakReference;

    .line 18
    .line 19
    iget-object v2, p0, Lcom/google/android/material/sidesheet/SideSheetBehavior;->b:Lwq/i;

    .line 20
    .line 21
    const/4 v3, 0x5

    .line 22
    const/4 v4, 0x0

    .line 23
    const/4 v5, 0x0

    .line 24
    if-nez v0, :cond_7

    .line 25
    .line 26
    new-instance v0, Ljava/lang/ref/WeakReference;

    .line 27
    .line 28
    invoke-direct {v0, p2}, Ljava/lang/ref/WeakReference;-><init>(Ljava/lang/Object;)V

    .line 29
    .line 30
    .line 31
    iput-object v0, p0, Lcom/google/android/material/sidesheet/SideSheetBehavior;->p:Ljava/lang/ref/WeakReference;

    .line 32
    .line 33
    new-instance v0, Landroid/view/animation/PathInterpolator;

    .line 34
    .line 35
    const v6, 0x3dcccccd    # 0.1f

    .line 36
    .line 37
    .line 38
    const/high16 v7, 0x3f800000    # 1.0f

    .line 39
    .line 40
    invoke-direct {v0, v6, v6, v4, v7}, Landroid/view/animation/PathInterpolator;-><init>(FFFF)V

    .line 41
    .line 42
    .line 43
    invoke-virtual {p2}, Landroid/view/View;->getContext()Landroid/content/Context;

    .line 44
    .line 45
    .line 46
    move-result-object v0

    .line 47
    const v6, 0x7f0403e5

    .line 48
    .line 49
    .line 50
    const/16 v7, 0x12c

    .line 51
    .line 52
    invoke-static {v0, v6, v7}, Lkp/o8;->d(Landroid/content/Context;II)I

    .line 53
    .line 54
    .line 55
    const v6, 0x7f0403ea

    .line 56
    .line 57
    .line 58
    const/16 v7, 0x96

    .line 59
    .line 60
    invoke-static {v0, v6, v7}, Lkp/o8;->d(Landroid/content/Context;II)I

    .line 61
    .line 62
    .line 63
    const v6, 0x7f0403e9

    .line 64
    .line 65
    .line 66
    const/16 v7, 0x64

    .line 67
    .line 68
    invoke-static {v0, v6, v7}, Lkp/o8;->d(Landroid/content/Context;II)I

    .line 69
    .line 70
    .line 71
    invoke-virtual {p2}, Landroid/view/View;->getResources()Landroid/content/res/Resources;

    .line 72
    .line 73
    .line 74
    move-result-object v0

    .line 75
    const v6, 0x7f0700de

    .line 76
    .line 77
    .line 78
    invoke-virtual {v0, v6}, Landroid/content/res/Resources;->getDimension(I)F

    .line 79
    .line 80
    .line 81
    const v6, 0x7f0700dd

    .line 82
    .line 83
    .line 84
    invoke-virtual {v0, v6}, Landroid/content/res/Resources;->getDimension(I)F

    .line 85
    .line 86
    .line 87
    const v6, 0x7f0700df

    .line 88
    .line 89
    .line 90
    invoke-virtual {v0, v6}, Landroid/content/res/Resources;->getDimension(I)F

    .line 91
    .line 92
    .line 93
    if-eqz v2, :cond_2

    .line 94
    .line 95
    invoke-virtual {p2, v2}, Landroid/view/View;->setBackground(Landroid/graphics/drawable/Drawable;)V

    .line 96
    .line 97
    .line 98
    const/high16 v0, -0x40800000    # -1.0f

    .line 99
    .line 100
    iget v6, p0, Lcom/google/android/material/sidesheet/SideSheetBehavior;->f:F

    .line 101
    .line 102
    cmpl-float v0, v6, v0

    .line 103
    .line 104
    if-nez v0, :cond_1

    .line 105
    .line 106
    invoke-virtual {p2}, Landroid/view/View;->getElevation()F

    .line 107
    .line 108
    .line 109
    move-result v6

    .line 110
    :cond_1
    invoke-virtual {v2, v6}, Lwq/i;->l(F)V

    .line 111
    .line 112
    .line 113
    goto :goto_0

    .line 114
    :cond_2
    iget-object v0, p0, Lcom/google/android/material/sidesheet/SideSheetBehavior;->c:Landroid/content/res/ColorStateList;

    .line 115
    .line 116
    if-eqz v0, :cond_3

    .line 117
    .line 118
    sget-object v6, Ld6/r0;->a:Ljava/util/WeakHashMap;

    .line 119
    .line 120
    invoke-static {p2, v0}, Ld6/k0;->g(Landroid/view/View;Landroid/content/res/ColorStateList;)V

    .line 121
    .line 122
    .line 123
    :cond_3
    :goto_0
    iget v0, p0, Lcom/google/android/material/sidesheet/SideSheetBehavior;->h:I

    .line 124
    .line 125
    if-ne v0, v3, :cond_4

    .line 126
    .line 127
    const/4 v0, 0x4

    .line 128
    goto :goto_1

    .line 129
    :cond_4
    move v0, v5

    .line 130
    :goto_1
    invoke-virtual {p2}, Landroid/view/View;->getVisibility()I

    .line 131
    .line 132
    .line 133
    move-result v6

    .line 134
    if-eq v6, v0, :cond_5

    .line 135
    .line 136
    invoke-virtual {p2, v0}, Landroid/view/View;->setVisibility(I)V

    .line 137
    .line 138
    .line 139
    :cond_5
    invoke-virtual {p0}, Lcom/google/android/material/sidesheet/SideSheetBehavior;->u()V

    .line 140
    .line 141
    .line 142
    invoke-virtual {p2}, Landroid/view/View;->getImportantForAccessibility()I

    .line 143
    .line 144
    .line 145
    move-result v0

    .line 146
    if-nez v0, :cond_6

    .line 147
    .line 148
    invoke-virtual {p2, v1}, Landroid/view/View;->setImportantForAccessibility(I)V

    .line 149
    .line 150
    .line 151
    :cond_6
    sget-object v0, Ld6/r0;->a:Ljava/util/WeakHashMap;

    .line 152
    .line 153
    invoke-static {p2}, Ld6/n0;->a(Landroid/view/View;)Ljava/lang/CharSequence;

    .line 154
    .line 155
    .line 156
    move-result-object v0

    .line 157
    check-cast v0, Ljava/lang/CharSequence;

    .line 158
    .line 159
    if-nez v0, :cond_7

    .line 160
    .line 161
    invoke-virtual {p2}, Landroid/view/View;->getResources()Landroid/content/res/Resources;

    .line 162
    .line 163
    .line 164
    move-result-object v0

    .line 165
    const v6, 0x7f121224

    .line 166
    .line 167
    .line 168
    invoke-virtual {v0, v6}, Landroid/content/res/Resources;->getString(I)Ljava/lang/String;

    .line 169
    .line 170
    .line 171
    move-result-object v0

    .line 172
    invoke-static {p2, v0}, Ld6/r0;->j(Landroid/view/View;Ljava/lang/CharSequence;)V

    .line 173
    .line 174
    .line 175
    :cond_7
    invoke-virtual {p2}, Landroid/view/View;->getLayoutParams()Landroid/view/ViewGroup$LayoutParams;

    .line 176
    .line 177
    .line 178
    move-result-object v0

    .line 179
    check-cast v0, Ll5/c;

    .line 180
    .line 181
    iget v0, v0, Ll5/c;->c:I

    .line 182
    .line 183
    invoke-static {v0, p3}, Landroid/view/Gravity;->getAbsoluteGravity(II)I

    .line 184
    .line 185
    .line 186
    move-result v0

    .line 187
    const/4 v6, 0x3

    .line 188
    if-ne v0, v6, :cond_8

    .line 189
    .line 190
    move v0, v1

    .line 191
    goto :goto_2

    .line 192
    :cond_8
    move v0, v5

    .line 193
    :goto_2
    iget-object v7, p0, Lcom/google/android/material/sidesheet/SideSheetBehavior;->a:Llp/df;

    .line 194
    .line 195
    if-eqz v7, :cond_9

    .line 196
    .line 197
    invoke-virtual {v7}, Llp/df;->k()I

    .line 198
    .line 199
    .line 200
    move-result v7

    .line 201
    if-eq v7, v0, :cond_f

    .line 202
    .line 203
    :cond_9
    const/4 v7, 0x0

    .line 204
    iget-object v8, p0, Lcom/google/android/material/sidesheet/SideSheetBehavior;->d:Lwq/m;

    .line 205
    .line 206
    if-nez v0, :cond_c

    .line 207
    .line 208
    new-instance v0, Lxq/a;

    .line 209
    .line 210
    invoke-direct {v0, p0, v1}, Lxq/a;-><init>(Lcom/google/android/material/sidesheet/SideSheetBehavior;I)V

    .line 211
    .line 212
    .line 213
    iput-object v0, p0, Lcom/google/android/material/sidesheet/SideSheetBehavior;->a:Llp/df;

    .line 214
    .line 215
    if-eqz v8, :cond_f

    .line 216
    .line 217
    iget-object v0, p0, Lcom/google/android/material/sidesheet/SideSheetBehavior;->p:Ljava/lang/ref/WeakReference;

    .line 218
    .line 219
    if-eqz v0, :cond_a

    .line 220
    .line 221
    invoke-virtual {v0}, Ljava/lang/ref/Reference;->get()Ljava/lang/Object;

    .line 222
    .line 223
    .line 224
    move-result-object v0

    .line 225
    check-cast v0, Landroid/view/View;

    .line 226
    .line 227
    if-eqz v0, :cond_a

    .line 228
    .line 229
    invoke-virtual {v0}, Landroid/view/View;->getLayoutParams()Landroid/view/ViewGroup$LayoutParams;

    .line 230
    .line 231
    .line 232
    move-result-object v9

    .line 233
    instance-of v9, v9, Ll5/c;

    .line 234
    .line 235
    if-eqz v9, :cond_a

    .line 236
    .line 237
    invoke-virtual {v0}, Landroid/view/View;->getLayoutParams()Landroid/view/ViewGroup$LayoutParams;

    .line 238
    .line 239
    .line 240
    move-result-object v0

    .line 241
    move-object v7, v0

    .line 242
    check-cast v7, Ll5/c;

    .line 243
    .line 244
    :cond_a
    if-eqz v7, :cond_b

    .line 245
    .line 246
    iget v0, v7, Landroid/view/ViewGroup$MarginLayoutParams;->rightMargin:I

    .line 247
    .line 248
    if-lez v0, :cond_b

    .line 249
    .line 250
    goto :goto_3

    .line 251
    :cond_b
    invoke-virtual {v8}, Lwq/m;->f()Lwq/l;

    .line 252
    .line 253
    .line 254
    move-result-object v0

    .line 255
    new-instance v7, Lwq/a;

    .line 256
    .line 257
    invoke-direct {v7, v4}, Lwq/a;-><init>(F)V

    .line 258
    .line 259
    .line 260
    iput-object v7, v0, Lwq/l;->f:Lwq/d;

    .line 261
    .line 262
    new-instance v7, Lwq/a;

    .line 263
    .line 264
    invoke-direct {v7, v4}, Lwq/a;-><init>(F)V

    .line 265
    .line 266
    .line 267
    iput-object v7, v0, Lwq/l;->g:Lwq/d;

    .line 268
    .line 269
    invoke-virtual {v0}, Lwq/l;->a()Lwq/m;

    .line 270
    .line 271
    .line 272
    move-result-object v0

    .line 273
    if-eqz v2, :cond_f

    .line 274
    .line 275
    invoke-virtual {v2, v0}, Lwq/i;->setShapeAppearanceModel(Lwq/m;)V

    .line 276
    .line 277
    .line 278
    goto :goto_3

    .line 279
    :cond_c
    if-ne v0, v1, :cond_18

    .line 280
    .line 281
    new-instance v0, Lxq/a;

    .line 282
    .line 283
    invoke-direct {v0, p0, v5}, Lxq/a;-><init>(Lcom/google/android/material/sidesheet/SideSheetBehavior;I)V

    .line 284
    .line 285
    .line 286
    iput-object v0, p0, Lcom/google/android/material/sidesheet/SideSheetBehavior;->a:Llp/df;

    .line 287
    .line 288
    if-eqz v8, :cond_f

    .line 289
    .line 290
    iget-object v0, p0, Lcom/google/android/material/sidesheet/SideSheetBehavior;->p:Ljava/lang/ref/WeakReference;

    .line 291
    .line 292
    if-eqz v0, :cond_d

    .line 293
    .line 294
    invoke-virtual {v0}, Ljava/lang/ref/Reference;->get()Ljava/lang/Object;

    .line 295
    .line 296
    .line 297
    move-result-object v0

    .line 298
    check-cast v0, Landroid/view/View;

    .line 299
    .line 300
    if-eqz v0, :cond_d

    .line 301
    .line 302
    invoke-virtual {v0}, Landroid/view/View;->getLayoutParams()Landroid/view/ViewGroup$LayoutParams;

    .line 303
    .line 304
    .line 305
    move-result-object v9

    .line 306
    instance-of v9, v9, Ll5/c;

    .line 307
    .line 308
    if-eqz v9, :cond_d

    .line 309
    .line 310
    invoke-virtual {v0}, Landroid/view/View;->getLayoutParams()Landroid/view/ViewGroup$LayoutParams;

    .line 311
    .line 312
    .line 313
    move-result-object v0

    .line 314
    move-object v7, v0

    .line 315
    check-cast v7, Ll5/c;

    .line 316
    .line 317
    :cond_d
    if-eqz v7, :cond_e

    .line 318
    .line 319
    iget v0, v7, Landroid/view/ViewGroup$MarginLayoutParams;->leftMargin:I

    .line 320
    .line 321
    if-lez v0, :cond_e

    .line 322
    .line 323
    goto :goto_3

    .line 324
    :cond_e
    invoke-virtual {v8}, Lwq/m;->f()Lwq/l;

    .line 325
    .line 326
    .line 327
    move-result-object v0

    .line 328
    new-instance v7, Lwq/a;

    .line 329
    .line 330
    invoke-direct {v7, v4}, Lwq/a;-><init>(F)V

    .line 331
    .line 332
    .line 333
    iput-object v7, v0, Lwq/l;->e:Lwq/d;

    .line 334
    .line 335
    new-instance v7, Lwq/a;

    .line 336
    .line 337
    invoke-direct {v7, v4}, Lwq/a;-><init>(F)V

    .line 338
    .line 339
    .line 340
    iput-object v7, v0, Lwq/l;->h:Lwq/d;

    .line 341
    .line 342
    invoke-virtual {v0}, Lwq/l;->a()Lwq/m;

    .line 343
    .line 344
    .line 345
    move-result-object v0

    .line 346
    if-eqz v2, :cond_f

    .line 347
    .line 348
    invoke-virtual {v2, v0}, Lwq/i;->setShapeAppearanceModel(Lwq/m;)V

    .line 349
    .line 350
    .line 351
    :cond_f
    :goto_3
    iget-object v0, p0, Lcom/google/android/material/sidesheet/SideSheetBehavior;->i:Lk6/f;

    .line 352
    .line 353
    if-nez v0, :cond_10

    .line 354
    .line 355
    new-instance v0, Lk6/f;

    .line 356
    .line 357
    invoke-virtual {p1}, Landroid/view/View;->getContext()Landroid/content/Context;

    .line 358
    .line 359
    .line 360
    move-result-object v2

    .line 361
    iget-object v4, p0, Lcom/google/android/material/sidesheet/SideSheetBehavior;->v:Liq/c;

    .line 362
    .line 363
    invoke-direct {v0, v2, p1, v4}, Lk6/f;-><init>(Landroid/content/Context;Landroid/view/ViewGroup;Lk6/e;)V

    .line 364
    .line 365
    .line 366
    iput-object v0, p0, Lcom/google/android/material/sidesheet/SideSheetBehavior;->i:Lk6/f;

    .line 367
    .line 368
    :cond_10
    iget-object v0, p0, Lcom/google/android/material/sidesheet/SideSheetBehavior;->a:Llp/df;

    .line 369
    .line 370
    invoke-virtual {v0, p2}, Llp/df;->i(Landroid/view/View;)I

    .line 371
    .line 372
    .line 373
    move-result v0

    .line 374
    invoke-virtual {p1, p2, p3}, Landroidx/coordinatorlayout/widget/CoordinatorLayout;->q(Landroid/view/View;I)V

    .line 375
    .line 376
    .line 377
    invoke-virtual {p1}, Landroid/view/View;->getWidth()I

    .line 378
    .line 379
    .line 380
    move-result p3

    .line 381
    iput p3, p0, Lcom/google/android/material/sidesheet/SideSheetBehavior;->m:I

    .line 382
    .line 383
    iget-object p3, p0, Lcom/google/android/material/sidesheet/SideSheetBehavior;->a:Llp/df;

    .line 384
    .line 385
    invoke-virtual {p3, p1}, Llp/df;->j(Landroidx/coordinatorlayout/widget/CoordinatorLayout;)I

    .line 386
    .line 387
    .line 388
    move-result p3

    .line 389
    iput p3, p0, Lcom/google/android/material/sidesheet/SideSheetBehavior;->n:I

    .line 390
    .line 391
    invoke-virtual {p2}, Landroid/view/View;->getWidth()I

    .line 392
    .line 393
    .line 394
    move-result p3

    .line 395
    iput p3, p0, Lcom/google/android/material/sidesheet/SideSheetBehavior;->l:I

    .line 396
    .line 397
    invoke-virtual {p2}, Landroid/view/View;->getLayoutParams()Landroid/view/ViewGroup$LayoutParams;

    .line 398
    .line 399
    .line 400
    move-result-object p3

    .line 401
    check-cast p3, Landroid/view/ViewGroup$MarginLayoutParams;

    .line 402
    .line 403
    if-eqz p3, :cond_11

    .line 404
    .line 405
    iget-object v2, p0, Lcom/google/android/material/sidesheet/SideSheetBehavior;->a:Llp/df;

    .line 406
    .line 407
    invoke-virtual {v2, p3}, Llp/df;->b(Landroid/view/ViewGroup$MarginLayoutParams;)I

    .line 408
    .line 409
    .line 410
    move-result p3

    .line 411
    goto :goto_4

    .line 412
    :cond_11
    move p3, v5

    .line 413
    :goto_4
    iput p3, p0, Lcom/google/android/material/sidesheet/SideSheetBehavior;->o:I

    .line 414
    .line 415
    iget p3, p0, Lcom/google/android/material/sidesheet/SideSheetBehavior;->h:I

    .line 416
    .line 417
    if-eq p3, v1, :cond_13

    .line 418
    .line 419
    const/4 v2, 0x2

    .line 420
    if-eq p3, v2, :cond_13

    .line 421
    .line 422
    if-eq p3, v6, :cond_14

    .line 423
    .line 424
    if-ne p3, v3, :cond_12

    .line 425
    .line 426
    iget-object p3, p0, Lcom/google/android/material/sidesheet/SideSheetBehavior;->a:Llp/df;

    .line 427
    .line 428
    invoke-virtual {p3}, Llp/df;->f()I

    .line 429
    .line 430
    .line 431
    move-result v5

    .line 432
    goto :goto_5

    .line 433
    :cond_12
    new-instance p1, Ljava/lang/IllegalStateException;

    .line 434
    .line 435
    new-instance p2, Ljava/lang/StringBuilder;

    .line 436
    .line 437
    const-string p3, "Unexpected value: "

    .line 438
    .line 439
    invoke-direct {p2, p3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 440
    .line 441
    .line 442
    iget p0, p0, Lcom/google/android/material/sidesheet/SideSheetBehavior;->h:I

    .line 443
    .line 444
    invoke-virtual {p2, p0}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 445
    .line 446
    .line 447
    invoke-virtual {p2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 448
    .line 449
    .line 450
    move-result-object p0

    .line 451
    invoke-direct {p1, p0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 452
    .line 453
    .line 454
    throw p1

    .line 455
    :cond_13
    iget-object p3, p0, Lcom/google/android/material/sidesheet/SideSheetBehavior;->a:Llp/df;

    .line 456
    .line 457
    invoke-virtual {p3, p2}, Llp/df;->i(Landroid/view/View;)I

    .line 458
    .line 459
    .line 460
    move-result p3

    .line 461
    sub-int v5, v0, p3

    .line 462
    .line 463
    :cond_14
    :goto_5
    sget-object p3, Ld6/r0;->a:Ljava/util/WeakHashMap;

    .line 464
    .line 465
    invoke-virtual {p2, v5}, Landroid/view/View;->offsetLeftAndRight(I)V

    .line 466
    .line 467
    .line 468
    iget-object p2, p0, Lcom/google/android/material/sidesheet/SideSheetBehavior;->q:Ljava/lang/ref/WeakReference;

    .line 469
    .line 470
    if-nez p2, :cond_15

    .line 471
    .line 472
    const/4 p2, -0x1

    .line 473
    iget p3, p0, Lcom/google/android/material/sidesheet/SideSheetBehavior;->r:I

    .line 474
    .line 475
    if-eq p3, p2, :cond_15

    .line 476
    .line 477
    invoke-virtual {p1, p3}, Landroid/view/View;->findViewById(I)Landroid/view/View;

    .line 478
    .line 479
    .line 480
    move-result-object p1

    .line 481
    if-eqz p1, :cond_15

    .line 482
    .line 483
    new-instance p2, Ljava/lang/ref/WeakReference;

    .line 484
    .line 485
    invoke-direct {p2, p1}, Ljava/lang/ref/WeakReference;-><init>(Ljava/lang/Object;)V

    .line 486
    .line 487
    .line 488
    iput-object p2, p0, Lcom/google/android/material/sidesheet/SideSheetBehavior;->q:Ljava/lang/ref/WeakReference;

    .line 489
    .line 490
    :cond_15
    iget-object p0, p0, Lcom/google/android/material/sidesheet/SideSheetBehavior;->u:Ljava/util/LinkedHashSet;

    .line 491
    .line 492
    invoke-interface {p0}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 493
    .line 494
    .line 495
    move-result-object p0

    .line 496
    :goto_6
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 497
    .line 498
    .line 499
    move-result p1

    .line 500
    if-eqz p1, :cond_17

    .line 501
    .line 502
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 503
    .line 504
    .line 505
    move-result-object p1

    .line 506
    if-nez p1, :cond_16

    .line 507
    .line 508
    goto :goto_6

    .line 509
    :cond_16
    new-instance p0, Ljava/lang/ClassCastException;

    .line 510
    .line 511
    invoke-direct {p0}, Ljava/lang/ClassCastException;-><init>()V

    .line 512
    .line 513
    .line 514
    throw p0

    .line 515
    :cond_17
    return v1

    .line 516
    :cond_18
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 517
    .line 518
    const-string p1, "Invalid sheet edge position value: "

    .line 519
    .line 520
    const-string p2, ". Must be 0 or 1."

    .line 521
    .line 522
    invoke-static {p1, v0, p2}, Lu/w;->e(Ljava/lang/String;ILjava/lang/String;)Ljava/lang/String;

    .line 523
    .line 524
    .line 525
    move-result-object p1

    .line 526
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 527
    .line 528
    .line 529
    throw p0
.end method

.method public final h(Landroidx/coordinatorlayout/widget/CoordinatorLayout;Landroid/view/View;III)Z
    .locals 2

    .line 1
    invoke-virtual {p2}, Landroid/view/View;->getLayoutParams()Landroid/view/ViewGroup$LayoutParams;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    check-cast p0, Landroid/view/ViewGroup$MarginLayoutParams;

    .line 6
    .line 7
    invoke-virtual {p1}, Landroid/view/View;->getPaddingLeft()I

    .line 8
    .line 9
    .line 10
    move-result v0

    .line 11
    invoke-virtual {p1}, Landroid/view/View;->getPaddingRight()I

    .line 12
    .line 13
    .line 14
    move-result v1

    .line 15
    add-int/2addr v1, v0

    .line 16
    iget v0, p0, Landroid/view/ViewGroup$MarginLayoutParams;->leftMargin:I

    .line 17
    .line 18
    add-int/2addr v1, v0

    .line 19
    iget v0, p0, Landroid/view/ViewGroup$MarginLayoutParams;->rightMargin:I

    .line 20
    .line 21
    add-int/2addr v1, v0

    .line 22
    add-int/2addr v1, p4

    .line 23
    iget p4, p0, Landroid/view/ViewGroup$MarginLayoutParams;->width:I

    .line 24
    .line 25
    invoke-static {p3, v1, p4}, Landroid/view/ViewGroup;->getChildMeasureSpec(III)I

    .line 26
    .line 27
    .line 28
    move-result p3

    .line 29
    invoke-virtual {p1}, Landroid/view/View;->getPaddingTop()I

    .line 30
    .line 31
    .line 32
    move-result p4

    .line 33
    invoke-virtual {p1}, Landroid/view/View;->getPaddingBottom()I

    .line 34
    .line 35
    .line 36
    move-result p1

    .line 37
    add-int/2addr p1, p4

    .line 38
    iget p4, p0, Landroid/view/ViewGroup$MarginLayoutParams;->topMargin:I

    .line 39
    .line 40
    add-int/2addr p1, p4

    .line 41
    iget p4, p0, Landroid/view/ViewGroup$MarginLayoutParams;->bottomMargin:I

    .line 42
    .line 43
    add-int/2addr p1, p4

    .line 44
    iget p0, p0, Landroid/view/ViewGroup$MarginLayoutParams;->height:I

    .line 45
    .line 46
    invoke-static {p5, p1, p0}, Landroid/view/ViewGroup;->getChildMeasureSpec(III)I

    .line 47
    .line 48
    .line 49
    move-result p0

    .line 50
    invoke-virtual {p2, p3, p0}, Landroid/view/View;->measure(II)V

    .line 51
    .line 52
    .line 53
    const/4 p0, 0x1

    .line 54
    return p0
.end method

.method public final m(Landroid/view/View;Landroid/os/Parcelable;)V
    .locals 0

    .line 1
    check-cast p2, Lxq/b;

    .line 2
    .line 3
    iget p1, p2, Lxq/b;->f:I

    .line 4
    .line 5
    const/4 p2, 0x1

    .line 6
    if-eq p1, p2, :cond_0

    .line 7
    .line 8
    const/4 p2, 0x2

    .line 9
    if-ne p1, p2, :cond_1

    .line 10
    .line 11
    :cond_0
    const/4 p1, 0x5

    .line 12
    :cond_1
    iput p1, p0, Lcom/google/android/material/sidesheet/SideSheetBehavior;->h:I

    .line 13
    .line 14
    return-void
.end method

.method public final n(Landroid/view/View;)Landroid/os/Parcelable;
    .locals 1

    .line 1
    new-instance p1, Lxq/b;

    .line 2
    .line 3
    sget-object v0, Landroid/view/View$BaseSavedState;->EMPTY_STATE:Landroid/view/AbsSavedState;

    .line 4
    .line 5
    invoke-direct {p1, p0}, Lxq/b;-><init>(Lcom/google/android/material/sidesheet/SideSheetBehavior;)V

    .line 6
    .line 7
    .line 8
    return-object p1
.end method

.method public final q(Landroid/view/View;Landroid/view/MotionEvent;)Z
    .locals 4

    .line 1
    invoke-virtual {p1}, Landroid/view/View;->isShown()Z

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
    invoke-virtual {p2}, Landroid/view/MotionEvent;->getActionMasked()I

    .line 10
    .line 11
    .line 12
    move-result v0

    .line 13
    iget v1, p0, Lcom/google/android/material/sidesheet/SideSheetBehavior;->h:I

    .line 14
    .line 15
    const/4 v2, 0x1

    .line 16
    if-ne v1, v2, :cond_1

    .line 17
    .line 18
    if-nez v0, :cond_1

    .line 19
    .line 20
    return v2

    .line 21
    :cond_1
    invoke-virtual {p0}, Lcom/google/android/material/sidesheet/SideSheetBehavior;->s()Z

    .line 22
    .line 23
    .line 24
    move-result v1

    .line 25
    if-eqz v1, :cond_2

    .line 26
    .line 27
    iget-object v1, p0, Lcom/google/android/material/sidesheet/SideSheetBehavior;->i:Lk6/f;

    .line 28
    .line 29
    invoke-virtual {v1, p2}, Lk6/f;->j(Landroid/view/MotionEvent;)V

    .line 30
    .line 31
    .line 32
    :cond_2
    if-nez v0, :cond_3

    .line 33
    .line 34
    iget-object v1, p0, Lcom/google/android/material/sidesheet/SideSheetBehavior;->s:Landroid/view/VelocityTracker;

    .line 35
    .line 36
    if-eqz v1, :cond_3

    .line 37
    .line 38
    invoke-virtual {v1}, Landroid/view/VelocityTracker;->recycle()V

    .line 39
    .line 40
    .line 41
    const/4 v1, 0x0

    .line 42
    iput-object v1, p0, Lcom/google/android/material/sidesheet/SideSheetBehavior;->s:Landroid/view/VelocityTracker;

    .line 43
    .line 44
    :cond_3
    iget-object v1, p0, Lcom/google/android/material/sidesheet/SideSheetBehavior;->s:Landroid/view/VelocityTracker;

    .line 45
    .line 46
    if-nez v1, :cond_4

    .line 47
    .line 48
    invoke-static {}, Landroid/view/VelocityTracker;->obtain()Landroid/view/VelocityTracker;

    .line 49
    .line 50
    .line 51
    move-result-object v1

    .line 52
    iput-object v1, p0, Lcom/google/android/material/sidesheet/SideSheetBehavior;->s:Landroid/view/VelocityTracker;

    .line 53
    .line 54
    :cond_4
    iget-object v1, p0, Lcom/google/android/material/sidesheet/SideSheetBehavior;->s:Landroid/view/VelocityTracker;

    .line 55
    .line 56
    invoke-virtual {v1, p2}, Landroid/view/VelocityTracker;->addMovement(Landroid/view/MotionEvent;)V

    .line 57
    .line 58
    .line 59
    invoke-virtual {p0}, Lcom/google/android/material/sidesheet/SideSheetBehavior;->s()Z

    .line 60
    .line 61
    .line 62
    move-result v1

    .line 63
    if-eqz v1, :cond_6

    .line 64
    .line 65
    const/4 v1, 0x2

    .line 66
    if-ne v0, v1, :cond_6

    .line 67
    .line 68
    iget-boolean v0, p0, Lcom/google/android/material/sidesheet/SideSheetBehavior;->j:Z

    .line 69
    .line 70
    if-nez v0, :cond_6

    .line 71
    .line 72
    invoke-virtual {p0}, Lcom/google/android/material/sidesheet/SideSheetBehavior;->s()Z

    .line 73
    .line 74
    .line 75
    move-result v0

    .line 76
    if-nez v0, :cond_5

    .line 77
    .line 78
    goto :goto_0

    .line 79
    :cond_5
    iget v0, p0, Lcom/google/android/material/sidesheet/SideSheetBehavior;->t:I

    .line 80
    .line 81
    int-to-float v0, v0

    .line 82
    invoke-virtual {p2}, Landroid/view/MotionEvent;->getX()F

    .line 83
    .line 84
    .line 85
    move-result v1

    .line 86
    sub-float/2addr v0, v1

    .line 87
    invoke-static {v0}, Ljava/lang/Math;->abs(F)F

    .line 88
    .line 89
    .line 90
    move-result v0

    .line 91
    iget-object v1, p0, Lcom/google/android/material/sidesheet/SideSheetBehavior;->i:Lk6/f;

    .line 92
    .line 93
    iget v3, v1, Lk6/f;->b:I

    .line 94
    .line 95
    int-to-float v3, v3

    .line 96
    cmpl-float v0, v0, v3

    .line 97
    .line 98
    if-lez v0, :cond_6

    .line 99
    .line 100
    invoke-virtual {p2}, Landroid/view/MotionEvent;->getActionIndex()I

    .line 101
    .line 102
    .line 103
    move-result v0

    .line 104
    invoke-virtual {p2, v0}, Landroid/view/MotionEvent;->getPointerId(I)I

    .line 105
    .line 106
    .line 107
    move-result p2

    .line 108
    invoke-virtual {v1, p1, p2}, Lk6/f;->b(Landroid/view/View;I)V

    .line 109
    .line 110
    .line 111
    :cond_6
    :goto_0
    iget-boolean p0, p0, Lcom/google/android/material/sidesheet/SideSheetBehavior;->j:Z

    .line 112
    .line 113
    xor-int/2addr p0, v2

    .line 114
    return p0
.end method

.method public final r(I)V
    .locals 2

    .line 1
    iget v0, p0, Lcom/google/android/material/sidesheet/SideSheetBehavior;->h:I

    .line 2
    .line 3
    if-ne v0, p1, :cond_0

    .line 4
    .line 5
    goto :goto_0

    .line 6
    :cond_0
    iput p1, p0, Lcom/google/android/material/sidesheet/SideSheetBehavior;->h:I

    .line 7
    .line 8
    const/4 v0, 0x3

    .line 9
    const/4 v1, 0x5

    .line 10
    iget-object p1, p0, Lcom/google/android/material/sidesheet/SideSheetBehavior;->p:Ljava/lang/ref/WeakReference;

    .line 11
    .line 12
    if-nez p1, :cond_1

    .line 13
    .line 14
    goto :goto_0

    .line 15
    :cond_1
    invoke-virtual {p1}, Ljava/lang/ref/Reference;->get()Ljava/lang/Object;

    .line 16
    .line 17
    .line 18
    move-result-object p1

    .line 19
    check-cast p1, Landroid/view/View;

    .line 20
    .line 21
    if-nez p1, :cond_2

    .line 22
    .line 23
    :goto_0
    return-void

    .line 24
    :cond_2
    iget v0, p0, Lcom/google/android/material/sidesheet/SideSheetBehavior;->h:I

    .line 25
    .line 26
    if-ne v0, v1, :cond_3

    .line 27
    .line 28
    const/4 v0, 0x4

    .line 29
    goto :goto_1

    .line 30
    :cond_3
    const/4 v0, 0x0

    .line 31
    :goto_1
    invoke-virtual {p1}, Landroid/view/View;->getVisibility()I

    .line 32
    .line 33
    .line 34
    move-result v1

    .line 35
    if-eq v1, v0, :cond_4

    .line 36
    .line 37
    invoke-virtual {p1, v0}, Landroid/view/View;->setVisibility(I)V

    .line 38
    .line 39
    .line 40
    :cond_4
    iget-object p1, p0, Lcom/google/android/material/sidesheet/SideSheetBehavior;->u:Ljava/util/LinkedHashSet;

    .line 41
    .line 42
    invoke-interface {p1}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 43
    .line 44
    .line 45
    move-result-object p1

    .line 46
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    .line 47
    .line 48
    .line 49
    move-result v0

    .line 50
    if-nez v0, :cond_5

    .line 51
    .line 52
    invoke-virtual {p0}, Lcom/google/android/material/sidesheet/SideSheetBehavior;->u()V

    .line 53
    .line 54
    .line 55
    return-void

    .line 56
    :cond_5
    invoke-static {p1}, Lf2/m0;->e(Ljava/util/Iterator;)Ljava/lang/ClassCastException;

    .line 57
    .line 58
    .line 59
    move-result-object p0

    .line 60
    throw p0
.end method

.method public final s()Z
    .locals 2

    .line 1
    iget-object v0, p0, Lcom/google/android/material/sidesheet/SideSheetBehavior;->i:Lk6/f;

    .line 2
    .line 3
    if-eqz v0, :cond_1

    .line 4
    .line 5
    iget-boolean v0, p0, Lcom/google/android/material/sidesheet/SideSheetBehavior;->g:Z

    .line 6
    .line 7
    const/4 v1, 0x1

    .line 8
    if-nez v0, :cond_0

    .line 9
    .line 10
    iget p0, p0, Lcom/google/android/material/sidesheet/SideSheetBehavior;->h:I

    .line 11
    .line 12
    if-ne p0, v1, :cond_1

    .line 13
    .line 14
    :cond_0
    return v1

    .line 15
    :cond_1
    const/4 p0, 0x0

    .line 16
    return p0
.end method

.method public final t(Landroid/view/View;IZ)V
    .locals 2

    .line 1
    const/4 v0, 0x3

    .line 2
    if-eq p2, v0, :cond_1

    .line 3
    .line 4
    const/4 v0, 0x5

    .line 5
    if-ne p2, v0, :cond_0

    .line 6
    .line 7
    iget-object v0, p0, Lcom/google/android/material/sidesheet/SideSheetBehavior;->a:Llp/df;

    .line 8
    .line 9
    invoke-virtual {v0}, Llp/df;->f()I

    .line 10
    .line 11
    .line 12
    move-result v0

    .line 13
    goto :goto_0

    .line 14
    :cond_0
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 15
    .line 16
    const-string p1, "Invalid state to get outer edge offset: "

    .line 17
    .line 18
    invoke-static {p2, p1}, Lkx/a;->h(ILjava/lang/String;)Ljava/lang/String;

    .line 19
    .line 20
    .line 21
    move-result-object p1

    .line 22
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 23
    .line 24
    .line 25
    throw p0

    .line 26
    :cond_1
    iget-object v0, p0, Lcom/google/android/material/sidesheet/SideSheetBehavior;->a:Llp/df;

    .line 27
    .line 28
    invoke-virtual {v0}, Llp/df;->e()I

    .line 29
    .line 30
    .line 31
    move-result v0

    .line 32
    :goto_0
    iget-object v1, p0, Lcom/google/android/material/sidesheet/SideSheetBehavior;->i:Lk6/f;

    .line 33
    .line 34
    if-eqz v1, :cond_4

    .line 35
    .line 36
    if-eqz p3, :cond_2

    .line 37
    .line 38
    invoke-virtual {p1}, Landroid/view/View;->getTop()I

    .line 39
    .line 40
    .line 41
    move-result p1

    .line 42
    invoke-virtual {v1, v0, p1}, Lk6/f;->o(II)Z

    .line 43
    .line 44
    .line 45
    move-result p1

    .line 46
    if-eqz p1, :cond_4

    .line 47
    .line 48
    goto :goto_1

    .line 49
    :cond_2
    invoke-virtual {p1}, Landroid/view/View;->getTop()I

    .line 50
    .line 51
    .line 52
    move-result p3

    .line 53
    iput-object p1, v1, Lk6/f;->r:Landroid/view/View;

    .line 54
    .line 55
    const/4 p1, -0x1

    .line 56
    iput p1, v1, Lk6/f;->c:I

    .line 57
    .line 58
    const/4 p1, 0x0

    .line 59
    invoke-virtual {v1, v0, p3, p1, p1}, Lk6/f;->h(IIII)Z

    .line 60
    .line 61
    .line 62
    move-result p1

    .line 63
    if-nez p1, :cond_3

    .line 64
    .line 65
    iget p3, v1, Lk6/f;->a:I

    .line 66
    .line 67
    if-nez p3, :cond_3

    .line 68
    .line 69
    iget-object p3, v1, Lk6/f;->r:Landroid/view/View;

    .line 70
    .line 71
    if-eqz p3, :cond_3

    .line 72
    .line 73
    const/4 p3, 0x0

    .line 74
    iput-object p3, v1, Lk6/f;->r:Landroid/view/View;

    .line 75
    .line 76
    :cond_3
    if-eqz p1, :cond_4

    .line 77
    .line 78
    :goto_1
    const/4 p1, 0x2

    .line 79
    invoke-virtual {p0, p1}, Lcom/google/android/material/sidesheet/SideSheetBehavior;->r(I)V

    .line 80
    .line 81
    .line 82
    iget-object p0, p0, Lcom/google/android/material/sidesheet/SideSheetBehavior;->e:Lh6/i;

    .line 83
    .line 84
    invoke-virtual {p0, p2}, Lh6/i;->b(I)V

    .line 85
    .line 86
    .line 87
    return-void

    .line 88
    :cond_4
    invoke-virtual {p0, p2}, Lcom/google/android/material/sidesheet/SideSheetBehavior;->r(I)V

    .line 89
    .line 90
    .line 91
    return-void
.end method

.method public final u()V
    .locals 5

    .line 1
    iget-object v0, p0, Lcom/google/android/material/sidesheet/SideSheetBehavior;->p:Ljava/lang/ref/WeakReference;

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    goto :goto_0

    .line 6
    :cond_0
    invoke-virtual {v0}, Ljava/lang/ref/Reference;->get()Ljava/lang/Object;

    .line 7
    .line 8
    .line 9
    move-result-object v0

    .line 10
    check-cast v0, Landroid/view/View;

    .line 11
    .line 12
    if-nez v0, :cond_1

    .line 13
    .line 14
    goto :goto_0

    .line 15
    :cond_1
    const/high16 v1, 0x40000

    .line 16
    .line 17
    invoke-static {v0, v1}, Ld6/r0;->g(Landroid/view/View;I)V

    .line 18
    .line 19
    .line 20
    const/4 v1, 0x0

    .line 21
    invoke-static {v0, v1}, Ld6/r0;->e(Landroid/view/View;I)V

    .line 22
    .line 23
    .line 24
    const/high16 v2, 0x100000

    .line 25
    .line 26
    invoke-static {v0, v2}, Ld6/r0;->g(Landroid/view/View;I)V

    .line 27
    .line 28
    .line 29
    invoke-static {v0, v1}, Ld6/r0;->e(Landroid/view/View;I)V

    .line 30
    .line 31
    .line 32
    iget v1, p0, Lcom/google/android/material/sidesheet/SideSheetBehavior;->h:I

    .line 33
    .line 34
    const/4 v2, 0x5

    .line 35
    if-eq v1, v2, :cond_2

    .line 36
    .line 37
    sget-object v1, Le6/c;->l:Le6/c;

    .line 38
    .line 39
    new-instance v3, La8/s;

    .line 40
    .line 41
    const/4 v4, 0x2

    .line 42
    invoke-direct {v3, p0, v2, v4}, La8/s;-><init>(Ljava/lang/Object;II)V

    .line 43
    .line 44
    .line 45
    invoke-static {v0, v1, v3}, Ld6/r0;->h(Landroid/view/View;Le6/c;Le6/m;)V

    .line 46
    .line 47
    .line 48
    :cond_2
    iget v1, p0, Lcom/google/android/material/sidesheet/SideSheetBehavior;->h:I

    .line 49
    .line 50
    const/4 v2, 0x3

    .line 51
    if-eq v1, v2, :cond_3

    .line 52
    .line 53
    sget-object v1, Le6/c;->j:Le6/c;

    .line 54
    .line 55
    new-instance v3, La8/s;

    .line 56
    .line 57
    const/4 v4, 0x2

    .line 58
    invoke-direct {v3, p0, v2, v4}, La8/s;-><init>(Ljava/lang/Object;II)V

    .line 59
    .line 60
    .line 61
    invoke-static {v0, v1, v3}, Ld6/r0;->h(Landroid/view/View;Le6/c;Le6/m;)V

    .line 62
    .line 63
    .line 64
    :cond_3
    :goto_0
    return-void
.end method
