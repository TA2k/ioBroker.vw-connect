.class public final Lk6/f;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final v:Lk6/d;


# instance fields
.field public a:I

.field public b:I

.field public c:I

.field public d:[F

.field public e:[F

.field public f:[F

.field public g:[F

.field public h:[I

.field public i:[I

.field public j:[I

.field public k:I

.field public l:Landroid/view/VelocityTracker;

.field public final m:F

.field public final n:F

.field public final o:I

.field public final p:Landroid/widget/OverScroller;

.field public final q:Lk6/e;

.field public r:Landroid/view/View;

.field public s:Z

.field public final t:Landroid/view/ViewGroup;

.field public final u:Laq/p;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Lk6/d;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-direct {v0, v1}, Lk6/d;-><init>(I)V

    .line 5
    .line 6
    .line 7
    sput-object v0, Lk6/f;->v:Lk6/d;

    .line 8
    .line 9
    return-void
.end method

.method public constructor <init>(Landroid/content/Context;Landroid/view/ViewGroup;Lk6/e;)V
    .locals 2

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    const/4 v0, -0x1

    .line 5
    iput v0, p0, Lk6/f;->c:I

    .line 6
    .line 7
    new-instance v0, Laq/p;

    .line 8
    .line 9
    const/16 v1, 0xa

    .line 10
    .line 11
    invoke-direct {v0, p0, v1}, Laq/p;-><init>(Ljava/lang/Object;I)V

    .line 12
    .line 13
    .line 14
    iput-object v0, p0, Lk6/f;->u:Laq/p;

    .line 15
    .line 16
    if-eqz p3, :cond_0

    .line 17
    .line 18
    iput-object p2, p0, Lk6/f;->t:Landroid/view/ViewGroup;

    .line 19
    .line 20
    iput-object p3, p0, Lk6/f;->q:Lk6/e;

    .line 21
    .line 22
    invoke-static {p1}, Landroid/view/ViewConfiguration;->get(Landroid/content/Context;)Landroid/view/ViewConfiguration;

    .line 23
    .line 24
    .line 25
    move-result-object p2

    .line 26
    invoke-virtual {p1}, Landroid/content/Context;->getResources()Landroid/content/res/Resources;

    .line 27
    .line 28
    .line 29
    move-result-object p3

    .line 30
    invoke-virtual {p3}, Landroid/content/res/Resources;->getDisplayMetrics()Landroid/util/DisplayMetrics;

    .line 31
    .line 32
    .line 33
    move-result-object p3

    .line 34
    iget p3, p3, Landroid/util/DisplayMetrics;->density:F

    .line 35
    .line 36
    const/high16 v0, 0x41a00000    # 20.0f

    .line 37
    .line 38
    mul-float/2addr p3, v0

    .line 39
    const/high16 v0, 0x3f000000    # 0.5f

    .line 40
    .line 41
    add-float/2addr p3, v0

    .line 42
    float-to-int p3, p3

    .line 43
    iput p3, p0, Lk6/f;->o:I

    .line 44
    .line 45
    invoke-virtual {p2}, Landroid/view/ViewConfiguration;->getScaledTouchSlop()I

    .line 46
    .line 47
    .line 48
    move-result p3

    .line 49
    iput p3, p0, Lk6/f;->b:I

    .line 50
    .line 51
    invoke-virtual {p2}, Landroid/view/ViewConfiguration;->getScaledMaximumFlingVelocity()I

    .line 52
    .line 53
    .line 54
    move-result p3

    .line 55
    int-to-float p3, p3

    .line 56
    iput p3, p0, Lk6/f;->m:F

    .line 57
    .line 58
    invoke-virtual {p2}, Landroid/view/ViewConfiguration;->getScaledMinimumFlingVelocity()I

    .line 59
    .line 60
    .line 61
    move-result p2

    .line 62
    int-to-float p2, p2

    .line 63
    iput p2, p0, Lk6/f;->n:F

    .line 64
    .line 65
    new-instance p2, Landroid/widget/OverScroller;

    .line 66
    .line 67
    sget-object p3, Lk6/f;->v:Lk6/d;

    .line 68
    .line 69
    invoke-direct {p2, p1, p3}, Landroid/widget/OverScroller;-><init>(Landroid/content/Context;Landroid/view/animation/Interpolator;)V

    .line 70
    .line 71
    .line 72
    iput-object p2, p0, Lk6/f;->p:Landroid/widget/OverScroller;

    .line 73
    .line 74
    return-void

    .line 75
    :cond_0
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 76
    .line 77
    const-string p1, "Callback may not be null"

    .line 78
    .line 79
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 80
    .line 81
    .line 82
    throw p0
.end method


# virtual methods
.method public final a()V
    .locals 2

    .line 1
    const/4 v0, -0x1

    .line 2
    iput v0, p0, Lk6/f;->c:I

    .line 3
    .line 4
    iget-object v0, p0, Lk6/f;->d:[F

    .line 5
    .line 6
    if-nez v0, :cond_0

    .line 7
    .line 8
    goto :goto_0

    .line 9
    :cond_0
    const/4 v1, 0x0

    .line 10
    invoke-static {v0, v1}, Ljava/util/Arrays;->fill([FF)V

    .line 11
    .line 12
    .line 13
    iget-object v0, p0, Lk6/f;->e:[F

    .line 14
    .line 15
    invoke-static {v0, v1}, Ljava/util/Arrays;->fill([FF)V

    .line 16
    .line 17
    .line 18
    iget-object v0, p0, Lk6/f;->f:[F

    .line 19
    .line 20
    invoke-static {v0, v1}, Ljava/util/Arrays;->fill([FF)V

    .line 21
    .line 22
    .line 23
    iget-object v0, p0, Lk6/f;->g:[F

    .line 24
    .line 25
    invoke-static {v0, v1}, Ljava/util/Arrays;->fill([FF)V

    .line 26
    .line 27
    .line 28
    iget-object v0, p0, Lk6/f;->h:[I

    .line 29
    .line 30
    const/4 v1, 0x0

    .line 31
    invoke-static {v0, v1}, Ljava/util/Arrays;->fill([II)V

    .line 32
    .line 33
    .line 34
    iget-object v0, p0, Lk6/f;->i:[I

    .line 35
    .line 36
    invoke-static {v0, v1}, Ljava/util/Arrays;->fill([II)V

    .line 37
    .line 38
    .line 39
    iget-object v0, p0, Lk6/f;->j:[I

    .line 40
    .line 41
    invoke-static {v0, v1}, Ljava/util/Arrays;->fill([II)V

    .line 42
    .line 43
    .line 44
    iput v1, p0, Lk6/f;->k:I

    .line 45
    .line 46
    :goto_0
    iget-object v0, p0, Lk6/f;->l:Landroid/view/VelocityTracker;

    .line 47
    .line 48
    if-eqz v0, :cond_1

    .line 49
    .line 50
    invoke-virtual {v0}, Landroid/view/VelocityTracker;->recycle()V

    .line 51
    .line 52
    .line 53
    const/4 v0, 0x0

    .line 54
    iput-object v0, p0, Lk6/f;->l:Landroid/view/VelocityTracker;

    .line 55
    .line 56
    :cond_1
    return-void
.end method

.method public final b(Landroid/view/View;I)V
    .locals 2

    .line 1
    invoke-virtual {p1}, Landroid/view/View;->getParent()Landroid/view/ViewParent;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    iget-object v1, p0, Lk6/f;->t:Landroid/view/ViewGroup;

    .line 6
    .line 7
    if-ne v0, v1, :cond_0

    .line 8
    .line 9
    iput-object p1, p0, Lk6/f;->r:Landroid/view/View;

    .line 10
    .line 11
    iput p2, p0, Lk6/f;->c:I

    .line 12
    .line 13
    iget-object v0, p0, Lk6/f;->q:Lk6/e;

    .line 14
    .line 15
    invoke-virtual {v0, p1, p2}, Lk6/e;->onViewCaptured(Landroid/view/View;I)V

    .line 16
    .line 17
    .line 18
    const/4 p1, 0x1

    .line 19
    invoke-virtual {p0, p1}, Lk6/f;->n(I)V

    .line 20
    .line 21
    .line 22
    return-void

    .line 23
    :cond_0
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 24
    .line 25
    new-instance p1, Ljava/lang/StringBuilder;

    .line 26
    .line 27
    const-string p2, "captureChildView: parameter must be a descendant of the ViewDragHelper\'s tracked parent view ("

    .line 28
    .line 29
    invoke-direct {p1, p2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 30
    .line 31
    .line 32
    invoke-virtual {p1, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 33
    .line 34
    .line 35
    const-string p2, ")"

    .line 36
    .line 37
    invoke-virtual {p1, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 38
    .line 39
    .line 40
    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 41
    .line 42
    .line 43
    move-result-object p1

    .line 44
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 45
    .line 46
    .line 47
    throw p0
.end method

.method public final c(Landroid/view/View;FF)Z
    .locals 4

    .line 1
    const/4 v0, 0x0

    .line 2
    if-nez p1, :cond_0

    .line 3
    .line 4
    goto :goto_3

    .line 5
    :cond_0
    iget-object v1, p0, Lk6/f;->q:Lk6/e;

    .line 6
    .line 7
    invoke-virtual {v1, p1}, Lk6/e;->getViewHorizontalDragRange(Landroid/view/View;)I

    .line 8
    .line 9
    .line 10
    move-result v2

    .line 11
    const/4 v3, 0x1

    .line 12
    if-lez v2, :cond_1

    .line 13
    .line 14
    move v2, v3

    .line 15
    goto :goto_0

    .line 16
    :cond_1
    move v2, v0

    .line 17
    :goto_0
    invoke-virtual {v1, p1}, Lk6/e;->getViewVerticalDragRange(Landroid/view/View;)I

    .line 18
    .line 19
    .line 20
    move-result p1

    .line 21
    if-lez p1, :cond_2

    .line 22
    .line 23
    move p1, v3

    .line 24
    goto :goto_1

    .line 25
    :cond_2
    move p1, v0

    .line 26
    :goto_1
    if-eqz v2, :cond_3

    .line 27
    .line 28
    if-eqz p1, :cond_3

    .line 29
    .line 30
    mul-float/2addr p2, p2

    .line 31
    mul-float/2addr p3, p3

    .line 32
    add-float/2addr p3, p2

    .line 33
    iget p0, p0, Lk6/f;->b:I

    .line 34
    .line 35
    mul-int/2addr p0, p0

    .line 36
    int-to-float p0, p0

    .line 37
    cmpl-float p0, p3, p0

    .line 38
    .line 39
    if-lez p0, :cond_5

    .line 40
    .line 41
    goto :goto_2

    .line 42
    :cond_3
    if-eqz v2, :cond_4

    .line 43
    .line 44
    invoke-static {p2}, Ljava/lang/Math;->abs(F)F

    .line 45
    .line 46
    .line 47
    move-result p1

    .line 48
    iget p0, p0, Lk6/f;->b:I

    .line 49
    .line 50
    int-to-float p0, p0

    .line 51
    cmpl-float p0, p1, p0

    .line 52
    .line 53
    if-lez p0, :cond_5

    .line 54
    .line 55
    goto :goto_2

    .line 56
    :cond_4
    if-eqz p1, :cond_5

    .line 57
    .line 58
    invoke-static {p3}, Ljava/lang/Math;->abs(F)F

    .line 59
    .line 60
    .line 61
    move-result p1

    .line 62
    iget p0, p0, Lk6/f;->b:I

    .line 63
    .line 64
    int-to-float p0, p0

    .line 65
    cmpl-float p0, p1, p0

    .line 66
    .line 67
    if-lez p0, :cond_5

    .line 68
    .line 69
    :goto_2
    return v3

    .line 70
    :cond_5
    :goto_3
    return v0
.end method

.method public final d(I)V
    .locals 4

    .line 1
    iget-object v0, p0, Lk6/f;->d:[F

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    iget v1, p0, Lk6/f;->k:I

    .line 6
    .line 7
    const/4 v2, 0x1

    .line 8
    shl-int/2addr v2, p1

    .line 9
    and-int v3, v1, v2

    .line 10
    .line 11
    if-eqz v3, :cond_0

    .line 12
    .line 13
    const/4 v3, 0x0

    .line 14
    aput v3, v0, p1

    .line 15
    .line 16
    iget-object v0, p0, Lk6/f;->e:[F

    .line 17
    .line 18
    aput v3, v0, p1

    .line 19
    .line 20
    iget-object v0, p0, Lk6/f;->f:[F

    .line 21
    .line 22
    aput v3, v0, p1

    .line 23
    .line 24
    iget-object v0, p0, Lk6/f;->g:[F

    .line 25
    .line 26
    aput v3, v0, p1

    .line 27
    .line 28
    iget-object v0, p0, Lk6/f;->h:[I

    .line 29
    .line 30
    const/4 v3, 0x0

    .line 31
    aput v3, v0, p1

    .line 32
    .line 33
    iget-object v0, p0, Lk6/f;->i:[I

    .line 34
    .line 35
    aput v3, v0, p1

    .line 36
    .line 37
    iget-object v0, p0, Lk6/f;->j:[I

    .line 38
    .line 39
    aput v3, v0, p1

    .line 40
    .line 41
    not-int p1, v2

    .line 42
    and-int/2addr p1, v1

    .line 43
    iput p1, p0, Lk6/f;->k:I

    .line 44
    .line 45
    :cond_0
    return-void
.end method

.method public final e(III)I
    .locals 3

    .line 1
    if-nez p1, :cond_0

    .line 2
    .line 3
    const/4 p0, 0x0

    .line 4
    return p0

    .line 5
    :cond_0
    iget-object p0, p0, Lk6/f;->t:Landroid/view/ViewGroup;

    .line 6
    .line 7
    invoke-virtual {p0}, Landroid/view/View;->getWidth()I

    .line 8
    .line 9
    .line 10
    move-result p0

    .line 11
    div-int/lit8 v0, p0, 0x2

    .line 12
    .line 13
    invoke-static {p1}, Ljava/lang/Math;->abs(I)I

    .line 14
    .line 15
    .line 16
    move-result v1

    .line 17
    int-to-float v1, v1

    .line 18
    int-to-float p0, p0

    .line 19
    div-float/2addr v1, p0

    .line 20
    const/high16 p0, 0x3f800000    # 1.0f

    .line 21
    .line 22
    invoke-static {p0, v1}, Ljava/lang/Math;->min(FF)F

    .line 23
    .line 24
    .line 25
    move-result v1

    .line 26
    int-to-float v0, v0

    .line 27
    const/high16 v2, 0x3f000000    # 0.5f

    .line 28
    .line 29
    sub-float/2addr v1, v2

    .line 30
    const v2, 0x3ef1463b

    .line 31
    .line 32
    .line 33
    mul-float/2addr v1, v2

    .line 34
    float-to-double v1, v1

    .line 35
    invoke-static {v1, v2}, Ljava/lang/Math;->sin(D)D

    .line 36
    .line 37
    .line 38
    move-result-wide v1

    .line 39
    double-to-float v1, v1

    .line 40
    mul-float/2addr v1, v0

    .line 41
    add-float/2addr v1, v0

    .line 42
    invoke-static {p2}, Ljava/lang/Math;->abs(I)I

    .line 43
    .line 44
    .line 45
    move-result p2

    .line 46
    if-lez p2, :cond_1

    .line 47
    .line 48
    int-to-float p0, p2

    .line 49
    div-float/2addr v1, p0

    .line 50
    invoke-static {v1}, Ljava/lang/Math;->abs(F)F

    .line 51
    .line 52
    .line 53
    move-result p0

    .line 54
    const/high16 p1, 0x447a0000    # 1000.0f

    .line 55
    .line 56
    mul-float/2addr p0, p1

    .line 57
    invoke-static {p0}, Ljava/lang/Math;->round(F)I

    .line 58
    .line 59
    .line 60
    move-result p0

    .line 61
    mul-int/lit8 p0, p0, 0x4

    .line 62
    .line 63
    goto :goto_0

    .line 64
    :cond_1
    invoke-static {p1}, Ljava/lang/Math;->abs(I)I

    .line 65
    .line 66
    .line 67
    move-result p1

    .line 68
    int-to-float p1, p1

    .line 69
    int-to-float p2, p3

    .line 70
    div-float/2addr p1, p2

    .line 71
    add-float/2addr p1, p0

    .line 72
    const/high16 p0, 0x43800000    # 256.0f

    .line 73
    .line 74
    mul-float/2addr p1, p0

    .line 75
    float-to-int p0, p1

    .line 76
    :goto_0
    const/16 p1, 0x258

    .line 77
    .line 78
    invoke-static {p0, p1}, Ljava/lang/Math;->min(II)I

    .line 79
    .line 80
    .line 81
    move-result p0

    .line 82
    return p0
.end method

.method public final f()Z
    .locals 10

    .line 1
    iget v0, p0, Lk6/f;->a:I

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    const/4 v2, 0x2

    .line 5
    if-ne v0, v2, :cond_5

    .line 6
    .line 7
    iget-object v0, p0, Lk6/f;->p:Landroid/widget/OverScroller;

    .line 8
    .line 9
    invoke-virtual {v0}, Landroid/widget/OverScroller;->computeScrollOffset()Z

    .line 10
    .line 11
    .line 12
    move-result v3

    .line 13
    invoke-virtual {v0}, Landroid/widget/OverScroller;->getCurrX()I

    .line 14
    .line 15
    .line 16
    move-result v6

    .line 17
    invoke-virtual {v0}, Landroid/widget/OverScroller;->getCurrY()I

    .line 18
    .line 19
    .line 20
    move-result v7

    .line 21
    iget-object v4, p0, Lk6/f;->r:Landroid/view/View;

    .line 22
    .line 23
    invoke-virtual {v4}, Landroid/view/View;->getLeft()I

    .line 24
    .line 25
    .line 26
    move-result v4

    .line 27
    sub-int v8, v6, v4

    .line 28
    .line 29
    iget-object v4, p0, Lk6/f;->r:Landroid/view/View;

    .line 30
    .line 31
    invoke-virtual {v4}, Landroid/view/View;->getTop()I

    .line 32
    .line 33
    .line 34
    move-result v4

    .line 35
    sub-int v9, v7, v4

    .line 36
    .line 37
    if-eqz v8, :cond_0

    .line 38
    .line 39
    iget-object v4, p0, Lk6/f;->r:Landroid/view/View;

    .line 40
    .line 41
    sget-object v5, Ld6/r0;->a:Ljava/util/WeakHashMap;

    .line 42
    .line 43
    invoke-virtual {v4, v8}, Landroid/view/View;->offsetLeftAndRight(I)V

    .line 44
    .line 45
    .line 46
    :cond_0
    if-eqz v9, :cond_1

    .line 47
    .line 48
    iget-object v4, p0, Lk6/f;->r:Landroid/view/View;

    .line 49
    .line 50
    sget-object v5, Ld6/r0;->a:Ljava/util/WeakHashMap;

    .line 51
    .line 52
    invoke-virtual {v4, v9}, Landroid/view/View;->offsetTopAndBottom(I)V

    .line 53
    .line 54
    .line 55
    :cond_1
    if-nez v8, :cond_2

    .line 56
    .line 57
    if-eqz v9, :cond_3

    .line 58
    .line 59
    :cond_2
    iget-object v4, p0, Lk6/f;->q:Lk6/e;

    .line 60
    .line 61
    iget-object v5, p0, Lk6/f;->r:Landroid/view/View;

    .line 62
    .line 63
    invoke-virtual/range {v4 .. v9}, Lk6/e;->onViewPositionChanged(Landroid/view/View;IIII)V

    .line 64
    .line 65
    .line 66
    :cond_3
    if-eqz v3, :cond_4

    .line 67
    .line 68
    invoke-virtual {v0}, Landroid/widget/OverScroller;->getFinalX()I

    .line 69
    .line 70
    .line 71
    move-result v4

    .line 72
    if-ne v6, v4, :cond_4

    .line 73
    .line 74
    invoke-virtual {v0}, Landroid/widget/OverScroller;->getFinalY()I

    .line 75
    .line 76
    .line 77
    move-result v4

    .line 78
    if-ne v7, v4, :cond_4

    .line 79
    .line 80
    invoke-virtual {v0}, Landroid/widget/OverScroller;->abortAnimation()V

    .line 81
    .line 82
    .line 83
    move v3, v1

    .line 84
    :cond_4
    if-nez v3, :cond_5

    .line 85
    .line 86
    iget-object v0, p0, Lk6/f;->t:Landroid/view/ViewGroup;

    .line 87
    .line 88
    iget-object v3, p0, Lk6/f;->u:Laq/p;

    .line 89
    .line 90
    invoke-virtual {v0, v3}, Landroid/view/View;->post(Ljava/lang/Runnable;)Z

    .line 91
    .line 92
    .line 93
    :cond_5
    iget p0, p0, Lk6/f;->a:I

    .line 94
    .line 95
    if-ne p0, v2, :cond_6

    .line 96
    .line 97
    const/4 p0, 0x1

    .line 98
    return p0

    .line 99
    :cond_6
    return v1
.end method

.method public final g(II)Landroid/view/View;
    .locals 4

    .line 1
    iget-object v0, p0, Lk6/f;->t:Landroid/view/ViewGroup;

    .line 2
    .line 3
    invoke-virtual {v0}, Landroid/view/ViewGroup;->getChildCount()I

    .line 4
    .line 5
    .line 6
    move-result v1

    .line 7
    add-int/lit8 v1, v1, -0x1

    .line 8
    .line 9
    :goto_0
    if-ltz v1, :cond_1

    .line 10
    .line 11
    iget-object v2, p0, Lk6/f;->q:Lk6/e;

    .line 12
    .line 13
    invoke-virtual {v2, v1}, Lk6/e;->getOrderedChildIndex(I)I

    .line 14
    .line 15
    .line 16
    move-result v2

    .line 17
    invoke-virtual {v0, v2}, Landroid/view/ViewGroup;->getChildAt(I)Landroid/view/View;

    .line 18
    .line 19
    .line 20
    move-result-object v2

    .line 21
    invoke-virtual {v2}, Landroid/view/View;->getLeft()I

    .line 22
    .line 23
    .line 24
    move-result v3

    .line 25
    if-lt p1, v3, :cond_0

    .line 26
    .line 27
    invoke-virtual {v2}, Landroid/view/View;->getRight()I

    .line 28
    .line 29
    .line 30
    move-result v3

    .line 31
    if-ge p1, v3, :cond_0

    .line 32
    .line 33
    invoke-virtual {v2}, Landroid/view/View;->getTop()I

    .line 34
    .line 35
    .line 36
    move-result v3

    .line 37
    if-lt p2, v3, :cond_0

    .line 38
    .line 39
    invoke-virtual {v2}, Landroid/view/View;->getBottom()I

    .line 40
    .line 41
    .line 42
    move-result v3

    .line 43
    if-ge p2, v3, :cond_0

    .line 44
    .line 45
    return-object v2

    .line 46
    :cond_0
    add-int/lit8 v1, v1, -0x1

    .line 47
    .line 48
    goto :goto_0

    .line 49
    :cond_1
    const/4 p0, 0x0

    .line 50
    return-object p0
.end method

.method public final h(IIII)Z
    .locals 10

    .line 1
    iget-object v0, p0, Lk6/f;->r:Landroid/view/View;

    .line 2
    .line 3
    invoke-virtual {v0}, Landroid/view/View;->getLeft()I

    .line 4
    .line 5
    .line 6
    move-result v2

    .line 7
    iget-object v0, p0, Lk6/f;->r:Landroid/view/View;

    .line 8
    .line 9
    invoke-virtual {v0}, Landroid/view/View;->getTop()I

    .line 10
    .line 11
    .line 12
    move-result v3

    .line 13
    sub-int v4, p1, v2

    .line 14
    .line 15
    sub-int v5, p2, v3

    .line 16
    .line 17
    const/4 p1, 0x0

    .line 18
    iget-object v1, p0, Lk6/f;->p:Landroid/widget/OverScroller;

    .line 19
    .line 20
    if-nez v4, :cond_0

    .line 21
    .line 22
    if-nez v5, :cond_0

    .line 23
    .line 24
    invoke-virtual {v1}, Landroid/widget/OverScroller;->abortAnimation()V

    .line 25
    .line 26
    .line 27
    invoke-virtual {p0, p1}, Lk6/f;->n(I)V

    .line 28
    .line 29
    .line 30
    return p1

    .line 31
    :cond_0
    iget-object p2, p0, Lk6/f;->r:Landroid/view/View;

    .line 32
    .line 33
    iget v0, p0, Lk6/f;->n:F

    .line 34
    .line 35
    float-to-int v0, v0

    .line 36
    iget v6, p0, Lk6/f;->m:F

    .line 37
    .line 38
    float-to-int v6, v6

    .line 39
    invoke-static {p3}, Ljava/lang/Math;->abs(I)I

    .line 40
    .line 41
    .line 42
    move-result v7

    .line 43
    if-ge v7, v0, :cond_1

    .line 44
    .line 45
    move p3, p1

    .line 46
    goto :goto_0

    .line 47
    :cond_1
    if-le v7, v6, :cond_3

    .line 48
    .line 49
    if-lez p3, :cond_2

    .line 50
    .line 51
    move p3, v6

    .line 52
    goto :goto_0

    .line 53
    :cond_2
    neg-int p3, v6

    .line 54
    :cond_3
    :goto_0
    invoke-static {p4}, Ljava/lang/Math;->abs(I)I

    .line 55
    .line 56
    .line 57
    move-result v7

    .line 58
    if-ge v7, v0, :cond_4

    .line 59
    .line 60
    move p4, p1

    .line 61
    goto :goto_1

    .line 62
    :cond_4
    if-le v7, v6, :cond_6

    .line 63
    .line 64
    if-lez p4, :cond_5

    .line 65
    .line 66
    move p4, v6

    .line 67
    goto :goto_1

    .line 68
    :cond_5
    neg-int p4, v6

    .line 69
    :cond_6
    :goto_1
    invoke-static {v4}, Ljava/lang/Math;->abs(I)I

    .line 70
    .line 71
    .line 72
    move-result p1

    .line 73
    invoke-static {v5}, Ljava/lang/Math;->abs(I)I

    .line 74
    .line 75
    .line 76
    move-result v0

    .line 77
    invoke-static {p3}, Ljava/lang/Math;->abs(I)I

    .line 78
    .line 79
    .line 80
    move-result v6

    .line 81
    invoke-static {p4}, Ljava/lang/Math;->abs(I)I

    .line 82
    .line 83
    .line 84
    move-result v7

    .line 85
    add-int v8, v6, v7

    .line 86
    .line 87
    add-int v9, p1, v0

    .line 88
    .line 89
    if-eqz p3, :cond_7

    .line 90
    .line 91
    int-to-float p1, v6

    .line 92
    int-to-float v6, v8

    .line 93
    :goto_2
    div-float/2addr p1, v6

    .line 94
    goto :goto_3

    .line 95
    :cond_7
    int-to-float p1, p1

    .line 96
    int-to-float v6, v9

    .line 97
    goto :goto_2

    .line 98
    :goto_3
    if-eqz p4, :cond_8

    .line 99
    .line 100
    int-to-float v0, v7

    .line 101
    int-to-float v6, v8

    .line 102
    :goto_4
    div-float/2addr v0, v6

    .line 103
    goto :goto_5

    .line 104
    :cond_8
    int-to-float v0, v0

    .line 105
    int-to-float v6, v9

    .line 106
    goto :goto_4

    .line 107
    :goto_5
    iget-object v6, p0, Lk6/f;->q:Lk6/e;

    .line 108
    .line 109
    invoke-virtual {v6, p2}, Lk6/e;->getViewHorizontalDragRange(Landroid/view/View;)I

    .line 110
    .line 111
    .line 112
    move-result v7

    .line 113
    invoke-virtual {p0, v4, p3, v7}, Lk6/f;->e(III)I

    .line 114
    .line 115
    .line 116
    move-result p3

    .line 117
    invoke-virtual {v6, p2}, Lk6/e;->getViewVerticalDragRange(Landroid/view/View;)I

    .line 118
    .line 119
    .line 120
    move-result p2

    .line 121
    invoke-virtual {p0, v5, p4, p2}, Lk6/f;->e(III)I

    .line 122
    .line 123
    .line 124
    move-result p2

    .line 125
    int-to-float p3, p3

    .line 126
    mul-float/2addr p3, p1

    .line 127
    int-to-float p1, p2

    .line 128
    mul-float/2addr p1, v0

    .line 129
    add-float/2addr p1, p3

    .line 130
    float-to-int v6, p1

    .line 131
    invoke-virtual/range {v1 .. v6}, Landroid/widget/OverScroller;->startScroll(IIIII)V

    .line 132
    .line 133
    .line 134
    const/4 p1, 0x2

    .line 135
    invoke-virtual {p0, p1}, Lk6/f;->n(I)V

    .line 136
    .line 137
    .line 138
    const/4 p0, 0x1

    .line 139
    return p0
.end method

.method public final i(I)Z
    .locals 2

    .line 1
    iget p0, p0, Lk6/f;->k:I

    .line 2
    .line 3
    const/4 v0, 0x1

    .line 4
    shl-int v1, v0, p1

    .line 5
    .line 6
    and-int/2addr p0, v1

    .line 7
    if-eqz p0, :cond_0

    .line 8
    .line 9
    return v0

    .line 10
    :cond_0
    new-instance p0, Ljava/lang/StringBuilder;

    .line 11
    .line 12
    const-string v0, "Ignoring pointerId="

    .line 13
    .line 14
    invoke-direct {p0, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 15
    .line 16
    .line 17
    invoke-virtual {p0, p1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 18
    .line 19
    .line 20
    const-string p1, " because ACTION_DOWN was not received for this pointer before ACTION_MOVE. It likely happened because  ViewDragHelper did not receive all the events in the event stream."

    .line 21
    .line 22
    invoke-virtual {p0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 23
    .line 24
    .line 25
    invoke-virtual {p0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 26
    .line 27
    .line 28
    move-result-object p0

    .line 29
    const-string p1, "ViewDragHelper"

    .line 30
    .line 31
    invoke-static {p1, p0}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I

    .line 32
    .line 33
    .line 34
    const/4 p0, 0x0

    .line 35
    return p0
.end method

.method public final j(Landroid/view/MotionEvent;)V
    .locals 18

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    invoke-virtual {v1}, Landroid/view/MotionEvent;->getActionMasked()I

    .line 6
    .line 7
    .line 8
    move-result v2

    .line 9
    invoke-virtual {v1}, Landroid/view/MotionEvent;->getActionIndex()I

    .line 10
    .line 11
    .line 12
    move-result v3

    .line 13
    if-nez v2, :cond_0

    .line 14
    .line 15
    invoke-virtual {v0}, Lk6/f;->a()V

    .line 16
    .line 17
    .line 18
    :cond_0
    iget-object v4, v0, Lk6/f;->l:Landroid/view/VelocityTracker;

    .line 19
    .line 20
    if-nez v4, :cond_1

    .line 21
    .line 22
    invoke-static {}, Landroid/view/VelocityTracker;->obtain()Landroid/view/VelocityTracker;

    .line 23
    .line 24
    .line 25
    move-result-object v4

    .line 26
    iput-object v4, v0, Lk6/f;->l:Landroid/view/VelocityTracker;

    .line 27
    .line 28
    :cond_1
    iget-object v4, v0, Lk6/f;->l:Landroid/view/VelocityTracker;

    .line 29
    .line 30
    invoke-virtual {v4, v1}, Landroid/view/VelocityTracker;->addMovement(Landroid/view/MotionEvent;)V

    .line 31
    .line 32
    .line 33
    const/4 v4, 0x0

    .line 34
    if-eqz v2, :cond_1b

    .line 35
    .line 36
    const/4 v5, 0x1

    .line 37
    if-eq v2, v5, :cond_19

    .line 38
    .line 39
    const/4 v6, 0x2

    .line 40
    iget-object v7, v0, Lk6/f;->q:Lk6/e;

    .line 41
    .line 42
    if-eq v2, v6, :cond_d

    .line 43
    .line 44
    const/4 v6, 0x3

    .line 45
    if-eq v2, v6, :cond_b

    .line 46
    .line 47
    const/4 v6, 0x5

    .line 48
    if-eq v2, v6, :cond_7

    .line 49
    .line 50
    const/4 v6, 0x6

    .line 51
    if-eq v2, v6, :cond_2

    .line 52
    .line 53
    goto/16 :goto_4

    .line 54
    .line 55
    :cond_2
    invoke-virtual {v1, v3}, Landroid/view/MotionEvent;->getPointerId(I)I

    .line 56
    .line 57
    .line 58
    move-result v2

    .line 59
    iget v3, v0, Lk6/f;->a:I

    .line 60
    .line 61
    if-ne v3, v5, :cond_6

    .line 62
    .line 63
    iget v3, v0, Lk6/f;->c:I

    .line 64
    .line 65
    if-ne v2, v3, :cond_6

    .line 66
    .line 67
    invoke-virtual {v1}, Landroid/view/MotionEvent;->getPointerCount()I

    .line 68
    .line 69
    .line 70
    move-result v3

    .line 71
    :goto_0
    const/4 v5, -0x1

    .line 72
    if-ge v4, v3, :cond_5

    .line 73
    .line 74
    invoke-virtual {v1, v4}, Landroid/view/MotionEvent;->getPointerId(I)I

    .line 75
    .line 76
    .line 77
    move-result v6

    .line 78
    iget v7, v0, Lk6/f;->c:I

    .line 79
    .line 80
    if-ne v6, v7, :cond_3

    .line 81
    .line 82
    goto :goto_1

    .line 83
    :cond_3
    invoke-virtual {v1, v4}, Landroid/view/MotionEvent;->getX(I)F

    .line 84
    .line 85
    .line 86
    move-result v7

    .line 87
    invoke-virtual {v1, v4}, Landroid/view/MotionEvent;->getY(I)F

    .line 88
    .line 89
    .line 90
    move-result v8

    .line 91
    float-to-int v7, v7

    .line 92
    float-to-int v8, v8

    .line 93
    invoke-virtual {v0, v7, v8}, Lk6/f;->g(II)Landroid/view/View;

    .line 94
    .line 95
    .line 96
    move-result-object v7

    .line 97
    iget-object v8, v0, Lk6/f;->r:Landroid/view/View;

    .line 98
    .line 99
    if-ne v7, v8, :cond_4

    .line 100
    .line 101
    invoke-virtual {v0, v8, v6}, Lk6/f;->q(Landroid/view/View;I)Z

    .line 102
    .line 103
    .line 104
    move-result v6

    .line 105
    if-eqz v6, :cond_4

    .line 106
    .line 107
    iget v1, v0, Lk6/f;->c:I

    .line 108
    .line 109
    goto :goto_2

    .line 110
    :cond_4
    :goto_1
    add-int/lit8 v4, v4, 0x1

    .line 111
    .line 112
    goto :goto_0

    .line 113
    :cond_5
    move v1, v5

    .line 114
    :goto_2
    if-ne v1, v5, :cond_6

    .line 115
    .line 116
    invoke-virtual {v0}, Lk6/f;->k()V

    .line 117
    .line 118
    .line 119
    :cond_6
    invoke-virtual {v0, v2}, Lk6/f;->d(I)V

    .line 120
    .line 121
    .line 122
    return-void

    .line 123
    :cond_7
    invoke-virtual {v1, v3}, Landroid/view/MotionEvent;->getPointerId(I)I

    .line 124
    .line 125
    .line 126
    move-result v2

    .line 127
    invoke-virtual {v1, v3}, Landroid/view/MotionEvent;->getX(I)F

    .line 128
    .line 129
    .line 130
    move-result v6

    .line 131
    invoke-virtual {v1, v3}, Landroid/view/MotionEvent;->getY(I)F

    .line 132
    .line 133
    .line 134
    move-result v1

    .line 135
    invoke-virtual {v0, v6, v1, v2}, Lk6/f;->l(FFI)V

    .line 136
    .line 137
    .line 138
    iget v3, v0, Lk6/f;->a:I

    .line 139
    .line 140
    if-nez v3, :cond_8

    .line 141
    .line 142
    float-to-int v3, v6

    .line 143
    float-to-int v1, v1

    .line 144
    invoke-virtual {v0, v3, v1}, Lk6/f;->g(II)Landroid/view/View;

    .line 145
    .line 146
    .line 147
    move-result-object v1

    .line 148
    invoke-virtual {v0, v1, v2}, Lk6/f;->q(Landroid/view/View;I)Z

    .line 149
    .line 150
    .line 151
    iget-object v0, v0, Lk6/f;->h:[I

    .line 152
    .line 153
    aget v0, v0, v2

    .line 154
    .line 155
    return-void

    .line 156
    :cond_8
    float-to-int v3, v6

    .line 157
    float-to-int v1, v1

    .line 158
    iget-object v6, v0, Lk6/f;->r:Landroid/view/View;

    .line 159
    .line 160
    if-nez v6, :cond_9

    .line 161
    .line 162
    goto :goto_3

    .line 163
    :cond_9
    invoke-virtual {v6}, Landroid/view/View;->getLeft()I

    .line 164
    .line 165
    .line 166
    move-result v7

    .line 167
    if-lt v3, v7, :cond_a

    .line 168
    .line 169
    invoke-virtual {v6}, Landroid/view/View;->getRight()I

    .line 170
    .line 171
    .line 172
    move-result v7

    .line 173
    if-ge v3, v7, :cond_a

    .line 174
    .line 175
    invoke-virtual {v6}, Landroid/view/View;->getTop()I

    .line 176
    .line 177
    .line 178
    move-result v3

    .line 179
    if-lt v1, v3, :cond_a

    .line 180
    .line 181
    invoke-virtual {v6}, Landroid/view/View;->getBottom()I

    .line 182
    .line 183
    .line 184
    move-result v3

    .line 185
    if-ge v1, v3, :cond_a

    .line 186
    .line 187
    move v4, v5

    .line 188
    :cond_a
    :goto_3
    if-eqz v4, :cond_e

    .line 189
    .line 190
    iget-object v1, v0, Lk6/f;->r:Landroid/view/View;

    .line 191
    .line 192
    invoke-virtual {v0, v1, v2}, Lk6/f;->q(Landroid/view/View;I)Z

    .line 193
    .line 194
    .line 195
    return-void

    .line 196
    :cond_b
    iget v1, v0, Lk6/f;->a:I

    .line 197
    .line 198
    if-ne v1, v5, :cond_c

    .line 199
    .line 200
    iput-boolean v5, v0, Lk6/f;->s:Z

    .line 201
    .line 202
    iget-object v1, v0, Lk6/f;->r:Landroid/view/View;

    .line 203
    .line 204
    const/4 v2, 0x0

    .line 205
    invoke-virtual {v7, v1, v2, v2}, Lk6/e;->onViewReleased(Landroid/view/View;FF)V

    .line 206
    .line 207
    .line 208
    iput-boolean v4, v0, Lk6/f;->s:Z

    .line 209
    .line 210
    iget v1, v0, Lk6/f;->a:I

    .line 211
    .line 212
    if-ne v1, v5, :cond_c

    .line 213
    .line 214
    invoke-virtual {v0, v4}, Lk6/f;->n(I)V

    .line 215
    .line 216
    .line 217
    :cond_c
    invoke-virtual {v0}, Lk6/f;->a()V

    .line 218
    .line 219
    .line 220
    return-void

    .line 221
    :cond_d
    iget v2, v0, Lk6/f;->a:I

    .line 222
    .line 223
    if-ne v2, v5, :cond_14

    .line 224
    .line 225
    iget v2, v0, Lk6/f;->c:I

    .line 226
    .line 227
    invoke-virtual {v0, v2}, Lk6/f;->i(I)Z

    .line 228
    .line 229
    .line 230
    move-result v2

    .line 231
    if-nez v2, :cond_f

    .line 232
    .line 233
    :cond_e
    :goto_4
    return-void

    .line 234
    :cond_f
    iget v2, v0, Lk6/f;->c:I

    .line 235
    .line 236
    invoke-virtual {v1, v2}, Landroid/view/MotionEvent;->findPointerIndex(I)I

    .line 237
    .line 238
    .line 239
    move-result v2

    .line 240
    invoke-virtual {v1, v2}, Landroid/view/MotionEvent;->getX(I)F

    .line 241
    .line 242
    .line 243
    move-result v3

    .line 244
    invoke-virtual {v1, v2}, Landroid/view/MotionEvent;->getY(I)F

    .line 245
    .line 246
    .line 247
    move-result v2

    .line 248
    iget-object v4, v0, Lk6/f;->f:[F

    .line 249
    .line 250
    iget v5, v0, Lk6/f;->c:I

    .line 251
    .line 252
    aget v4, v4, v5

    .line 253
    .line 254
    sub-float/2addr v3, v4

    .line 255
    float-to-int v3, v3

    .line 256
    iget-object v4, v0, Lk6/f;->g:[F

    .line 257
    .line 258
    aget v4, v4, v5

    .line 259
    .line 260
    sub-float/2addr v2, v4

    .line 261
    float-to-int v2, v2

    .line 262
    iget-object v4, v0, Lk6/f;->r:Landroid/view/View;

    .line 263
    .line 264
    invoke-virtual {v4}, Landroid/view/View;->getLeft()I

    .line 265
    .line 266
    .line 267
    move-result v4

    .line 268
    add-int/2addr v4, v3

    .line 269
    iget-object v5, v0, Lk6/f;->r:Landroid/view/View;

    .line 270
    .line 271
    invoke-virtual {v5}, Landroid/view/View;->getTop()I

    .line 272
    .line 273
    .line 274
    move-result v5

    .line 275
    add-int/2addr v5, v2

    .line 276
    iget-object v6, v0, Lk6/f;->r:Landroid/view/View;

    .line 277
    .line 278
    invoke-virtual {v6}, Landroid/view/View;->getLeft()I

    .line 279
    .line 280
    .line 281
    move-result v6

    .line 282
    iget-object v8, v0, Lk6/f;->r:Landroid/view/View;

    .line 283
    .line 284
    invoke-virtual {v8}, Landroid/view/View;->getTop()I

    .line 285
    .line 286
    .line 287
    move-result v8

    .line 288
    if-eqz v3, :cond_10

    .line 289
    .line 290
    iget-object v9, v0, Lk6/f;->r:Landroid/view/View;

    .line 291
    .line 292
    invoke-virtual {v7, v9, v4, v3}, Lk6/e;->clampViewPositionHorizontal(Landroid/view/View;II)I

    .line 293
    .line 294
    .line 295
    move-result v4

    .line 296
    iget-object v9, v0, Lk6/f;->r:Landroid/view/View;

    .line 297
    .line 298
    sub-int v10, v4, v6

    .line 299
    .line 300
    sget-object v11, Ld6/r0;->a:Ljava/util/WeakHashMap;

    .line 301
    .line 302
    invoke-virtual {v9, v10}, Landroid/view/View;->offsetLeftAndRight(I)V

    .line 303
    .line 304
    .line 305
    :cond_10
    move v14, v4

    .line 306
    if-eqz v2, :cond_11

    .line 307
    .line 308
    iget-object v4, v0, Lk6/f;->r:Landroid/view/View;

    .line 309
    .line 310
    invoke-virtual {v7, v4, v5, v2}, Lk6/e;->clampViewPositionVertical(Landroid/view/View;II)I

    .line 311
    .line 312
    .line 313
    move-result v5

    .line 314
    iget-object v4, v0, Lk6/f;->r:Landroid/view/View;

    .line 315
    .line 316
    sub-int v7, v5, v8

    .line 317
    .line 318
    sget-object v9, Ld6/r0;->a:Ljava/util/WeakHashMap;

    .line 319
    .line 320
    invoke-virtual {v4, v7}, Landroid/view/View;->offsetTopAndBottom(I)V

    .line 321
    .line 322
    .line 323
    :cond_11
    move v15, v5

    .line 324
    if-nez v3, :cond_12

    .line 325
    .line 326
    if-eqz v2, :cond_13

    .line 327
    .line 328
    :cond_12
    sub-int v16, v14, v6

    .line 329
    .line 330
    sub-int v17, v15, v8

    .line 331
    .line 332
    iget-object v12, v0, Lk6/f;->q:Lk6/e;

    .line 333
    .line 334
    iget-object v13, v0, Lk6/f;->r:Landroid/view/View;

    .line 335
    .line 336
    invoke-virtual/range {v12 .. v17}, Lk6/e;->onViewPositionChanged(Landroid/view/View;IIII)V

    .line 337
    .line 338
    .line 339
    :cond_13
    invoke-virtual/range {p0 .. p1}, Lk6/f;->m(Landroid/view/MotionEvent;)V

    .line 340
    .line 341
    .line 342
    return-void

    .line 343
    :cond_14
    invoke-virtual {v1}, Landroid/view/MotionEvent;->getPointerCount()I

    .line 344
    .line 345
    .line 346
    move-result v2

    .line 347
    :goto_5
    if-ge v4, v2, :cond_18

    .line 348
    .line 349
    invoke-virtual {v1, v4}, Landroid/view/MotionEvent;->getPointerId(I)I

    .line 350
    .line 351
    .line 352
    move-result v3

    .line 353
    invoke-virtual {v0, v3}, Lk6/f;->i(I)Z

    .line 354
    .line 355
    .line 356
    move-result v6

    .line 357
    if-nez v6, :cond_15

    .line 358
    .line 359
    goto :goto_6

    .line 360
    :cond_15
    invoke-virtual {v1, v4}, Landroid/view/MotionEvent;->getX(I)F

    .line 361
    .line 362
    .line 363
    move-result v6

    .line 364
    invoke-virtual {v1, v4}, Landroid/view/MotionEvent;->getY(I)F

    .line 365
    .line 366
    .line 367
    move-result v7

    .line 368
    iget-object v8, v0, Lk6/f;->d:[F

    .line 369
    .line 370
    aget v8, v8, v3

    .line 371
    .line 372
    sub-float v8, v6, v8

    .line 373
    .line 374
    iget-object v9, v0, Lk6/f;->e:[F

    .line 375
    .line 376
    aget v9, v9, v3

    .line 377
    .line 378
    sub-float v9, v7, v9

    .line 379
    .line 380
    invoke-static {v8}, Ljava/lang/Math;->abs(F)F

    .line 381
    .line 382
    .line 383
    invoke-static {v9}, Ljava/lang/Math;->abs(F)F

    .line 384
    .line 385
    .line 386
    iget-object v10, v0, Lk6/f;->h:[I

    .line 387
    .line 388
    aget v10, v10, v3

    .line 389
    .line 390
    invoke-static {v9}, Ljava/lang/Math;->abs(F)F

    .line 391
    .line 392
    .line 393
    invoke-static {v8}, Ljava/lang/Math;->abs(F)F

    .line 394
    .line 395
    .line 396
    iget-object v10, v0, Lk6/f;->h:[I

    .line 397
    .line 398
    aget v10, v10, v3

    .line 399
    .line 400
    invoke-static {v8}, Ljava/lang/Math;->abs(F)F

    .line 401
    .line 402
    .line 403
    invoke-static {v9}, Ljava/lang/Math;->abs(F)F

    .line 404
    .line 405
    .line 406
    iget-object v10, v0, Lk6/f;->h:[I

    .line 407
    .line 408
    aget v10, v10, v3

    .line 409
    .line 410
    invoke-static {v9}, Ljava/lang/Math;->abs(F)F

    .line 411
    .line 412
    .line 413
    invoke-static {v8}, Ljava/lang/Math;->abs(F)F

    .line 414
    .line 415
    .line 416
    iget-object v10, v0, Lk6/f;->h:[I

    .line 417
    .line 418
    aget v10, v10, v3

    .line 419
    .line 420
    iget v10, v0, Lk6/f;->a:I

    .line 421
    .line 422
    if-ne v10, v5, :cond_16

    .line 423
    .line 424
    goto :goto_7

    .line 425
    :cond_16
    float-to-int v6, v6

    .line 426
    float-to-int v7, v7

    .line 427
    invoke-virtual {v0, v6, v7}, Lk6/f;->g(II)Landroid/view/View;

    .line 428
    .line 429
    .line 430
    move-result-object v6

    .line 431
    invoke-virtual {v0, v6, v8, v9}, Lk6/f;->c(Landroid/view/View;FF)Z

    .line 432
    .line 433
    .line 434
    move-result v7

    .line 435
    if-eqz v7, :cond_17

    .line 436
    .line 437
    invoke-virtual {v0, v6, v3}, Lk6/f;->q(Landroid/view/View;I)Z

    .line 438
    .line 439
    .line 440
    move-result v3

    .line 441
    if-eqz v3, :cond_17

    .line 442
    .line 443
    goto :goto_7

    .line 444
    :cond_17
    :goto_6
    add-int/lit8 v4, v4, 0x1

    .line 445
    .line 446
    goto :goto_5

    .line 447
    :cond_18
    :goto_7
    invoke-virtual/range {p0 .. p1}, Lk6/f;->m(Landroid/view/MotionEvent;)V

    .line 448
    .line 449
    .line 450
    return-void

    .line 451
    :cond_19
    iget v1, v0, Lk6/f;->a:I

    .line 452
    .line 453
    if-ne v1, v5, :cond_1a

    .line 454
    .line 455
    invoke-virtual {v0}, Lk6/f;->k()V

    .line 456
    .line 457
    .line 458
    :cond_1a
    invoke-virtual {v0}, Lk6/f;->a()V

    .line 459
    .line 460
    .line 461
    return-void

    .line 462
    :cond_1b
    invoke-virtual {v1}, Landroid/view/MotionEvent;->getX()F

    .line 463
    .line 464
    .line 465
    move-result v2

    .line 466
    invoke-virtual {v1}, Landroid/view/MotionEvent;->getY()F

    .line 467
    .line 468
    .line 469
    move-result v3

    .line 470
    invoke-virtual {v1, v4}, Landroid/view/MotionEvent;->getPointerId(I)I

    .line 471
    .line 472
    .line 473
    move-result v1

    .line 474
    float-to-int v4, v2

    .line 475
    float-to-int v5, v3

    .line 476
    invoke-virtual {v0, v4, v5}, Lk6/f;->g(II)Landroid/view/View;

    .line 477
    .line 478
    .line 479
    move-result-object v4

    .line 480
    invoke-virtual {v0, v2, v3, v1}, Lk6/f;->l(FFI)V

    .line 481
    .line 482
    .line 483
    invoke-virtual {v0, v4, v1}, Lk6/f;->q(Landroid/view/View;I)Z

    .line 484
    .line 485
    .line 486
    iget-object v0, v0, Lk6/f;->h:[I

    .line 487
    .line 488
    aget v0, v0, v1

    .line 489
    .line 490
    return-void
.end method

.method public final k()V
    .locals 6

    .line 1
    iget-object v0, p0, Lk6/f;->l:Landroid/view/VelocityTracker;

    .line 2
    .line 3
    const/16 v1, 0x3e8

    .line 4
    .line 5
    iget v2, p0, Lk6/f;->m:F

    .line 6
    .line 7
    invoke-virtual {v0, v1, v2}, Landroid/view/VelocityTracker;->computeCurrentVelocity(IF)V

    .line 8
    .line 9
    .line 10
    iget-object v0, p0, Lk6/f;->l:Landroid/view/VelocityTracker;

    .line 11
    .line 12
    iget v1, p0, Lk6/f;->c:I

    .line 13
    .line 14
    invoke-virtual {v0, v1}, Landroid/view/VelocityTracker;->getXVelocity(I)F

    .line 15
    .line 16
    .line 17
    move-result v0

    .line 18
    invoke-static {v0}, Ljava/lang/Math;->abs(F)F

    .line 19
    .line 20
    .line 21
    move-result v1

    .line 22
    iget v3, p0, Lk6/f;->n:F

    .line 23
    .line 24
    cmpg-float v4, v1, v3

    .line 25
    .line 26
    const/4 v5, 0x0

    .line 27
    if-gez v4, :cond_0

    .line 28
    .line 29
    move v0, v5

    .line 30
    goto :goto_0

    .line 31
    :cond_0
    cmpl-float v1, v1, v2

    .line 32
    .line 33
    if-lez v1, :cond_2

    .line 34
    .line 35
    cmpl-float v0, v0, v5

    .line 36
    .line 37
    if-lez v0, :cond_1

    .line 38
    .line 39
    move v0, v2

    .line 40
    goto :goto_0

    .line 41
    :cond_1
    neg-float v0, v2

    .line 42
    :cond_2
    :goto_0
    iget-object v1, p0, Lk6/f;->l:Landroid/view/VelocityTracker;

    .line 43
    .line 44
    iget v4, p0, Lk6/f;->c:I

    .line 45
    .line 46
    invoke-virtual {v1, v4}, Landroid/view/VelocityTracker;->getYVelocity(I)F

    .line 47
    .line 48
    .line 49
    move-result v1

    .line 50
    invoke-static {v1}, Ljava/lang/Math;->abs(F)F

    .line 51
    .line 52
    .line 53
    move-result v4

    .line 54
    cmpg-float v3, v4, v3

    .line 55
    .line 56
    if-gez v3, :cond_3

    .line 57
    .line 58
    move v2, v5

    .line 59
    goto :goto_1

    .line 60
    :cond_3
    cmpl-float v3, v4, v2

    .line 61
    .line 62
    if-lez v3, :cond_5

    .line 63
    .line 64
    cmpl-float v1, v1, v5

    .line 65
    .line 66
    if-lez v1, :cond_4

    .line 67
    .line 68
    goto :goto_1

    .line 69
    :cond_4
    neg-float v2, v2

    .line 70
    goto :goto_1

    .line 71
    :cond_5
    move v2, v1

    .line 72
    :goto_1
    const/4 v1, 0x1

    .line 73
    iput-boolean v1, p0, Lk6/f;->s:Z

    .line 74
    .line 75
    iget-object v3, p0, Lk6/f;->q:Lk6/e;

    .line 76
    .line 77
    iget-object v4, p0, Lk6/f;->r:Landroid/view/View;

    .line 78
    .line 79
    invoke-virtual {v3, v4, v0, v2}, Lk6/e;->onViewReleased(Landroid/view/View;FF)V

    .line 80
    .line 81
    .line 82
    const/4 v0, 0x0

    .line 83
    iput-boolean v0, p0, Lk6/f;->s:Z

    .line 84
    .line 85
    iget v2, p0, Lk6/f;->a:I

    .line 86
    .line 87
    if-ne v2, v1, :cond_6

    .line 88
    .line 89
    invoke-virtual {p0, v0}, Lk6/f;->n(I)V

    .line 90
    .line 91
    .line 92
    :cond_6
    return-void
.end method

.method public final l(FFI)V
    .locals 10

    .line 1
    iget-object v0, p0, Lk6/f;->d:[F

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    if-eqz v0, :cond_0

    .line 5
    .line 6
    array-length v2, v0

    .line 7
    if-gt v2, p3, :cond_2

    .line 8
    .line 9
    :cond_0
    add-int/lit8 v2, p3, 0x1

    .line 10
    .line 11
    new-array v3, v2, [F

    .line 12
    .line 13
    new-array v4, v2, [F

    .line 14
    .line 15
    new-array v5, v2, [F

    .line 16
    .line 17
    new-array v6, v2, [F

    .line 18
    .line 19
    new-array v7, v2, [I

    .line 20
    .line 21
    new-array v8, v2, [I

    .line 22
    .line 23
    new-array v2, v2, [I

    .line 24
    .line 25
    if-eqz v0, :cond_1

    .line 26
    .line 27
    array-length v9, v0

    .line 28
    invoke-static {v0, v1, v3, v1, v9}, Ljava/lang/System;->arraycopy(Ljava/lang/Object;ILjava/lang/Object;II)V

    .line 29
    .line 30
    .line 31
    iget-object v0, p0, Lk6/f;->e:[F

    .line 32
    .line 33
    array-length v9, v0

    .line 34
    invoke-static {v0, v1, v4, v1, v9}, Ljava/lang/System;->arraycopy(Ljava/lang/Object;ILjava/lang/Object;II)V

    .line 35
    .line 36
    .line 37
    iget-object v0, p0, Lk6/f;->f:[F

    .line 38
    .line 39
    array-length v9, v0

    .line 40
    invoke-static {v0, v1, v5, v1, v9}, Ljava/lang/System;->arraycopy(Ljava/lang/Object;ILjava/lang/Object;II)V

    .line 41
    .line 42
    .line 43
    iget-object v0, p0, Lk6/f;->g:[F

    .line 44
    .line 45
    array-length v9, v0

    .line 46
    invoke-static {v0, v1, v6, v1, v9}, Ljava/lang/System;->arraycopy(Ljava/lang/Object;ILjava/lang/Object;II)V

    .line 47
    .line 48
    .line 49
    iget-object v0, p0, Lk6/f;->h:[I

    .line 50
    .line 51
    array-length v9, v0

    .line 52
    invoke-static {v0, v1, v7, v1, v9}, Ljava/lang/System;->arraycopy(Ljava/lang/Object;ILjava/lang/Object;II)V

    .line 53
    .line 54
    .line 55
    iget-object v0, p0, Lk6/f;->i:[I

    .line 56
    .line 57
    array-length v9, v0

    .line 58
    invoke-static {v0, v1, v8, v1, v9}, Ljava/lang/System;->arraycopy(Ljava/lang/Object;ILjava/lang/Object;II)V

    .line 59
    .line 60
    .line 61
    iget-object v0, p0, Lk6/f;->j:[I

    .line 62
    .line 63
    array-length v9, v0

    .line 64
    invoke-static {v0, v1, v2, v1, v9}, Ljava/lang/System;->arraycopy(Ljava/lang/Object;ILjava/lang/Object;II)V

    .line 65
    .line 66
    .line 67
    :cond_1
    iput-object v3, p0, Lk6/f;->d:[F

    .line 68
    .line 69
    iput-object v4, p0, Lk6/f;->e:[F

    .line 70
    .line 71
    iput-object v5, p0, Lk6/f;->f:[F

    .line 72
    .line 73
    iput-object v6, p0, Lk6/f;->g:[F

    .line 74
    .line 75
    iput-object v7, p0, Lk6/f;->h:[I

    .line 76
    .line 77
    iput-object v8, p0, Lk6/f;->i:[I

    .line 78
    .line 79
    iput-object v2, p0, Lk6/f;->j:[I

    .line 80
    .line 81
    :cond_2
    iget-object v0, p0, Lk6/f;->d:[F

    .line 82
    .line 83
    iget-object v2, p0, Lk6/f;->f:[F

    .line 84
    .line 85
    aput p1, v2, p3

    .line 86
    .line 87
    aput p1, v0, p3

    .line 88
    .line 89
    iget-object v0, p0, Lk6/f;->e:[F

    .line 90
    .line 91
    iget-object v2, p0, Lk6/f;->g:[F

    .line 92
    .line 93
    aput p2, v2, p3

    .line 94
    .line 95
    aput p2, v0, p3

    .line 96
    .line 97
    iget-object v0, p0, Lk6/f;->h:[I

    .line 98
    .line 99
    float-to-int p1, p1

    .line 100
    float-to-int p2, p2

    .line 101
    iget-object v2, p0, Lk6/f;->t:Landroid/view/ViewGroup;

    .line 102
    .line 103
    invoke-virtual {v2}, Landroid/view/View;->getLeft()I

    .line 104
    .line 105
    .line 106
    move-result v3

    .line 107
    iget v4, p0, Lk6/f;->o:I

    .line 108
    .line 109
    add-int/2addr v3, v4

    .line 110
    const/4 v5, 0x1

    .line 111
    if-ge p1, v3, :cond_3

    .line 112
    .line 113
    move v1, v5

    .line 114
    :cond_3
    invoke-virtual {v2}, Landroid/view/View;->getTop()I

    .line 115
    .line 116
    .line 117
    move-result v3

    .line 118
    add-int/2addr v3, v4

    .line 119
    if-ge p2, v3, :cond_4

    .line 120
    .line 121
    or-int/lit8 v1, v1, 0x4

    .line 122
    .line 123
    :cond_4
    invoke-virtual {v2}, Landroid/view/View;->getRight()I

    .line 124
    .line 125
    .line 126
    move-result v3

    .line 127
    sub-int/2addr v3, v4

    .line 128
    if-le p1, v3, :cond_5

    .line 129
    .line 130
    or-int/lit8 v1, v1, 0x2

    .line 131
    .line 132
    :cond_5
    invoke-virtual {v2}, Landroid/view/View;->getBottom()I

    .line 133
    .line 134
    .line 135
    move-result p1

    .line 136
    sub-int/2addr p1, v4

    .line 137
    if-le p2, p1, :cond_6

    .line 138
    .line 139
    or-int/lit8 v1, v1, 0x8

    .line 140
    .line 141
    :cond_6
    aput v1, v0, p3

    .line 142
    .line 143
    iget p1, p0, Lk6/f;->k:I

    .line 144
    .line 145
    shl-int p2, v5, p3

    .line 146
    .line 147
    or-int/2addr p1, p2

    .line 148
    iput p1, p0, Lk6/f;->k:I

    .line 149
    .line 150
    return-void
.end method

.method public final m(Landroid/view/MotionEvent;)V
    .locals 6

    .line 1
    invoke-virtual {p1}, Landroid/view/MotionEvent;->getPointerCount()I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    const/4 v1, 0x0

    .line 6
    :goto_0
    if-ge v1, v0, :cond_1

    .line 7
    .line 8
    invoke-virtual {p1, v1}, Landroid/view/MotionEvent;->getPointerId(I)I

    .line 9
    .line 10
    .line 11
    move-result v2

    .line 12
    invoke-virtual {p0, v2}, Lk6/f;->i(I)Z

    .line 13
    .line 14
    .line 15
    move-result v3

    .line 16
    if-nez v3, :cond_0

    .line 17
    .line 18
    goto :goto_1

    .line 19
    :cond_0
    invoke-virtual {p1, v1}, Landroid/view/MotionEvent;->getX(I)F

    .line 20
    .line 21
    .line 22
    move-result v3

    .line 23
    invoke-virtual {p1, v1}, Landroid/view/MotionEvent;->getY(I)F

    .line 24
    .line 25
    .line 26
    move-result v4

    .line 27
    iget-object v5, p0, Lk6/f;->f:[F

    .line 28
    .line 29
    aput v3, v5, v2

    .line 30
    .line 31
    iget-object v3, p0, Lk6/f;->g:[F

    .line 32
    .line 33
    aput v4, v3, v2

    .line 34
    .line 35
    :goto_1
    add-int/lit8 v1, v1, 0x1

    .line 36
    .line 37
    goto :goto_0

    .line 38
    :cond_1
    return-void
.end method

.method public final n(I)V
    .locals 2

    .line 1
    iget-object v0, p0, Lk6/f;->t:Landroid/view/ViewGroup;

    .line 2
    .line 3
    iget-object v1, p0, Lk6/f;->u:Laq/p;

    .line 4
    .line 5
    invoke-virtual {v0, v1}, Landroid/view/View;->removeCallbacks(Ljava/lang/Runnable;)Z

    .line 6
    .line 7
    .line 8
    iget v0, p0, Lk6/f;->a:I

    .line 9
    .line 10
    if-eq v0, p1, :cond_0

    .line 11
    .line 12
    iput p1, p0, Lk6/f;->a:I

    .line 13
    .line 14
    iget-object v0, p0, Lk6/f;->q:Lk6/e;

    .line 15
    .line 16
    invoke-virtual {v0, p1}, Lk6/e;->onViewDragStateChanged(I)V

    .line 17
    .line 18
    .line 19
    iget p1, p0, Lk6/f;->a:I

    .line 20
    .line 21
    if-nez p1, :cond_0

    .line 22
    .line 23
    const/4 p1, 0x0

    .line 24
    iput-object p1, p0, Lk6/f;->r:Landroid/view/View;

    .line 25
    .line 26
    :cond_0
    return-void
.end method

.method public final o(II)Z
    .locals 3

    .line 1
    iget-boolean v0, p0, Lk6/f;->s:Z

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    iget-object v0, p0, Lk6/f;->l:Landroid/view/VelocityTracker;

    .line 6
    .line 7
    iget v1, p0, Lk6/f;->c:I

    .line 8
    .line 9
    invoke-virtual {v0, v1}, Landroid/view/VelocityTracker;->getXVelocity(I)F

    .line 10
    .line 11
    .line 12
    move-result v0

    .line 13
    float-to-int v0, v0

    .line 14
    iget-object v1, p0, Lk6/f;->l:Landroid/view/VelocityTracker;

    .line 15
    .line 16
    iget v2, p0, Lk6/f;->c:I

    .line 17
    .line 18
    invoke-virtual {v1, v2}, Landroid/view/VelocityTracker;->getYVelocity(I)F

    .line 19
    .line 20
    .line 21
    move-result v1

    .line 22
    float-to-int v1, v1

    .line 23
    invoke-virtual {p0, p1, p2, v0, v1}, Lk6/f;->h(IIII)Z

    .line 24
    .line 25
    .line 26
    move-result p0

    .line 27
    return p0

    .line 28
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 29
    .line 30
    const-string p1, "Cannot settleCapturedViewAt outside of a call to Callback#onViewReleased"

    .line 31
    .line 32
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 33
    .line 34
    .line 35
    throw p0
.end method

.method public final p(Landroid/view/MotionEvent;)Z
    .locals 17

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    invoke-virtual {v1}, Landroid/view/MotionEvent;->getActionMasked()I

    .line 6
    .line 7
    .line 8
    move-result v2

    .line 9
    invoke-virtual {v1}, Landroid/view/MotionEvent;->getActionIndex()I

    .line 10
    .line 11
    .line 12
    move-result v3

    .line 13
    if-nez v2, :cond_0

    .line 14
    .line 15
    invoke-virtual {v0}, Lk6/f;->a()V

    .line 16
    .line 17
    .line 18
    :cond_0
    iget-object v4, v0, Lk6/f;->l:Landroid/view/VelocityTracker;

    .line 19
    .line 20
    if-nez v4, :cond_1

    .line 21
    .line 22
    invoke-static {}, Landroid/view/VelocityTracker;->obtain()Landroid/view/VelocityTracker;

    .line 23
    .line 24
    .line 25
    move-result-object v4

    .line 26
    iput-object v4, v0, Lk6/f;->l:Landroid/view/VelocityTracker;

    .line 27
    .line 28
    :cond_1
    iget-object v4, v0, Lk6/f;->l:Landroid/view/VelocityTracker;

    .line 29
    .line 30
    invoke-virtual {v4, v1}, Landroid/view/VelocityTracker;->addMovement(Landroid/view/MotionEvent;)V

    .line 31
    .line 32
    .line 33
    const/4 v4, 0x2

    .line 34
    const/4 v6, 0x1

    .line 35
    if-eqz v2, :cond_f

    .line 36
    .line 37
    if-eq v2, v6, :cond_e

    .line 38
    .line 39
    if-eq v2, v4, :cond_5

    .line 40
    .line 41
    const/4 v7, 0x3

    .line 42
    if-eq v2, v7, :cond_e

    .line 43
    .line 44
    const/4 v7, 0x5

    .line 45
    if-eq v2, v7, :cond_3

    .line 46
    .line 47
    const/4 v4, 0x6

    .line 48
    if-eq v2, v4, :cond_2

    .line 49
    .line 50
    goto/16 :goto_4

    .line 51
    .line 52
    :cond_2
    invoke-virtual {v1, v3}, Landroid/view/MotionEvent;->getPointerId(I)I

    .line 53
    .line 54
    .line 55
    move-result v1

    .line 56
    invoke-virtual {v0, v1}, Lk6/f;->d(I)V

    .line 57
    .line 58
    .line 59
    goto/16 :goto_4

    .line 60
    .line 61
    :cond_3
    invoke-virtual {v1, v3}, Landroid/view/MotionEvent;->getPointerId(I)I

    .line 62
    .line 63
    .line 64
    move-result v2

    .line 65
    invoke-virtual {v1, v3}, Landroid/view/MotionEvent;->getX(I)F

    .line 66
    .line 67
    .line 68
    move-result v7

    .line 69
    invoke-virtual {v1, v3}, Landroid/view/MotionEvent;->getY(I)F

    .line 70
    .line 71
    .line 72
    move-result v1

    .line 73
    invoke-virtual {v0, v7, v1, v2}, Lk6/f;->l(FFI)V

    .line 74
    .line 75
    .line 76
    iget v3, v0, Lk6/f;->a:I

    .line 77
    .line 78
    if-nez v3, :cond_4

    .line 79
    .line 80
    iget-object v1, v0, Lk6/f;->h:[I

    .line 81
    .line 82
    aget v1, v1, v2

    .line 83
    .line 84
    goto/16 :goto_4

    .line 85
    .line 86
    :cond_4
    if-ne v3, v4, :cond_11

    .line 87
    .line 88
    float-to-int v3, v7

    .line 89
    float-to-int v1, v1

    .line 90
    invoke-virtual {v0, v3, v1}, Lk6/f;->g(II)Landroid/view/View;

    .line 91
    .line 92
    .line 93
    move-result-object v1

    .line 94
    iget-object v3, v0, Lk6/f;->r:Landroid/view/View;

    .line 95
    .line 96
    if-ne v1, v3, :cond_11

    .line 97
    .line 98
    invoke-virtual {v0, v1, v2}, Lk6/f;->q(Landroid/view/View;I)Z

    .line 99
    .line 100
    .line 101
    goto/16 :goto_4

    .line 102
    .line 103
    :cond_5
    iget-object v2, v0, Lk6/f;->d:[F

    .line 104
    .line 105
    if-eqz v2, :cond_11

    .line 106
    .line 107
    iget-object v2, v0, Lk6/f;->e:[F

    .line 108
    .line 109
    if-nez v2, :cond_6

    .line 110
    .line 111
    goto/16 :goto_4

    .line 112
    .line 113
    :cond_6
    invoke-virtual {v1}, Landroid/view/MotionEvent;->getPointerCount()I

    .line 114
    .line 115
    .line 116
    move-result v2

    .line 117
    const/4 v3, 0x0

    .line 118
    :goto_0
    if-ge v3, v2, :cond_d

    .line 119
    .line 120
    invoke-virtual {v1, v3}, Landroid/view/MotionEvent;->getPointerId(I)I

    .line 121
    .line 122
    .line 123
    move-result v4

    .line 124
    invoke-virtual {v0, v4}, Lk6/f;->i(I)Z

    .line 125
    .line 126
    .line 127
    move-result v7

    .line 128
    if-nez v7, :cond_7

    .line 129
    .line 130
    goto/16 :goto_2

    .line 131
    .line 132
    :cond_7
    invoke-virtual {v1, v3}, Landroid/view/MotionEvent;->getX(I)F

    .line 133
    .line 134
    .line 135
    move-result v7

    .line 136
    invoke-virtual {v1, v3}, Landroid/view/MotionEvent;->getY(I)F

    .line 137
    .line 138
    .line 139
    move-result v8

    .line 140
    iget-object v9, v0, Lk6/f;->d:[F

    .line 141
    .line 142
    aget v9, v9, v4

    .line 143
    .line 144
    sub-float v9, v7, v9

    .line 145
    .line 146
    iget-object v10, v0, Lk6/f;->e:[F

    .line 147
    .line 148
    aget v10, v10, v4

    .line 149
    .line 150
    sub-float v10, v8, v10

    .line 151
    .line 152
    float-to-int v7, v7

    .line 153
    float-to-int v8, v8

    .line 154
    invoke-virtual {v0, v7, v8}, Lk6/f;->g(II)Landroid/view/View;

    .line 155
    .line 156
    .line 157
    move-result-object v7

    .line 158
    if-eqz v7, :cond_8

    .line 159
    .line 160
    invoke-virtual {v0, v7, v9, v10}, Lk6/f;->c(Landroid/view/View;FF)Z

    .line 161
    .line 162
    .line 163
    move-result v8

    .line 164
    if-eqz v8, :cond_8

    .line 165
    .line 166
    move v8, v6

    .line 167
    goto :goto_1

    .line 168
    :cond_8
    const/4 v8, 0x0

    .line 169
    :goto_1
    if-eqz v8, :cond_a

    .line 170
    .line 171
    invoke-virtual {v7}, Landroid/view/View;->getLeft()I

    .line 172
    .line 173
    .line 174
    move-result v11

    .line 175
    float-to-int v12, v9

    .line 176
    add-int v13, v11, v12

    .line 177
    .line 178
    iget-object v14, v0, Lk6/f;->q:Lk6/e;

    .line 179
    .line 180
    invoke-virtual {v14, v7, v13, v12}, Lk6/e;->clampViewPositionHorizontal(Landroid/view/View;II)I

    .line 181
    .line 182
    .line 183
    move-result v12

    .line 184
    invoke-virtual {v7}, Landroid/view/View;->getTop()I

    .line 185
    .line 186
    .line 187
    move-result v13

    .line 188
    float-to-int v15, v10

    .line 189
    add-int v5, v13, v15

    .line 190
    .line 191
    invoke-virtual {v14, v7, v5, v15}, Lk6/e;->clampViewPositionVertical(Landroid/view/View;II)I

    .line 192
    .line 193
    .line 194
    move-result v5

    .line 195
    invoke-virtual {v14, v7}, Lk6/e;->getViewHorizontalDragRange(Landroid/view/View;)I

    .line 196
    .line 197
    .line 198
    move-result v15

    .line 199
    invoke-virtual {v14, v7}, Lk6/e;->getViewVerticalDragRange(Landroid/view/View;)I

    .line 200
    .line 201
    .line 202
    move-result v14

    .line 203
    if-eqz v15, :cond_9

    .line 204
    .line 205
    if-lez v15, :cond_a

    .line 206
    .line 207
    if-ne v12, v11, :cond_a

    .line 208
    .line 209
    :cond_9
    if-eqz v14, :cond_d

    .line 210
    .line 211
    if-lez v14, :cond_a

    .line 212
    .line 213
    if-ne v5, v13, :cond_a

    .line 214
    .line 215
    goto :goto_3

    .line 216
    :cond_a
    invoke-static {v9}, Ljava/lang/Math;->abs(F)F

    .line 217
    .line 218
    .line 219
    invoke-static {v10}, Ljava/lang/Math;->abs(F)F

    .line 220
    .line 221
    .line 222
    iget-object v5, v0, Lk6/f;->h:[I

    .line 223
    .line 224
    aget v5, v5, v4

    .line 225
    .line 226
    invoke-static {v10}, Ljava/lang/Math;->abs(F)F

    .line 227
    .line 228
    .line 229
    invoke-static {v9}, Ljava/lang/Math;->abs(F)F

    .line 230
    .line 231
    .line 232
    iget-object v5, v0, Lk6/f;->h:[I

    .line 233
    .line 234
    aget v5, v5, v4

    .line 235
    .line 236
    invoke-static {v9}, Ljava/lang/Math;->abs(F)F

    .line 237
    .line 238
    .line 239
    invoke-static {v10}, Ljava/lang/Math;->abs(F)F

    .line 240
    .line 241
    .line 242
    iget-object v5, v0, Lk6/f;->h:[I

    .line 243
    .line 244
    aget v5, v5, v4

    .line 245
    .line 246
    invoke-static {v10}, Ljava/lang/Math;->abs(F)F

    .line 247
    .line 248
    .line 249
    invoke-static {v9}, Ljava/lang/Math;->abs(F)F

    .line 250
    .line 251
    .line 252
    iget-object v5, v0, Lk6/f;->h:[I

    .line 253
    .line 254
    aget v5, v5, v4

    .line 255
    .line 256
    iget v5, v0, Lk6/f;->a:I

    .line 257
    .line 258
    if-ne v5, v6, :cond_b

    .line 259
    .line 260
    goto :goto_3

    .line 261
    :cond_b
    if-eqz v8, :cond_c

    .line 262
    .line 263
    invoke-virtual {v0, v7, v4}, Lk6/f;->q(Landroid/view/View;I)Z

    .line 264
    .line 265
    .line 266
    move-result v4

    .line 267
    if-eqz v4, :cond_c

    .line 268
    .line 269
    goto :goto_3

    .line 270
    :cond_c
    :goto_2
    add-int/lit8 v3, v3, 0x1

    .line 271
    .line 272
    goto/16 :goto_0

    .line 273
    .line 274
    :cond_d
    :goto_3
    invoke-virtual/range {p0 .. p1}, Lk6/f;->m(Landroid/view/MotionEvent;)V

    .line 275
    .line 276
    .line 277
    goto :goto_4

    .line 278
    :cond_e
    invoke-virtual {v0}, Lk6/f;->a()V

    .line 279
    .line 280
    .line 281
    goto :goto_4

    .line 282
    :cond_f
    invoke-virtual {v1}, Landroid/view/MotionEvent;->getX()F

    .line 283
    .line 284
    .line 285
    move-result v2

    .line 286
    invoke-virtual {v1}, Landroid/view/MotionEvent;->getY()F

    .line 287
    .line 288
    .line 289
    move-result v3

    .line 290
    const/4 v5, 0x0

    .line 291
    invoke-virtual {v1, v5}, Landroid/view/MotionEvent;->getPointerId(I)I

    .line 292
    .line 293
    .line 294
    move-result v1

    .line 295
    invoke-virtual {v0, v2, v3, v1}, Lk6/f;->l(FFI)V

    .line 296
    .line 297
    .line 298
    float-to-int v2, v2

    .line 299
    float-to-int v3, v3

    .line 300
    invoke-virtual {v0, v2, v3}, Lk6/f;->g(II)Landroid/view/View;

    .line 301
    .line 302
    .line 303
    move-result-object v2

    .line 304
    iget-object v3, v0, Lk6/f;->r:Landroid/view/View;

    .line 305
    .line 306
    if-ne v2, v3, :cond_10

    .line 307
    .line 308
    iget v3, v0, Lk6/f;->a:I

    .line 309
    .line 310
    if-ne v3, v4, :cond_10

    .line 311
    .line 312
    invoke-virtual {v0, v2, v1}, Lk6/f;->q(Landroid/view/View;I)Z

    .line 313
    .line 314
    .line 315
    :cond_10
    iget-object v2, v0, Lk6/f;->h:[I

    .line 316
    .line 317
    aget v1, v2, v1

    .line 318
    .line 319
    :cond_11
    :goto_4
    iget v0, v0, Lk6/f;->a:I

    .line 320
    .line 321
    if-ne v0, v6, :cond_12

    .line 322
    .line 323
    return v6

    .line 324
    :cond_12
    const/16 v16, 0x0

    .line 325
    .line 326
    return v16
.end method

.method public final q(Landroid/view/View;I)Z
    .locals 2

    .line 1
    iget-object v0, p0, Lk6/f;->r:Landroid/view/View;

    .line 2
    .line 3
    const/4 v1, 0x1

    .line 4
    if-ne p1, v0, :cond_0

    .line 5
    .line 6
    iget v0, p0, Lk6/f;->c:I

    .line 7
    .line 8
    if-ne v0, p2, :cond_0

    .line 9
    .line 10
    return v1

    .line 11
    :cond_0
    if-eqz p1, :cond_1

    .line 12
    .line 13
    iget-object v0, p0, Lk6/f;->q:Lk6/e;

    .line 14
    .line 15
    invoke-virtual {v0, p1, p2}, Lk6/e;->tryCaptureView(Landroid/view/View;I)Z

    .line 16
    .line 17
    .line 18
    move-result v0

    .line 19
    if-eqz v0, :cond_1

    .line 20
    .line 21
    iput p2, p0, Lk6/f;->c:I

    .line 22
    .line 23
    invoke-virtual {p0, p1, p2}, Lk6/f;->b(Landroid/view/View;I)V

    .line 24
    .line 25
    .line 26
    return v1

    .line 27
    :cond_1
    const/4 p0, 0x0

    .line 28
    return p0
.end method
