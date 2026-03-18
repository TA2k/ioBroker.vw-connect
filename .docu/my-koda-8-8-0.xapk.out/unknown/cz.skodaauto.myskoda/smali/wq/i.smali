.class public Lwq/i;
.super Landroid/graphics/drawable/Drawable;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lwq/v;


# static fields
.field public static final F:[Lwq/h;


# instance fields
.field public A:Lr6/f;

.field public final B:[Lr6/e;

.field public C:[F

.field public D:[F

.field public E:Lgr/k;

.field public final d:Lro/f;

.field public e:Lwq/g;

.field public final f:[Lwq/t;

.field public final g:[Lwq/t;

.field public final h:Ljava/util/BitSet;

.field public i:Z

.field public j:Z

.field public final k:Landroid/graphics/Matrix;

.field public final l:Landroid/graphics/Path;

.field public final m:Landroid/graphics/Path;

.field public final n:Landroid/graphics/RectF;

.field public final o:Landroid/graphics/RectF;

.field public final p:Landroid/graphics/Region;

.field public final q:Landroid/graphics/Region;

.field public final r:Landroid/graphics/Paint;

.field public final s:Landroid/graphics/Paint;

.field public final t:Lpv/g;

.field public final u:Lac/i;

.field public v:Landroid/graphics/PorterDuffColorFilter;

.field public w:Landroid/graphics/PorterDuffColorFilter;

.field public final x:Landroid/graphics/RectF;

.field public y:Z

.field public z:Lwq/m;


# direct methods
.method static constructor <clinit>()V
    .locals 3

    .line 1
    new-instance v0, Landroid/graphics/Paint;

    .line 2
    .line 3
    const/4 v1, 0x1

    .line 4
    invoke-direct {v0, v1}, Landroid/graphics/Paint;-><init>(I)V

    .line 5
    .line 6
    .line 7
    const/4 v1, -0x1

    .line 8
    invoke-virtual {v0, v1}, Landroid/graphics/Paint;->setColor(I)V

    .line 9
    .line 10
    .line 11
    new-instance v1, Landroid/graphics/PorterDuffXfermode;

    .line 12
    .line 13
    sget-object v2, Landroid/graphics/PorterDuff$Mode;->DST_OUT:Landroid/graphics/PorterDuff$Mode;

    .line 14
    .line 15
    invoke-direct {v1, v2}, Landroid/graphics/PorterDuffXfermode;-><init>(Landroid/graphics/PorterDuff$Mode;)V

    .line 16
    .line 17
    .line 18
    invoke-virtual {v0, v1}, Landroid/graphics/Paint;->setXfermode(Landroid/graphics/Xfermode;)Landroid/graphics/Xfermode;

    .line 19
    .line 20
    .line 21
    const/4 v0, 0x4

    .line 22
    new-array v0, v0, [Lwq/h;

    .line 23
    .line 24
    sput-object v0, Lwq/i;->F:[Lwq/h;

    .line 25
    .line 26
    const/4 v0, 0x0

    .line 27
    :goto_0
    sget-object v1, Lwq/i;->F:[Lwq/h;

    .line 28
    .line 29
    array-length v2, v1

    .line 30
    if-ge v0, v2, :cond_0

    .line 31
    .line 32
    new-instance v2, Lwq/h;

    .line 33
    .line 34
    invoke-direct {v2, v0}, Lwq/h;-><init>(I)V

    .line 35
    .line 36
    .line 37
    aput-object v2, v1, v0

    .line 38
    .line 39
    add-int/lit8 v0, v0, 0x1

    .line 40
    .line 41
    goto :goto_0

    .line 42
    :cond_0
    return-void
.end method

.method public constructor <init>()V
    .locals 1

    .line 1
    new-instance v0, Lwq/m;

    invoke-direct {v0}, Lwq/m;-><init>()V

    invoke-direct {p0, v0}, Lwq/i;-><init>(Lwq/m;)V

    return-void
.end method

.method public constructor <init>(Landroid/content/Context;Landroid/util/AttributeSet;II)V
    .locals 0

    .line 2
    invoke-static {p1, p2, p3, p4}, Lwq/m;->b(Landroid/content/Context;Landroid/util/AttributeSet;II)Lwq/l;

    move-result-object p1

    invoke-virtual {p1}, Lwq/l;->a()Lwq/m;

    move-result-object p1

    invoke-direct {p0, p1}, Lwq/i;-><init>(Lwq/m;)V

    return-void
.end method

.method public constructor <init>(Lwq/g;)V
    .locals 6

    .line 4
    invoke-direct {p0}, Landroid/graphics/drawable/Drawable;-><init>()V

    .line 5
    new-instance v0, Lro/f;

    const/16 v1, 0xd

    invoke-direct {v0, p0, v1}, Lro/f;-><init>(Ljava/lang/Object;I)V

    iput-object v0, p0, Lwq/i;->d:Lro/f;

    const/4 v0, 0x4

    .line 6
    new-array v1, v0, [Lwq/t;

    iput-object v1, p0, Lwq/i;->f:[Lwq/t;

    .line 7
    new-array v1, v0, [Lwq/t;

    iput-object v1, p0, Lwq/i;->g:[Lwq/t;

    .line 8
    new-instance v1, Ljava/util/BitSet;

    const/16 v2, 0x8

    invoke-direct {v1, v2}, Ljava/util/BitSet;-><init>(I)V

    iput-object v1, p0, Lwq/i;->h:Ljava/util/BitSet;

    .line 9
    new-instance v1, Landroid/graphics/Matrix;

    invoke-direct {v1}, Landroid/graphics/Matrix;-><init>()V

    iput-object v1, p0, Lwq/i;->k:Landroid/graphics/Matrix;

    .line 10
    new-instance v1, Landroid/graphics/Path;

    invoke-direct {v1}, Landroid/graphics/Path;-><init>()V

    iput-object v1, p0, Lwq/i;->l:Landroid/graphics/Path;

    .line 11
    new-instance v1, Landroid/graphics/Path;

    invoke-direct {v1}, Landroid/graphics/Path;-><init>()V

    iput-object v1, p0, Lwq/i;->m:Landroid/graphics/Path;

    .line 12
    new-instance v1, Landroid/graphics/RectF;

    invoke-direct {v1}, Landroid/graphics/RectF;-><init>()V

    iput-object v1, p0, Lwq/i;->n:Landroid/graphics/RectF;

    .line 13
    new-instance v1, Landroid/graphics/RectF;

    invoke-direct {v1}, Landroid/graphics/RectF;-><init>()V

    iput-object v1, p0, Lwq/i;->o:Landroid/graphics/RectF;

    .line 14
    new-instance v1, Landroid/graphics/Region;

    invoke-direct {v1}, Landroid/graphics/Region;-><init>()V

    iput-object v1, p0, Lwq/i;->p:Landroid/graphics/Region;

    .line 15
    new-instance v1, Landroid/graphics/Region;

    invoke-direct {v1}, Landroid/graphics/Region;-><init>()V

    iput-object v1, p0, Lwq/i;->q:Landroid/graphics/Region;

    .line 16
    new-instance v1, Landroid/graphics/Paint;

    const/4 v2, 0x1

    invoke-direct {v1, v2}, Landroid/graphics/Paint;-><init>(I)V

    iput-object v1, p0, Lwq/i;->r:Landroid/graphics/Paint;

    .line 17
    new-instance v3, Landroid/graphics/Paint;

    invoke-direct {v3, v2}, Landroid/graphics/Paint;-><init>(I)V

    iput-object v3, p0, Lwq/i;->s:Landroid/graphics/Paint;

    .line 18
    new-instance v4, Lvq/a;

    invoke-direct {v4}, Lvq/a;-><init>()V

    .line 19
    invoke-static {}, Landroid/os/Looper;->getMainLooper()Landroid/os/Looper;

    move-result-object v4

    invoke-virtual {v4}, Landroid/os/Looper;->getThread()Ljava/lang/Thread;

    move-result-object v4

    invoke-static {}, Ljava/lang/Thread;->currentThread()Ljava/lang/Thread;

    move-result-object v5

    if-ne v4, v5, :cond_0

    .line 20
    sget-object v4, Lwq/n;->a:Lac/i;

    goto :goto_0

    .line 21
    :cond_0
    new-instance v4, Lac/i;

    invoke-direct {v4}, Lac/i;-><init>()V

    :goto_0
    iput-object v4, p0, Lwq/i;->u:Lac/i;

    .line 22
    new-instance v4, Landroid/graphics/RectF;

    invoke-direct {v4}, Landroid/graphics/RectF;-><init>()V

    iput-object v4, p0, Lwq/i;->x:Landroid/graphics/RectF;

    .line 23
    iput-boolean v2, p0, Lwq/i;->y:Z

    .line 24
    new-array v0, v0, [Lr6/e;

    iput-object v0, p0, Lwq/i;->B:[Lr6/e;

    .line 25
    iput-object p1, p0, Lwq/i;->e:Lwq/g;

    .line 26
    sget-object p1, Landroid/graphics/Paint$Style;->STROKE:Landroid/graphics/Paint$Style;

    invoke-virtual {v3, p1}, Landroid/graphics/Paint;->setStyle(Landroid/graphics/Paint$Style;)V

    .line 27
    sget-object p1, Landroid/graphics/Paint$Style;->FILL:Landroid/graphics/Paint$Style;

    invoke-virtual {v1, p1}, Landroid/graphics/Paint;->setStyle(Landroid/graphics/Paint$Style;)V

    .line 28
    invoke-virtual {p0}, Lwq/i;->q()Z

    .line 29
    invoke-virtual {p0}, Landroid/graphics/drawable/Drawable;->getState()[I

    move-result-object p1

    invoke-virtual {p0, p1}, Lwq/i;->o([I)Z

    .line 30
    new-instance p1, Lpv/g;

    const/16 v0, 0x15

    invoke-direct {p1, p0, v0}, Lpv/g;-><init>(Ljava/lang/Object;I)V

    iput-object p1, p0, Lwq/i;->t:Lpv/g;

    return-void
.end method

.method public constructor <init>(Lwq/m;)V
    .locals 1

    .line 3
    new-instance v0, Lwq/g;

    invoke-direct {v0, p1}, Lwq/g;-><init>(Lwq/m;)V

    invoke-direct {p0, v0}, Lwq/i;-><init>(Lwq/g;)V

    return-void
.end method

.method public static b(Landroid/graphics/RectF;Lwq/m;[F)F
    .locals 3

    .line 1
    if-nez p2, :cond_0

    .line 2
    .line 3
    invoke-virtual {p1, p0}, Lwq/m;->e(Landroid/graphics/RectF;)Z

    .line 4
    .line 5
    .line 6
    move-result p2

    .line 7
    if-eqz p2, :cond_4

    .line 8
    .line 9
    iget-object p1, p1, Lwq/m;->e:Lwq/d;

    .line 10
    .line 11
    invoke-interface {p1, p0}, Lwq/d;->a(Landroid/graphics/RectF;)F

    .line 12
    .line 13
    .line 14
    move-result p0

    .line 15
    return p0

    .line 16
    :cond_0
    array-length p0, p2

    .line 17
    const/4 v0, 0x0

    .line 18
    const/4 v1, 0x1

    .line 19
    if-gt p0, v1, :cond_1

    .line 20
    .line 21
    goto :goto_1

    .line 22
    :cond_1
    aget p0, p2, v0

    .line 23
    .line 24
    :goto_0
    array-length v2, p2

    .line 25
    if-ge v1, v2, :cond_3

    .line 26
    .line 27
    aget v2, p2, v1

    .line 28
    .line 29
    cmpl-float v2, v2, p0

    .line 30
    .line 31
    if-eqz v2, :cond_2

    .line 32
    .line 33
    goto :goto_2

    .line 34
    :cond_2
    add-int/lit8 v1, v1, 0x1

    .line 35
    .line 36
    goto :goto_0

    .line 37
    :cond_3
    :goto_1
    invoke-virtual {p1}, Lwq/m;->d()Z

    .line 38
    .line 39
    .line 40
    move-result p0

    .line 41
    if-eqz p0, :cond_4

    .line 42
    .line 43
    aget p0, p2, v0

    .line 44
    .line 45
    return p0

    .line 46
    :cond_4
    :goto_2
    const/high16 p0, -0x40800000    # -1.0f

    .line 47
    .line 48
    return p0
.end method


# virtual methods
.method public final a(Landroid/graphics/RectF;Landroid/graphics/Path;)V
    .locals 8

    .line 1
    iget-object v0, p0, Lwq/i;->e:Lwq/g;

    .line 2
    .line 3
    iget-object v2, v0, Lwq/g;->a:Lwq/m;

    .line 4
    .line 5
    iget-object v3, p0, Lwq/i;->C:[F

    .line 6
    .line 7
    iget v4, v0, Lwq/g;->j:F

    .line 8
    .line 9
    iget-object v6, p0, Lwq/i;->t:Lpv/g;

    .line 10
    .line 11
    iget-object v1, p0, Lwq/i;->u:Lac/i;

    .line 12
    .line 13
    move-object v5, p1

    .line 14
    move-object v7, p2

    .line 15
    invoke-virtual/range {v1 .. v7}, Lac/i;->b(Lwq/m;[FFLandroid/graphics/RectF;Lpv/g;Landroid/graphics/Path;)V

    .line 16
    .line 17
    .line 18
    iget-object p1, p0, Lwq/i;->e:Lwq/g;

    .line 19
    .line 20
    iget p1, p1, Lwq/g;->i:F

    .line 21
    .line 22
    const/high16 p2, 0x3f800000    # 1.0f

    .line 23
    .line 24
    cmpl-float p1, p1, p2

    .line 25
    .line 26
    if-eqz p1, :cond_0

    .line 27
    .line 28
    iget-object p1, p0, Lwq/i;->k:Landroid/graphics/Matrix;

    .line 29
    .line 30
    invoke-virtual {p1}, Landroid/graphics/Matrix;->reset()V

    .line 31
    .line 32
    .line 33
    iget-object p2, p0, Lwq/i;->e:Lwq/g;

    .line 34
    .line 35
    iget p2, p2, Lwq/g;->i:F

    .line 36
    .line 37
    invoke-virtual {v5}, Landroid/graphics/RectF;->width()F

    .line 38
    .line 39
    .line 40
    move-result v0

    .line 41
    const/high16 v1, 0x40000000    # 2.0f

    .line 42
    .line 43
    div-float/2addr v0, v1

    .line 44
    invoke-virtual {v5}, Landroid/graphics/RectF;->height()F

    .line 45
    .line 46
    .line 47
    move-result v2

    .line 48
    div-float/2addr v2, v1

    .line 49
    invoke-virtual {p1, p2, p2, v0, v2}, Landroid/graphics/Matrix;->setScale(FFFF)V

    .line 50
    .line 51
    .line 52
    invoke-virtual {v7, p1}, Landroid/graphics/Path;->transform(Landroid/graphics/Matrix;)V

    .line 53
    .line 54
    .line 55
    :cond_0
    iget-object p0, p0, Lwq/i;->x:Landroid/graphics/RectF;

    .line 56
    .line 57
    const/4 p1, 0x1

    .line 58
    invoke-virtual {v7, p0, p1}, Landroid/graphics/Path;->computeBounds(Landroid/graphics/RectF;Z)V

    .line 59
    .line 60
    .line 61
    return-void
.end method

.method public final c(I)I
    .locals 5

    .line 1
    iget-object p0, p0, Lwq/i;->e:Lwq/g;

    .line 2
    .line 3
    iget v0, p0, Lwq/g;->n:F

    .line 4
    .line 5
    const/4 v1, 0x0

    .line 6
    add-float/2addr v0, v1

    .line 7
    iget v2, p0, Lwq/g;->m:F

    .line 8
    .line 9
    add-float/2addr v0, v2

    .line 10
    iget-object p0, p0, Lwq/g;->c:Lqq/a;

    .line 11
    .line 12
    if-eqz p0, :cond_3

    .line 13
    .line 14
    iget-boolean v2, p0, Lqq/a;->a:Z

    .line 15
    .line 16
    if-eqz v2, :cond_3

    .line 17
    .line 18
    const/16 v2, 0xff

    .line 19
    .line 20
    invoke-static {p1, v2}, Ls5/a;->e(II)I

    .line 21
    .line 22
    .line 23
    move-result v3

    .line 24
    iget v4, p0, Lqq/a;->d:I

    .line 25
    .line 26
    if-ne v3, v4, :cond_3

    .line 27
    .line 28
    iget v3, p0, Lqq/a;->e:F

    .line 29
    .line 30
    cmpg-float v4, v3, v1

    .line 31
    .line 32
    if-lez v4, :cond_1

    .line 33
    .line 34
    cmpg-float v4, v0, v1

    .line 35
    .line 36
    if-gtz v4, :cond_0

    .line 37
    .line 38
    goto :goto_0

    .line 39
    :cond_0
    div-float/2addr v0, v3

    .line 40
    float-to-double v3, v0

    .line 41
    invoke-static {v3, v4}, Ljava/lang/Math;->log1p(D)D

    .line 42
    .line 43
    .line 44
    move-result-wide v3

    .line 45
    double-to-float v0, v3

    .line 46
    const/high16 v3, 0x40900000    # 4.5f

    .line 47
    .line 48
    mul-float/2addr v0, v3

    .line 49
    const/high16 v3, 0x40000000    # 2.0f

    .line 50
    .line 51
    add-float/2addr v0, v3

    .line 52
    const/high16 v3, 0x42c80000    # 100.0f

    .line 53
    .line 54
    div-float/2addr v0, v3

    .line 55
    const/high16 v3, 0x3f800000    # 1.0f

    .line 56
    .line 57
    invoke-static {v0, v3}, Ljava/lang/Math;->min(FF)F

    .line 58
    .line 59
    .line 60
    move-result v0

    .line 61
    goto :goto_1

    .line 62
    :cond_1
    :goto_0
    move v0, v1

    .line 63
    :goto_1
    invoke-static {p1}, Landroid/graphics/Color;->alpha(I)I

    .line 64
    .line 65
    .line 66
    move-result v3

    .line 67
    invoke-static {p1, v2}, Ls5/a;->e(II)I

    .line 68
    .line 69
    .line 70
    move-result p1

    .line 71
    iget v2, p0, Lqq/a;->b:I

    .line 72
    .line 73
    invoke-static {v0, p1, v2}, Ljp/ua;->b(FII)I

    .line 74
    .line 75
    .line 76
    move-result p1

    .line 77
    cmpl-float v0, v0, v1

    .line 78
    .line 79
    if-lez v0, :cond_2

    .line 80
    .line 81
    iget p0, p0, Lqq/a;->c:I

    .line 82
    .line 83
    if-eqz p0, :cond_2

    .line 84
    .line 85
    sget v0, Lqq/a;->f:I

    .line 86
    .line 87
    invoke-static {p0, v0}, Ls5/a;->e(II)I

    .line 88
    .line 89
    .line 90
    move-result p0

    .line 91
    invoke-static {p0, p1}, Ls5/a;->c(II)I

    .line 92
    .line 93
    .line 94
    move-result p1

    .line 95
    :cond_2
    invoke-static {p1, v3}, Ls5/a;->e(II)I

    .line 96
    .line 97
    .line 98
    move-result p0

    .line 99
    return p0

    .line 100
    :cond_3
    return p1
.end method

.method public final d(Landroid/graphics/Canvas;Landroid/graphics/Paint;Landroid/graphics/Path;Lwq/m;[FLandroid/graphics/RectF;)V
    .locals 0

    .line 1
    invoke-static {p6, p4, p5}, Lwq/i;->b(Landroid/graphics/RectF;Lwq/m;[F)F

    .line 2
    .line 3
    .line 4
    move-result p4

    .line 5
    const/4 p5, 0x0

    .line 6
    cmpl-float p5, p4, p5

    .line 7
    .line 8
    if-ltz p5, :cond_0

    .line 9
    .line 10
    iget-object p0, p0, Lwq/i;->e:Lwq/g;

    .line 11
    .line 12
    iget p0, p0, Lwq/g;->j:F

    .line 13
    .line 14
    mul-float/2addr p4, p0

    .line 15
    invoke-virtual {p1, p6, p4, p4, p2}, Landroid/graphics/Canvas;->drawRoundRect(Landroid/graphics/RectF;FFLandroid/graphics/Paint;)V

    .line 16
    .line 17
    .line 18
    return-void

    .line 19
    :cond_0
    invoke-virtual {p1, p3, p2}, Landroid/graphics/Canvas;->drawPath(Landroid/graphics/Path;Landroid/graphics/Paint;)V

    .line 20
    .line 21
    .line 22
    return-void
.end method

.method public draw(Landroid/graphics/Canvas;)V
    .locals 18

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget-object v1, v0, Lwq/i;->v:Landroid/graphics/PorterDuffColorFilter;

    .line 4
    .line 5
    iget-object v2, v0, Lwq/i;->r:Landroid/graphics/Paint;

    .line 6
    .line 7
    invoke-virtual {v2, v1}, Landroid/graphics/Paint;->setColorFilter(Landroid/graphics/ColorFilter;)Landroid/graphics/ColorFilter;

    .line 8
    .line 9
    .line 10
    invoke-virtual {v2}, Landroid/graphics/Paint;->getAlpha()I

    .line 11
    .line 12
    .line 13
    move-result v7

    .line 14
    iget-object v1, v0, Lwq/i;->e:Lwq/g;

    .line 15
    .line 16
    iget v1, v1, Lwq/g;->l:I

    .line 17
    .line 18
    ushr-int/lit8 v3, v1, 0x7

    .line 19
    .line 20
    add-int/2addr v1, v3

    .line 21
    mul-int/2addr v1, v7

    .line 22
    ushr-int/lit8 v1, v1, 0x8

    .line 23
    .line 24
    invoke-virtual {v2, v1}, Landroid/graphics/Paint;->setAlpha(I)V

    .line 25
    .line 26
    .line 27
    iget-object v1, v0, Lwq/i;->w:Landroid/graphics/PorterDuffColorFilter;

    .line 28
    .line 29
    iget-object v8, v0, Lwq/i;->s:Landroid/graphics/Paint;

    .line 30
    .line 31
    invoke-virtual {v8, v1}, Landroid/graphics/Paint;->setColorFilter(Landroid/graphics/ColorFilter;)Landroid/graphics/ColorFilter;

    .line 32
    .line 33
    .line 34
    iget-object v1, v0, Lwq/i;->e:Lwq/g;

    .line 35
    .line 36
    iget v1, v1, Lwq/g;->k:F

    .line 37
    .line 38
    invoke-virtual {v8, v1}, Landroid/graphics/Paint;->setStrokeWidth(F)V

    .line 39
    .line 40
    .line 41
    invoke-virtual {v8}, Landroid/graphics/Paint;->getAlpha()I

    .line 42
    .line 43
    .line 44
    move-result v9

    .line 45
    iget-object v1, v0, Lwq/i;->e:Lwq/g;

    .line 46
    .line 47
    iget v1, v1, Lwq/g;->l:I

    .line 48
    .line 49
    ushr-int/lit8 v3, v1, 0x7

    .line 50
    .line 51
    add-int/2addr v1, v3

    .line 52
    mul-int/2addr v1, v9

    .line 53
    ushr-int/lit8 v1, v1, 0x8

    .line 54
    .line 55
    invoke-virtual {v8, v1}, Landroid/graphics/Paint;->setAlpha(I)V

    .line 56
    .line 57
    .line 58
    iget-object v1, v0, Lwq/i;->e:Lwq/g;

    .line 59
    .line 60
    iget-object v1, v1, Lwq/g;->q:Landroid/graphics/Paint$Style;

    .line 61
    .line 62
    sget-object v3, Landroid/graphics/Paint$Style;->FILL_AND_STROKE:Landroid/graphics/Paint$Style;

    .line 63
    .line 64
    const/4 v10, 0x0

    .line 65
    if-eq v1, v3, :cond_0

    .line 66
    .line 67
    sget-object v3, Landroid/graphics/Paint$Style;->FILL:Landroid/graphics/Paint$Style;

    .line 68
    .line 69
    if-ne v1, v3, :cond_7

    .line 70
    .line 71
    :cond_0
    iget-boolean v1, v0, Lwq/i;->i:Z

    .line 72
    .line 73
    iget-object v3, v0, Lwq/i;->l:Landroid/graphics/Path;

    .line 74
    .line 75
    if-eqz v1, :cond_1

    .line 76
    .line 77
    invoke-virtual {v0}, Lwq/i;->f()Landroid/graphics/RectF;

    .line 78
    .line 79
    .line 80
    move-result-object v1

    .line 81
    invoke-virtual {v0, v1, v3}, Lwq/i;->a(Landroid/graphics/RectF;Landroid/graphics/Path;)V

    .line 82
    .line 83
    .line 84
    iput-boolean v10, v0, Lwq/i;->i:Z

    .line 85
    .line 86
    :cond_1
    iget-object v1, v0, Lwq/i;->e:Lwq/g;

    .line 87
    .line 88
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 89
    .line 90
    .line 91
    iget v4, v1, Lwq/g;->o:I

    .line 92
    .line 93
    if-lez v4, :cond_6

    .line 94
    .line 95
    iget-object v1, v1, Lwq/g;->a:Lwq/m;

    .line 96
    .line 97
    invoke-virtual {v0}, Lwq/i;->f()Landroid/graphics/RectF;

    .line 98
    .line 99
    .line 100
    move-result-object v4

    .line 101
    invoke-virtual {v1, v4}, Lwq/m;->e(Landroid/graphics/RectF;)Z

    .line 102
    .line 103
    .line 104
    move-result v1

    .line 105
    if-nez v1, :cond_6

    .line 106
    .line 107
    iget-object v1, v0, Lwq/i;->C:[F

    .line 108
    .line 109
    if-eqz v1, :cond_5

    .line 110
    .line 111
    array-length v4, v1

    .line 112
    const/4 v5, 0x1

    .line 113
    if-gt v4, v5, :cond_2

    .line 114
    .line 115
    goto :goto_1

    .line 116
    :cond_2
    aget v4, v1, v10

    .line 117
    .line 118
    :goto_0
    array-length v6, v1

    .line 119
    if-ge v5, v6, :cond_4

    .line 120
    .line 121
    aget v6, v1, v5

    .line 122
    .line 123
    cmpl-float v6, v6, v4

    .line 124
    .line 125
    if-eqz v6, :cond_3

    .line 126
    .line 127
    goto :goto_2

    .line 128
    :cond_3
    add-int/lit8 v5, v5, 0x1

    .line 129
    .line 130
    goto :goto_0

    .line 131
    :cond_4
    :goto_1
    iget-object v1, v0, Lwq/i;->e:Lwq/g;

    .line 132
    .line 133
    iget-object v1, v1, Lwq/g;->a:Lwq/m;

    .line 134
    .line 135
    invoke-virtual {v1}, Lwq/m;->d()Z

    .line 136
    .line 137
    .line 138
    move-result v1

    .line 139
    if-eqz v1, :cond_5

    .line 140
    .line 141
    goto :goto_3

    .line 142
    :cond_5
    :goto_2
    invoke-virtual {v3}, Landroid/graphics/Path;->isConvex()Z

    .line 143
    .line 144
    .line 145
    :cond_6
    :goto_3
    iget-object v1, v0, Lwq/i;->e:Lwq/g;

    .line 146
    .line 147
    iget-object v4, v1, Lwq/g;->a:Lwq/m;

    .line 148
    .line 149
    iget-object v5, v0, Lwq/i;->C:[F

    .line 150
    .line 151
    invoke-virtual {v0}, Lwq/i;->f()Landroid/graphics/RectF;

    .line 152
    .line 153
    .line 154
    move-result-object v6

    .line 155
    move-object/from16 v1, p1

    .line 156
    .line 157
    invoke-virtual/range {v0 .. v6}, Lwq/i;->d(Landroid/graphics/Canvas;Landroid/graphics/Paint;Landroid/graphics/Path;Lwq/m;[FLandroid/graphics/RectF;)V

    .line 158
    .line 159
    .line 160
    :cond_7
    invoke-virtual {v0}, Lwq/i;->i()Z

    .line 161
    .line 162
    .line 163
    move-result v1

    .line 164
    if-eqz v1, :cond_c

    .line 165
    .line 166
    iget-boolean v1, v0, Lwq/i;->j:Z

    .line 167
    .line 168
    if-eqz v1, :cond_b

    .line 169
    .line 170
    iget-object v1, v0, Lwq/i;->e:Lwq/g;

    .line 171
    .line 172
    iget-object v1, v1, Lwq/g;->a:Lwq/m;

    .line 173
    .line 174
    invoke-virtual {v1}, Lwq/m;->f()Lwq/l;

    .line 175
    .line 176
    .line 177
    move-result-object v3

    .line 178
    iget-object v4, v1, Lwq/m;->e:Lwq/d;

    .line 179
    .line 180
    iget-object v5, v0, Lwq/i;->d:Lro/f;

    .line 181
    .line 182
    invoke-virtual {v5, v4}, Lro/f;->b(Lwq/d;)Lwq/d;

    .line 183
    .line 184
    .line 185
    move-result-object v4

    .line 186
    iput-object v4, v3, Lwq/l;->e:Lwq/d;

    .line 187
    .line 188
    iget-object v4, v1, Lwq/m;->f:Lwq/d;

    .line 189
    .line 190
    invoke-virtual {v5, v4}, Lro/f;->b(Lwq/d;)Lwq/d;

    .line 191
    .line 192
    .line 193
    move-result-object v4

    .line 194
    iput-object v4, v3, Lwq/l;->f:Lwq/d;

    .line 195
    .line 196
    iget-object v4, v1, Lwq/m;->h:Lwq/d;

    .line 197
    .line 198
    invoke-virtual {v5, v4}, Lro/f;->b(Lwq/d;)Lwq/d;

    .line 199
    .line 200
    .line 201
    move-result-object v4

    .line 202
    iput-object v4, v3, Lwq/l;->h:Lwq/d;

    .line 203
    .line 204
    iget-object v1, v1, Lwq/m;->g:Lwq/d;

    .line 205
    .line 206
    invoke-virtual {v5, v1}, Lro/f;->b(Lwq/d;)Lwq/d;

    .line 207
    .line 208
    .line 209
    move-result-object v1

    .line 210
    iput-object v1, v3, Lwq/l;->g:Lwq/d;

    .line 211
    .line 212
    invoke-virtual {v3}, Lwq/l;->a()Lwq/m;

    .line 213
    .line 214
    .line 215
    move-result-object v1

    .line 216
    iput-object v1, v0, Lwq/i;->z:Lwq/m;

    .line 217
    .line 218
    iget-object v1, v0, Lwq/i;->C:[F

    .line 219
    .line 220
    if-nez v1, :cond_8

    .line 221
    .line 222
    const/4 v1, 0x0

    .line 223
    iput-object v1, v0, Lwq/i;->D:[F

    .line 224
    .line 225
    goto :goto_5

    .line 226
    :cond_8
    iget-object v3, v0, Lwq/i;->D:[F

    .line 227
    .line 228
    if-nez v3, :cond_9

    .line 229
    .line 230
    array-length v1, v1

    .line 231
    new-array v1, v1, [F

    .line 232
    .line 233
    iput-object v1, v0, Lwq/i;->D:[F

    .line 234
    .line 235
    :cond_9
    invoke-virtual {v0}, Lwq/i;->h()F

    .line 236
    .line 237
    .line 238
    move-result v1

    .line 239
    move v3, v10

    .line 240
    :goto_4
    iget-object v4, v0, Lwq/i;->C:[F

    .line 241
    .line 242
    array-length v5, v4

    .line 243
    if-ge v3, v5, :cond_a

    .line 244
    .line 245
    iget-object v5, v0, Lwq/i;->D:[F

    .line 246
    .line 247
    aget v4, v4, v3

    .line 248
    .line 249
    sub-float/2addr v4, v1

    .line 250
    const/4 v6, 0x0

    .line 251
    invoke-static {v6, v4}, Ljava/lang/Math;->max(FF)F

    .line 252
    .line 253
    .line 254
    move-result v4

    .line 255
    aput v4, v5, v3

    .line 256
    .line 257
    add-int/lit8 v3, v3, 0x1

    .line 258
    .line 259
    goto :goto_4

    .line 260
    :cond_a
    :goto_5
    iget-object v12, v0, Lwq/i;->z:Lwq/m;

    .line 261
    .line 262
    iget-object v13, v0, Lwq/i;->D:[F

    .line 263
    .line 264
    iget-object v1, v0, Lwq/i;->e:Lwq/g;

    .line 265
    .line 266
    iget v14, v1, Lwq/g;->j:F

    .line 267
    .line 268
    invoke-virtual {v0}, Lwq/i;->f()Landroid/graphics/RectF;

    .line 269
    .line 270
    .line 271
    move-result-object v1

    .line 272
    iget-object v15, v0, Lwq/i;->o:Landroid/graphics/RectF;

    .line 273
    .line 274
    invoke-virtual {v15, v1}, Landroid/graphics/RectF;->set(Landroid/graphics/RectF;)V

    .line 275
    .line 276
    .line 277
    invoke-virtual {v0}, Lwq/i;->h()F

    .line 278
    .line 279
    .line 280
    move-result v1

    .line 281
    invoke-virtual {v15, v1, v1}, Landroid/graphics/RectF;->inset(FF)V

    .line 282
    .line 283
    .line 284
    const/16 v16, 0x0

    .line 285
    .line 286
    iget-object v1, v0, Lwq/i;->m:Landroid/graphics/Path;

    .line 287
    .line 288
    iget-object v11, v0, Lwq/i;->u:Lac/i;

    .line 289
    .line 290
    move-object/from16 v17, v1

    .line 291
    .line 292
    invoke-virtual/range {v11 .. v17}, Lac/i;->b(Lwq/m;[FFLandroid/graphics/RectF;Lpv/g;Landroid/graphics/Path;)V

    .line 293
    .line 294
    .line 295
    iput-boolean v10, v0, Lwq/i;->j:Z

    .line 296
    .line 297
    :cond_b
    invoke-virtual/range {p0 .. p1}, Lwq/i;->e(Landroid/graphics/Canvas;)V

    .line 298
    .line 299
    .line 300
    :cond_c
    invoke-virtual {v2, v7}, Landroid/graphics/Paint;->setAlpha(I)V

    .line 301
    .line 302
    .line 303
    invoke-virtual {v8, v9}, Landroid/graphics/Paint;->setAlpha(I)V

    .line 304
    .line 305
    .line 306
    return-void
.end method

.method public e(Landroid/graphics/Canvas;)V
    .locals 7

    .line 1
    iget-object v4, p0, Lwq/i;->z:Lwq/m;

    .line 2
    .line 3
    iget-object v5, p0, Lwq/i;->D:[F

    .line 4
    .line 5
    invoke-virtual {p0}, Lwq/i;->f()Landroid/graphics/RectF;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    iget-object v6, p0, Lwq/i;->o:Landroid/graphics/RectF;

    .line 10
    .line 11
    invoke-virtual {v6, v0}, Landroid/graphics/RectF;->set(Landroid/graphics/RectF;)V

    .line 12
    .line 13
    .line 14
    invoke-virtual {p0}, Lwq/i;->h()F

    .line 15
    .line 16
    .line 17
    move-result v0

    .line 18
    invoke-virtual {v6, v0, v0}, Landroid/graphics/RectF;->inset(FF)V

    .line 19
    .line 20
    .line 21
    iget-object v2, p0, Lwq/i;->s:Landroid/graphics/Paint;

    .line 22
    .line 23
    iget-object v3, p0, Lwq/i;->m:Landroid/graphics/Path;

    .line 24
    .line 25
    move-object v0, p0

    .line 26
    move-object v1, p1

    .line 27
    invoke-virtual/range {v0 .. v6}, Lwq/i;->d(Landroid/graphics/Canvas;Landroid/graphics/Paint;Landroid/graphics/Path;Lwq/m;[FLandroid/graphics/RectF;)V

    .line 28
    .line 29
    .line 30
    return-void
.end method

.method public final f()Landroid/graphics/RectF;
    .locals 1

    .line 1
    invoke-virtual {p0}, Landroid/graphics/drawable/Drawable;->getBounds()Landroid/graphics/Rect;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    iget-object p0, p0, Lwq/i;->n:Landroid/graphics/RectF;

    .line 6
    .line 7
    invoke-virtual {p0, v0}, Landroid/graphics/RectF;->set(Landroid/graphics/Rect;)V

    .line 8
    .line 9
    .line 10
    return-object p0
.end method

.method public final g()F
    .locals 5

    .line 1
    iget-object v0, p0, Lwq/i;->C:[F

    .line 2
    .line 3
    const/high16 v1, 0x40000000    # 2.0f

    .line 4
    .line 5
    if-eqz v0, :cond_0

    .line 6
    .line 7
    const/4 p0, 0x3

    .line 8
    aget p0, v0, p0

    .line 9
    .line 10
    const/4 v2, 0x2

    .line 11
    aget v2, v0, v2

    .line 12
    .line 13
    add-float/2addr p0, v2

    .line 14
    const/4 v2, 0x1

    .line 15
    aget v2, v0, v2

    .line 16
    .line 17
    sub-float/2addr p0, v2

    .line 18
    const/4 v2, 0x0

    .line 19
    aget v0, v0, v2

    .line 20
    .line 21
    sub-float/2addr p0, v0

    .line 22
    div-float/2addr p0, v1

    .line 23
    return p0

    .line 24
    :cond_0
    invoke-virtual {p0}, Lwq/i;->f()Landroid/graphics/RectF;

    .line 25
    .line 26
    .line 27
    move-result-object v0

    .line 28
    iget-object v2, p0, Lwq/i;->e:Lwq/g;

    .line 29
    .line 30
    iget-object v2, v2, Lwq/g;->a:Lwq/m;

    .line 31
    .line 32
    iget-object v3, p0, Lwq/i;->u:Lac/i;

    .line 33
    .line 34
    invoke-virtual {v3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 35
    .line 36
    .line 37
    iget-object v2, v2, Lwq/m;->e:Lwq/d;

    .line 38
    .line 39
    invoke-interface {v2, v0}, Lwq/d;->a(Landroid/graphics/RectF;)F

    .line 40
    .line 41
    .line 42
    move-result v2

    .line 43
    iget-object v4, p0, Lwq/i;->e:Lwq/g;

    .line 44
    .line 45
    iget-object v4, v4, Lwq/g;->a:Lwq/m;

    .line 46
    .line 47
    invoke-virtual {v3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 48
    .line 49
    .line 50
    iget-object v4, v4, Lwq/m;->h:Lwq/d;

    .line 51
    .line 52
    invoke-interface {v4, v0}, Lwq/d;->a(Landroid/graphics/RectF;)F

    .line 53
    .line 54
    .line 55
    move-result v4

    .line 56
    add-float/2addr v4, v2

    .line 57
    iget-object v2, p0, Lwq/i;->e:Lwq/g;

    .line 58
    .line 59
    iget-object v2, v2, Lwq/g;->a:Lwq/m;

    .line 60
    .line 61
    invoke-virtual {v3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 62
    .line 63
    .line 64
    iget-object v2, v2, Lwq/m;->g:Lwq/d;

    .line 65
    .line 66
    invoke-interface {v2, v0}, Lwq/d;->a(Landroid/graphics/RectF;)F

    .line 67
    .line 68
    .line 69
    move-result v2

    .line 70
    sub-float/2addr v4, v2

    .line 71
    iget-object p0, p0, Lwq/i;->e:Lwq/g;

    .line 72
    .line 73
    iget-object p0, p0, Lwq/g;->a:Lwq/m;

    .line 74
    .line 75
    invoke-virtual {v3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 76
    .line 77
    .line 78
    iget-object p0, p0, Lwq/m;->f:Lwq/d;

    .line 79
    .line 80
    invoke-interface {p0, v0}, Lwq/d;->a(Landroid/graphics/RectF;)F

    .line 81
    .line 82
    .line 83
    move-result p0

    .line 84
    sub-float/2addr v4, p0

    .line 85
    div-float/2addr v4, v1

    .line 86
    return v4
.end method

.method public getAlpha()I
    .locals 0

    .line 1
    iget-object p0, p0, Lwq/i;->e:Lwq/g;

    .line 2
    .line 3
    iget p0, p0, Lwq/g;->l:I

    .line 4
    .line 5
    return p0
.end method

.method public final getConstantState()Landroid/graphics/drawable/Drawable$ConstantState;
    .locals 0

    .line 1
    iget-object p0, p0, Lwq/i;->e:Lwq/g;

    .line 2
    .line 3
    return-object p0
.end method

.method public getOpacity()I
    .locals 0

    .line 1
    const/4 p0, -0x3

    .line 2
    return p0
.end method

.method public getOutline(Landroid/graphics/Outline;)V
    .locals 3

    .line 1
    iget-object v0, p0, Lwq/i;->e:Lwq/g;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 4
    .line 5
    .line 6
    invoke-virtual {p0}, Lwq/i;->f()Landroid/graphics/RectF;

    .line 7
    .line 8
    .line 9
    move-result-object v0

    .line 10
    invoke-virtual {v0}, Landroid/graphics/RectF;->isEmpty()Z

    .line 11
    .line 12
    .line 13
    move-result v1

    .line 14
    if-eqz v1, :cond_0

    .line 15
    .line 16
    return-void

    .line 17
    :cond_0
    iget-object v1, p0, Lwq/i;->e:Lwq/g;

    .line 18
    .line 19
    iget-object v1, v1, Lwq/g;->a:Lwq/m;

    .line 20
    .line 21
    iget-object v2, p0, Lwq/i;->C:[F

    .line 22
    .line 23
    invoke-static {v0, v1, v2}, Lwq/i;->b(Landroid/graphics/RectF;Lwq/m;[F)F

    .line 24
    .line 25
    .line 26
    move-result v1

    .line 27
    const/4 v2, 0x0

    .line 28
    cmpl-float v2, v1, v2

    .line 29
    .line 30
    if-ltz v2, :cond_1

    .line 31
    .line 32
    invoke-virtual {p0}, Landroid/graphics/drawable/Drawable;->getBounds()Landroid/graphics/Rect;

    .line 33
    .line 34
    .line 35
    move-result-object v0

    .line 36
    iget-object p0, p0, Lwq/i;->e:Lwq/g;

    .line 37
    .line 38
    iget p0, p0, Lwq/g;->j:F

    .line 39
    .line 40
    mul-float/2addr v1, p0

    .line 41
    invoke-virtual {p1, v0, v1}, Landroid/graphics/Outline;->setRoundRect(Landroid/graphics/Rect;F)V

    .line 42
    .line 43
    .line 44
    return-void

    .line 45
    :cond_1
    iget-boolean v1, p0, Lwq/i;->i:Z

    .line 46
    .line 47
    iget-object v2, p0, Lwq/i;->l:Landroid/graphics/Path;

    .line 48
    .line 49
    if-eqz v1, :cond_2

    .line 50
    .line 51
    invoke-virtual {p0, v0, v2}, Lwq/i;->a(Landroid/graphics/RectF;Landroid/graphics/Path;)V

    .line 52
    .line 53
    .line 54
    const/4 v0, 0x0

    .line 55
    iput-boolean v0, p0, Lwq/i;->i:Z

    .line 56
    .line 57
    :cond_2
    sget p0, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 58
    .line 59
    const/16 v0, 0x1e

    .line 60
    .line 61
    if-lt p0, v0, :cond_3

    .line 62
    .line 63
    invoke-static {p1, v2}, Lpq/b;->a(Landroid/graphics/Outline;Landroid/graphics/Path;)V

    .line 64
    .line 65
    .line 66
    return-void

    .line 67
    :cond_3
    :try_start_0
    invoke-static {p1, v2}, Lpq/a;->a(Landroid/graphics/Outline;Landroid/graphics/Path;)V
    :try_end_0
    .catch Ljava/lang/IllegalArgumentException; {:try_start_0 .. :try_end_0} :catch_0

    .line 68
    .line 69
    .line 70
    :catch_0
    return-void
.end method

.method public final getPadding(Landroid/graphics/Rect;)Z
    .locals 1

    .line 1
    iget-object v0, p0, Lwq/i;->e:Lwq/g;

    .line 2
    .line 3
    iget-object v0, v0, Lwq/g;->h:Landroid/graphics/Rect;

    .line 4
    .line 5
    if-eqz v0, :cond_0

    .line 6
    .line 7
    invoke-virtual {p1, v0}, Landroid/graphics/Rect;->set(Landroid/graphics/Rect;)V

    .line 8
    .line 9
    .line 10
    const/4 p0, 0x1

    .line 11
    return p0

    .line 12
    :cond_0
    invoke-super {p0, p1}, Landroid/graphics/drawable/Drawable;->getPadding(Landroid/graphics/Rect;)Z

    .line 13
    .line 14
    .line 15
    move-result p0

    .line 16
    return p0
.end method

.method public final getTransparentRegion()Landroid/graphics/Region;
    .locals 3

    .line 1
    invoke-virtual {p0}, Landroid/graphics/drawable/Drawable;->getBounds()Landroid/graphics/Rect;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    iget-object v1, p0, Lwq/i;->p:Landroid/graphics/Region;

    .line 6
    .line 7
    invoke-virtual {v1, v0}, Landroid/graphics/Region;->set(Landroid/graphics/Rect;)Z

    .line 8
    .line 9
    .line 10
    invoke-virtual {p0}, Lwq/i;->f()Landroid/graphics/RectF;

    .line 11
    .line 12
    .line 13
    move-result-object v0

    .line 14
    iget-object v2, p0, Lwq/i;->l:Landroid/graphics/Path;

    .line 15
    .line 16
    invoke-virtual {p0, v0, v2}, Lwq/i;->a(Landroid/graphics/RectF;Landroid/graphics/Path;)V

    .line 17
    .line 18
    .line 19
    iget-object p0, p0, Lwq/i;->q:Landroid/graphics/Region;

    .line 20
    .line 21
    invoke-virtual {p0, v2, v1}, Landroid/graphics/Region;->setPath(Landroid/graphics/Path;Landroid/graphics/Region;)Z

    .line 22
    .line 23
    .line 24
    sget-object v0, Landroid/graphics/Region$Op;->DIFFERENCE:Landroid/graphics/Region$Op;

    .line 25
    .line 26
    invoke-virtual {v1, p0, v0}, Landroid/graphics/Region;->op(Landroid/graphics/Region;Landroid/graphics/Region$Op;)Z

    .line 27
    .line 28
    .line 29
    return-object v1
.end method

.method public final h()F
    .locals 1

    .line 1
    invoke-virtual {p0}, Lwq/i;->i()Z

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    if-eqz v0, :cond_0

    .line 6
    .line 7
    iget-object p0, p0, Lwq/i;->s:Landroid/graphics/Paint;

    .line 8
    .line 9
    invoke-virtual {p0}, Landroid/graphics/Paint;->getStrokeWidth()F

    .line 10
    .line 11
    .line 12
    move-result p0

    .line 13
    const/high16 v0, 0x40000000    # 2.0f

    .line 14
    .line 15
    div-float/2addr p0, v0

    .line 16
    return p0

    .line 17
    :cond_0
    const/4 p0, 0x0

    .line 18
    return p0
.end method

.method public final i()Z
    .locals 2

    .line 1
    iget-object v0, p0, Lwq/i;->e:Lwq/g;

    .line 2
    .line 3
    iget-object v0, v0, Lwq/g;->q:Landroid/graphics/Paint$Style;

    .line 4
    .line 5
    sget-object v1, Landroid/graphics/Paint$Style;->FILL_AND_STROKE:Landroid/graphics/Paint$Style;

    .line 6
    .line 7
    if-eq v0, v1, :cond_0

    .line 8
    .line 9
    sget-object v1, Landroid/graphics/Paint$Style;->STROKE:Landroid/graphics/Paint$Style;

    .line 10
    .line 11
    if-ne v0, v1, :cond_1

    .line 12
    .line 13
    :cond_0
    iget-object p0, p0, Lwq/i;->s:Landroid/graphics/Paint;

    .line 14
    .line 15
    invoke-virtual {p0}, Landroid/graphics/Paint;->getStrokeWidth()F

    .line 16
    .line 17
    .line 18
    move-result p0

    .line 19
    const/4 v0, 0x0

    .line 20
    cmpl-float p0, p0, v0

    .line 21
    .line 22
    if-lez p0, :cond_1

    .line 23
    .line 24
    const/4 p0, 0x1

    .line 25
    return p0

    .line 26
    :cond_1
    const/4 p0, 0x0

    .line 27
    return p0
.end method

.method public final invalidateSelf()V
    .locals 1

    .line 1
    const/4 v0, 0x1

    .line 2
    iput-boolean v0, p0, Lwq/i;->i:Z

    .line 3
    .line 4
    iput-boolean v0, p0, Lwq/i;->j:Z

    .line 5
    .line 6
    invoke-super {p0}, Landroid/graphics/drawable/Drawable;->invalidateSelf()V

    .line 7
    .line 8
    .line 9
    return-void
.end method

.method public isStateful()Z
    .locals 1

    .line 1
    invoke-super {p0}, Landroid/graphics/drawable/Drawable;->isStateful()Z

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    if-nez v0, :cond_4

    .line 6
    .line 7
    iget-object v0, p0, Lwq/i;->e:Lwq/g;

    .line 8
    .line 9
    iget-object v0, v0, Lwq/g;->f:Landroid/content/res/ColorStateList;

    .line 10
    .line 11
    if-eqz v0, :cond_0

    .line 12
    .line 13
    invoke-virtual {v0}, Landroid/content/res/ColorStateList;->isStateful()Z

    .line 14
    .line 15
    .line 16
    move-result v0

    .line 17
    if-nez v0, :cond_4

    .line 18
    .line 19
    :cond_0
    iget-object v0, p0, Lwq/i;->e:Lwq/g;

    .line 20
    .line 21
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 22
    .line 23
    .line 24
    iget-object v0, p0, Lwq/i;->e:Lwq/g;

    .line 25
    .line 26
    iget-object v0, v0, Lwq/g;->e:Landroid/content/res/ColorStateList;

    .line 27
    .line 28
    if-eqz v0, :cond_1

    .line 29
    .line 30
    invoke-virtual {v0}, Landroid/content/res/ColorStateList;->isStateful()Z

    .line 31
    .line 32
    .line 33
    move-result v0

    .line 34
    if-nez v0, :cond_4

    .line 35
    .line 36
    :cond_1
    iget-object v0, p0, Lwq/i;->e:Lwq/g;

    .line 37
    .line 38
    iget-object v0, v0, Lwq/g;->d:Landroid/content/res/ColorStateList;

    .line 39
    .line 40
    if-eqz v0, :cond_2

    .line 41
    .line 42
    invoke-virtual {v0}, Landroid/content/res/ColorStateList;->isStateful()Z

    .line 43
    .line 44
    .line 45
    move-result v0

    .line 46
    if-nez v0, :cond_4

    .line 47
    .line 48
    :cond_2
    iget-object p0, p0, Lwq/i;->e:Lwq/g;

    .line 49
    .line 50
    iget-object p0, p0, Lwq/g;->b:Lwq/x;

    .line 51
    .line 52
    if-eqz p0, :cond_3

    .line 53
    .line 54
    invoke-virtual {p0}, Lwq/x;->d()Z

    .line 55
    .line 56
    .line 57
    move-result p0

    .line 58
    if-eqz p0, :cond_3

    .line 59
    .line 60
    goto :goto_0

    .line 61
    :cond_3
    const/4 p0, 0x0

    .line 62
    return p0

    .line 63
    :cond_4
    :goto_0
    const/4 p0, 0x1

    .line 64
    return p0
.end method

.method public final j(Landroid/content/Context;)V
    .locals 2

    .line 1
    iget-object v0, p0, Lwq/i;->e:Lwq/g;

    .line 2
    .line 3
    new-instance v1, Lqq/a;

    .line 4
    .line 5
    invoke-direct {v1, p1}, Lqq/a;-><init>(Landroid/content/Context;)V

    .line 6
    .line 7
    .line 8
    iput-object v1, v0, Lwq/g;->c:Lqq/a;

    .line 9
    .line 10
    invoke-virtual {p0}, Lwq/i;->r()V

    .line 11
    .line 12
    .line 13
    return-void
.end method

.method public final k(Lr6/f;)V
    .locals 5

    .line 1
    iget-object v0, p0, Lwq/i;->A:Lr6/f;

    .line 2
    .line 3
    if-eq v0, p1, :cond_2

    .line 4
    .line 5
    iput-object p1, p0, Lwq/i;->A:Lr6/f;

    .line 6
    .line 7
    const/4 v0, 0x0

    .line 8
    :goto_0
    iget-object v1, p0, Lwq/i;->B:[Lr6/e;

    .line 9
    .line 10
    array-length v2, v1

    .line 11
    if-ge v0, v2, :cond_1

    .line 12
    .line 13
    aget-object v2, v1, v0

    .line 14
    .line 15
    if-nez v2, :cond_0

    .line 16
    .line 17
    new-instance v2, Lr6/e;

    .line 18
    .line 19
    sget-object v3, Lwq/i;->F:[Lwq/h;

    .line 20
    .line 21
    aget-object v3, v3, v0

    .line 22
    .line 23
    invoke-direct {v2, p0, v3}, Lr6/e;-><init>(Lwq/v;Lkp/l;)V

    .line 24
    .line 25
    .line 26
    aput-object v2, v1, v0

    .line 27
    .line 28
    :cond_0
    aget-object v1, v1, v0

    .line 29
    .line 30
    new-instance v2, Lr6/f;

    .line 31
    .line 32
    invoke-direct {v2}, Lr6/f;-><init>()V

    .line 33
    .line 34
    .line 35
    iget-wide v3, p1, Lr6/f;->b:D

    .line 36
    .line 37
    double-to-float v3, v3

    .line 38
    invoke-virtual {v2, v3}, Lr6/f;->a(F)V

    .line 39
    .line 40
    .line 41
    iget-wide v3, p1, Lr6/f;->a:D

    .line 42
    .line 43
    mul-double/2addr v3, v3

    .line 44
    double-to-float v3, v3

    .line 45
    invoke-virtual {v2, v3}, Lr6/f;->b(F)V

    .line 46
    .line 47
    .line 48
    iput-object v2, v1, Lr6/e;->m:Lr6/f;

    .line 49
    .line 50
    add-int/lit8 v0, v0, 0x1

    .line 51
    .line 52
    goto :goto_0

    .line 53
    :cond_1
    invoke-virtual {p0}, Landroid/graphics/drawable/Drawable;->getState()[I

    .line 54
    .line 55
    .line 56
    move-result-object p1

    .line 57
    const/4 v0, 0x1

    .line 58
    invoke-virtual {p0, p1, v0}, Lwq/i;->p([IZ)V

    .line 59
    .line 60
    .line 61
    invoke-virtual {p0}, Lwq/i;->invalidateSelf()V

    .line 62
    .line 63
    .line 64
    :cond_2
    return-void
.end method

.method public final l(F)V
    .locals 2

    .line 1
    iget-object v0, p0, Lwq/i;->e:Lwq/g;

    .line 2
    .line 3
    iget v1, v0, Lwq/g;->n:F

    .line 4
    .line 5
    cmpl-float v1, v1, p1

    .line 6
    .line 7
    if-eqz v1, :cond_0

    .line 8
    .line 9
    iput p1, v0, Lwq/g;->n:F

    .line 10
    .line 11
    invoke-virtual {p0}, Lwq/i;->r()V

    .line 12
    .line 13
    .line 14
    :cond_0
    return-void
.end method

.method public final m(Landroid/content/res/ColorStateList;)V
    .locals 2

    .line 1
    iget-object v0, p0, Lwq/i;->e:Lwq/g;

    .line 2
    .line 3
    iget-object v1, v0, Lwq/g;->d:Landroid/content/res/ColorStateList;

    .line 4
    .line 5
    if-eq v1, p1, :cond_0

    .line 6
    .line 7
    iput-object p1, v0, Lwq/g;->d:Landroid/content/res/ColorStateList;

    .line 8
    .line 9
    invoke-virtual {p0}, Landroid/graphics/drawable/Drawable;->getState()[I

    .line 10
    .line 11
    .line 12
    move-result-object p1

    .line 13
    invoke-virtual {p0, p1}, Lwq/i;->onStateChange([I)Z

    .line 14
    .line 15
    .line 16
    :cond_0
    return-void
.end method

.method public mutate()Landroid/graphics/drawable/Drawable;
    .locals 2

    .line 1
    new-instance v0, Lwq/g;

    .line 2
    .line 3
    iget-object v1, p0, Lwq/i;->e:Lwq/g;

    .line 4
    .line 5
    invoke-direct {v0, v1}, Lwq/g;-><init>(Lwq/g;)V

    .line 6
    .line 7
    .line 8
    iput-object v0, p0, Lwq/i;->e:Lwq/g;

    .line 9
    .line 10
    return-object p0
.end method

.method public final n(Lwq/x;)V
    .locals 2

    .line 1
    iget-object v0, p0, Lwq/i;->e:Lwq/g;

    .line 2
    .line 3
    iget-object v1, v0, Lwq/g;->b:Lwq/x;

    .line 4
    .line 5
    if-eq v1, p1, :cond_0

    .line 6
    .line 7
    iput-object p1, v0, Lwq/g;->b:Lwq/x;

    .line 8
    .line 9
    invoke-virtual {p0}, Landroid/graphics/drawable/Drawable;->getState()[I

    .line 10
    .line 11
    .line 12
    move-result-object p1

    .line 13
    const/4 v0, 0x1

    .line 14
    invoke-virtual {p0, p1, v0}, Lwq/i;->p([IZ)V

    .line 15
    .line 16
    .line 17
    invoke-virtual {p0}, Lwq/i;->invalidateSelf()V

    .line 18
    .line 19
    .line 20
    :cond_0
    return-void
.end method

.method public final o([I)Z
    .locals 4

    .line 1
    iget-object v0, p0, Lwq/i;->e:Lwq/g;

    .line 2
    .line 3
    iget-object v0, v0, Lwq/g;->d:Landroid/content/res/ColorStateList;

    .line 4
    .line 5
    const/4 v1, 0x1

    .line 6
    if-eqz v0, :cond_0

    .line 7
    .line 8
    iget-object v0, p0, Lwq/i;->r:Landroid/graphics/Paint;

    .line 9
    .line 10
    invoke-virtual {v0}, Landroid/graphics/Paint;->getColor()I

    .line 11
    .line 12
    .line 13
    move-result v2

    .line 14
    iget-object v3, p0, Lwq/i;->e:Lwq/g;

    .line 15
    .line 16
    iget-object v3, v3, Lwq/g;->d:Landroid/content/res/ColorStateList;

    .line 17
    .line 18
    invoke-virtual {v3, p1, v2}, Landroid/content/res/ColorStateList;->getColorForState([II)I

    .line 19
    .line 20
    .line 21
    move-result v3

    .line 22
    if-eq v2, v3, :cond_0

    .line 23
    .line 24
    invoke-virtual {v0, v3}, Landroid/graphics/Paint;->setColor(I)V

    .line 25
    .line 26
    .line 27
    move v0, v1

    .line 28
    goto :goto_0

    .line 29
    :cond_0
    const/4 v0, 0x0

    .line 30
    :goto_0
    iget-object v2, p0, Lwq/i;->e:Lwq/g;

    .line 31
    .line 32
    iget-object v2, v2, Lwq/g;->e:Landroid/content/res/ColorStateList;

    .line 33
    .line 34
    if-eqz v2, :cond_1

    .line 35
    .line 36
    iget-object v2, p0, Lwq/i;->s:Landroid/graphics/Paint;

    .line 37
    .line 38
    invoke-virtual {v2}, Landroid/graphics/Paint;->getColor()I

    .line 39
    .line 40
    .line 41
    move-result v3

    .line 42
    iget-object p0, p0, Lwq/i;->e:Lwq/g;

    .line 43
    .line 44
    iget-object p0, p0, Lwq/g;->e:Landroid/content/res/ColorStateList;

    .line 45
    .line 46
    invoke-virtual {p0, p1, v3}, Landroid/content/res/ColorStateList;->getColorForState([II)I

    .line 47
    .line 48
    .line 49
    move-result p0

    .line 50
    if-eq v3, p0, :cond_1

    .line 51
    .line 52
    invoke-virtual {v2, p0}, Landroid/graphics/Paint;->setColor(I)V

    .line 53
    .line 54
    .line 55
    return v1

    .line 56
    :cond_1
    return v0
.end method

.method public final onBoundsChange(Landroid/graphics/Rect;)V
    .locals 2

    .line 1
    const/4 v0, 0x1

    .line 2
    iput-boolean v0, p0, Lwq/i;->i:Z

    .line 3
    .line 4
    iput-boolean v0, p0, Lwq/i;->j:Z

    .line 5
    .line 6
    invoke-super {p0, p1}, Landroid/graphics/drawable/Drawable;->onBoundsChange(Landroid/graphics/Rect;)V

    .line 7
    .line 8
    .line 9
    iget-object v0, p0, Lwq/i;->e:Lwq/g;

    .line 10
    .line 11
    iget-object v0, v0, Lwq/g;->b:Lwq/x;

    .line 12
    .line 13
    if-eqz v0, :cond_0

    .line 14
    .line 15
    invoke-virtual {p1}, Landroid/graphics/Rect;->isEmpty()Z

    .line 16
    .line 17
    .line 18
    move-result v0

    .line 19
    if-nez v0, :cond_0

    .line 20
    .line 21
    invoke-virtual {p0}, Landroid/graphics/drawable/Drawable;->getState()[I

    .line 22
    .line 23
    .line 24
    move-result-object v0

    .line 25
    iget-boolean v1, p0, Lwq/i;->y:Z

    .line 26
    .line 27
    invoke-virtual {p0, v0, v1}, Lwq/i;->p([IZ)V

    .line 28
    .line 29
    .line 30
    :cond_0
    invoke-virtual {p1}, Landroid/graphics/Rect;->isEmpty()Z

    .line 31
    .line 32
    .line 33
    move-result p1

    .line 34
    iput-boolean p1, p0, Lwq/i;->y:Z

    .line 35
    .line 36
    return-void
.end method

.method public onStateChange([I)Z
    .locals 2

    .line 1
    iget-object v0, p0, Lwq/i;->e:Lwq/g;

    .line 2
    .line 3
    iget-object v0, v0, Lwq/g;->b:Lwq/x;

    .line 4
    .line 5
    const/4 v1, 0x0

    .line 6
    if-eqz v0, :cond_0

    .line 7
    .line 8
    invoke-virtual {p0, p1, v1}, Lwq/i;->p([IZ)V

    .line 9
    .line 10
    .line 11
    :cond_0
    invoke-virtual {p0, p1}, Lwq/i;->o([I)Z

    .line 12
    .line 13
    .line 14
    move-result p1

    .line 15
    invoke-virtual {p0}, Lwq/i;->q()Z

    .line 16
    .line 17
    .line 18
    move-result v0

    .line 19
    if-nez p1, :cond_1

    .line 20
    .line 21
    if-eqz v0, :cond_2

    .line 22
    .line 23
    :cond_1
    const/4 v1, 0x1

    .line 24
    :cond_2
    if-eqz v1, :cond_3

    .line 25
    .line 26
    invoke-virtual {p0}, Lwq/i;->invalidateSelf()V

    .line 27
    .line 28
    .line 29
    :cond_3
    return v1
.end method

.method public final p([IZ)V
    .locals 16

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    invoke-virtual {v0}, Lwq/i;->f()Landroid/graphics/RectF;

    .line 6
    .line 7
    .line 8
    move-result-object v2

    .line 9
    iget-object v3, v0, Lwq/i;->e:Lwq/g;

    .line 10
    .line 11
    iget-object v3, v3, Lwq/g;->b:Lwq/x;

    .line 12
    .line 13
    if-eqz v3, :cond_13

    .line 14
    .line 15
    invoke-virtual {v2}, Landroid/graphics/RectF;->isEmpty()Z

    .line 16
    .line 17
    .line 18
    move-result v3

    .line 19
    if-eqz v3, :cond_0

    .line 20
    .line 21
    goto/16 :goto_8

    .line 22
    .line 23
    :cond_0
    iget-object v3, v0, Lwq/i;->A:Lr6/f;

    .line 24
    .line 25
    const/4 v5, 0x1

    .line 26
    if-nez v3, :cond_1

    .line 27
    .line 28
    move v3, v5

    .line 29
    goto :goto_0

    .line 30
    :cond_1
    const/4 v3, 0x0

    .line 31
    :goto_0
    or-int v3, p2, v3

    .line 32
    .line 33
    iget-object v6, v0, Lwq/i;->C:[F

    .line 34
    .line 35
    const/4 v7, 0x4

    .line 36
    if-nez v6, :cond_2

    .line 37
    .line 38
    new-array v6, v7, [F

    .line 39
    .line 40
    iput-object v6, v0, Lwq/i;->C:[F

    .line 41
    .line 42
    :cond_2
    iget-object v6, v0, Lwq/i;->e:Lwq/g;

    .line 43
    .line 44
    iget-object v6, v6, Lwq/g;->b:Lwq/x;

    .line 45
    .line 46
    iget-object v8, v6, Lwq/x;->d:[Lwq/m;

    .line 47
    .line 48
    iget v9, v6, Lwq/x;->a:I

    .line 49
    .line 50
    iget-object v10, v6, Lwq/x;->c:[[I

    .line 51
    .line 52
    iget-object v11, v6, Lwq/x;->h:Lwq/w;

    .line 53
    .line 54
    iget-object v12, v6, Lwq/x;->g:Lwq/w;

    .line 55
    .line 56
    iget-object v13, v6, Lwq/x;->f:Lwq/w;

    .line 57
    .line 58
    iget-object v6, v6, Lwq/x;->e:Lwq/w;

    .line 59
    .line 60
    const/4 v14, 0x0

    .line 61
    :goto_1
    if-ge v14, v9, :cond_4

    .line 62
    .line 63
    aget-object v4, v10, v14

    .line 64
    .line 65
    invoke-static {v4, v1}, Landroid/util/StateSet;->stateSetMatches([I[I)Z

    .line 66
    .line 67
    .line 68
    move-result v4

    .line 69
    if-eqz v4, :cond_3

    .line 70
    .line 71
    goto :goto_2

    .line 72
    :cond_3
    add-int/lit8 v14, v14, 0x1

    .line 73
    .line 74
    goto :goto_1

    .line 75
    :cond_4
    const/4 v14, -0x1

    .line 76
    :goto_2
    if-gez v14, :cond_7

    .line 77
    .line 78
    sget-object v4, Landroid/util/StateSet;->WILD_CARD:[I

    .line 79
    .line 80
    const/4 v14, 0x0

    .line 81
    :goto_3
    if-ge v14, v9, :cond_6

    .line 82
    .line 83
    aget-object v15, v10, v14

    .line 84
    .line 85
    invoke-static {v15, v4}, Landroid/util/StateSet;->stateSetMatches([I[I)Z

    .line 86
    .line 87
    .line 88
    move-result v15

    .line 89
    if-eqz v15, :cond_5

    .line 90
    .line 91
    move v15, v14

    .line 92
    goto :goto_4

    .line 93
    :cond_5
    add-int/lit8 v14, v14, 0x1

    .line 94
    .line 95
    goto :goto_3

    .line 96
    :cond_6
    const/4 v15, -0x1

    .line 97
    :goto_4
    move v14, v15

    .line 98
    :cond_7
    if-nez v6, :cond_8

    .line 99
    .line 100
    if-nez v13, :cond_8

    .line 101
    .line 102
    if-nez v12, :cond_8

    .line 103
    .line 104
    if-nez v11, :cond_8

    .line 105
    .line 106
    aget-object v1, v8, v14

    .line 107
    .line 108
    goto :goto_5

    .line 109
    :cond_8
    aget-object v4, v8, v14

    .line 110
    .line 111
    invoke-virtual {v4}, Lwq/m;->f()Lwq/l;

    .line 112
    .line 113
    .line 114
    move-result-object v4

    .line 115
    if-eqz v6, :cond_9

    .line 116
    .line 117
    invoke-virtual {v6, v1}, Lwq/w;->c([I)Lwq/d;

    .line 118
    .line 119
    .line 120
    move-result-object v6

    .line 121
    iput-object v6, v4, Lwq/l;->e:Lwq/d;

    .line 122
    .line 123
    :cond_9
    if-eqz v13, :cond_a

    .line 124
    .line 125
    invoke-virtual {v13, v1}, Lwq/w;->c([I)Lwq/d;

    .line 126
    .line 127
    .line 128
    move-result-object v6

    .line 129
    iput-object v6, v4, Lwq/l;->f:Lwq/d;

    .line 130
    .line 131
    :cond_a
    if-eqz v12, :cond_b

    .line 132
    .line 133
    invoke-virtual {v12, v1}, Lwq/w;->c([I)Lwq/d;

    .line 134
    .line 135
    .line 136
    move-result-object v6

    .line 137
    iput-object v6, v4, Lwq/l;->h:Lwq/d;

    .line 138
    .line 139
    :cond_b
    if-eqz v11, :cond_c

    .line 140
    .line 141
    invoke-virtual {v11, v1}, Lwq/w;->c([I)Lwq/d;

    .line 142
    .line 143
    .line 144
    move-result-object v1

    .line 145
    iput-object v1, v4, Lwq/l;->g:Lwq/d;

    .line 146
    .line 147
    :cond_c
    invoke-virtual {v4}, Lwq/l;->a()Lwq/m;

    .line 148
    .line 149
    .line 150
    move-result-object v1

    .line 151
    :goto_5
    const/4 v4, 0x0

    .line 152
    :goto_6
    if-ge v4, v7, :cond_12

    .line 153
    .line 154
    iget-object v6, v0, Lwq/i;->u:Lac/i;

    .line 155
    .line 156
    invoke-virtual {v6}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 157
    .line 158
    .line 159
    if-eq v4, v5, :cond_f

    .line 160
    .line 161
    const/4 v6, 0x2

    .line 162
    if-eq v4, v6, :cond_e

    .line 163
    .line 164
    const/4 v6, 0x3

    .line 165
    if-eq v4, v6, :cond_d

    .line 166
    .line 167
    iget-object v6, v1, Lwq/m;->f:Lwq/d;

    .line 168
    .line 169
    goto :goto_7

    .line 170
    :cond_d
    iget-object v6, v1, Lwq/m;->e:Lwq/d;

    .line 171
    .line 172
    goto :goto_7

    .line 173
    :cond_e
    iget-object v6, v1, Lwq/m;->h:Lwq/d;

    .line 174
    .line 175
    goto :goto_7

    .line 176
    :cond_f
    iget-object v6, v1, Lwq/m;->g:Lwq/d;

    .line 177
    .line 178
    :goto_7
    invoke-interface {v6, v2}, Lwq/d;->a(Landroid/graphics/RectF;)F

    .line 179
    .line 180
    .line 181
    move-result v6

    .line 182
    if-eqz v3, :cond_10

    .line 183
    .line 184
    iget-object v8, v0, Lwq/i;->C:[F

    .line 185
    .line 186
    aput v6, v8, v4

    .line 187
    .line 188
    :cond_10
    iget-object v8, v0, Lwq/i;->B:[Lr6/e;

    .line 189
    .line 190
    aget-object v9, v8, v4

    .line 191
    .line 192
    if-eqz v9, :cond_11

    .line 193
    .line 194
    invoke-virtual {v9, v6}, Lr6/e;->a(F)V

    .line 195
    .line 196
    .line 197
    if-eqz v3, :cond_11

    .line 198
    .line 199
    aget-object v6, v8, v4

    .line 200
    .line 201
    invoke-virtual {v6}, Lr6/e;->d()V

    .line 202
    .line 203
    .line 204
    :cond_11
    add-int/lit8 v4, v4, 0x1

    .line 205
    .line 206
    goto :goto_6

    .line 207
    :cond_12
    if-eqz v3, :cond_13

    .line 208
    .line 209
    invoke-virtual {v0}, Lwq/i;->invalidateSelf()V

    .line 210
    .line 211
    .line 212
    :cond_13
    :goto_8
    return-void
.end method

.method public final q()Z
    .locals 7

    .line 1
    iget-object v0, p0, Lwq/i;->v:Landroid/graphics/PorterDuffColorFilter;

    .line 2
    .line 3
    iget-object v1, p0, Lwq/i;->w:Landroid/graphics/PorterDuffColorFilter;

    .line 4
    .line 5
    iget-object v2, p0, Lwq/i;->e:Lwq/g;

    .line 6
    .line 7
    iget-object v3, v2, Lwq/g;->f:Landroid/content/res/ColorStateList;

    .line 8
    .line 9
    iget-object v2, v2, Lwq/g;->g:Landroid/graphics/PorterDuff$Mode;

    .line 10
    .line 11
    const/4 v4, 0x1

    .line 12
    if-eqz v3, :cond_1

    .line 13
    .line 14
    if-nez v2, :cond_0

    .line 15
    .line 16
    goto :goto_0

    .line 17
    :cond_0
    invoke-virtual {p0}, Landroid/graphics/drawable/Drawable;->getState()[I

    .line 18
    .line 19
    .line 20
    move-result-object v5

    .line 21
    const/4 v6, 0x0

    .line 22
    invoke-virtual {v3, v5, v6}, Landroid/content/res/ColorStateList;->getColorForState([II)I

    .line 23
    .line 24
    .line 25
    move-result v3

    .line 26
    invoke-virtual {p0, v3}, Lwq/i;->c(I)I

    .line 27
    .line 28
    .line 29
    move-result v3

    .line 30
    new-instance v5, Landroid/graphics/PorterDuffColorFilter;

    .line 31
    .line 32
    invoke-direct {v5, v3, v2}, Landroid/graphics/PorterDuffColorFilter;-><init>(ILandroid/graphics/PorterDuff$Mode;)V

    .line 33
    .line 34
    .line 35
    goto :goto_1

    .line 36
    :cond_1
    :goto_0
    iget-object v2, p0, Lwq/i;->r:Landroid/graphics/Paint;

    .line 37
    .line 38
    invoke-virtual {v2}, Landroid/graphics/Paint;->getColor()I

    .line 39
    .line 40
    .line 41
    move-result v2

    .line 42
    invoke-virtual {p0, v2}, Lwq/i;->c(I)I

    .line 43
    .line 44
    .line 45
    move-result v3

    .line 46
    if-eq v3, v2, :cond_2

    .line 47
    .line 48
    new-instance v5, Landroid/graphics/PorterDuffColorFilter;

    .line 49
    .line 50
    sget-object v2, Landroid/graphics/PorterDuff$Mode;->SRC_IN:Landroid/graphics/PorterDuff$Mode;

    .line 51
    .line 52
    invoke-direct {v5, v3, v2}, Landroid/graphics/PorterDuffColorFilter;-><init>(ILandroid/graphics/PorterDuff$Mode;)V

    .line 53
    .line 54
    .line 55
    goto :goto_1

    .line 56
    :cond_2
    const/4 v5, 0x0

    .line 57
    :goto_1
    iput-object v5, p0, Lwq/i;->v:Landroid/graphics/PorterDuffColorFilter;

    .line 58
    .line 59
    iget-object v2, p0, Lwq/i;->e:Lwq/g;

    .line 60
    .line 61
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 62
    .line 63
    .line 64
    const/4 v2, 0x0

    .line 65
    iput-object v2, p0, Lwq/i;->w:Landroid/graphics/PorterDuffColorFilter;

    .line 66
    .line 67
    iget-object v2, p0, Lwq/i;->e:Lwq/g;

    .line 68
    .line 69
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 70
    .line 71
    .line 72
    iget-object v2, p0, Lwq/i;->v:Landroid/graphics/PorterDuffColorFilter;

    .line 73
    .line 74
    invoke-static {v0, v2}, Ljava/util/Objects;->equals(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 75
    .line 76
    .line 77
    move-result v0

    .line 78
    if-eqz v0, :cond_4

    .line 79
    .line 80
    iget-object p0, p0, Lwq/i;->w:Landroid/graphics/PorterDuffColorFilter;

    .line 81
    .line 82
    invoke-static {v1, p0}, Ljava/util/Objects;->equals(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 83
    .line 84
    .line 85
    move-result p0

    .line 86
    if-nez p0, :cond_3

    .line 87
    .line 88
    goto :goto_2

    .line 89
    :cond_3
    const/4 p0, 0x0

    .line 90
    return p0

    .line 91
    :cond_4
    :goto_2
    return v4
.end method

.method public final r()V
    .locals 4

    .line 1
    iget-object v0, p0, Lwq/i;->e:Lwq/g;

    .line 2
    .line 3
    iget v1, v0, Lwq/g;->n:F

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    add-float/2addr v1, v2

    .line 7
    const/high16 v2, 0x3f400000    # 0.75f

    .line 8
    .line 9
    mul-float/2addr v2, v1

    .line 10
    float-to-double v2, v2

    .line 11
    invoke-static {v2, v3}, Ljava/lang/Math;->ceil(D)D

    .line 12
    .line 13
    .line 14
    move-result-wide v2

    .line 15
    double-to-int v2, v2

    .line 16
    iput v2, v0, Lwq/g;->o:I

    .line 17
    .line 18
    iget-object v0, p0, Lwq/i;->e:Lwq/g;

    .line 19
    .line 20
    const/high16 v2, 0x3e800000    # 0.25f

    .line 21
    .line 22
    mul-float/2addr v1, v2

    .line 23
    float-to-double v1, v1

    .line 24
    invoke-static {v1, v2}, Ljava/lang/Math;->ceil(D)D

    .line 25
    .line 26
    .line 27
    move-result-wide v1

    .line 28
    double-to-int v1, v1

    .line 29
    iput v1, v0, Lwq/g;->p:I

    .line 30
    .line 31
    invoke-virtual {p0}, Lwq/i;->q()Z

    .line 32
    .line 33
    .line 34
    invoke-super {p0}, Landroid/graphics/drawable/Drawable;->invalidateSelf()V

    .line 35
    .line 36
    .line 37
    return-void
.end method

.method public setAlpha(I)V
    .locals 2

    .line 1
    iget-object v0, p0, Lwq/i;->e:Lwq/g;

    .line 2
    .line 3
    iget v1, v0, Lwq/g;->l:I

    .line 4
    .line 5
    if-eq v1, p1, :cond_0

    .line 6
    .line 7
    iput p1, v0, Lwq/g;->l:I

    .line 8
    .line 9
    invoke-super {p0}, Landroid/graphics/drawable/Drawable;->invalidateSelf()V

    .line 10
    .line 11
    .line 12
    :cond_0
    return-void
.end method

.method public setColorFilter(Landroid/graphics/ColorFilter;)V
    .locals 0

    .line 1
    iget-object p1, p0, Lwq/i;->e:Lwq/g;

    .line 2
    .line 3
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 4
    .line 5
    .line 6
    invoke-super {p0}, Landroid/graphics/drawable/Drawable;->invalidateSelf()V

    .line 7
    .line 8
    .line 9
    return-void
.end method

.method public final setShapeAppearanceModel(Lwq/m;)V
    .locals 1

    .line 1
    iget-object v0, p0, Lwq/i;->e:Lwq/g;

    .line 2
    .line 3
    iput-object p1, v0, Lwq/g;->a:Lwq/m;

    .line 4
    .line 5
    const/4 p1, 0x0

    .line 6
    iput-object p1, v0, Lwq/g;->b:Lwq/x;

    .line 7
    .line 8
    iput-object p1, p0, Lwq/i;->C:[F

    .line 9
    .line 10
    iput-object p1, p0, Lwq/i;->D:[F

    .line 11
    .line 12
    invoke-virtual {p0}, Lwq/i;->invalidateSelf()V

    .line 13
    .line 14
    .line 15
    return-void
.end method

.method public final setTint(I)V
    .locals 0

    .line 1
    invoke-static {p1}, Landroid/content/res/ColorStateList;->valueOf(I)Landroid/content/res/ColorStateList;

    .line 2
    .line 3
    .line 4
    move-result-object p1

    .line 5
    invoke-virtual {p0, p1}, Lwq/i;->setTintList(Landroid/content/res/ColorStateList;)V

    .line 6
    .line 7
    .line 8
    return-void
.end method

.method public setTintList(Landroid/content/res/ColorStateList;)V
    .locals 1

    .line 1
    iget-object v0, p0, Lwq/i;->e:Lwq/g;

    .line 2
    .line 3
    iput-object p1, v0, Lwq/g;->f:Landroid/content/res/ColorStateList;

    .line 4
    .line 5
    invoke-virtual {p0}, Lwq/i;->q()Z

    .line 6
    .line 7
    .line 8
    invoke-super {p0}, Landroid/graphics/drawable/Drawable;->invalidateSelf()V

    .line 9
    .line 10
    .line 11
    return-void
.end method

.method public setTintMode(Landroid/graphics/PorterDuff$Mode;)V
    .locals 2

    .line 1
    iget-object v0, p0, Lwq/i;->e:Lwq/g;

    .line 2
    .line 3
    iget-object v1, v0, Lwq/g;->g:Landroid/graphics/PorterDuff$Mode;

    .line 4
    .line 5
    if-eq v1, p1, :cond_0

    .line 6
    .line 7
    iput-object p1, v0, Lwq/g;->g:Landroid/graphics/PorterDuff$Mode;

    .line 8
    .line 9
    invoke-virtual {p0}, Lwq/i;->q()Z

    .line 10
    .line 11
    .line 12
    invoke-super {p0}, Landroid/graphics/drawable/Drawable;->invalidateSelf()V

    .line 13
    .line 14
    .line 15
    :cond_0
    return-void
.end method
