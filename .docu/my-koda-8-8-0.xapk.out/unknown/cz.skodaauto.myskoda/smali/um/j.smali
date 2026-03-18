.class public final Lum/j;
.super Landroid/graphics/drawable/Drawable;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Landroid/graphics/drawable/Drawable$Callback;
.implements Landroid/graphics/drawable/Animatable;


# static fields
.field public static final J:Ljava/util/List;

.field public static final K:Ljava/util/concurrent/ThreadPoolExecutor;


# instance fields
.field public final A:[F

.field public B:Landroid/graphics/Matrix;

.field public C:Z

.field public final D:Ljava/util/concurrent/Semaphore;

.field public final E:Lm8/o;

.field public F:F

.field public G:I

.field public H:I

.field public I:I

.field public d:Lum/a;

.field public final e:Lgn/e;

.field public final f:Z

.field public final g:Ljava/util/ArrayList;

.field public h:Lzm/a;

.field public i:Landroidx/lifecycle/c1;

.field public final j:Lpv/g;

.field public k:Z

.field public l:Ldn/c;

.field public m:I

.field public n:Z

.field public o:Z

.field public final p:Landroid/graphics/Matrix;

.field public q:Landroid/graphics/Bitmap;

.field public r:Landroid/graphics/Canvas;

.field public s:Landroid/graphics/Rect;

.field public t:Landroid/graphics/RectF;

.field public u:Ldn/i;

.field public v:Landroid/graphics/Rect;

.field public w:Landroid/graphics/Rect;

.field public x:Landroid/graphics/RectF;

.field public y:Landroid/graphics/RectF;

.field public z:Landroid/graphics/Matrix;


# direct methods
.method static constructor <clinit>()V
    .locals 9

    .line 1
    const-string v0, "reduced-motion"

    .line 2
    .line 3
    const-string v1, "reducedmotion"

    .line 4
    .line 5
    const-string v2, "reduced motion"

    .line 6
    .line 7
    const-string v3, "reduced_motion"

    .line 8
    .line 9
    filled-new-array {v2, v3, v0, v1}, [Ljava/lang/String;

    .line 10
    .line 11
    .line 12
    move-result-object v0

    .line 13
    invoke-static {v0}, Ljava/util/Arrays;->asList([Ljava/lang/Object;)Ljava/util/List;

    .line 14
    .line 15
    .line 16
    move-result-object v0

    .line 17
    sput-object v0, Lum/j;->J:Ljava/util/List;

    .line 18
    .line 19
    new-instance v1, Ljava/util/concurrent/ThreadPoolExecutor;

    .line 20
    .line 21
    sget-object v6, Ljava/util/concurrent/TimeUnit;->MILLISECONDS:Ljava/util/concurrent/TimeUnit;

    .line 22
    .line 23
    new-instance v7, Ljava/util/concurrent/LinkedBlockingQueue;

    .line 24
    .line 25
    invoke-direct {v7}, Ljava/util/concurrent/LinkedBlockingQueue;-><init>()V

    .line 26
    .line 27
    .line 28
    new-instance v8, Lgn/d;

    .line 29
    .line 30
    invoke-direct {v8}, Lgn/d;-><init>()V

    .line 31
    .line 32
    .line 33
    const/4 v2, 0x0

    .line 34
    const/4 v3, 0x2

    .line 35
    const-wide/16 v4, 0x23

    .line 36
    .line 37
    invoke-direct/range {v1 .. v8}, Ljava/util/concurrent/ThreadPoolExecutor;-><init>(IIJLjava/util/concurrent/TimeUnit;Ljava/util/concurrent/BlockingQueue;Ljava/util/concurrent/ThreadFactory;)V

    .line 38
    .line 39
    .line 40
    sput-object v1, Lum/j;->K:Ljava/util/concurrent/ThreadPoolExecutor;

    .line 41
    .line 42
    return-void
.end method

.method public constructor <init>()V
    .locals 4

    .line 1
    invoke-direct {p0}, Landroid/graphics/drawable/Drawable;-><init>()V

    .line 2
    .line 3
    .line 4
    new-instance v0, Lgn/e;

    .line 5
    .line 6
    invoke-direct {v0}, Lgn/e;-><init>()V

    .line 7
    .line 8
    .line 9
    iput-object v0, p0, Lum/j;->e:Lgn/e;

    .line 10
    .line 11
    const/4 v1, 0x1

    .line 12
    iput-boolean v1, p0, Lum/j;->f:Z

    .line 13
    .line 14
    iput v1, p0, Lum/j;->G:I

    .line 15
    .line 16
    new-instance v2, Ljava/util/ArrayList;

    .line 17
    .line 18
    invoke-direct {v2}, Ljava/util/ArrayList;-><init>()V

    .line 19
    .line 20
    .line 21
    iput-object v2, p0, Lum/j;->g:Ljava/util/ArrayList;

    .line 22
    .line 23
    new-instance v2, Lpv/g;

    .line 24
    .line 25
    const/16 v3, 0xc

    .line 26
    .line 27
    invoke-direct {v2, v3}, Lpv/g;-><init>(I)V

    .line 28
    .line 29
    .line 30
    iput-object v2, p0, Lum/j;->j:Lpv/g;

    .line 31
    .line 32
    iput-boolean v1, p0, Lum/j;->k:Z

    .line 33
    .line 34
    const/16 v2, 0xff

    .line 35
    .line 36
    iput v2, p0, Lum/j;->m:I

    .line 37
    .line 38
    iput v1, p0, Lum/j;->H:I

    .line 39
    .line 40
    const/4 v2, 0x0

    .line 41
    iput-boolean v2, p0, Lum/j;->o:Z

    .line 42
    .line 43
    new-instance v3, Landroid/graphics/Matrix;

    .line 44
    .line 45
    invoke-direct {v3}, Landroid/graphics/Matrix;-><init>()V

    .line 46
    .line 47
    .line 48
    iput-object v3, p0, Lum/j;->p:Landroid/graphics/Matrix;

    .line 49
    .line 50
    const/16 v3, 0x9

    .line 51
    .line 52
    new-array v3, v3, [F

    .line 53
    .line 54
    iput-object v3, p0, Lum/j;->A:[F

    .line 55
    .line 56
    iput-boolean v2, p0, Lum/j;->C:Z

    .line 57
    .line 58
    new-instance v2, Lum/f;

    .line 59
    .line 60
    const/4 v3, 0x0

    .line 61
    invoke-direct {v2, p0, v3}, Lum/f;-><init>(Ljava/lang/Object;I)V

    .line 62
    .line 63
    .line 64
    new-instance v3, Ljava/util/concurrent/Semaphore;

    .line 65
    .line 66
    invoke-direct {v3, v1}, Ljava/util/concurrent/Semaphore;-><init>(I)V

    .line 67
    .line 68
    .line 69
    iput-object v3, p0, Lum/j;->D:Ljava/util/concurrent/Semaphore;

    .line 70
    .line 71
    new-instance v1, Lm8/o;

    .line 72
    .line 73
    const/16 v3, 0x11

    .line 74
    .line 75
    invoke-direct {v1, p0, v3}, Lm8/o;-><init>(Ljava/lang/Object;I)V

    .line 76
    .line 77
    .line 78
    iput-object v1, p0, Lum/j;->E:Lm8/o;

    .line 79
    .line 80
    const v1, -0x800001

    .line 81
    .line 82
    .line 83
    iput v1, p0, Lum/j;->F:F

    .line 84
    .line 85
    invoke-virtual {v0, v2}, Lgn/e;->addUpdateListener(Landroid/animation/ValueAnimator$AnimatorUpdateListener;)V

    .line 86
    .line 87
    .line 88
    return-void
.end method

.method public static d(Landroid/graphics/Rect;Landroid/graphics/RectF;)V
    .locals 5

    .line 1
    iget v0, p1, Landroid/graphics/RectF;->left:F

    .line 2
    .line 3
    float-to-double v0, v0

    .line 4
    invoke-static {v0, v1}, Ljava/lang/Math;->floor(D)D

    .line 5
    .line 6
    .line 7
    move-result-wide v0

    .line 8
    double-to-int v0, v0

    .line 9
    iget v1, p1, Landroid/graphics/RectF;->top:F

    .line 10
    .line 11
    float-to-double v1, v1

    .line 12
    invoke-static {v1, v2}, Ljava/lang/Math;->floor(D)D

    .line 13
    .line 14
    .line 15
    move-result-wide v1

    .line 16
    double-to-int v1, v1

    .line 17
    iget v2, p1, Landroid/graphics/RectF;->right:F

    .line 18
    .line 19
    float-to-double v2, v2

    .line 20
    invoke-static {v2, v3}, Ljava/lang/Math;->ceil(D)D

    .line 21
    .line 22
    .line 23
    move-result-wide v2

    .line 24
    double-to-int v2, v2

    .line 25
    iget p1, p1, Landroid/graphics/RectF;->bottom:F

    .line 26
    .line 27
    float-to-double v3, p1

    .line 28
    invoke-static {v3, v4}, Ljava/lang/Math;->ceil(D)D

    .line 29
    .line 30
    .line 31
    move-result-wide v3

    .line 32
    double-to-int p1, v3

    .line 33
    invoke-virtual {p0, v0, v1, v2, p1}, Landroid/graphics/Rect;->set(IIII)V

    .line 34
    .line 35
    .line 36
    return-void
.end method


# virtual methods
.method public final a(Landroid/content/Context;)Z
    .locals 1

    .line 1
    iget-boolean p0, p0, Lum/j;->f:Z

    .line 2
    .line 3
    if-eqz p0, :cond_1

    .line 4
    .line 5
    if-eqz p1, :cond_0

    .line 6
    .line 7
    sget-object p0, Lgn/h;->a:Landroid/graphics/Matrix;

    .line 8
    .line 9
    invoke-virtual {p1}, Landroid/content/Context;->getContentResolver()Landroid/content/ContentResolver;

    .line 10
    .line 11
    .line 12
    move-result-object p0

    .line 13
    const-string p1, "animator_duration_scale"

    .line 14
    .line 15
    const/high16 v0, 0x3f800000    # 1.0f

    .line 16
    .line 17
    invoke-static {p0, p1, v0}, Landroid/provider/Settings$Global;->getFloat(Landroid/content/ContentResolver;Ljava/lang/String;F)F

    .line 18
    .line 19
    .line 20
    move-result p0

    .line 21
    const/4 p1, 0x0

    .line 22
    cmpl-float p0, p0, p1

    .line 23
    .line 24
    if-eqz p0, :cond_1

    .line 25
    .line 26
    :cond_0
    const/4 p0, 0x1

    .line 27
    return p0

    .line 28
    :cond_1
    const/4 p0, 0x0

    .line 29
    return p0
.end method

.method public final b()V
    .locals 31

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget-object v3, v0, Lum/j;->d:Lum/a;

    .line 4
    .line 5
    if-nez v3, :cond_0

    .line 6
    .line 7
    return-void

    .line 8
    :cond_0
    new-instance v1, Ldn/c;

    .line 9
    .line 10
    sget-object v2, Len/q;->a:Lb81/c;

    .line 11
    .line 12
    iget-object v2, v3, Lum/a;->k:Landroid/graphics/Rect;

    .line 13
    .line 14
    move-object v4, v1

    .line 15
    new-instance v1, Ldn/e;

    .line 16
    .line 17
    move-object v5, v2

    .line 18
    sget-object v2, Ljava/util/Collections;->EMPTY_LIST:Ljava/util/List;

    .line 19
    .line 20
    new-instance v12, Lbn/e;

    .line 21
    .line 22
    invoke-direct {v12}, Lbn/e;-><init>()V

    .line 23
    .line 24
    .line 25
    invoke-virtual {v5}, Landroid/graphics/Rect;->width()I

    .line 26
    .line 27
    .line 28
    move-result v6

    .line 29
    int-to-float v6, v6

    .line 30
    invoke-virtual {v5}, Landroid/graphics/Rect;->height()I

    .line 31
    .line 32
    .line 33
    move-result v5

    .line 34
    int-to-float v5, v5

    .line 35
    const/16 v27, 0x0

    .line 36
    .line 37
    const/16 v28, 0x1

    .line 38
    .line 39
    move-object v7, v4

    .line 40
    const-string v4, "__container"

    .line 41
    .line 42
    move/from16 v19, v5

    .line 43
    .line 44
    move/from16 v18, v6

    .line 45
    .line 46
    const-wide/16 v5, -0x1

    .line 47
    .line 48
    move-object v8, v7

    .line 49
    const/4 v7, 0x1

    .line 50
    move-object v10, v8

    .line 51
    const-wide/16 v8, -0x1

    .line 52
    .line 53
    move-object v11, v10

    .line 54
    const/4 v10, 0x0

    .line 55
    const/4 v13, 0x0

    .line 56
    const/4 v14, 0x0

    .line 57
    const/4 v15, 0x0

    .line 58
    const/16 v16, 0x0

    .line 59
    .line 60
    const/16 v17, 0x0

    .line 61
    .line 62
    const/16 v20, 0x0

    .line 63
    .line 64
    const/16 v21, 0x0

    .line 65
    .line 66
    const/16 v23, 0x1

    .line 67
    .line 68
    const/16 v24, 0x0

    .line 69
    .line 70
    const/16 v25, 0x0

    .line 71
    .line 72
    const/16 v26, 0x0

    .line 73
    .line 74
    move-object/from16 v22, v11

    .line 75
    .line 76
    move-object v11, v2

    .line 77
    move-object/from16 v29, v22

    .line 78
    .line 79
    move-object/from16 v22, v2

    .line 80
    .line 81
    move-object/from16 v30, v29

    .line 82
    .line 83
    invoke-direct/range {v1 .. v28}, Ldn/e;-><init>(Ljava/util/List;Lum/a;Ljava/lang/String;JIJLjava/lang/String;Ljava/util/List;Lbn/e;IIIFFFFLbn/a;Lb81/c;Ljava/util/List;ILbn/b;ZLaq/a;Landroidx/lifecycle/c1;I)V

    .line 84
    .line 85
    .line 86
    iget-object v2, v3, Lum/a;->j:Ljava/util/ArrayList;

    .line 87
    .line 88
    move-object/from16 v4, v30

    .line 89
    .line 90
    invoke-direct {v4, v0, v1, v2, v3}, Ldn/c;-><init>(Lum/j;Ldn/e;Ljava/util/List;Lum/a;)V

    .line 91
    .line 92
    .line 93
    iput-object v4, v0, Lum/j;->l:Ldn/c;

    .line 94
    .line 95
    iget-boolean v0, v0, Lum/j;->k:Z

    .line 96
    .line 97
    iput-boolean v0, v4, Ldn/c;->I:Z

    .line 98
    .line 99
    return-void
.end method

.method public final c()V
    .locals 5

    .line 1
    iget-object v0, p0, Lum/j;->d:Lum/a;

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    return-void

    .line 6
    :cond_0
    iget v1, p0, Lum/j;->H:I

    .line 7
    .line 8
    iget v0, v0, Lum/a;->o:I

    .line 9
    .line 10
    invoke-static {v1}, Lu/w;->o(I)I

    .line 11
    .line 12
    .line 13
    move-result v1

    .line 14
    const/4 v2, 0x0

    .line 15
    const/4 v3, 0x1

    .line 16
    if-eq v1, v3, :cond_2

    .line 17
    .line 18
    const/4 v4, 0x2

    .line 19
    if-eq v1, v4, :cond_1

    .line 20
    .line 21
    const/4 v1, 0x4

    .line 22
    if-le v0, v1, :cond_2

    .line 23
    .line 24
    :cond_1
    move v2, v3

    .line 25
    :cond_2
    iput-boolean v2, p0, Lum/j;->o:Z

    .line 26
    .line 27
    return-void
.end method

.method public final draw(Landroid/graphics/Canvas;)V
    .locals 8

    .line 1
    iget-object v0, p0, Lum/j;->l:Ldn/c;

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    goto/16 :goto_5

    .line 6
    .line 7
    :cond_0
    iget v1, p0, Lum/j;->I:I

    .line 8
    .line 9
    const/4 v2, 0x1

    .line 10
    if-eqz v1, :cond_1

    .line 11
    .line 12
    goto :goto_0

    .line 13
    :cond_1
    move v1, v2

    .line 14
    :goto_0
    const/4 v3, 0x2

    .line 15
    const/4 v4, 0x0

    .line 16
    if-ne v1, v3, :cond_2

    .line 17
    .line 18
    goto :goto_1

    .line 19
    :cond_2
    move v2, v4

    .line 20
    :goto_1
    iget-object v1, p0, Lum/j;->E:Lm8/o;

    .line 21
    .line 22
    sget-object v3, Lum/j;->K:Ljava/util/concurrent/ThreadPoolExecutor;

    .line 23
    .line 24
    iget-object v5, p0, Lum/j;->e:Lgn/e;

    .line 25
    .line 26
    iget-object v6, p0, Lum/j;->D:Ljava/util/concurrent/Semaphore;

    .line 27
    .line 28
    if-eqz v2, :cond_3

    .line 29
    .line 30
    :try_start_0
    invoke-virtual {v6}, Ljava/util/concurrent/Semaphore;->acquire()V

    .line 31
    .line 32
    .line 33
    goto :goto_2

    .line 34
    :catchall_0
    move-exception p0

    .line 35
    goto :goto_4

    .line 36
    :cond_3
    :goto_2
    if-eqz v2, :cond_4

    .line 37
    .line 38
    invoke-virtual {p0}, Lum/j;->m()Z

    .line 39
    .line 40
    .line 41
    move-result v7

    .line 42
    if-eqz v7, :cond_4

    .line 43
    .line 44
    invoke-virtual {v5}, Lgn/e;->a()F

    .line 45
    .line 46
    .line 47
    move-result v7

    .line 48
    invoke-virtual {p0, v7}, Lum/j;->l(F)V

    .line 49
    .line 50
    .line 51
    :cond_4
    iget-boolean v7, p0, Lum/j;->o:Z

    .line 52
    .line 53
    if-eqz v7, :cond_5

    .line 54
    .line 55
    invoke-virtual {p0, p1, v0}, Lum/j;->i(Landroid/graphics/Canvas;Ldn/c;)V

    .line 56
    .line 57
    .line 58
    goto :goto_3

    .line 59
    :cond_5
    invoke-virtual {p0, p1}, Lum/j;->e(Landroid/graphics/Canvas;)V

    .line 60
    .line 61
    .line 62
    :goto_3
    iput-boolean v4, p0, Lum/j;->C:Z
    :try_end_0
    .catch Ljava/lang/InterruptedException; {:try_start_0 .. :try_end_0} :catch_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 63
    .line 64
    if-eqz v2, :cond_7

    .line 65
    .line 66
    invoke-virtual {v6}, Ljava/util/concurrent/Semaphore;->release()V

    .line 67
    .line 68
    .line 69
    iget p0, v0, Ldn/c;->H:F

    .line 70
    .line 71
    invoke-virtual {v5}, Lgn/e;->a()F

    .line 72
    .line 73
    .line 74
    move-result p1

    .line 75
    cmpl-float p0, p0, p1

    .line 76
    .line 77
    if-eqz p0, :cond_7

    .line 78
    .line 79
    invoke-virtual {v3, v1}, Ljava/util/concurrent/ThreadPoolExecutor;->execute(Ljava/lang/Runnable;)V

    .line 80
    .line 81
    .line 82
    return-void

    .line 83
    :goto_4
    if-eqz v2, :cond_6

    .line 84
    .line 85
    invoke-virtual {v6}, Ljava/util/concurrent/Semaphore;->release()V

    .line 86
    .line 87
    .line 88
    iget p1, v0, Ldn/c;->H:F

    .line 89
    .line 90
    invoke-virtual {v5}, Lgn/e;->a()F

    .line 91
    .line 92
    .line 93
    move-result v0

    .line 94
    cmpl-float p1, p1, v0

    .line 95
    .line 96
    if-eqz p1, :cond_6

    .line 97
    .line 98
    invoke-virtual {v3, v1}, Ljava/util/concurrent/ThreadPoolExecutor;->execute(Ljava/lang/Runnable;)V

    .line 99
    .line 100
    .line 101
    :cond_6
    throw p0

    .line 102
    :catch_0
    if-eqz v2, :cond_7

    .line 103
    .line 104
    invoke-virtual {v6}, Ljava/util/concurrent/Semaphore;->release()V

    .line 105
    .line 106
    .line 107
    iget p0, v0, Ldn/c;->H:F

    .line 108
    .line 109
    invoke-virtual {v5}, Lgn/e;->a()F

    .line 110
    .line 111
    .line 112
    move-result p1

    .line 113
    cmpl-float p0, p0, p1

    .line 114
    .line 115
    if-eqz p0, :cond_7

    .line 116
    .line 117
    invoke-virtual {v3, v1}, Ljava/util/concurrent/ThreadPoolExecutor;->execute(Ljava/lang/Runnable;)V

    .line 118
    .line 119
    .line 120
    :cond_7
    :goto_5
    return-void
.end method

.method public final e(Landroid/graphics/Canvas;)V
    .locals 6

    .line 1
    iget-object v0, p0, Lum/j;->l:Ldn/c;

    .line 2
    .line 3
    iget-object v1, p0, Lum/j;->d:Lum/a;

    .line 4
    .line 5
    if-eqz v0, :cond_2

    .line 6
    .line 7
    if-nez v1, :cond_0

    .line 8
    .line 9
    goto :goto_0

    .line 10
    :cond_0
    iget-object v2, p0, Lum/j;->p:Landroid/graphics/Matrix;

    .line 11
    .line 12
    invoke-virtual {v2}, Landroid/graphics/Matrix;->reset()V

    .line 13
    .line 14
    .line 15
    invoke-virtual {p0}, Landroid/graphics/drawable/Drawable;->getBounds()Landroid/graphics/Rect;

    .line 16
    .line 17
    .line 18
    move-result-object v3

    .line 19
    invoke-virtual {v3}, Landroid/graphics/Rect;->isEmpty()Z

    .line 20
    .line 21
    .line 22
    move-result v4

    .line 23
    if-nez v4, :cond_1

    .line 24
    .line 25
    invoke-virtual {v3}, Landroid/graphics/Rect;->width()I

    .line 26
    .line 27
    .line 28
    move-result v4

    .line 29
    int-to-float v4, v4

    .line 30
    iget-object v5, v1, Lum/a;->k:Landroid/graphics/Rect;

    .line 31
    .line 32
    invoke-virtual {v5}, Landroid/graphics/Rect;->width()I

    .line 33
    .line 34
    .line 35
    move-result v5

    .line 36
    int-to-float v5, v5

    .line 37
    div-float/2addr v4, v5

    .line 38
    invoke-virtual {v3}, Landroid/graphics/Rect;->height()I

    .line 39
    .line 40
    .line 41
    move-result v5

    .line 42
    int-to-float v5, v5

    .line 43
    iget-object v1, v1, Lum/a;->k:Landroid/graphics/Rect;

    .line 44
    .line 45
    invoke-virtual {v1}, Landroid/graphics/Rect;->height()I

    .line 46
    .line 47
    .line 48
    move-result v1

    .line 49
    int-to-float v1, v1

    .line 50
    div-float/2addr v5, v1

    .line 51
    iget v1, v3, Landroid/graphics/Rect;->left:I

    .line 52
    .line 53
    int-to-float v1, v1

    .line 54
    iget v3, v3, Landroid/graphics/Rect;->top:I

    .line 55
    .line 56
    int-to-float v3, v3

    .line 57
    invoke-virtual {v2, v1, v3}, Landroid/graphics/Matrix;->preTranslate(FF)Z

    .line 58
    .line 59
    .line 60
    invoke-virtual {v2, v4, v5}, Landroid/graphics/Matrix;->preScale(FF)Z

    .line 61
    .line 62
    .line 63
    :cond_1
    iget p0, p0, Lum/j;->m:I

    .line 64
    .line 65
    const/4 v1, 0x0

    .line 66
    invoke-virtual {v0, p1, v2, p0, v1}, Ldn/b;->c(Landroid/graphics/Canvas;Landroid/graphics/Matrix;ILgn/a;)V

    .line 67
    .line 68
    .line 69
    :cond_2
    :goto_0
    return-void
.end method

.method public final f()Landroid/content/Context;
    .locals 2

    .line 1
    invoke-virtual {p0}, Landroid/graphics/drawable/Drawable;->getCallback()Landroid/graphics/drawable/Drawable$Callback;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    const/4 v0, 0x0

    .line 6
    if-nez p0, :cond_0

    .line 7
    .line 8
    return-object v0

    .line 9
    :cond_0
    instance-of v1, p0, Landroid/view/View;

    .line 10
    .line 11
    if-eqz v1, :cond_1

    .line 12
    .line 13
    check-cast p0, Landroid/view/View;

    .line 14
    .line 15
    invoke-virtual {p0}, Landroid/view/View;->getContext()Landroid/content/Context;

    .line 16
    .line 17
    .line 18
    move-result-object p0

    .line 19
    return-object p0

    .line 20
    :cond_1
    return-object v0
.end method

.method public final g()Lan/f;
    .locals 10

    .line 1
    sget-object v0, Lum/j;->J:Ljava/util/List;

    .line 2
    .line 3
    invoke-interface {v0}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    const/4 v1, 0x0

    .line 8
    move-object v2, v1

    .line 9
    :cond_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 10
    .line 11
    .line 12
    move-result v3

    .line 13
    if-eqz v3, :cond_4

    .line 14
    .line 15
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 16
    .line 17
    .line 18
    move-result-object v2

    .line 19
    check-cast v2, Ljava/lang/String;

    .line 20
    .line 21
    iget-object v3, p0, Lum/j;->d:Lum/a;

    .line 22
    .line 23
    iget-object v4, v3, Lum/a;->g:Ljava/util/ArrayList;

    .line 24
    .line 25
    invoke-virtual {v4}, Ljava/util/ArrayList;->size()I

    .line 26
    .line 27
    .line 28
    move-result v4

    .line 29
    const/4 v5, 0x0

    .line 30
    move v6, v5

    .line 31
    :goto_0
    if-ge v6, v4, :cond_3

    .line 32
    .line 33
    iget-object v7, v3, Lum/a;->g:Ljava/util/ArrayList;

    .line 34
    .line 35
    invoke-virtual {v7, v6}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 36
    .line 37
    .line 38
    move-result-object v7

    .line 39
    check-cast v7, Lan/f;

    .line 40
    .line 41
    iget-object v8, v7, Lan/f;->a:Ljava/lang/String;

    .line 42
    .line 43
    invoke-virtual {v8, v2}, Ljava/lang/String;->equalsIgnoreCase(Ljava/lang/String;)Z

    .line 44
    .line 45
    .line 46
    move-result v9

    .line 47
    if-eqz v9, :cond_1

    .line 48
    .line 49
    goto :goto_1

    .line 50
    :cond_1
    const-string v9, "\r"

    .line 51
    .line 52
    invoke-virtual {v8, v9}, Ljava/lang/String;->endsWith(Ljava/lang/String;)Z

    .line 53
    .line 54
    .line 55
    move-result v9

    .line 56
    if-eqz v9, :cond_2

    .line 57
    .line 58
    invoke-virtual {v8}, Ljava/lang/String;->length()I

    .line 59
    .line 60
    .line 61
    move-result v9

    .line 62
    add-int/lit8 v9, v9, -0x1

    .line 63
    .line 64
    invoke-virtual {v8, v5, v9}, Ljava/lang/String;->substring(II)Ljava/lang/String;

    .line 65
    .line 66
    .line 67
    move-result-object v8

    .line 68
    invoke-virtual {v8, v2}, Ljava/lang/String;->equalsIgnoreCase(Ljava/lang/String;)Z

    .line 69
    .line 70
    .line 71
    move-result v8

    .line 72
    if-eqz v8, :cond_2

    .line 73
    .line 74
    :goto_1
    move-object v2, v7

    .line 75
    goto :goto_2

    .line 76
    :cond_2
    add-int/lit8 v6, v6, 0x1

    .line 77
    .line 78
    goto :goto_0

    .line 79
    :cond_3
    move-object v2, v1

    .line 80
    :goto_2
    if-eqz v2, :cond_0

    .line 81
    .line 82
    :cond_4
    return-object v2
.end method

.method public final getAlpha()I
    .locals 0

    .line 1
    iget p0, p0, Lum/j;->m:I

    .line 2
    .line 3
    return p0
.end method

.method public final getIntrinsicHeight()I
    .locals 0

    .line 1
    iget-object p0, p0, Lum/j;->d:Lum/a;

    .line 2
    .line 3
    if-nez p0, :cond_0

    .line 4
    .line 5
    const/4 p0, -0x1

    .line 6
    return p0

    .line 7
    :cond_0
    iget-object p0, p0, Lum/a;->k:Landroid/graphics/Rect;

    .line 8
    .line 9
    invoke-virtual {p0}, Landroid/graphics/Rect;->height()I

    .line 10
    .line 11
    .line 12
    move-result p0

    .line 13
    return p0
.end method

.method public final getIntrinsicWidth()I
    .locals 0

    .line 1
    iget-object p0, p0, Lum/j;->d:Lum/a;

    .line 2
    .line 3
    if-nez p0, :cond_0

    .line 4
    .line 5
    const/4 p0, -0x1

    .line 6
    return p0

    .line 7
    :cond_0
    iget-object p0, p0, Lum/a;->k:Landroid/graphics/Rect;

    .line 8
    .line 9
    invoke-virtual {p0}, Landroid/graphics/Rect;->width()I

    .line 10
    .line 11
    .line 12
    move-result p0

    .line 13
    return p0
.end method

.method public final getOpacity()I
    .locals 0

    .line 1
    const/4 p0, -0x3

    .line 2
    return p0
.end method

.method public final h()V
    .locals 5

    .line 1
    iget-object v0, p0, Lum/j;->l:Ldn/c;

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    new-instance v0, Lum/e;

    .line 6
    .line 7
    const/4 v1, 0x1

    .line 8
    invoke-direct {v0, p0, v1}, Lum/e;-><init>(Lum/j;I)V

    .line 9
    .line 10
    .line 11
    iget-object p0, p0, Lum/j;->g:Ljava/util/ArrayList;

    .line 12
    .line 13
    invoke-virtual {p0, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 14
    .line 15
    .line 16
    return-void

    .line 17
    :cond_0
    invoke-virtual {p0}, Lum/j;->c()V

    .line 18
    .line 19
    .line 20
    invoke-virtual {p0}, Lum/j;->f()Landroid/content/Context;

    .line 21
    .line 22
    .line 23
    move-result-object v0

    .line 24
    invoke-virtual {p0, v0}, Lum/j;->a(Landroid/content/Context;)Z

    .line 25
    .line 26
    .line 27
    move-result v0

    .line 28
    const/4 v1, 0x1

    .line 29
    iget-object v2, p0, Lum/j;->e:Lgn/e;

    .line 30
    .line 31
    if-nez v0, :cond_1

    .line 32
    .line 33
    invoke-virtual {v2}, Landroid/animation/ValueAnimator;->getRepeatCount()I

    .line 34
    .line 35
    .line 36
    move-result v0

    .line 37
    if-nez v0, :cond_6

    .line 38
    .line 39
    :cond_1
    invoke-virtual {p0}, Landroid/graphics/drawable/Drawable;->isVisible()Z

    .line 40
    .line 41
    .line 42
    move-result v0

    .line 43
    if-eqz v0, :cond_5

    .line 44
    .line 45
    iput-boolean v1, v2, Lgn/e;->p:Z

    .line 46
    .line 47
    invoke-virtual {v2}, Lgn/e;->d()Z

    .line 48
    .line 49
    .line 50
    move-result v0

    .line 51
    iget-object v3, v2, Lgn/e;->e:Ljava/util/concurrent/CopyOnWriteArraySet;

    .line 52
    .line 53
    invoke-virtual {v3}, Ljava/util/concurrent/CopyOnWriteArraySet;->iterator()Ljava/util/Iterator;

    .line 54
    .line 55
    .line 56
    move-result-object v3

    .line 57
    :goto_0
    invoke-interface {v3}, Ljava/util/Iterator;->hasNext()Z

    .line 58
    .line 59
    .line 60
    move-result v4

    .line 61
    if-eqz v4, :cond_2

    .line 62
    .line 63
    invoke-interface {v3}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 64
    .line 65
    .line 66
    move-result-object v4

    .line 67
    check-cast v4, Landroid/animation/Animator$AnimatorListener;

    .line 68
    .line 69
    invoke-interface {v4, v2, v0}, Landroid/animation/Animator$AnimatorListener;->onAnimationStart(Landroid/animation/Animator;Z)V

    .line 70
    .line 71
    .line 72
    goto :goto_0

    .line 73
    :cond_2
    invoke-virtual {v2}, Lgn/e;->d()Z

    .line 74
    .line 75
    .line 76
    move-result v0

    .line 77
    if-eqz v0, :cond_3

    .line 78
    .line 79
    invoke-virtual {v2}, Lgn/e;->b()F

    .line 80
    .line 81
    .line 82
    move-result v0

    .line 83
    goto :goto_1

    .line 84
    :cond_3
    invoke-virtual {v2}, Lgn/e;->c()F

    .line 85
    .line 86
    .line 87
    move-result v0

    .line 88
    :goto_1
    float-to-int v0, v0

    .line 89
    int-to-float v0, v0

    .line 90
    invoke-virtual {v2, v0}, Lgn/e;->i(F)V

    .line 91
    .line 92
    .line 93
    const-wide/16 v3, 0x0

    .line 94
    .line 95
    iput-wide v3, v2, Lgn/e;->i:J

    .line 96
    .line 97
    const/4 v0, 0x0

    .line 98
    iput v0, v2, Lgn/e;->l:I

    .line 99
    .line 100
    iget-boolean v3, v2, Lgn/e;->p:Z

    .line 101
    .line 102
    if-eqz v3, :cond_4

    .line 103
    .line 104
    invoke-virtual {v2, v0}, Lgn/e;->h(Z)V

    .line 105
    .line 106
    .line 107
    invoke-static {}, Landroid/view/Choreographer;->getInstance()Landroid/view/Choreographer;

    .line 108
    .line 109
    .line 110
    move-result-object v0

    .line 111
    invoke-virtual {v0, v2}, Landroid/view/Choreographer;->postFrameCallback(Landroid/view/Choreographer$FrameCallback;)V

    .line 112
    .line 113
    .line 114
    :cond_4
    iput v1, p0, Lum/j;->G:I

    .line 115
    .line 116
    goto :goto_2

    .line 117
    :cond_5
    const/4 v0, 0x2

    .line 118
    iput v0, p0, Lum/j;->G:I

    .line 119
    .line 120
    :cond_6
    :goto_2
    invoke-virtual {p0}, Lum/j;->f()Landroid/content/Context;

    .line 121
    .line 122
    .line 123
    move-result-object v0

    .line 124
    invoke-virtual {p0, v0}, Lum/j;->a(Landroid/content/Context;)Z

    .line 125
    .line 126
    .line 127
    move-result v0

    .line 128
    if-nez v0, :cond_9

    .line 129
    .line 130
    invoke-virtual {p0}, Lum/j;->g()Lan/f;

    .line 131
    .line 132
    .line 133
    move-result-object v0

    .line 134
    if-eqz v0, :cond_7

    .line 135
    .line 136
    iget v0, v0, Lan/f;->b:F

    .line 137
    .line 138
    float-to-int v0, v0

    .line 139
    invoke-virtual {p0, v0}, Lum/j;->k(I)V

    .line 140
    .line 141
    .line 142
    goto :goto_4

    .line 143
    :cond_7
    iget v0, v2, Lgn/e;->g:F

    .line 144
    .line 145
    const/4 v3, 0x0

    .line 146
    cmpg-float v0, v0, v3

    .line 147
    .line 148
    if-gez v0, :cond_8

    .line 149
    .line 150
    invoke-virtual {v2}, Lgn/e;->c()F

    .line 151
    .line 152
    .line 153
    move-result v0

    .line 154
    goto :goto_3

    .line 155
    :cond_8
    invoke-virtual {v2}, Lgn/e;->b()F

    .line 156
    .line 157
    .line 158
    move-result v0

    .line 159
    :goto_3
    float-to-int v0, v0

    .line 160
    invoke-virtual {p0, v0}, Lum/j;->k(I)V

    .line 161
    .line 162
    .line 163
    :goto_4
    invoke-virtual {v2, v1}, Lgn/e;->h(Z)V

    .line 164
    .line 165
    .line 166
    invoke-virtual {v2}, Lgn/e;->d()Z

    .line 167
    .line 168
    .line 169
    move-result v0

    .line 170
    invoke-virtual {v2, v0}, Lgn/e;->e(Z)V

    .line 171
    .line 172
    .line 173
    invoke-virtual {p0}, Landroid/graphics/drawable/Drawable;->isVisible()Z

    .line 174
    .line 175
    .line 176
    move-result v0

    .line 177
    if-nez v0, :cond_9

    .line 178
    .line 179
    iput v1, p0, Lum/j;->G:I

    .line 180
    .line 181
    :cond_9
    return-void
.end method

.method public final i(Landroid/graphics/Canvas;Ldn/c;)V
    .locals 10

    .line 1
    iget-object v0, p0, Lum/j;->d:Lum/a;

    .line 2
    .line 3
    if-eqz v0, :cond_c

    .line 4
    .line 5
    if-nez p2, :cond_0

    .line 6
    .line 7
    goto/16 :goto_5

    .line 8
    .line 9
    :cond_0
    iget-object v0, p0, Lum/j;->r:Landroid/graphics/Canvas;

    .line 10
    .line 11
    if-eqz v0, :cond_1

    .line 12
    .line 13
    goto :goto_0

    .line 14
    :cond_1
    new-instance v0, Landroid/graphics/Canvas;

    .line 15
    .line 16
    invoke-direct {v0}, Landroid/graphics/Canvas;-><init>()V

    .line 17
    .line 18
    .line 19
    iput-object v0, p0, Lum/j;->r:Landroid/graphics/Canvas;

    .line 20
    .line 21
    new-instance v0, Landroid/graphics/RectF;

    .line 22
    .line 23
    invoke-direct {v0}, Landroid/graphics/RectF;-><init>()V

    .line 24
    .line 25
    .line 26
    iput-object v0, p0, Lum/j;->y:Landroid/graphics/RectF;

    .line 27
    .line 28
    new-instance v0, Landroid/graphics/Matrix;

    .line 29
    .line 30
    invoke-direct {v0}, Landroid/graphics/Matrix;-><init>()V

    .line 31
    .line 32
    .line 33
    iput-object v0, p0, Lum/j;->z:Landroid/graphics/Matrix;

    .line 34
    .line 35
    new-instance v0, Landroid/graphics/Matrix;

    .line 36
    .line 37
    invoke-direct {v0}, Landroid/graphics/Matrix;-><init>()V

    .line 38
    .line 39
    .line 40
    iput-object v0, p0, Lum/j;->B:Landroid/graphics/Matrix;

    .line 41
    .line 42
    new-instance v0, Landroid/graphics/Rect;

    .line 43
    .line 44
    invoke-direct {v0}, Landroid/graphics/Rect;-><init>()V

    .line 45
    .line 46
    .line 47
    iput-object v0, p0, Lum/j;->s:Landroid/graphics/Rect;

    .line 48
    .line 49
    new-instance v0, Landroid/graphics/RectF;

    .line 50
    .line 51
    invoke-direct {v0}, Landroid/graphics/RectF;-><init>()V

    .line 52
    .line 53
    .line 54
    iput-object v0, p0, Lum/j;->t:Landroid/graphics/RectF;

    .line 55
    .line 56
    new-instance v0, Ldn/i;

    .line 57
    .line 58
    invoke-direct {v0}, Ldn/i;-><init>()V

    .line 59
    .line 60
    .line 61
    iput-object v0, p0, Lum/j;->u:Ldn/i;

    .line 62
    .line 63
    new-instance v0, Landroid/graphics/Rect;

    .line 64
    .line 65
    invoke-direct {v0}, Landroid/graphics/Rect;-><init>()V

    .line 66
    .line 67
    .line 68
    iput-object v0, p0, Lum/j;->v:Landroid/graphics/Rect;

    .line 69
    .line 70
    new-instance v0, Landroid/graphics/Rect;

    .line 71
    .line 72
    invoke-direct {v0}, Landroid/graphics/Rect;-><init>()V

    .line 73
    .line 74
    .line 75
    iput-object v0, p0, Lum/j;->w:Landroid/graphics/Rect;

    .line 76
    .line 77
    new-instance v0, Landroid/graphics/RectF;

    .line 78
    .line 79
    invoke-direct {v0}, Landroid/graphics/RectF;-><init>()V

    .line 80
    .line 81
    .line 82
    iput-object v0, p0, Lum/j;->x:Landroid/graphics/RectF;

    .line 83
    .line 84
    :goto_0
    iget-object v0, p0, Lum/j;->z:Landroid/graphics/Matrix;

    .line 85
    .line 86
    invoke-virtual {p1, v0}, Landroid/graphics/Canvas;->getMatrix(Landroid/graphics/Matrix;)V

    .line 87
    .line 88
    .line 89
    iget-object v0, p0, Lum/j;->s:Landroid/graphics/Rect;

    .line 90
    .line 91
    invoke-virtual {p1, v0}, Landroid/graphics/Canvas;->getClipBounds(Landroid/graphics/Rect;)Z

    .line 92
    .line 93
    .line 94
    iget-object v0, p0, Lum/j;->s:Landroid/graphics/Rect;

    .line 95
    .line 96
    iget-object v1, p0, Lum/j;->t:Landroid/graphics/RectF;

    .line 97
    .line 98
    iget v2, v0, Landroid/graphics/Rect;->left:I

    .line 99
    .line 100
    int-to-float v2, v2

    .line 101
    iget v3, v0, Landroid/graphics/Rect;->top:I

    .line 102
    .line 103
    int-to-float v3, v3

    .line 104
    iget v4, v0, Landroid/graphics/Rect;->right:I

    .line 105
    .line 106
    int-to-float v4, v4

    .line 107
    iget v0, v0, Landroid/graphics/Rect;->bottom:I

    .line 108
    .line 109
    int-to-float v0, v0

    .line 110
    invoke-virtual {v1, v2, v3, v4, v0}, Landroid/graphics/RectF;->set(FFFF)V

    .line 111
    .line 112
    .line 113
    iget-object v0, p0, Lum/j;->z:Landroid/graphics/Matrix;

    .line 114
    .line 115
    iget-object v1, p0, Lum/j;->t:Landroid/graphics/RectF;

    .line 116
    .line 117
    invoke-virtual {v0, v1}, Landroid/graphics/Matrix;->mapRect(Landroid/graphics/RectF;)Z

    .line 118
    .line 119
    .line 120
    iget-object v0, p0, Lum/j;->t:Landroid/graphics/RectF;

    .line 121
    .line 122
    iget-object v1, p0, Lum/j;->s:Landroid/graphics/Rect;

    .line 123
    .line 124
    invoke-static {v1, v0}, Lum/j;->d(Landroid/graphics/Rect;Landroid/graphics/RectF;)V

    .line 125
    .line 126
    .line 127
    iget-boolean v0, p0, Lum/j;->k:Z

    .line 128
    .line 129
    const/4 v1, 0x0

    .line 130
    const/4 v2, 0x0

    .line 131
    if-eqz v0, :cond_2

    .line 132
    .line 133
    iget-object v0, p0, Lum/j;->y:Landroid/graphics/RectF;

    .line 134
    .line 135
    invoke-virtual {p0}, Lum/j;->getIntrinsicWidth()I

    .line 136
    .line 137
    .line 138
    move-result v3

    .line 139
    int-to-float v3, v3

    .line 140
    invoke-virtual {p0}, Lum/j;->getIntrinsicHeight()I

    .line 141
    .line 142
    .line 143
    move-result v4

    .line 144
    int-to-float v4, v4

    .line 145
    const/4 v5, 0x0

    .line 146
    invoke-virtual {v0, v5, v5, v3, v4}, Landroid/graphics/RectF;->set(FFFF)V

    .line 147
    .line 148
    .line 149
    goto :goto_1

    .line 150
    :cond_2
    iget-object v0, p0, Lum/j;->y:Landroid/graphics/RectF;

    .line 151
    .line 152
    invoke-virtual {p2, v0, v1, v2}, Ldn/c;->e(Landroid/graphics/RectF;Landroid/graphics/Matrix;Z)V

    .line 153
    .line 154
    .line 155
    :goto_1
    iget-object v0, p0, Lum/j;->z:Landroid/graphics/Matrix;

    .line 156
    .line 157
    iget-object v3, p0, Lum/j;->y:Landroid/graphics/RectF;

    .line 158
    .line 159
    invoke-virtual {v0, v3}, Landroid/graphics/Matrix;->mapRect(Landroid/graphics/RectF;)Z

    .line 160
    .line 161
    .line 162
    invoke-virtual {p0}, Landroid/graphics/drawable/Drawable;->getBounds()Landroid/graphics/Rect;

    .line 163
    .line 164
    .line 165
    move-result-object v0

    .line 166
    invoke-virtual {v0}, Landroid/graphics/Rect;->width()I

    .line 167
    .line 168
    .line 169
    move-result v3

    .line 170
    int-to-float v3, v3

    .line 171
    invoke-virtual {p0}, Lum/j;->getIntrinsicWidth()I

    .line 172
    .line 173
    .line 174
    move-result v4

    .line 175
    int-to-float v4, v4

    .line 176
    div-float/2addr v3, v4

    .line 177
    invoke-virtual {v0}, Landroid/graphics/Rect;->height()I

    .line 178
    .line 179
    .line 180
    move-result v0

    .line 181
    int-to-float v0, v0

    .line 182
    invoke-virtual {p0}, Lum/j;->getIntrinsicHeight()I

    .line 183
    .line 184
    .line 185
    move-result v4

    .line 186
    int-to-float v4, v4

    .line 187
    div-float/2addr v0, v4

    .line 188
    iget-object v4, p0, Lum/j;->y:Landroid/graphics/RectF;

    .line 189
    .line 190
    iget v5, v4, Landroid/graphics/RectF;->left:F

    .line 191
    .line 192
    mul-float/2addr v5, v3

    .line 193
    iget v6, v4, Landroid/graphics/RectF;->top:F

    .line 194
    .line 195
    mul-float/2addr v6, v0

    .line 196
    iget v7, v4, Landroid/graphics/RectF;->right:F

    .line 197
    .line 198
    mul-float/2addr v7, v3

    .line 199
    iget v8, v4, Landroid/graphics/RectF;->bottom:F

    .line 200
    .line 201
    mul-float/2addr v8, v0

    .line 202
    invoke-virtual {v4, v5, v6, v7, v8}, Landroid/graphics/RectF;->set(FFFF)V

    .line 203
    .line 204
    .line 205
    invoke-virtual {p0}, Landroid/graphics/drawable/Drawable;->getCallback()Landroid/graphics/drawable/Drawable$Callback;

    .line 206
    .line 207
    .line 208
    move-result-object v4

    .line 209
    instance-of v5, v4, Landroid/view/View;

    .line 210
    .line 211
    const/4 v6, 0x1

    .line 212
    if-nez v5, :cond_4

    .line 213
    .line 214
    :cond_3
    move v4, v2

    .line 215
    goto :goto_2

    .line 216
    :cond_4
    check-cast v4, Landroid/view/View;

    .line 217
    .line 218
    invoke-virtual {v4}, Landroid/view/View;->getParent()Landroid/view/ViewParent;

    .line 219
    .line 220
    .line 221
    move-result-object v4

    .line 222
    instance-of v5, v4, Landroid/view/ViewGroup;

    .line 223
    .line 224
    if-eqz v5, :cond_3

    .line 225
    .line 226
    check-cast v4, Landroid/view/ViewGroup;

    .line 227
    .line 228
    invoke-virtual {v4}, Landroid/view/ViewGroup;->getClipChildren()Z

    .line 229
    .line 230
    .line 231
    move-result v4

    .line 232
    xor-int/2addr v4, v6

    .line 233
    :goto_2
    if-nez v4, :cond_5

    .line 234
    .line 235
    iget-object v4, p0, Lum/j;->y:Landroid/graphics/RectF;

    .line 236
    .line 237
    iget-object v5, p0, Lum/j;->s:Landroid/graphics/Rect;

    .line 238
    .line 239
    iget v7, v5, Landroid/graphics/Rect;->left:I

    .line 240
    .line 241
    int-to-float v7, v7

    .line 242
    iget v8, v5, Landroid/graphics/Rect;->top:I

    .line 243
    .line 244
    int-to-float v8, v8

    .line 245
    iget v9, v5, Landroid/graphics/Rect;->right:I

    .line 246
    .line 247
    int-to-float v9, v9

    .line 248
    iget v5, v5, Landroid/graphics/Rect;->bottom:I

    .line 249
    .line 250
    int-to-float v5, v5

    .line 251
    invoke-virtual {v4, v7, v8, v9, v5}, Landroid/graphics/RectF;->intersect(FFFF)Z

    .line 252
    .line 253
    .line 254
    :cond_5
    iget-object v4, p0, Lum/j;->y:Landroid/graphics/RectF;

    .line 255
    .line 256
    invoke-virtual {v4}, Landroid/graphics/RectF;->width()F

    .line 257
    .line 258
    .line 259
    move-result v4

    .line 260
    float-to-double v4, v4

    .line 261
    invoke-static {v4, v5}, Ljava/lang/Math;->ceil(D)D

    .line 262
    .line 263
    .line 264
    move-result-wide v4

    .line 265
    double-to-int v4, v4

    .line 266
    iget-object v5, p0, Lum/j;->y:Landroid/graphics/RectF;

    .line 267
    .line 268
    invoke-virtual {v5}, Landroid/graphics/RectF;->height()F

    .line 269
    .line 270
    .line 271
    move-result v5

    .line 272
    float-to-double v7, v5

    .line 273
    invoke-static {v7, v8}, Ljava/lang/Math;->ceil(D)D

    .line 274
    .line 275
    .line 276
    move-result-wide v7

    .line 277
    double-to-int v5, v7

    .line 278
    if-lez v4, :cond_c

    .line 279
    .line 280
    if-gtz v5, :cond_6

    .line 281
    .line 282
    goto/16 :goto_5

    .line 283
    .line 284
    :cond_6
    iget-object v7, p0, Lum/j;->q:Landroid/graphics/Bitmap;

    .line 285
    .line 286
    if-eqz v7, :cond_9

    .line 287
    .line 288
    invoke-virtual {v7}, Landroid/graphics/Bitmap;->getWidth()I

    .line 289
    .line 290
    .line 291
    move-result v7

    .line 292
    if-lt v7, v4, :cond_9

    .line 293
    .line 294
    iget-object v7, p0, Lum/j;->q:Landroid/graphics/Bitmap;

    .line 295
    .line 296
    invoke-virtual {v7}, Landroid/graphics/Bitmap;->getHeight()I

    .line 297
    .line 298
    .line 299
    move-result v7

    .line 300
    if-ge v7, v5, :cond_7

    .line 301
    .line 302
    goto :goto_3

    .line 303
    :cond_7
    iget-object v7, p0, Lum/j;->q:Landroid/graphics/Bitmap;

    .line 304
    .line 305
    invoke-virtual {v7}, Landroid/graphics/Bitmap;->getWidth()I

    .line 306
    .line 307
    .line 308
    move-result v7

    .line 309
    if-gt v7, v4, :cond_8

    .line 310
    .line 311
    iget-object v7, p0, Lum/j;->q:Landroid/graphics/Bitmap;

    .line 312
    .line 313
    invoke-virtual {v7}, Landroid/graphics/Bitmap;->getHeight()I

    .line 314
    .line 315
    .line 316
    move-result v7

    .line 317
    if-le v7, v5, :cond_a

    .line 318
    .line 319
    :cond_8
    iget-object v7, p0, Lum/j;->q:Landroid/graphics/Bitmap;

    .line 320
    .line 321
    invoke-static {v7, v2, v2, v4, v5}, Landroid/graphics/Bitmap;->createBitmap(Landroid/graphics/Bitmap;IIII)Landroid/graphics/Bitmap;

    .line 322
    .line 323
    .line 324
    move-result-object v7

    .line 325
    iput-object v7, p0, Lum/j;->q:Landroid/graphics/Bitmap;

    .line 326
    .line 327
    iget-object v8, p0, Lum/j;->r:Landroid/graphics/Canvas;

    .line 328
    .line 329
    invoke-virtual {v8, v7}, Landroid/graphics/Canvas;->setBitmap(Landroid/graphics/Bitmap;)V

    .line 330
    .line 331
    .line 332
    iput-boolean v6, p0, Lum/j;->C:Z

    .line 333
    .line 334
    goto :goto_4

    .line 335
    :cond_9
    :goto_3
    sget-object v7, Landroid/graphics/Bitmap$Config;->ARGB_8888:Landroid/graphics/Bitmap$Config;

    .line 336
    .line 337
    invoke-static {v4, v5, v7}, Landroid/graphics/Bitmap;->createBitmap(IILandroid/graphics/Bitmap$Config;)Landroid/graphics/Bitmap;

    .line 338
    .line 339
    .line 340
    move-result-object v7

    .line 341
    iput-object v7, p0, Lum/j;->q:Landroid/graphics/Bitmap;

    .line 342
    .line 343
    iget-object v8, p0, Lum/j;->r:Landroid/graphics/Canvas;

    .line 344
    .line 345
    invoke-virtual {v8, v7}, Landroid/graphics/Canvas;->setBitmap(Landroid/graphics/Bitmap;)V

    .line 346
    .line 347
    .line 348
    iput-boolean v6, p0, Lum/j;->C:Z

    .line 349
    .line 350
    :cond_a
    :goto_4
    iget-boolean v6, p0, Lum/j;->C:Z

    .line 351
    .line 352
    if-eqz v6, :cond_b

    .line 353
    .line 354
    iget-object v6, p0, Lum/j;->z:Landroid/graphics/Matrix;

    .line 355
    .line 356
    iget-object v7, p0, Lum/j;->A:[F

    .line 357
    .line 358
    invoke-virtual {v6, v7}, Landroid/graphics/Matrix;->getValues([F)V

    .line 359
    .line 360
    .line 361
    aget v6, v7, v2

    .line 362
    .line 363
    const/4 v8, 0x4

    .line 364
    aget v7, v7, v8

    .line 365
    .line 366
    iget-object v8, p0, Lum/j;->z:Landroid/graphics/Matrix;

    .line 367
    .line 368
    iget-object v9, p0, Lum/j;->p:Landroid/graphics/Matrix;

    .line 369
    .line 370
    invoke-virtual {v9, v8}, Landroid/graphics/Matrix;->set(Landroid/graphics/Matrix;)V

    .line 371
    .line 372
    .line 373
    invoke-virtual {v9, v3, v0}, Landroid/graphics/Matrix;->preScale(FF)Z

    .line 374
    .line 375
    .line 376
    iget-object v0, p0, Lum/j;->y:Landroid/graphics/RectF;

    .line 377
    .line 378
    iget v3, v0, Landroid/graphics/RectF;->left:F

    .line 379
    .line 380
    neg-float v3, v3

    .line 381
    iget v0, v0, Landroid/graphics/RectF;->top:F

    .line 382
    .line 383
    neg-float v0, v0

    .line 384
    invoke-virtual {v9, v3, v0}, Landroid/graphics/Matrix;->postTranslate(FF)Z

    .line 385
    .line 386
    .line 387
    const/high16 v0, 0x3f800000    # 1.0f

    .line 388
    .line 389
    div-float v3, v0, v6

    .line 390
    .line 391
    div-float/2addr v0, v7

    .line 392
    invoke-virtual {v9, v3, v0}, Landroid/graphics/Matrix;->postScale(FF)Z

    .line 393
    .line 394
    .line 395
    iget-object v0, p0, Lum/j;->q:Landroid/graphics/Bitmap;

    .line 396
    .line 397
    invoke-virtual {v0, v2}, Landroid/graphics/Bitmap;->eraseColor(I)V

    .line 398
    .line 399
    .line 400
    iget-object v0, p0, Lum/j;->r:Landroid/graphics/Canvas;

    .line 401
    .line 402
    sget-object v3, Lgn/h;->a:Landroid/graphics/Matrix;

    .line 403
    .line 404
    invoke-virtual {v0, v3}, Landroid/graphics/Canvas;->setMatrix(Landroid/graphics/Matrix;)V

    .line 405
    .line 406
    .line 407
    iget-object v0, p0, Lum/j;->r:Landroid/graphics/Canvas;

    .line 408
    .line 409
    invoke-virtual {v0, v6, v7}, Landroid/graphics/Canvas;->scale(FF)V

    .line 410
    .line 411
    .line 412
    iget-object v0, p0, Lum/j;->r:Landroid/graphics/Canvas;

    .line 413
    .line 414
    iget v3, p0, Lum/j;->m:I

    .line 415
    .line 416
    invoke-virtual {p2, v0, v9, v3, v1}, Ldn/b;->c(Landroid/graphics/Canvas;Landroid/graphics/Matrix;ILgn/a;)V

    .line 417
    .line 418
    .line 419
    iget-object p2, p0, Lum/j;->z:Landroid/graphics/Matrix;

    .line 420
    .line 421
    iget-object v0, p0, Lum/j;->B:Landroid/graphics/Matrix;

    .line 422
    .line 423
    invoke-virtual {p2, v0}, Landroid/graphics/Matrix;->invert(Landroid/graphics/Matrix;)Z

    .line 424
    .line 425
    .line 426
    iget-object p2, p0, Lum/j;->B:Landroid/graphics/Matrix;

    .line 427
    .line 428
    iget-object v0, p0, Lum/j;->x:Landroid/graphics/RectF;

    .line 429
    .line 430
    iget-object v1, p0, Lum/j;->y:Landroid/graphics/RectF;

    .line 431
    .line 432
    invoke-virtual {p2, v0, v1}, Landroid/graphics/Matrix;->mapRect(Landroid/graphics/RectF;Landroid/graphics/RectF;)Z

    .line 433
    .line 434
    .line 435
    iget-object p2, p0, Lum/j;->x:Landroid/graphics/RectF;

    .line 436
    .line 437
    iget-object v0, p0, Lum/j;->w:Landroid/graphics/Rect;

    .line 438
    .line 439
    invoke-static {v0, p2}, Lum/j;->d(Landroid/graphics/Rect;Landroid/graphics/RectF;)V

    .line 440
    .line 441
    .line 442
    :cond_b
    iget-object p2, p0, Lum/j;->v:Landroid/graphics/Rect;

    .line 443
    .line 444
    invoke-virtual {p2, v2, v2, v4, v5}, Landroid/graphics/Rect;->set(IIII)V

    .line 445
    .line 446
    .line 447
    iget-object p2, p0, Lum/j;->q:Landroid/graphics/Bitmap;

    .line 448
    .line 449
    iget-object v0, p0, Lum/j;->v:Landroid/graphics/Rect;

    .line 450
    .line 451
    iget-object v1, p0, Lum/j;->w:Landroid/graphics/Rect;

    .line 452
    .line 453
    iget-object p0, p0, Lum/j;->u:Ldn/i;

    .line 454
    .line 455
    invoke-virtual {p1, p2, v0, v1, p0}, Landroid/graphics/Canvas;->drawBitmap(Landroid/graphics/Bitmap;Landroid/graphics/Rect;Landroid/graphics/Rect;Landroid/graphics/Paint;)V

    .line 456
    .line 457
    .line 458
    :cond_c
    :goto_5
    return-void
.end method

.method public final invalidateDrawable(Landroid/graphics/drawable/Drawable;)V
    .locals 0

    .line 1
    invoke-virtual {p0}, Landroid/graphics/drawable/Drawable;->getCallback()Landroid/graphics/drawable/Drawable$Callback;

    .line 2
    .line 3
    .line 4
    move-result-object p1

    .line 5
    if-nez p1, :cond_0

    .line 6
    .line 7
    return-void

    .line 8
    :cond_0
    invoke-interface {p1, p0}, Landroid/graphics/drawable/Drawable$Callback;->invalidateDrawable(Landroid/graphics/drawable/Drawable;)V

    .line 9
    .line 10
    .line 11
    return-void
.end method

.method public final invalidateSelf()V
    .locals 1

    .line 1
    iget-boolean v0, p0, Lum/j;->C:Z

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    goto :goto_0

    .line 6
    :cond_0
    const/4 v0, 0x1

    .line 7
    iput-boolean v0, p0, Lum/j;->C:Z

    .line 8
    .line 9
    invoke-virtual {p0}, Landroid/graphics/drawable/Drawable;->getCallback()Landroid/graphics/drawable/Drawable$Callback;

    .line 10
    .line 11
    .line 12
    move-result-object v0

    .line 13
    if-eqz v0, :cond_1

    .line 14
    .line 15
    invoke-interface {v0, p0}, Landroid/graphics/drawable/Drawable$Callback;->invalidateDrawable(Landroid/graphics/drawable/Drawable;)V

    .line 16
    .line 17
    .line 18
    :cond_1
    :goto_0
    return-void
.end method

.method public final isRunning()Z
    .locals 0

    .line 1
    iget-object p0, p0, Lum/j;->e:Lgn/e;

    .line 2
    .line 3
    if-nez p0, :cond_0

    .line 4
    .line 5
    const/4 p0, 0x0

    .line 6
    return p0

    .line 7
    :cond_0
    iget-boolean p0, p0, Lgn/e;->p:Z

    .line 8
    .line 9
    return p0
.end method

.method public final j()V
    .locals 5

    .line 1
    iget-object v0, p0, Lum/j;->l:Ldn/c;

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    new-instance v0, Lum/e;

    .line 6
    .line 7
    const/4 v1, 0x0

    .line 8
    invoke-direct {v0, p0, v1}, Lum/e;-><init>(Lum/j;I)V

    .line 9
    .line 10
    .line 11
    iget-object p0, p0, Lum/j;->g:Ljava/util/ArrayList;

    .line 12
    .line 13
    invoke-virtual {p0, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 14
    .line 15
    .line 16
    return-void

    .line 17
    :cond_0
    invoke-virtual {p0}, Lum/j;->c()V

    .line 18
    .line 19
    .line 20
    invoke-virtual {p0}, Lum/j;->f()Landroid/content/Context;

    .line 21
    .line 22
    .line 23
    move-result-object v0

    .line 24
    invoke-virtual {p0, v0}, Lum/j;->a(Landroid/content/Context;)Z

    .line 25
    .line 26
    .line 27
    move-result v0

    .line 28
    const/4 v1, 0x1

    .line 29
    iget-object v2, p0, Lum/j;->e:Lgn/e;

    .line 30
    .line 31
    if-nez v0, :cond_1

    .line 32
    .line 33
    invoke-virtual {v2}, Landroid/animation/ValueAnimator;->getRepeatCount()I

    .line 34
    .line 35
    .line 36
    move-result v0

    .line 37
    if-nez v0, :cond_6

    .line 38
    .line 39
    :cond_1
    invoke-virtual {p0}, Landroid/graphics/drawable/Drawable;->isVisible()Z

    .line 40
    .line 41
    .line 42
    move-result v0

    .line 43
    if-eqz v0, :cond_5

    .line 44
    .line 45
    iput-boolean v1, v2, Lgn/e;->p:Z

    .line 46
    .line 47
    const/4 v0, 0x0

    .line 48
    invoke-virtual {v2, v0}, Lgn/e;->h(Z)V

    .line 49
    .line 50
    .line 51
    invoke-static {}, Landroid/view/Choreographer;->getInstance()Landroid/view/Choreographer;

    .line 52
    .line 53
    .line 54
    move-result-object v0

    .line 55
    invoke-virtual {v0, v2}, Landroid/view/Choreographer;->postFrameCallback(Landroid/view/Choreographer$FrameCallback;)V

    .line 56
    .line 57
    .line 58
    const-wide/16 v3, 0x0

    .line 59
    .line 60
    iput-wide v3, v2, Lgn/e;->i:J

    .line 61
    .line 62
    invoke-virtual {v2}, Lgn/e;->d()Z

    .line 63
    .line 64
    .line 65
    move-result v0

    .line 66
    if-eqz v0, :cond_2

    .line 67
    .line 68
    iget v0, v2, Lgn/e;->k:F

    .line 69
    .line 70
    invoke-virtual {v2}, Lgn/e;->c()F

    .line 71
    .line 72
    .line 73
    move-result v3

    .line 74
    cmpl-float v0, v0, v3

    .line 75
    .line 76
    if-nez v0, :cond_2

    .line 77
    .line 78
    invoke-virtual {v2}, Lgn/e;->b()F

    .line 79
    .line 80
    .line 81
    move-result v0

    .line 82
    invoke-virtual {v2, v0}, Lgn/e;->i(F)V

    .line 83
    .line 84
    .line 85
    goto :goto_0

    .line 86
    :cond_2
    invoke-virtual {v2}, Lgn/e;->d()Z

    .line 87
    .line 88
    .line 89
    move-result v0

    .line 90
    if-nez v0, :cond_3

    .line 91
    .line 92
    iget v0, v2, Lgn/e;->k:F

    .line 93
    .line 94
    invoke-virtual {v2}, Lgn/e;->b()F

    .line 95
    .line 96
    .line 97
    move-result v3

    .line 98
    cmpl-float v0, v0, v3

    .line 99
    .line 100
    if-nez v0, :cond_3

    .line 101
    .line 102
    invoke-virtual {v2}, Lgn/e;->c()F

    .line 103
    .line 104
    .line 105
    move-result v0

    .line 106
    invoke-virtual {v2, v0}, Lgn/e;->i(F)V

    .line 107
    .line 108
    .line 109
    :cond_3
    :goto_0
    iget-object v0, v2, Lgn/e;->f:Ljava/util/concurrent/CopyOnWriteArraySet;

    .line 110
    .line 111
    invoke-virtual {v0}, Ljava/util/concurrent/CopyOnWriteArraySet;->iterator()Ljava/util/Iterator;

    .line 112
    .line 113
    .line 114
    move-result-object v0

    .line 115
    :goto_1
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 116
    .line 117
    .line 118
    move-result v3

    .line 119
    if-eqz v3, :cond_4

    .line 120
    .line 121
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 122
    .line 123
    .line 124
    move-result-object v3

    .line 125
    check-cast v3, Landroid/animation/Animator$AnimatorPauseListener;

    .line 126
    .line 127
    invoke-interface {v3, v2}, Landroid/animation/Animator$AnimatorPauseListener;->onAnimationResume(Landroid/animation/Animator;)V

    .line 128
    .line 129
    .line 130
    goto :goto_1

    .line 131
    :cond_4
    iput v1, p0, Lum/j;->G:I

    .line 132
    .line 133
    goto :goto_2

    .line 134
    :cond_5
    const/4 v0, 0x3

    .line 135
    iput v0, p0, Lum/j;->G:I

    .line 136
    .line 137
    :cond_6
    :goto_2
    invoke-virtual {p0}, Lum/j;->f()Landroid/content/Context;

    .line 138
    .line 139
    .line 140
    move-result-object v0

    .line 141
    invoke-virtual {p0, v0}, Lum/j;->a(Landroid/content/Context;)Z

    .line 142
    .line 143
    .line 144
    move-result v0

    .line 145
    if-nez v0, :cond_8

    .line 146
    .line 147
    iget v0, v2, Lgn/e;->g:F

    .line 148
    .line 149
    const/4 v3, 0x0

    .line 150
    cmpg-float v0, v0, v3

    .line 151
    .line 152
    if-gez v0, :cond_7

    .line 153
    .line 154
    invoke-virtual {v2}, Lgn/e;->c()F

    .line 155
    .line 156
    .line 157
    move-result v0

    .line 158
    goto :goto_3

    .line 159
    :cond_7
    invoke-virtual {v2}, Lgn/e;->b()F

    .line 160
    .line 161
    .line 162
    move-result v0

    .line 163
    :goto_3
    float-to-int v0, v0

    .line 164
    invoke-virtual {p0, v0}, Lum/j;->k(I)V

    .line 165
    .line 166
    .line 167
    invoke-virtual {v2, v1}, Lgn/e;->h(Z)V

    .line 168
    .line 169
    .line 170
    invoke-virtual {v2}, Lgn/e;->d()Z

    .line 171
    .line 172
    .line 173
    move-result v0

    .line 174
    invoke-virtual {v2, v0}, Lgn/e;->e(Z)V

    .line 175
    .line 176
    .line 177
    invoke-virtual {p0}, Landroid/graphics/drawable/Drawable;->isVisible()Z

    .line 178
    .line 179
    .line 180
    move-result v0

    .line 181
    if-nez v0, :cond_8

    .line 182
    .line 183
    iput v1, p0, Lum/j;->G:I

    .line 184
    .line 185
    :cond_8
    return-void
.end method

.method public final k(I)V
    .locals 1

    .line 1
    iget-object v0, p0, Lum/j;->d:Lum/a;

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    new-instance v0, Lum/h;

    .line 6
    .line 7
    invoke-direct {v0, p0, p1}, Lum/h;-><init>(Lum/j;I)V

    .line 8
    .line 9
    .line 10
    iget-object p0, p0, Lum/j;->g:Ljava/util/ArrayList;

    .line 11
    .line 12
    invoke-virtual {p0, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 13
    .line 14
    .line 15
    return-void

    .line 16
    :cond_0
    iget-object p0, p0, Lum/j;->e:Lgn/e;

    .line 17
    .line 18
    int-to-float p1, p1

    .line 19
    invoke-virtual {p0, p1}, Lgn/e;->i(F)V

    .line 20
    .line 21
    .line 22
    return-void
.end method

.method public final l(F)V
    .locals 2

    .line 1
    iget-object v0, p0, Lum/j;->d:Lum/a;

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    new-instance v0, Lum/g;

    .line 6
    .line 7
    invoke-direct {v0, p0, p1}, Lum/g;-><init>(Lum/j;F)V

    .line 8
    .line 9
    .line 10
    iget-object p0, p0, Lum/j;->g:Ljava/util/ArrayList;

    .line 11
    .line 12
    invoke-virtual {p0, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 13
    .line 14
    .line 15
    return-void

    .line 16
    :cond_0
    iget v1, v0, Lum/a;->l:F

    .line 17
    .line 18
    iget v0, v0, Lum/a;->m:F

    .line 19
    .line 20
    invoke-static {v1, v0, p1}, Lgn/f;->e(FFF)F

    .line 21
    .line 22
    .line 23
    move-result p1

    .line 24
    iget-object p0, p0, Lum/j;->e:Lgn/e;

    .line 25
    .line 26
    invoke-virtual {p0, p1}, Lgn/e;->i(F)V

    .line 27
    .line 28
    .line 29
    return-void
.end method

.method public final m()Z
    .locals 4

    .line 1
    iget-object v0, p0, Lum/j;->d:Lum/a;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    if-nez v0, :cond_0

    .line 5
    .line 6
    return v1

    .line 7
    :cond_0
    iget v2, p0, Lum/j;->F:F

    .line 8
    .line 9
    iget-object v3, p0, Lum/j;->e:Lgn/e;

    .line 10
    .line 11
    invoke-virtual {v3}, Lgn/e;->a()F

    .line 12
    .line 13
    .line 14
    move-result v3

    .line 15
    iput v3, p0, Lum/j;->F:F

    .line 16
    .line 17
    invoke-virtual {v0}, Lum/a;->b()F

    .line 18
    .line 19
    .line 20
    move-result p0

    .line 21
    sub-float/2addr v3, v2

    .line 22
    invoke-static {v3}, Ljava/lang/Math;->abs(F)F

    .line 23
    .line 24
    .line 25
    move-result v0

    .line 26
    mul-float/2addr v0, p0

    .line 27
    const/high16 p0, 0x42480000    # 50.0f

    .line 28
    .line 29
    cmpl-float p0, v0, p0

    .line 30
    .line 31
    if-ltz p0, :cond_1

    .line 32
    .line 33
    const/4 p0, 0x1

    .line 34
    return p0

    .line 35
    :cond_1
    return v1
.end method

.method public final scheduleDrawable(Landroid/graphics/drawable/Drawable;Ljava/lang/Runnable;J)V
    .locals 0

    .line 1
    invoke-virtual {p0}, Landroid/graphics/drawable/Drawable;->getCallback()Landroid/graphics/drawable/Drawable$Callback;

    .line 2
    .line 3
    .line 4
    move-result-object p1

    .line 5
    if-nez p1, :cond_0

    .line 6
    .line 7
    return-void

    .line 8
    :cond_0
    invoke-interface {p1, p0, p2, p3, p4}, Landroid/graphics/drawable/Drawable$Callback;->scheduleDrawable(Landroid/graphics/drawable/Drawable;Ljava/lang/Runnable;J)V

    .line 9
    .line 10
    .line 11
    return-void
.end method

.method public final setAlpha(I)V
    .locals 0

    .line 1
    iput p1, p0, Lum/j;->m:I

    .line 2
    .line 3
    invoke-virtual {p0}, Lum/j;->invalidateSelf()V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public final setColorFilter(Landroid/graphics/ColorFilter;)V
    .locals 0

    .line 1
    const-string p0, "Use addColorFilter instead."

    .line 2
    .line 3
    invoke-static {p0}, Lgn/c;->a(Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public final setVisible(ZZ)Z
    .locals 4

    .line 1
    invoke-virtual {p0}, Landroid/graphics/drawable/Drawable;->isVisible()Z

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    invoke-super {p0, p1, p2}, Landroid/graphics/drawable/Drawable;->setVisible(ZZ)Z

    .line 6
    .line 7
    .line 8
    move-result p2

    .line 9
    const/4 v1, 0x3

    .line 10
    if-eqz p1, :cond_1

    .line 11
    .line 12
    iget p1, p0, Lum/j;->G:I

    .line 13
    .line 14
    const/4 v0, 0x2

    .line 15
    if-ne p1, v0, :cond_0

    .line 16
    .line 17
    invoke-virtual {p0}, Lum/j;->h()V

    .line 18
    .line 19
    .line 20
    return p2

    .line 21
    :cond_0
    if-ne p1, v1, :cond_5

    .line 22
    .line 23
    invoke-virtual {p0}, Lum/j;->j()V

    .line 24
    .line 25
    .line 26
    return p2

    .line 27
    :cond_1
    iget-object p1, p0, Lum/j;->e:Lgn/e;

    .line 28
    .line 29
    iget-boolean v2, p1, Lgn/e;->p:Z

    .line 30
    .line 31
    const/4 v3, 0x1

    .line 32
    if-eqz v2, :cond_4

    .line 33
    .line 34
    iget-object v0, p0, Lum/j;->g:Ljava/util/ArrayList;

    .line 35
    .line 36
    invoke-virtual {v0}, Ljava/util/ArrayList;->clear()V

    .line 37
    .line 38
    .line 39
    invoke-virtual {p1, v3}, Lgn/e;->h(Z)V

    .line 40
    .line 41
    .line 42
    iget-object v0, p1, Lgn/e;->f:Ljava/util/concurrent/CopyOnWriteArraySet;

    .line 43
    .line 44
    invoke-virtual {v0}, Ljava/util/concurrent/CopyOnWriteArraySet;->iterator()Ljava/util/Iterator;

    .line 45
    .line 46
    .line 47
    move-result-object v0

    .line 48
    :goto_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 49
    .line 50
    .line 51
    move-result v2

    .line 52
    if-eqz v2, :cond_2

    .line 53
    .line 54
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 55
    .line 56
    .line 57
    move-result-object v2

    .line 58
    check-cast v2, Landroid/animation/Animator$AnimatorPauseListener;

    .line 59
    .line 60
    invoke-interface {v2, p1}, Landroid/animation/Animator$AnimatorPauseListener;->onAnimationPause(Landroid/animation/Animator;)V

    .line 61
    .line 62
    .line 63
    goto :goto_0

    .line 64
    :cond_2
    invoke-virtual {p0}, Landroid/graphics/drawable/Drawable;->isVisible()Z

    .line 65
    .line 66
    .line 67
    move-result p1

    .line 68
    if-nez p1, :cond_3

    .line 69
    .line 70
    iput v3, p0, Lum/j;->G:I

    .line 71
    .line 72
    :cond_3
    iput v1, p0, Lum/j;->G:I

    .line 73
    .line 74
    return p2

    .line 75
    :cond_4
    if-eqz v0, :cond_5

    .line 76
    .line 77
    iput v3, p0, Lum/j;->G:I

    .line 78
    .line 79
    :cond_5
    return p2
.end method

.method public final start()V
    .locals 2

    .line 1
    invoke-virtual {p0}, Landroid/graphics/drawable/Drawable;->getCallback()Landroid/graphics/drawable/Drawable$Callback;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    instance-of v1, v0, Landroid/view/View;

    .line 6
    .line 7
    if-eqz v1, :cond_0

    .line 8
    .line 9
    check-cast v0, Landroid/view/View;

    .line 10
    .line 11
    invoke-virtual {v0}, Landroid/view/View;->isInEditMode()Z

    .line 12
    .line 13
    .line 14
    move-result v0

    .line 15
    if-eqz v0, :cond_0

    .line 16
    .line 17
    return-void

    .line 18
    :cond_0
    invoke-virtual {p0}, Lum/j;->h()V

    .line 19
    .line 20
    .line 21
    return-void
.end method

.method public final stop()V
    .locals 3

    .line 1
    iget-object v0, p0, Lum/j;->g:Ljava/util/ArrayList;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/util/ArrayList;->clear()V

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lum/j;->e:Lgn/e;

    .line 7
    .line 8
    const/4 v1, 0x1

    .line 9
    invoke-virtual {v0, v1}, Lgn/e;->h(Z)V

    .line 10
    .line 11
    .line 12
    invoke-virtual {v0}, Lgn/e;->d()Z

    .line 13
    .line 14
    .line 15
    move-result v2

    .line 16
    invoke-virtual {v0, v2}, Lgn/e;->e(Z)V

    .line 17
    .line 18
    .line 19
    invoke-virtual {p0}, Landroid/graphics/drawable/Drawable;->isVisible()Z

    .line 20
    .line 21
    .line 22
    move-result v0

    .line 23
    if-nez v0, :cond_0

    .line 24
    .line 25
    iput v1, p0, Lum/j;->G:I

    .line 26
    .line 27
    :cond_0
    return-void
.end method

.method public final unscheduleDrawable(Landroid/graphics/drawable/Drawable;Ljava/lang/Runnable;)V
    .locals 0

    .line 1
    invoke-virtual {p0}, Landroid/graphics/drawable/Drawable;->getCallback()Landroid/graphics/drawable/Drawable$Callback;

    .line 2
    .line 3
    .line 4
    move-result-object p1

    .line 5
    if-nez p1, :cond_0

    .line 6
    .line 7
    return-void

    .line 8
    :cond_0
    invoke-interface {p1, p0, p2}, Landroid/graphics/drawable/Drawable$Callback;->unscheduleDrawable(Landroid/graphics/drawable/Drawable;Ljava/lang/Runnable;)V

    .line 9
    .line 10
    .line 11
    return-void
.end method
