.class public Lcom/salesforce/marketingcloud/media/n;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/lang/Runnable;


# annotations
.annotation build Landroid/annotation/SuppressLint;
    value = {
        "UnknownNullness"
    }
.end annotation


# static fields
.field private static final n:Ljava/lang/String; = "ImageHandler-"

.field private static final o:Ljava/lang/String; = "ImageHandler-Idle"

.field private static final p:Ljava/lang/ThreadLocal;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/lang/ThreadLocal<",
            "Ljava/lang/StringBuilder;",
            ">;"
        }
    .end annotation
.end field

.field private static final q:Lcom/salesforce/marketingcloud/media/v;


# instance fields
.field final b:Lcom/salesforce/marketingcloud/media/o;

.field final c:Lcom/salesforce/marketingcloud/media/h;

.field final d:Ljava/lang/String;

.field final e:Lcom/salesforce/marketingcloud/media/v;

.field final f:Lcom/salesforce/marketingcloud/media/c;

.field g:Lcom/salesforce/marketingcloud/media/t;

.field h:Lcom/salesforce/marketingcloud/media/a;

.field i:Ljava/util/List;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/List<",
            "Lcom/salesforce/marketingcloud/media/a;",
            ">;"
        }
    .end annotation
.end field

.field j:Lcom/salesforce/marketingcloud/media/v$b;

.field k:Ljava/util/concurrent/Future;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/concurrent/Future<",
            "*>;"
        }
    .end annotation
.end field

.field l:Ljava/lang/Exception;

.field m:Lcom/salesforce/marketingcloud/media/o$c;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    new-instance v0, Lcom/salesforce/marketingcloud/media/n$a;

    .line 2
    .line 3
    invoke-direct {v0}, Lcom/salesforce/marketingcloud/media/n$a;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lcom/salesforce/marketingcloud/media/n;->p:Ljava/lang/ThreadLocal;

    .line 7
    .line 8
    new-instance v0, Lcom/salesforce/marketingcloud/media/n$b;

    .line 9
    .line 10
    invoke-direct {v0}, Lcom/salesforce/marketingcloud/media/n$b;-><init>()V

    .line 11
    .line 12
    .line 13
    sput-object v0, Lcom/salesforce/marketingcloud/media/n;->q:Lcom/salesforce/marketingcloud/media/v;

    .line 14
    .line 15
    return-void
.end method

.method public constructor <init>(Lcom/salesforce/marketingcloud/media/o;Lcom/salesforce/marketingcloud/media/h;Lcom/salesforce/marketingcloud/media/c;Lcom/salesforce/marketingcloud/media/a;Lcom/salesforce/marketingcloud/media/v;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lcom/salesforce/marketingcloud/media/n;->b:Lcom/salesforce/marketingcloud/media/o;

    .line 5
    .line 6
    iput-object p2, p0, Lcom/salesforce/marketingcloud/media/n;->c:Lcom/salesforce/marketingcloud/media/h;

    .line 7
    .line 8
    iput-object p3, p0, Lcom/salesforce/marketingcloud/media/n;->f:Lcom/salesforce/marketingcloud/media/c;

    .line 9
    .line 10
    iput-object p4, p0, Lcom/salesforce/marketingcloud/media/n;->h:Lcom/salesforce/marketingcloud/media/a;

    .line 11
    .line 12
    invoke-virtual {p4}, Lcom/salesforce/marketingcloud/media/a;->c()Ljava/lang/String;

    .line 13
    .line 14
    .line 15
    move-result-object p1

    .line 16
    iput-object p1, p0, Lcom/salesforce/marketingcloud/media/n;->d:Ljava/lang/String;

    .line 17
    .line 18
    invoke-virtual {p4}, Lcom/salesforce/marketingcloud/media/a;->e()Lcom/salesforce/marketingcloud/media/t;

    .line 19
    .line 20
    .line 21
    move-result-object p1

    .line 22
    iput-object p1, p0, Lcom/salesforce/marketingcloud/media/n;->g:Lcom/salesforce/marketingcloud/media/t;

    .line 23
    .line 24
    iput-object p5, p0, Lcom/salesforce/marketingcloud/media/n;->e:Lcom/salesforce/marketingcloud/media/v;

    .line 25
    .line 26
    invoke-virtual {p4}, Lcom/salesforce/marketingcloud/media/a;->d()Lcom/salesforce/marketingcloud/media/o$c;

    .line 27
    .line 28
    .line 29
    move-result-object p1

    .line 30
    iput-object p1, p0, Lcom/salesforce/marketingcloud/media/n;->m:Lcom/salesforce/marketingcloud/media/o$c;

    .line 31
    .line 32
    return-void
.end method

.method public static a(Lcom/salesforce/marketingcloud/media/t;Landroid/graphics/Bitmap;)Landroid/graphics/Bitmap;
    .locals 12

    .line 13
    invoke-virtual {p1}, Landroid/graphics/Bitmap;->getWidth()I

    move-result v0

    .line 14
    invoke-virtual {p1}, Landroid/graphics/Bitmap;->getHeight()I

    move-result v1

    .line 15
    iget v2, p0, Lcom/salesforce/marketingcloud/media/t;->i:F

    .line 16
    iget v3, p0, Lcom/salesforce/marketingcloud/media/t;->j:F

    .line 17
    new-instance v4, Landroid/graphics/RectF;

    int-to-float v0, v0

    int-to-float v1, v1

    const/4 v5, 0x0

    invoke-direct {v4, v5, v5, v0, v1}, Landroid/graphics/RectF;-><init>(FFFF)V

    .line 18
    new-instance v6, Landroid/graphics/RectF;

    invoke-direct {v6, v5, v5, v0, v1}, Landroid/graphics/RectF;-><init>(FFFF)V

    .line 19
    new-instance v0, Landroid/graphics/Paint;

    invoke-direct {v0}, Landroid/graphics/Paint;-><init>()V

    .line 20
    new-instance v1, Landroid/graphics/Paint;

    invoke-direct {v1}, Landroid/graphics/Paint;-><init>()V

    .line 21
    invoke-virtual {p1}, Landroid/graphics/Bitmap;->getWidth()I

    move-result v7

    invoke-virtual {p1}, Landroid/graphics/Bitmap;->getHeight()I

    move-result v8

    sget-object v9, Landroid/graphics/Bitmap$Config;->ARGB_8888:Landroid/graphics/Bitmap$Config;

    invoke-static {v7, v8, v9}, Landroid/graphics/Bitmap;->createBitmap(IILandroid/graphics/Bitmap$Config;)Landroid/graphics/Bitmap;

    move-result-object v7

    .line 22
    new-instance v8, Landroid/graphics/Canvas;

    invoke-direct {v8, v7}, Landroid/graphics/Canvas;-><init>(Landroid/graphics/Bitmap;)V

    const/4 v9, 0x1

    .line 23
    invoke-virtual {v0, v9}, Landroid/graphics/Paint;->setAntiAlias(Z)V

    .line 24
    new-instance v10, Landroid/graphics/BitmapShader;

    sget-object v11, Landroid/graphics/Shader$TileMode;->CLAMP:Landroid/graphics/Shader$TileMode;

    invoke-direct {v10, p1, v11, v11}, Landroid/graphics/BitmapShader;-><init>(Landroid/graphics/Bitmap;Landroid/graphics/Shader$TileMode;Landroid/graphics/Shader$TileMode;)V

    invoke-virtual {v0, v10}, Landroid/graphics/Paint;->setShader(Landroid/graphics/Shader;)Landroid/graphics/Shader;

    .line 25
    sget-object v10, Landroid/graphics/Paint$Style;->STROKE:Landroid/graphics/Paint$Style;

    invoke-virtual {v1, v10}, Landroid/graphics/Paint;->setStyle(Landroid/graphics/Paint$Style;)V

    .line 26
    invoke-virtual {v1, v9}, Landroid/graphics/Paint;->setAntiAlias(Z)V

    cmpl-float v9, v3, v5

    if-lez v9, :cond_0

    .line 27
    invoke-virtual {v1, v3}, Landroid/graphics/Paint;->setStrokeWidth(F)V

    .line 28
    iget p0, p0, Lcom/salesforce/marketingcloud/media/t;->k:I

    invoke-virtual {v1, p0}, Landroid/graphics/Paint;->setColor(I)V

    const/high16 p0, 0x40000000    # 2.0f

    div-float/2addr v3, p0

    .line 29
    invoke-virtual {v6, v3, v3}, Landroid/graphics/RectF;->inset(FF)V

    float-to-double v10, v3

    .line 30
    invoke-static {v10, v11}, Ljava/lang/Math;->floor(D)D

    move-result-wide v10

    double-to-float p0, v10

    .line 31
    invoke-virtual {v4, p0, p0}, Landroid/graphics/RectF;->inset(FF)V

    :cond_0
    cmpl-float p0, v2, v5

    if-lez p0, :cond_1

    .line 32
    invoke-virtual {v8, v4, v2, v2, v0}, Landroid/graphics/Canvas;->drawRoundRect(Landroid/graphics/RectF;FFLandroid/graphics/Paint;)V

    if-lez v9, :cond_2

    .line 33
    invoke-virtual {v8, v6, v2, v2, v1}, Landroid/graphics/Canvas;->drawRoundRect(Landroid/graphics/RectF;FFLandroid/graphics/Paint;)V

    goto :goto_0

    .line 34
    :cond_1
    invoke-virtual {v8, v4, v0}, Landroid/graphics/Canvas;->drawRect(Landroid/graphics/RectF;Landroid/graphics/Paint;)V

    if-lez v9, :cond_2

    .line 35
    invoke-virtual {v8, v6, v1}, Landroid/graphics/Canvas;->drawRect(Landroid/graphics/RectF;Landroid/graphics/Paint;)V

    :cond_2
    :goto_0
    if-eq p1, v7, :cond_3

    .line 36
    invoke-virtual {p1}, Landroid/graphics/Bitmap;->recycle()V

    return-object v7

    :cond_3
    return-object p1
.end method

.method public static a(Lcom/salesforce/marketingcloud/media/o;Lcom/salesforce/marketingcloud/media/h;Lcom/salesforce/marketingcloud/media/c;Lcom/salesforce/marketingcloud/media/a;)Lcom/salesforce/marketingcloud/media/n;
    .locals 12

    .line 1
    invoke-virtual {p3}, Lcom/salesforce/marketingcloud/media/a;->e()Lcom/salesforce/marketingcloud/media/t;

    move-result-object v0

    .line 2
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/media/o;->a()Ljava/util/List;

    move-result-object v1

    .line 3
    invoke-interface {v1}, Ljava/util/List;->size()I

    move-result v2

    const/4 v3, 0x0

    :goto_0
    if-ge v3, v2, :cond_1

    .line 4
    invoke-interface {v1, v3}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v4

    move-object v10, v4

    check-cast v10, Lcom/salesforce/marketingcloud/media/v;

    .line 5
    invoke-virtual {v10, v0}, Lcom/salesforce/marketingcloud/media/v;->a(Lcom/salesforce/marketingcloud/media/t;)Z

    move-result v4

    if-eqz v4, :cond_0

    .line 6
    new-instance v5, Lcom/salesforce/marketingcloud/media/n;

    move-object v6, p0

    move-object v7, p1

    move-object v8, p2

    move-object v9, p3

    invoke-direct/range {v5 .. v10}, Lcom/salesforce/marketingcloud/media/n;-><init>(Lcom/salesforce/marketingcloud/media/o;Lcom/salesforce/marketingcloud/media/h;Lcom/salesforce/marketingcloud/media/c;Lcom/salesforce/marketingcloud/media/a;Lcom/salesforce/marketingcloud/media/v;)V

    return-object v5

    :cond_0
    move-object v6, p0

    move-object v7, p1

    move-object v8, p2

    move-object v9, p3

    add-int/lit8 v3, v3, 0x1

    goto :goto_0

    :cond_1
    move-object v6, p0

    move-object v7, p1

    move-object v8, p2

    move-object v9, p3

    .line 7
    new-instance p0, Lcom/salesforce/marketingcloud/media/n;

    sget-object v11, Lcom/salesforce/marketingcloud/media/n;->q:Lcom/salesforce/marketingcloud/media/v;

    move-object v10, v9

    move-object v9, v8

    move-object v8, v7

    move-object v7, v6

    move-object v6, p0

    invoke-direct/range {v6 .. v11}, Lcom/salesforce/marketingcloud/media/n;-><init>(Lcom/salesforce/marketingcloud/media/o;Lcom/salesforce/marketingcloud/media/h;Lcom/salesforce/marketingcloud/media/c;Lcom/salesforce/marketingcloud/media/a;Lcom/salesforce/marketingcloud/media/v;)V

    return-object v6
.end method

.method public static a(Lcom/salesforce/marketingcloud/media/t;)V
    .locals 3

    .line 8
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/media/t;->b()Ljava/lang/String;

    move-result-object p0

    .line 9
    sget-object v0, Lcom/salesforce/marketingcloud/media/n;->p:Ljava/lang/ThreadLocal;

    invoke-virtual {v0}, Ljava/lang/ThreadLocal;->get()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Ljava/lang/StringBuilder;

    .line 10
    invoke-virtual {p0}, Ljava/lang/String;->length()I

    move-result v1

    const/16 v2, 0xd

    add-int/2addr v1, v2

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->ensureCapacity(I)V

    .line 11
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->length()I

    move-result v1

    invoke-virtual {v0, v2, v1, p0}, Ljava/lang/StringBuilder;->replace(IILjava/lang/String;)Ljava/lang/StringBuilder;

    .line 12
    invoke-static {}, Ljava/lang/Thread;->currentThread()Ljava/lang/Thread;

    move-result-object p0

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    invoke-virtual {p0, v0}, Ljava/lang/Thread;->setName(Ljava/lang/String;)V

    return-void
.end method

.method public static b(Lcom/salesforce/marketingcloud/media/t;Landroid/graphics/Bitmap;)Landroid/graphics/Bitmap;
    .locals 11

    .line 1
    invoke-virtual {p1}, Landroid/graphics/Bitmap;->getWidth()I

    move-result v0

    .line 2
    invoke-virtual {p1}, Landroid/graphics/Bitmap;->getHeight()I

    move-result v1

    .line 3
    new-instance v7, Landroid/graphics/Matrix;

    invoke-direct {v7}, Landroid/graphics/Matrix;-><init>()V

    .line 4
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/media/t;->d()Z

    move-result v2

    const/4 v3, 0x0

    if-eqz v2, :cond_d

    .line 5
    iget v2, p0, Lcom/salesforce/marketingcloud/media/t;->e:I

    .line 6
    iget v4, p0, Lcom/salesforce/marketingcloud/media/t;->f:I

    .line 7
    iget-boolean v5, p0, Lcom/salesforce/marketingcloud/media/t;->g:Z

    if-eqz v5, :cond_4

    if-eqz v2, :cond_0

    int-to-float p0, v2

    int-to-float v5, v0

    :goto_0
    div-float/2addr p0, v5

    goto :goto_1

    :cond_0
    int-to-float p0, v4

    int-to-float v5, v1

    goto :goto_0

    :goto_1
    if-eqz v4, :cond_1

    int-to-float v5, v4

    int-to-float v6, v1

    :goto_2
    div-float/2addr v5, v6

    goto :goto_3

    :cond_1
    int-to-float v5, v2

    int-to-float v6, v0

    goto :goto_2

    :goto_3
    cmpl-float v6, p0, v5

    if-lez v6, :cond_2

    int-to-float v2, v1

    div-float/2addr v5, p0

    mul-float/2addr v5, v2

    float-to-double v5, v5

    .line 8
    invoke-static {v5, v6}, Ljava/lang/Math;->ceil(D)D

    move-result-wide v5

    double-to-int v2, v5

    sub-int/2addr v1, v2

    .line 9
    div-int/lit8 v1, v1, 0x2

    int-to-float v4, v4

    int-to-float v5, v2

    div-float v5, v4, v5

    move v10, v2

    move v2, v1

    move v1, v10

    goto :goto_4

    :cond_2
    cmpg-float v4, p0, v5

    if-gez v4, :cond_3

    int-to-float v4, v0

    div-float/2addr p0, v5

    mul-float/2addr p0, v4

    float-to-double v8, p0

    .line 10
    invoke-static {v8, v9}, Ljava/lang/Math;->ceil(D)D

    move-result-wide v8

    double-to-int p0, v8

    sub-int/2addr v0, p0

    .line 11
    div-int/lit8 v0, v0, 0x2

    int-to-float v2, v2

    int-to-float v4, p0

    div-float/2addr v2, v4

    move v10, v0

    move v0, p0

    move p0, v2

    move v2, v3

    move v3, v10

    goto :goto_4

    :cond_3
    move v2, v3

    move p0, v5

    .line 12
    :goto_4
    invoke-virtual {v7, p0, v5}, Landroid/graphics/Matrix;->preScale(FF)Z

    move v4, v2

    :goto_5
    move v5, v0

    move v6, v1

    goto :goto_10

    .line 13
    :cond_4
    iget-boolean p0, p0, Lcom/salesforce/marketingcloud/media/t;->h:Z

    if-eqz p0, :cond_8

    if-eqz v2, :cond_5

    int-to-float p0, v2

    int-to-float v5, v0

    :goto_6
    div-float/2addr p0, v5

    goto :goto_7

    :cond_5
    int-to-float p0, v4

    int-to-float v5, v1

    goto :goto_6

    :goto_7
    if-eqz v4, :cond_6

    int-to-float v2, v4

    int-to-float v4, v1

    :goto_8
    div-float/2addr v2, v4

    goto :goto_9

    :cond_6
    int-to-float v2, v2

    int-to-float v4, v0

    goto :goto_8

    :goto_9
    cmpg-float v4, p0, v2

    if-gez v4, :cond_7

    goto :goto_a

    :cond_7
    move p0, v2

    .line 14
    :goto_a
    invoke-virtual {v7, p0, p0}, Landroid/graphics/Matrix;->preScale(FF)Z

    goto :goto_f

    :cond_8
    if-nez v2, :cond_9

    if-eqz v4, :cond_d

    :cond_9
    if-ne v2, v0, :cond_a

    if-eq v4, v1, :cond_d

    :cond_a
    if-eqz v2, :cond_b

    int-to-float p0, v2

    int-to-float v5, v0

    :goto_b
    div-float/2addr p0, v5

    goto :goto_c

    :cond_b
    int-to-float p0, v4

    int-to-float v5, v1

    goto :goto_b

    :goto_c
    if-eqz v4, :cond_c

    int-to-float v2, v4

    int-to-float v4, v1

    :goto_d
    div-float/2addr v2, v4

    goto :goto_e

    :cond_c
    int-to-float v2, v2

    int-to-float v4, v0

    goto :goto_d

    .line 15
    :goto_e
    invoke-virtual {v7, p0, v2}, Landroid/graphics/Matrix;->preScale(FF)Z

    :cond_d
    :goto_f
    move v4, v3

    goto :goto_5

    :goto_10
    const/4 v8, 0x1

    move-object v2, p1

    .line 16
    invoke-static/range {v2 .. v8}, Landroid/graphics/Bitmap;->createBitmap(Landroid/graphics/Bitmap;IIIILandroid/graphics/Matrix;Z)Landroid/graphics/Bitmap;

    move-result-object p0

    if-eq p0, v2, :cond_e

    .line 17
    invoke-virtual {v2}, Landroid/graphics/Bitmap;->recycle()V

    return-object p0

    :cond_e
    return-object v2
.end method


# virtual methods
.method public a(Lcom/salesforce/marketingcloud/media/a;)V
    .locals 2

    .line 41
    iget-object v0, p0, Lcom/salesforce/marketingcloud/media/n;->h:Lcom/salesforce/marketingcloud/media/a;

    if-nez v0, :cond_0

    .line 42
    iput-object p1, p0, Lcom/salesforce/marketingcloud/media/n;->h:Lcom/salesforce/marketingcloud/media/a;

    return-void

    .line 43
    :cond_0
    iget-object v0, p0, Lcom/salesforce/marketingcloud/media/n;->i:Ljava/util/List;

    if-nez v0, :cond_1

    .line 44
    new-instance v0, Ljava/util/ArrayList;

    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    iput-object v0, p0, Lcom/salesforce/marketingcloud/media/n;->i:Ljava/util/List;

    .line 45
    :cond_1
    iget-object v0, p0, Lcom/salesforce/marketingcloud/media/n;->i:Ljava/util/List;

    invoke-interface {v0, p1}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 46
    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/media/a;->d()Lcom/salesforce/marketingcloud/media/o$c;

    move-result-object p1

    .line 47
    invoke-virtual {p1}, Ljava/lang/Enum;->ordinal()I

    move-result v0

    iget-object v1, p0, Lcom/salesforce/marketingcloud/media/n;->m:Lcom/salesforce/marketingcloud/media/o$c;

    invoke-virtual {v1}, Ljava/lang/Enum;->ordinal()I

    move-result v1

    if-le v0, v1, :cond_2

    .line 48
    iput-object p1, p0, Lcom/salesforce/marketingcloud/media/n;->m:Lcom/salesforce/marketingcloud/media/o$c;

    :cond_2
    return-void
.end method

.method public a()Z
    .locals 2

    .line 37
    iget-object v0, p0, Lcom/salesforce/marketingcloud/media/n;->h:Lcom/salesforce/marketingcloud/media/a;

    const/4 v1, 0x0

    if-nez v0, :cond_1

    iget-object v0, p0, Lcom/salesforce/marketingcloud/media/n;->i:Ljava/util/List;

    if-eqz v0, :cond_0

    .line 38
    invoke-interface {v0}, Ljava/util/List;->isEmpty()Z

    move-result v0

    if-eqz v0, :cond_1

    .line 39
    :cond_0
    iget-object p0, p0, Lcom/salesforce/marketingcloud/media/n;->k:Ljava/util/concurrent/Future;

    if-eqz p0, :cond_1

    .line 40
    invoke-interface {p0, v1}, Ljava/util/concurrent/Future;->cancel(Z)Z

    move-result p0

    if-eqz p0, :cond_1

    const/4 p0, 0x1

    return p0

    :cond_1
    return v1
.end method

.method public b()Lcom/salesforce/marketingcloud/media/v$b;
    .locals 7

    .line 18
    iget-object v0, p0, Lcom/salesforce/marketingcloud/media/n;->g:Lcom/salesforce/marketingcloud/media/t;

    iget v0, v0, Lcom/salesforce/marketingcloud/media/t;->d:I

    invoke-static {v0}, Lcom/salesforce/marketingcloud/media/t$b;->a(I)Z

    move-result v0

    if-eqz v0, :cond_0

    .line 19
    iget-object v0, p0, Lcom/salesforce/marketingcloud/media/n;->f:Lcom/salesforce/marketingcloud/media/c;

    iget-object v1, p0, Lcom/salesforce/marketingcloud/media/n;->d:Ljava/lang/String;

    invoke-virtual {v0, v1}, Lcom/salesforce/marketingcloud/media/c;->a(Ljava/lang/String;)Landroid/graphics/Bitmap;

    move-result-object v0

    if-eqz v0, :cond_0

    .line 20
    new-instance p0, Lcom/salesforce/marketingcloud/media/v$b;

    sget-object v1, Lcom/salesforce/marketingcloud/media/o$b;->c:Lcom/salesforce/marketingcloud/media/o$b;

    invoke-direct {p0, v0, v1}, Lcom/salesforce/marketingcloud/media/v$b;-><init>(Landroid/graphics/Bitmap;Lcom/salesforce/marketingcloud/media/o$b;)V

    return-object p0

    .line 21
    :cond_0
    new-instance v0, Ljava/util/concurrent/atomic/AtomicReference;

    invoke-direct {v0}, Ljava/util/concurrent/atomic/AtomicReference;-><init>()V

    .line 22
    new-instance v1, Ljava/util/concurrent/atomic/AtomicReference;

    invoke-direct {v1}, Ljava/util/concurrent/atomic/AtomicReference;-><init>()V

    .line 23
    new-instance v2, Ljava/util/concurrent/CountDownLatch;

    const/4 v3, 0x1

    invoke-direct {v2, v3}, Ljava/util/concurrent/CountDownLatch;-><init>(I)V

    .line 24
    :try_start_0
    iget-object v3, p0, Lcom/salesforce/marketingcloud/media/n;->e:Lcom/salesforce/marketingcloud/media/v;

    iget-object v4, p0, Lcom/salesforce/marketingcloud/media/n;->b:Lcom/salesforce/marketingcloud/media/o;

    iget-object v5, p0, Lcom/salesforce/marketingcloud/media/n;->g:Lcom/salesforce/marketingcloud/media/t;

    new-instance v6, Lcom/salesforce/marketingcloud/media/n$c;

    invoke-direct {v6, p0, v0, v2, v1}, Lcom/salesforce/marketingcloud/media/n$c;-><init>(Lcom/salesforce/marketingcloud/media/n;Ljava/util/concurrent/atomic/AtomicReference;Ljava/util/concurrent/CountDownLatch;Ljava/util/concurrent/atomic/AtomicReference;)V

    invoke-virtual {v3, v4, v5, v6}, Lcom/salesforce/marketingcloud/media/v;->a(Lcom/salesforce/marketingcloud/media/o;Lcom/salesforce/marketingcloud/media/t;Lcom/salesforce/marketingcloud/media/v$a;)V

    .line 25
    invoke-virtual {v2}, Ljava/util/concurrent/CountDownLatch;->await()V
    :try_end_0
    .catch Ljava/lang/InterruptedException; {:try_start_0 .. :try_end_0} :catch_0

    .line 26
    invoke-virtual {v1}, Ljava/util/concurrent/atomic/AtomicReference;->get()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Ljava/lang/Throwable;

    if-nez v1, :cond_4

    .line 27
    invoke-virtual {v0}, Ljava/util/concurrent/atomic/AtomicReference;->get()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Lcom/salesforce/marketingcloud/media/v$b;

    .line 28
    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/media/v$b;->d()Z

    move-result v1

    if-eqz v1, :cond_3

    .line 29
    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/media/v$b;->a()Landroid/graphics/Bitmap;

    move-result-object v1

    .line 30
    iget-object v2, p0, Lcom/salesforce/marketingcloud/media/n;->g:Lcom/salesforce/marketingcloud/media/t;

    invoke-virtual {v2}, Lcom/salesforce/marketingcloud/media/t;->e()Z

    move-result v2

    if-eqz v2, :cond_3

    .line 31
    iget-object v2, p0, Lcom/salesforce/marketingcloud/media/n;->g:Lcom/salesforce/marketingcloud/media/t;

    invoke-virtual {v2}, Lcom/salesforce/marketingcloud/media/t;->d()Z

    move-result v2

    if-eqz v2, :cond_1

    .line 32
    iget-object v2, p0, Lcom/salesforce/marketingcloud/media/n;->g:Lcom/salesforce/marketingcloud/media/t;

    invoke-static {v2, v1}, Lcom/salesforce/marketingcloud/media/n;->b(Lcom/salesforce/marketingcloud/media/t;Landroid/graphics/Bitmap;)Landroid/graphics/Bitmap;

    move-result-object v1

    .line 33
    :cond_1
    iget-object v2, p0, Lcom/salesforce/marketingcloud/media/n;->g:Lcom/salesforce/marketingcloud/media/t;

    invoke-virtual {v2}, Lcom/salesforce/marketingcloud/media/t;->c()Z

    move-result v2

    if-eqz v2, :cond_2

    .line 34
    iget-object p0, p0, Lcom/salesforce/marketingcloud/media/n;->g:Lcom/salesforce/marketingcloud/media/t;

    invoke-static {p0, v1}, Lcom/salesforce/marketingcloud/media/n;->a(Lcom/salesforce/marketingcloud/media/t;Landroid/graphics/Bitmap;)Landroid/graphics/Bitmap;

    move-result-object v1

    .line 35
    :cond_2
    new-instance p0, Lcom/salesforce/marketingcloud/media/v$b;

    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/media/v$b;->c()Lcom/salesforce/marketingcloud/media/o$b;

    move-result-object v0

    invoke-direct {p0, v1, v0}, Lcom/salesforce/marketingcloud/media/v$b;-><init>(Landroid/graphics/Bitmap;Lcom/salesforce/marketingcloud/media/o$b;)V

    return-object p0

    :cond_3
    return-object v0

    .line 36
    :cond_4
    new-instance p0, Ljava/lang/RuntimeException;

    invoke-direct {p0, v1}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/Throwable;)V

    throw p0

    :catch_0
    move-exception p0

    .line 37
    new-instance v0, Ljava/io/InterruptedIOException;

    invoke-virtual {p0}, Ljava/lang/Throwable;->getMessage()Ljava/lang/String;

    move-result-object p0

    invoke-direct {v0, p0}, Ljava/io/InterruptedIOException;-><init>(Ljava/lang/String;)V

    throw v0
.end method

.method public b(Lcom/salesforce/marketingcloud/media/a;)V
    .locals 1

    .line 38
    iget-object v0, p0, Lcom/salesforce/marketingcloud/media/n;->h:Lcom/salesforce/marketingcloud/media/a;

    if-ne v0, p1, :cond_0

    const/4 p1, 0x0

    .line 39
    iput-object p1, p0, Lcom/salesforce/marketingcloud/media/n;->h:Lcom/salesforce/marketingcloud/media/a;

    return-void

    .line 40
    :cond_0
    iget-object p0, p0, Lcom/salesforce/marketingcloud/media/n;->i:Ljava/util/List;

    if-eqz p0, :cond_1

    .line 41
    invoke-interface {p0, p1}, Ljava/util/List;->remove(Ljava/lang/Object;)Z

    :cond_1
    return-void
.end method

.method public c()Lcom/salesforce/marketingcloud/media/a;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/media/n;->h:Lcom/salesforce/marketingcloud/media/a;

    .line 2
    .line 3
    return-object p0
.end method

.method public d()Ljava/util/List;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/List<",
            "Lcom/salesforce/marketingcloud/media/a;",
            ">;"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/media/n;->i:Ljava/util/List;

    .line 2
    .line 3
    return-object p0
.end method

.method public e()Lcom/salesforce/marketingcloud/media/t;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/media/n;->g:Lcom/salesforce/marketingcloud/media/t;

    .line 2
    .line 3
    return-object p0
.end method

.method public f()Ljava/lang/Exception;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/media/n;->l:Ljava/lang/Exception;

    .line 2
    .line 3
    return-object p0
.end method

.method public g()Lcom/salesforce/marketingcloud/media/o;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/media/n;->b:Lcom/salesforce/marketingcloud/media/o;

    .line 2
    .line 3
    return-object p0
.end method

.method public h()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/media/n;->d:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public i()Lcom/salesforce/marketingcloud/media/v$b;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/media/n;->j:Lcom/salesforce/marketingcloud/media/v$b;

    .line 2
    .line 3
    return-object p0
.end method

.method public j()Z
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/media/n;->k:Ljava/util/concurrent/Future;

    .line 2
    .line 3
    if-eqz p0, :cond_0

    .line 4
    .line 5
    invoke-interface {p0}, Ljava/util/concurrent/Future;->isCancelled()Z

    .line 6
    .line 7
    .line 8
    move-result p0

    .line 9
    if-eqz p0, :cond_0

    .line 10
    .line 11
    const/4 p0, 0x1

    .line 12
    return p0

    .line 13
    :cond_0
    const/4 p0, 0x0

    .line 14
    return p0
.end method

.method public run()V
    .locals 4

    .line 1
    const-string v0, "ImageHandler-Idle"

    .line 2
    .line 3
    :try_start_0
    iget-object v1, p0, Lcom/salesforce/marketingcloud/media/n;->g:Lcom/salesforce/marketingcloud/media/t;

    .line 4
    .line 5
    invoke-static {v1}, Lcom/salesforce/marketingcloud/media/n;->a(Lcom/salesforce/marketingcloud/media/t;)V

    .line 6
    .line 7
    .line 8
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/media/n;->b()Lcom/salesforce/marketingcloud/media/v$b;

    .line 9
    .line 10
    .line 11
    move-result-object v1

    .line 12
    iput-object v1, p0, Lcom/salesforce/marketingcloud/media/n;->j:Lcom/salesforce/marketingcloud/media/v$b;

    .line 13
    .line 14
    invoke-virtual {v1}, Lcom/salesforce/marketingcloud/media/v$b;->d()Z

    .line 15
    .line 16
    .line 17
    move-result v1

    .line 18
    if-nez v1, :cond_0

    .line 19
    .line 20
    iget-object v1, p0, Lcom/salesforce/marketingcloud/media/n;->c:Lcom/salesforce/marketingcloud/media/h;

    .line 21
    .line 22
    invoke-virtual {v1, p0}, Lcom/salesforce/marketingcloud/media/h;->c(Lcom/salesforce/marketingcloud/media/n;)V

    .line 23
    .line 24
    .line 25
    goto :goto_1

    .line 26
    :catchall_0
    move-exception p0

    .line 27
    goto :goto_2

    .line 28
    :catch_0
    move-exception v1

    .line 29
    goto :goto_0

    .line 30
    :cond_0
    const-string v1, "IMAGE"

    .line 31
    .line 32
    const-string v2, "onSuccess - Loaded from: %s"

    .line 33
    .line 34
    iget-object v3, p0, Lcom/salesforce/marketingcloud/media/n;->j:Lcom/salesforce/marketingcloud/media/v$b;

    .line 35
    .line 36
    invoke-virtual {v3}, Lcom/salesforce/marketingcloud/media/v$b;->c()Lcom/salesforce/marketingcloud/media/o$b;

    .line 37
    .line 38
    .line 39
    move-result-object v3

    .line 40
    filled-new-array {v3}, [Ljava/lang/Object;

    .line 41
    .line 42
    .line 43
    move-result-object v3

    .line 44
    invoke-static {v1, v2, v3}, Lcom/salesforce/marketingcloud/g;->a(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 45
    .line 46
    .line 47
    iget-object v1, p0, Lcom/salesforce/marketingcloud/media/n;->c:Lcom/salesforce/marketingcloud/media/h;

    .line 48
    .line 49
    invoke-virtual {v1, p0}, Lcom/salesforce/marketingcloud/media/h;->b(Lcom/salesforce/marketingcloud/media/n;)V
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 50
    .line 51
    .line 52
    goto :goto_1

    .line 53
    :goto_0
    :try_start_1
    iput-object v1, p0, Lcom/salesforce/marketingcloud/media/n;->l:Ljava/lang/Exception;

    .line 54
    .line 55
    iget-object v1, p0, Lcom/salesforce/marketingcloud/media/n;->c:Lcom/salesforce/marketingcloud/media/h;

    .line 56
    .line 57
    invoke-virtual {v1, p0}, Lcom/salesforce/marketingcloud/media/h;->c(Lcom/salesforce/marketingcloud/media/n;)V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 58
    .line 59
    .line 60
    :goto_1
    invoke-static {}, Ljava/lang/Thread;->currentThread()Ljava/lang/Thread;

    .line 61
    .line 62
    .line 63
    move-result-object p0

    .line 64
    invoke-virtual {p0, v0}, Ljava/lang/Thread;->setName(Ljava/lang/String;)V

    .line 65
    .line 66
    .line 67
    return-void

    .line 68
    :goto_2
    invoke-static {}, Ljava/lang/Thread;->currentThread()Ljava/lang/Thread;

    .line 69
    .line 70
    .line 71
    move-result-object v1

    .line 72
    invoke-virtual {v1, v0}, Ljava/lang/Thread;->setName(Ljava/lang/String;)V

    .line 73
    .line 74
    .line 75
    throw p0
.end method
