.class public abstract Llp/wc;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(Landroid/content/Context;)Lk4/o;
    .locals 4

    .line 1
    new-instance v0, Lk4/o;

    .line 2
    .line 3
    new-instance v1, Lcq/r1;

    .line 4
    .line 5
    invoke-direct {v1, p0}, Lcq/r1;-><init>(Landroid/content/Context;)V

    .line 6
    .line 7
    .line 8
    sget v2, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 9
    .line 10
    const/16 v3, 0x1f

    .line 11
    .line 12
    if-lt v2, v3, :cond_0

    .line 13
    .line 14
    sget-object v2, Lk4/y;->a:Lk4/y;

    .line 15
    .line 16
    invoke-virtual {v2, p0}, Lk4/y;->a(Landroid/content/Context;)I

    .line 17
    .line 18
    .line 19
    move-result p0

    .line 20
    goto :goto_0

    .line 21
    :cond_0
    const/4 p0, 0x0

    .line 22
    :goto_0
    new-instance v2, Lk4/c;

    .line 23
    .line 24
    invoke-direct {v2, p0}, Lk4/c;-><init>(I)V

    .line 25
    .line 26
    .line 27
    invoke-direct {v0, v1, v2}, Lk4/o;-><init>(Lcq/r1;Lk4/c;)V

    .line 28
    .line 29
    .line 30
    return-object v0
.end method

.method public static final b(Landroid/content/Context;)I
    .locals 1

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-static {p0}, Llp/wc;->d(Landroid/content/Context;)Landroid/graphics/Point;

    .line 7
    .line 8
    .line 9
    move-result-object p0

    .line 10
    iget p0, p0, Landroid/graphics/Point;->y:I

    .line 11
    .line 12
    return p0
.end method

.method public static final c(Landroid/content/Context;)I
    .locals 1

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-static {p0}, Llp/wc;->d(Landroid/content/Context;)Landroid/graphics/Point;

    .line 7
    .line 8
    .line 9
    move-result-object p0

    .line 10
    iget p0, p0, Landroid/graphics/Point;->x:I

    .line 11
    .line 12
    return p0
.end method

.method public static final d(Landroid/content/Context;)Landroid/graphics/Point;
    .locals 2

    .line 1
    const-class v0, Landroid/view/WindowManager;

    .line 2
    .line 3
    invoke-virtual {p0, v0}, Landroid/content/Context;->getSystemService(Ljava/lang/Class;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Landroid/view/WindowManager;

    .line 8
    .line 9
    sget v0, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 10
    .line 11
    const/16 v1, 0x1e

    .line 12
    .line 13
    if-lt v0, v1, :cond_0

    .line 14
    .line 15
    invoke-static {p0}, Ln01/a;->h(Landroid/view/WindowManager;)Landroid/view/WindowMetrics;

    .line 16
    .line 17
    .line 18
    move-result-object p0

    .line 19
    const-string v0, "getCurrentWindowMetrics(...)"

    .line 20
    .line 21
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 22
    .line 23
    .line 24
    invoke-static {p0}, Ln01/a;->f(Landroid/view/WindowMetrics;)Landroid/graphics/Rect;

    .line 25
    .line 26
    .line 27
    move-result-object p0

    .line 28
    const-string v0, "getBounds(...)"

    .line 29
    .line 30
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 31
    .line 32
    .line 33
    new-instance v0, Landroid/graphics/Point;

    .line 34
    .line 35
    invoke-virtual {p0}, Landroid/graphics/Rect;->width()I

    .line 36
    .line 37
    .line 38
    move-result v1

    .line 39
    invoke-virtual {p0}, Landroid/graphics/Rect;->height()I

    .line 40
    .line 41
    .line 42
    move-result p0

    .line 43
    invoke-direct {v0, v1, p0}, Landroid/graphics/Point;-><init>(II)V

    .line 44
    .line 45
    .line 46
    return-object v0

    .line 47
    :cond_0
    new-instance v0, Landroid/util/DisplayMetrics;

    .line 48
    .line 49
    invoke-direct {v0}, Landroid/util/DisplayMetrics;-><init>()V

    .line 50
    .line 51
    .line 52
    invoke-interface {p0}, Landroid/view/WindowManager;->getDefaultDisplay()Landroid/view/Display;

    .line 53
    .line 54
    .line 55
    move-result-object p0

    .line 56
    invoke-virtual {p0, v0}, Landroid/view/Display;->getRealMetrics(Landroid/util/DisplayMetrics;)V

    .line 57
    .line 58
    .line 59
    new-instance p0, Landroid/graphics/Point;

    .line 60
    .line 61
    iget v1, v0, Landroid/util/DisplayMetrics;->widthPixels:I

    .line 62
    .line 63
    iget v0, v0, Landroid/util/DisplayMetrics;->heightPixels:I

    .line 64
    .line 65
    invoke-direct {p0, v1, v0}, Landroid/graphics/Point;-><init>(II)V

    .line 66
    .line 67
    .line 68
    return-object p0
.end method

.method public static final e(Landroid/content/Context;Ljava/lang/String;)I
    .locals 3

    .line 1
    invoke-virtual {p0}, Landroid/content/Context;->getResources()Landroid/content/res/Resources;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    const-string v1, "dimen"

    .line 6
    .line 7
    const-string v2, "android"

    .line 8
    .line 9
    invoke-virtual {v0, p1, v1, v2}, Landroid/content/res/Resources;->getIdentifier(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)I

    .line 10
    .line 11
    .line 12
    move-result p1

    .line 13
    if-lez p1, :cond_0

    .line 14
    .line 15
    invoke-virtual {p0}, Landroid/content/Context;->getResources()Landroid/content/res/Resources;

    .line 16
    .line 17
    .line 18
    move-result-object p0

    .line 19
    invoke-virtual {p0, p1}, Landroid/content/res/Resources;->getDimensionPixelSize(I)I

    .line 20
    .line 21
    .line 22
    move-result p0

    .line 23
    return p0

    .line 24
    :cond_0
    const/4 p0, 0x0

    .line 25
    return p0
.end method
