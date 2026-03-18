.class public abstract Llp/ie;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(Lkw/l;Lkw/g;Lkw/i;Landroid/graphics/RectF;FF)F
    .locals 1

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "context"

    .line 7
    .line 8
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    const-string v0, "horizontalDimensions"

    .line 12
    .line 13
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    const-string v0, "bounds"

    .line 17
    .line 18
    invoke-static {p3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 19
    .line 20
    .line 21
    instance-of v0, p0, Lkw/j;

    .line 22
    .line 23
    if-eqz v0, :cond_0

    .line 24
    .line 25
    check-cast p0, Lkw/j;

    .line 26
    .line 27
    invoke-virtual {p0, p1, p2, p3, p4}, Lkw/j;->a(Lkw/g;Lkw/i;Landroid/graphics/RectF;F)F

    .line 28
    .line 29
    .line 30
    move-result p0

    .line 31
    sub-float/2addr p0, p5

    .line 32
    return p0

    .line 33
    :cond_0
    instance-of p1, p0, Lkw/k;

    .line 34
    .line 35
    if-eqz p1, :cond_1

    .line 36
    .line 37
    check-cast p0, Lkw/k;

    .line 38
    .line 39
    iget p0, p0, Lkw/k;->a:F

    .line 40
    .line 41
    return p0

    .line 42
    :cond_1
    new-instance p0, La8/r0;

    .line 43
    .line 44
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 45
    .line 46
    .line 47
    throw p0
.end method
