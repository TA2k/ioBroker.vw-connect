.class public final synthetic Lkw/m;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lkw/p;


# virtual methods
.method public final a(Lkw/g;Lkw/i;Landroid/graphics/RectF;)F
    .locals 0

    .line 1
    const-string p0, "horizontalDimensions"

    .line 2
    .line 3
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string p0, "bounds"

    .line 7
    .line 8
    invoke-static {p3, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    invoke-virtual {p2, p1}, Lkw/i;->c(Lkw/g;)F

    .line 12
    .line 13
    .line 14
    move-result p0

    .line 15
    const/4 p1, 0x0

    .line 16
    cmpg-float p1, p0, p1

    .line 17
    .line 18
    if-nez p1, :cond_0

    .line 19
    .line 20
    const/high16 p0, 0x3f800000    # 1.0f

    .line 21
    .line 22
    return p0

    .line 23
    :cond_0
    invoke-virtual {p3}, Landroid/graphics/RectF;->width()F

    .line 24
    .line 25
    .line 26
    move-result p1

    .line 27
    iget p3, p2, Lkw/i;->d:F

    .line 28
    .line 29
    iget p2, p2, Lkw/i;->e:F

    .line 30
    .line 31
    add-float/2addr p3, p2

    .line 32
    sub-float/2addr p1, p3

    .line 33
    div-float/2addr p1, p0

    .line 34
    return p1
.end method
