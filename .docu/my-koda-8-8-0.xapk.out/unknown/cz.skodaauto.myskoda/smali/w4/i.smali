.class public abstract Lw4/i;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Lw4/h;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    new-instance v0, Lw4/h;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lw4/i;->a:Lw4/h;

    .line 7
    .line 8
    return-void
.end method

.method public static final a(Landroid/view/View;Landroid/view/View;)Z
    .locals 1

    .line 1
    invoke-virtual {p1}, Landroid/view/View;->getParent()Landroid/view/ViewParent;

    .line 2
    .line 3
    .line 4
    move-result-object p1

    .line 5
    :goto_0
    if-eqz p1, :cond_1

    .line 6
    .line 7
    invoke-virtual {p0}, Landroid/view/View;->getParent()Landroid/view/ViewParent;

    .line 8
    .line 9
    .line 10
    move-result-object v0

    .line 11
    if-ne p1, v0, :cond_0

    .line 12
    .line 13
    const/4 p0, 0x1

    .line 14
    return p0

    .line 15
    :cond_0
    invoke-interface {p1}, Landroid/view/ViewParent;->getParent()Landroid/view/ViewParent;

    .line 16
    .line 17
    .line 18
    move-result-object p1

    .line 19
    goto :goto_0

    .line 20
    :cond_1
    const/4 p0, 0x0

    .line 21
    return p0
.end method

.method public static final b(Lc3/j;Landroid/view/View;Landroid/view/View;)Landroid/graphics/Rect;
    .locals 6

    .line 1
    const/4 v0, 0x2

    .line 2
    new-array v1, v0, [I

    .line 3
    .line 4
    invoke-virtual {p1, v1}, Landroid/view/View;->getLocationOnScreen([I)V

    .line 5
    .line 6
    .line 7
    new-array p1, v0, [I

    .line 8
    .line 9
    invoke-virtual {p2, p1}, Landroid/view/View;->getLocationOnScreen([I)V

    .line 10
    .line 11
    .line 12
    check-cast p0, Lc3/l;

    .line 13
    .line 14
    iget-object p0, p0, Lc3/l;->c:Lc3/v;

    .line 15
    .line 16
    invoke-static {p0}, Lc3/f;->g(Lc3/v;)Lc3/v;

    .line 17
    .line 18
    .line 19
    move-result-object p0

    .line 20
    const/4 p2, 0x0

    .line 21
    if-eqz p0, :cond_0

    .line 22
    .line 23
    invoke-static {p0}, Lc3/f;->j(Lc3/v;)Ld3/c;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    goto :goto_0

    .line 28
    :cond_0
    move-object p0, p2

    .line 29
    :goto_0
    if-nez p0, :cond_1

    .line 30
    .line 31
    return-object p2

    .line 32
    :cond_1
    new-instance p2, Landroid/graphics/Rect;

    .line 33
    .line 34
    iget v0, p0, Ld3/c;->a:F

    .line 35
    .line 36
    float-to-int v0, v0

    .line 37
    const/4 v2, 0x0

    .line 38
    aget v3, v1, v2

    .line 39
    .line 40
    add-int/2addr v0, v3

    .line 41
    aget v2, p1, v2

    .line 42
    .line 43
    sub-int/2addr v0, v2

    .line 44
    iget v4, p0, Ld3/c;->b:F

    .line 45
    .line 46
    float-to-int v4, v4

    .line 47
    const/4 v5, 0x1

    .line 48
    aget v1, v1, v5

    .line 49
    .line 50
    add-int/2addr v4, v1

    .line 51
    aget p1, p1, v5

    .line 52
    .line 53
    sub-int/2addr v4, p1

    .line 54
    iget v5, p0, Ld3/c;->c:F

    .line 55
    .line 56
    float-to-int v5, v5

    .line 57
    add-int/2addr v5, v3

    .line 58
    sub-int/2addr v5, v2

    .line 59
    iget p0, p0, Ld3/c;->d:F

    .line 60
    .line 61
    float-to-int p0, p0

    .line 62
    add-int/2addr p0, v1

    .line 63
    sub-int/2addr p0, p1

    .line 64
    invoke-direct {p2, v0, v4, v5, p0}, Landroid/graphics/Rect;-><init>(IIII)V

    .line 65
    .line 66
    .line 67
    return-object p2
.end method

.method public static final c(Lx2/r;)Landroid/view/View;
    .locals 1

    .line 1
    iget-object p0, p0, Lx2/r;->d:Lx2/r;

    .line 2
    .line 3
    invoke-static {p0}, Lv3/f;->x(Lv3/m;)Lv3/h0;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    iget-object p0, p0, Lv3/h0;->q:Lw4/o;

    .line 8
    .line 9
    if-eqz p0, :cond_0

    .line 10
    .line 11
    invoke-virtual {p0}, Lw4/g;->getInteropView()Landroid/view/View;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    goto :goto_0

    .line 16
    :cond_0
    const/4 p0, 0x0

    .line 17
    :goto_0
    if-eqz p0, :cond_1

    .line 18
    .line 19
    return-object p0

    .line 20
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 21
    .line 22
    const-string v0, "Could not fetch interop view"

    .line 23
    .line 24
    invoke-direct {p0, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 25
    .line 26
    .line 27
    throw p0
.end method

.method public static final d(Lw4/o;Lv3/h0;)V
    .locals 4

    .line 1
    iget-object p1, p1, Lv3/h0;->H:Lg1/q;

    .line 2
    .line 3
    iget-object p1, p1, Lg1/q;->d:Ljava/lang/Object;

    .line 4
    .line 5
    check-cast p1, Lv3/u;

    .line 6
    .line 7
    const-wide/16 v0, 0x0

    .line 8
    .line 9
    invoke-virtual {p1, v0, v1}, Lv3/f1;->R(J)J

    .line 10
    .line 11
    .line 12
    move-result-wide v0

    .line 13
    const/16 p1, 0x20

    .line 14
    .line 15
    shr-long v2, v0, p1

    .line 16
    .line 17
    long-to-int p1, v2

    .line 18
    invoke-static {p1}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 19
    .line 20
    .line 21
    move-result p1

    .line 22
    invoke-static {p1}, Ljava/lang/Math;->round(F)I

    .line 23
    .line 24
    .line 25
    move-result p1

    .line 26
    const-wide v2, 0xffffffffL

    .line 27
    .line 28
    .line 29
    .line 30
    .line 31
    and-long/2addr v0, v2

    .line 32
    long-to-int v0, v0

    .line 33
    invoke-static {v0}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 34
    .line 35
    .line 36
    move-result v0

    .line 37
    invoke-static {v0}, Ljava/lang/Math;->round(F)I

    .line 38
    .line 39
    .line 40
    move-result v0

    .line 41
    invoke-virtual {p0}, Landroid/view/View;->getMeasuredWidth()I

    .line 42
    .line 43
    .line 44
    move-result v1

    .line 45
    add-int/2addr v1, p1

    .line 46
    invoke-virtual {p0}, Landroid/view/View;->getMeasuredHeight()I

    .line 47
    .line 48
    .line 49
    move-result v2

    .line 50
    add-int/2addr v2, v0

    .line 51
    invoke-virtual {p0, p1, v0, v1, v2}, Landroid/view/View;->layout(IIII)V

    .line 52
    .line 53
    .line 54
    return-void
.end method
