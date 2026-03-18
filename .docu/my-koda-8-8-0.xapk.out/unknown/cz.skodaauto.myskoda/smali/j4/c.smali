.class public final Lj4/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Landroid/text/style/LeadingMarginSpan;


# virtual methods
.method public final drawLeadingMargin(Landroid/graphics/Canvas;Landroid/graphics/Paint;IIIIILjava/lang/CharSequence;IIZLandroid/text/Layout;)V
    .locals 0

    .line 1
    if-eqz p12, :cond_1

    .line 2
    .line 3
    if-eqz p2, :cond_1

    .line 4
    .line 5
    invoke-virtual {p12, p9}, Landroid/text/Layout;->getLineForOffset(I)I

    .line 6
    .line 7
    .line 8
    move-result p0

    .line 9
    invoke-virtual {p12}, Landroid/text/Layout;->getLineCount()I

    .line 10
    .line 11
    .line 12
    move-result p3

    .line 13
    add-int/lit8 p3, p3, -0x1

    .line 14
    .line 15
    if-ne p0, p3, :cond_1

    .line 16
    .line 17
    sget-object p3, Lh4/k;->a:Lh4/i;

    .line 18
    .line 19
    invoke-virtual {p12, p0}, Landroid/text/Layout;->getEllipsisCount(I)I

    .line 20
    .line 21
    .line 22
    move-result p3

    .line 23
    if-lez p3, :cond_1

    .line 24
    .line 25
    invoke-static {p12, p0, p2}, Llp/kb;->a(Landroid/text/Layout;ILandroid/graphics/Paint;)F

    .line 26
    .line 27
    .line 28
    move-result p3

    .line 29
    invoke-static {p12, p0, p2}, Llp/kb;->b(Landroid/text/Layout;ILandroid/graphics/Paint;)F

    .line 30
    .line 31
    .line 32
    move-result p0

    .line 33
    add-float/2addr p0, p3

    .line 34
    const/4 p2, 0x0

    .line 35
    cmpg-float p3, p0, p2

    .line 36
    .line 37
    if-nez p3, :cond_0

    .line 38
    .line 39
    return-void

    .line 40
    :cond_0
    invoke-static {p1}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 41
    .line 42
    .line 43
    invoke-virtual {p1, p0, p2}, Landroid/graphics/Canvas;->translate(FF)V

    .line 44
    .line 45
    .line 46
    :cond_1
    return-void
.end method

.method public final getLeadingMargin(Z)I
    .locals 0

    .line 1
    const/4 p0, 0x0

    .line 2
    return p0
.end method
