.class public abstract Lb/v;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# virtual methods
.method public a(Lb/k0;Lb/k0;Landroid/view/Window;Landroid/view/View;ZZ)V
    .locals 0

    .line 1
    const-string p0, "statusBarStyle"

    .line 2
    .line 3
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string p0, "navigationBarStyle"

    .line 7
    .line 8
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    const-string p0, "window"

    .line 12
    .line 13
    invoke-static {p3, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    const-string p0, "view"

    .line 17
    .line 18
    invoke-static {p4, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 19
    .line 20
    .line 21
    const/4 p0, 0x0

    .line 22
    invoke-static {p3, p0}, Ljp/pf;->b(Landroid/view/Window;Z)V

    .line 23
    .line 24
    .line 25
    if-eqz p5, :cond_0

    .line 26
    .line 27
    iget p0, p1, Lb/k0;->b:I

    .line 28
    .line 29
    goto :goto_0

    .line 30
    :cond_0
    iget p0, p1, Lb/k0;->a:I

    .line 31
    .line 32
    :goto_0
    invoke-virtual {p3, p0}, Landroid/view/Window;->setStatusBarColor(I)V

    .line 33
    .line 34
    .line 35
    if-eqz p6, :cond_1

    .line 36
    .line 37
    iget p0, p2, Lb/k0;->b:I

    .line 38
    .line 39
    goto :goto_1

    .line 40
    :cond_1
    iget p0, p2, Lb/k0;->a:I

    .line 41
    .line 42
    :goto_1
    invoke-virtual {p3, p0}, Landroid/view/Window;->setNavigationBarColor(I)V

    .line 43
    .line 44
    .line 45
    new-instance p0, Laq/a;

    .line 46
    .line 47
    invoke-direct {p0, p4}, Laq/a;-><init>(Landroid/view/View;)V

    .line 48
    .line 49
    .line 50
    sget p1, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 51
    .line 52
    const/16 p2, 0x23

    .line 53
    .line 54
    if-lt p1, p2, :cond_2

    .line 55
    .line 56
    new-instance p1, Ld6/z1;

    .line 57
    .line 58
    invoke-direct {p1, p3, p0}, Ld6/y1;-><init>(Landroid/view/Window;Laq/a;)V

    .line 59
    .line 60
    .line 61
    goto :goto_2

    .line 62
    :cond_2
    const/16 p2, 0x1e

    .line 63
    .line 64
    if-lt p1, p2, :cond_3

    .line 65
    .line 66
    new-instance p1, Ld6/y1;

    .line 67
    .line 68
    invoke-direct {p1, p3, p0}, Ld6/y1;-><init>(Landroid/view/Window;Laq/a;)V

    .line 69
    .line 70
    .line 71
    goto :goto_2

    .line 72
    :cond_3
    new-instance p1, Ld6/x1;

    .line 73
    .line 74
    invoke-direct {p1, p3, p0}, Ld6/x1;-><init>(Landroid/view/Window;Laq/a;)V

    .line 75
    .line 76
    .line 77
    :goto_2
    xor-int/lit8 p0, p5, 0x1

    .line 78
    .line 79
    invoke-virtual {p1, p0}, Ljp/rf;->c(Z)V

    .line 80
    .line 81
    .line 82
    xor-int/lit8 p0, p6, 0x1

    .line 83
    .line 84
    invoke-virtual {p1, p0}, Ljp/rf;->b(Z)V

    .line 85
    .line 86
    .line 87
    return-void
.end method
