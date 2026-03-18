.class public final synthetic Lnw/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/q;


# instance fields
.field public final synthetic d:Lnw/g;

.field public final synthetic e:Lnw/e;

.field public final synthetic f:Lc1/h2;

.field public final synthetic g:Lkotlin/jvm/internal/c0;

.field public final synthetic h:Lkotlin/jvm/internal/c0;


# direct methods
.method public synthetic constructor <init>(Lnw/g;Lnw/e;Lc1/h2;Lkotlin/jvm/internal/c0;Lkotlin/jvm/internal/c0;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lnw/b;->d:Lnw/g;

    .line 5
    .line 6
    iput-object p2, p0, Lnw/b;->e:Lnw/e;

    .line 7
    .line 8
    iput-object p3, p0, Lnw/b;->f:Lc1/h2;

    .line 9
    .line 10
    iput-object p4, p0, Lnw/b;->g:Lkotlin/jvm/internal/c0;

    .line 11
    .line 12
    iput-object p5, p0, Lnw/b;->h:Lkotlin/jvm/internal/c0;

    .line 13
    .line 14
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 7

    .line 1
    check-cast p1, Lmw/i;

    .line 2
    .line 3
    check-cast p2, Ljava/lang/Float;

    .line 4
    .line 5
    invoke-virtual {p2}, Ljava/lang/Float;->floatValue()F

    .line 6
    .line 7
    .line 8
    move-result v5

    .line 9
    check-cast p3, Ljava/lang/Float;

    .line 10
    .line 11
    invoke-virtual {p3}, Ljava/lang/Float;->floatValue()F

    .line 12
    .line 13
    .line 14
    move-result v4

    .line 15
    check-cast p4, Ljava/lang/Float;

    .line 16
    .line 17
    check-cast p5, Ljava/lang/Float;

    .line 18
    .line 19
    const-string p2, "<unused var>"

    .line 20
    .line 21
    invoke-static {p1, p2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 22
    .line 23
    .line 24
    iget-object p1, p0, Lnw/b;->d:Lnw/g;

    .line 25
    .line 26
    iget-object v0, p1, Lnw/g;->h:Landroid/graphics/Path;

    .line 27
    .line 28
    invoke-virtual {v0}, Landroid/graphics/Path;->isEmpty()Z

    .line 29
    .line 30
    .line 31
    move-result p1

    .line 32
    iget-object p2, p0, Lnw/b;->g:Lkotlin/jvm/internal/c0;

    .line 33
    .line 34
    iget-object p3, p0, Lnw/b;->h:Lkotlin/jvm/internal/c0;

    .line 35
    .line 36
    if-eqz p1, :cond_0

    .line 37
    .line 38
    invoke-virtual {v0, v5, v4}, Landroid/graphics/Path;->moveTo(FF)V

    .line 39
    .line 40
    .line 41
    goto :goto_0

    .line 42
    :cond_0
    iget-object p1, p0, Lnw/b;->e:Lnw/e;

    .line 43
    .line 44
    iget-object p1, p1, Lnw/e;->c:Lnw/a;

    .line 45
    .line 46
    iget p4, p2, Lkotlin/jvm/internal/c0;->d:F

    .line 47
    .line 48
    iget v2, p3, Lkotlin/jvm/internal/c0;->d:F

    .line 49
    .line 50
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 51
    .line 52
    .line 53
    const-string p1, "context"

    .line 54
    .line 55
    iget-object p0, p0, Lnw/b;->f:Lc1/h2;

    .line 56
    .line 57
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 58
    .line 59
    .line 60
    const/4 p1, 0x4

    .line 61
    int-to-float p1, p1

    .line 62
    sub-float p5, v4, v2

    .line 63
    .line 64
    invoke-static {p5}, Ljava/lang/Math;->abs(F)F

    .line 65
    .line 66
    .line 67
    move-result p5

    .line 68
    mul-float/2addr p5, p1

    .line 69
    iget-object p0, p0, Lc1/h2;->c:Ljava/lang/Object;

    .line 70
    .line 71
    check-cast p0, Landroid/graphics/RectF;

    .line 72
    .line 73
    invoke-virtual {p0}, Landroid/graphics/RectF;->height()F

    .line 74
    .line 75
    .line 76
    move-result p0

    .line 77
    div-float/2addr p5, p0

    .line 78
    const/high16 p0, 0x3f800000    # 1.0f

    .line 79
    .line 80
    cmpl-float p1, p5, p0

    .line 81
    .line 82
    if-lez p1, :cond_1

    .line 83
    .line 84
    move p5, p0

    .line 85
    :cond_1
    const/high16 p0, 0x3f000000    # 0.5f

    .line 86
    .line 87
    mul-float/2addr p5, p0

    .line 88
    sub-float p0, v5, p4

    .line 89
    .line 90
    mul-float/2addr p0, p5

    .line 91
    add-float v1, p4, p0

    .line 92
    .line 93
    sub-float v3, v5, p0

    .line 94
    .line 95
    move v6, v4

    .line 96
    invoke-virtual/range {v0 .. v6}, Landroid/graphics/Path;->cubicTo(FFFFFF)V

    .line 97
    .line 98
    .line 99
    :goto_0
    iput v5, p2, Lkotlin/jvm/internal/c0;->d:F

    .line 100
    .line 101
    iput v4, p3, Lkotlin/jvm/internal/c0;->d:F

    .line 102
    .line 103
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 104
    .line 105
    return-object p0
.end method
