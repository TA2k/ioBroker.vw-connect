.class public final Lin/t1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lin/l0;


# instance fields
.field public a:F

.field public b:F

.field public final c:Ljava/lang/Object;


# direct methods
.method public constructor <init>(FF)V
    .locals 11

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    iput p1, p0, Lin/t1;->a:F

    .line 3
    iput p2, p0, Lin/t1;->b:F

    .line 4
    new-instance v0, Ljava/util/ArrayList;

    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    const/16 v1, 0x8

    int-to-float v2, v1

    div-float v7, p1, v2

    const/16 p1, 0x1f

    int-to-float v2, p1

    div-float v8, p2, v2

    const/4 p2, 0x0

    .line 5
    invoke-static {p2, v1}, Lkp/r9;->m(II)Lgy0/j;

    move-result-object v1

    .line 6
    invoke-virtual {v1}, Lgy0/h;->iterator()Ljava/util/Iterator;

    move-result-object v1

    :cond_0
    move-object v2, v1

    check-cast v2, Lgy0/i;

    .line 7
    iget-boolean v2, v2, Lgy0/i;->f:Z

    if-eqz v2, :cond_1

    .line 8
    move-object v2, v1

    check-cast v2, Lmx0/w;

    invoke-virtual {v2}, Lmx0/w;->nextInt()I

    move-result v4

    .line 9
    invoke-static {p2, p1}, Lkp/r9;->m(II)Lgy0/j;

    move-result-object v2

    .line 10
    invoke-virtual {v2}, Lgy0/h;->iterator()Ljava/util/Iterator;

    move-result-object v2

    :goto_0
    move-object v3, v2

    check-cast v3, Lgy0/i;

    .line 11
    iget-boolean v3, v3, Lgy0/i;->f:Z

    if-eqz v3, :cond_0

    .line 12
    move-object v3, v2

    check-cast v3, Lmx0/w;

    invoke-virtual {v3}, Lmx0/w;->nextInt()I

    move-result v5

    .line 13
    new-instance v3, Lu71/b;

    .line 14
    new-instance v6, Lu71/a;

    int-to-float v9, v4

    mul-float/2addr v9, v7

    int-to-float v10, v5

    mul-float/2addr v10, v8

    invoke-direct {v6, v9, v10}, Lu71/a;-><init>(FF)V

    .line 15
    invoke-direct/range {v3 .. v8}, Lu71/b;-><init>(IILu71/a;FF)V

    .line 16
    invoke-virtual {v0, v3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto :goto_0

    .line 17
    :cond_1
    iput-object v0, p0, Lin/t1;->c:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Li4/c;)V
    .locals 1

    .line 18
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 19
    new-instance v0, Landroid/graphics/Path;

    invoke-direct {v0}, Landroid/graphics/Path;-><init>()V

    iput-object v0, p0, Lin/t1;->c:Ljava/lang/Object;

    if-nez p1, :cond_0

    return-void

    .line 20
    :cond_0
    invoke-virtual {p1, p0}, Li4/c;->r(Lin/l0;)V

    return-void
.end method


# virtual methods
.method public a(FFFF)V
    .locals 1

    .line 1
    iget-object v0, p0, Lin/t1;->c:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Landroid/graphics/Path;

    .line 4
    .line 5
    invoke-virtual {v0, p1, p2, p3, p4}, Landroid/graphics/Path;->quadTo(FFFF)V

    .line 6
    .line 7
    .line 8
    iput p3, p0, Lin/t1;->a:F

    .line 9
    .line 10
    iput p4, p0, Lin/t1;->b:F

    .line 11
    .line 12
    return-void
.end method

.method public b(FF)V
    .locals 1

    .line 1
    iget-object v0, p0, Lin/t1;->c:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Landroid/graphics/Path;

    .line 4
    .line 5
    invoke-virtual {v0, p1, p2}, Landroid/graphics/Path;->moveTo(FF)V

    .line 6
    .line 7
    .line 8
    iput p1, p0, Lin/t1;->a:F

    .line 9
    .line 10
    iput p2, p0, Lin/t1;->b:F

    .line 11
    .line 12
    return-void
.end method

.method public c(FFFFFF)V
    .locals 8

    .line 1
    iget-object v0, p0, Lin/t1;->c:Ljava/lang/Object;

    .line 2
    .line 3
    move-object v1, v0

    .line 4
    check-cast v1, Landroid/graphics/Path;

    .line 5
    .line 6
    move v2, p1

    .line 7
    move v3, p2

    .line 8
    move v4, p3

    .line 9
    move v5, p4

    .line 10
    move v6, p5

    .line 11
    move v7, p6

    .line 12
    invoke-virtual/range {v1 .. v7}, Landroid/graphics/Path;->cubicTo(FFFFFF)V

    .line 13
    .line 14
    .line 15
    iput v6, p0, Lin/t1;->a:F

    .line 16
    .line 17
    iput v7, p0, Lin/t1;->b:F

    .line 18
    .line 19
    return-void
.end method

.method public close()V
    .locals 0

    .line 1
    iget-object p0, p0, Lin/t1;->c:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Landroid/graphics/Path;

    .line 4
    .line 5
    invoke-virtual {p0}, Landroid/graphics/Path;->close()V

    .line 6
    .line 7
    .line 8
    return-void
.end method

.method public d(FFFZZFF)V
    .locals 10

    .line 1
    iget v0, p0, Lin/t1;->a:F

    .line 2
    .line 3
    iget v1, p0, Lin/t1;->b:F

    .line 4
    .line 5
    move-object v9, p0

    .line 6
    move v2, p1

    .line 7
    move v3, p2

    .line 8
    move v4, p3

    .line 9
    move v5, p4

    .line 10
    move v6, p5

    .line 11
    move/from16 v7, p6

    .line 12
    .line 13
    move/from16 v8, p7

    .line 14
    .line 15
    invoke-static/range {v0 .. v9}, Lin/z1;->h(FFFFFZZFFLin/l0;)V

    .line 16
    .line 17
    .line 18
    iput v7, p0, Lin/t1;->a:F

    .line 19
    .line 20
    iput v8, p0, Lin/t1;->b:F

    .line 21
    .line 22
    return-void
.end method

.method public e(FF)V
    .locals 1

    .line 1
    iget-object v0, p0, Lin/t1;->c:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Landroid/graphics/Path;

    .line 4
    .line 5
    invoke-virtual {v0, p1, p2}, Landroid/graphics/Path;->lineTo(FF)V

    .line 6
    .line 7
    .line 8
    iput p1, p0, Lin/t1;->a:F

    .line 9
    .line 10
    iput p2, p0, Lin/t1;->b:F

    .line 11
    .line 12
    return-void
.end method
