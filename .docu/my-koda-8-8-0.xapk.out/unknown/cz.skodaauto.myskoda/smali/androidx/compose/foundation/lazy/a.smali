.class public final Landroidx/compose/foundation/lazy/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public a:Ll2/g1;

.field public b:Ll2/g1;


# direct methods
.method public static a(Landroidx/compose/foundation/lazy/a;Lx2/s;)Lx2/s;
    .locals 12

    .line 1
    const/4 v0, 0x0

    .line 2
    const/high16 v1, 0x43c80000    # 400.0f

    .line 3
    .line 4
    const/4 v2, 0x0

    .line 5
    const/4 v3, 0x5

    .line 6
    invoke-static {v0, v1, v2, v3}, Lc1/d;->t(FFLjava/lang/Object;I)Lc1/f1;

    .line 7
    .line 8
    .line 9
    move-result-object v4

    .line 10
    const/4 v5, 0x1

    .line 11
    int-to-long v6, v5

    .line 12
    const/16 v8, 0x20

    .line 13
    .line 14
    shl-long v8, v6, v8

    .line 15
    .line 16
    const-wide v10, 0xffffffffL

    .line 17
    .line 18
    .line 19
    .line 20
    .line 21
    and-long/2addr v6, v10

    .line 22
    or-long/2addr v6, v8

    .line 23
    new-instance v8, Lt4/j;

    .line 24
    .line 25
    invoke-direct {v8, v6, v7}, Lt4/j;-><init>(J)V

    .line 26
    .line 27
    .line 28
    invoke-static {v0, v1, v8, v5}, Lc1/d;->t(FFLjava/lang/Object;I)Lc1/f1;

    .line 29
    .line 30
    .line 31
    move-result-object v5

    .line 32
    invoke-static {v0, v1, v2, v3}, Lc1/d;->t(FFLjava/lang/Object;I)Lc1/f1;

    .line 33
    .line 34
    .line 35
    move-result-object v0

    .line 36
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 37
    .line 38
    .line 39
    new-instance p0, Landroidx/compose/foundation/lazy/layout/LazyLayoutAnimateItemElement;

    .line 40
    .line 41
    invoke-direct {p0, v4, v5, v0}, Landroidx/compose/foundation/lazy/layout/LazyLayoutAnimateItemElement;-><init>(Lc1/f1;Lc1/f1;Lc1/f1;)V

    .line 42
    .line 43
    .line 44
    invoke-interface {p1, p0}, Lx2/s;->g(Lx2/s;)Lx2/s;

    .line 45
    .line 46
    .line 47
    move-result-object p0

    .line 48
    return-object p0
.end method

.method public static c(Landroidx/compose/foundation/lazy/a;)Lx2/s;
    .locals 3

    .line 1
    iget-object v0, p0, Landroidx/compose/foundation/lazy/a;->a:Ll2/g1;

    .line 2
    .line 3
    iget-object p0, p0, Landroidx/compose/foundation/lazy/a;->b:Ll2/g1;

    .line 4
    .line 5
    new-instance v1, Landroidx/compose/foundation/lazy/ParentSizeElement;

    .line 6
    .line 7
    const/high16 v2, 0x3f800000    # 1.0f

    .line 8
    .line 9
    invoke-direct {v1, v2, v0, p0}, Landroidx/compose/foundation/lazy/ParentSizeElement;-><init>(FLl2/t2;Ll2/t2;)V

    .line 10
    .line 11
    .line 12
    return-object v1
.end method

.method public static d(Landroidx/compose/foundation/lazy/a;)Lx2/s;
    .locals 4

    .line 1
    iget-object p0, p0, Landroidx/compose/foundation/lazy/a;->a:Ll2/g1;

    .line 2
    .line 3
    new-instance v0, Landroidx/compose/foundation/lazy/ParentSizeElement;

    .line 4
    .line 5
    const/4 v1, 0x0

    .line 6
    const/4 v2, 0x4

    .line 7
    const/high16 v3, 0x3f800000    # 1.0f

    .line 8
    .line 9
    invoke-direct {v0, v3, p0, v1, v2}, Landroidx/compose/foundation/lazy/ParentSizeElement;-><init>(FLl2/g1;Ll2/g1;I)V

    .line 10
    .line 11
    .line 12
    return-object v0
.end method


# virtual methods
.method public final b(Lx2/s;F)Lx2/s;
    .locals 3

    .line 1
    iget-object p0, p0, Landroidx/compose/foundation/lazy/a;->b:Ll2/g1;

    .line 2
    .line 3
    new-instance v0, Landroidx/compose/foundation/lazy/ParentSizeElement;

    .line 4
    .line 5
    const/4 v1, 0x0

    .line 6
    const/4 v2, 0x2

    .line 7
    invoke-direct {v0, p2, v1, p0, v2}, Landroidx/compose/foundation/lazy/ParentSizeElement;-><init>(FLl2/g1;Ll2/g1;I)V

    .line 8
    .line 9
    .line 10
    invoke-interface {p1, v0}, Lx2/s;->g(Lx2/s;)Lx2/s;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    return-object p0
.end method
