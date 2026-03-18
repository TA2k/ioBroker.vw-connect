.class public abstract Lw71/d;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:D

.field public static final synthetic b:I


# direct methods
.method static constructor <clinit>()V
    .locals 4

    .line 1
    const-wide/high16 v0, 0x4024000000000000L    # 10.0

    .line 2
    .line 3
    const-wide/high16 v2, 0x4014000000000000L    # 5.0

    .line 4
    .line 5
    invoke-static {v0, v1, v2, v3}, Ljava/lang/Math;->pow(DD)D

    .line 6
    .line 7
    .line 8
    move-result-wide v0

    .line 9
    sput-wide v0, Lw71/d;->a:D

    .line 10
    .line 11
    return-void
.end method

.method public static final a(Lw71/c;Lw71/c;)D
    .locals 4

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "vector"

    .line 7
    .line 8
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    iget-wide v0, p0, Lw71/c;->a:D

    .line 12
    .line 13
    iget-wide v2, p1, Lw71/c;->a:D

    .line 14
    .line 15
    sub-double/2addr v0, v2

    .line 16
    iget-wide v2, p0, Lw71/c;->b:D

    .line 17
    .line 18
    iget-wide p0, p1, Lw71/c;->b:D

    .line 19
    .line 20
    sub-double/2addr v2, p0

    .line 21
    invoke-static {v0, v1, v2, v3}, Ljava/lang/Math;->hypot(DD)D

    .line 22
    .line 23
    .line 24
    move-result-wide p0

    .line 25
    return-wide p0
.end method

.method public static final b(Lw71/c;Lw71/c;)D
    .locals 6

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "vector"

    .line 7
    .line 8
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    iget-wide v0, p1, Lw71/c;->a:D

    .line 12
    .line 13
    iget-wide v2, p0, Lw71/c;->a:D

    .line 14
    .line 15
    sub-double/2addr v0, v2

    .line 16
    const/4 v2, 0x2

    .line 17
    int-to-double v2, v2

    .line 18
    invoke-static {v0, v1, v2, v3}, Ljava/lang/Math;->pow(DD)D

    .line 19
    .line 20
    .line 21
    move-result-wide v0

    .line 22
    iget-wide v4, p1, Lw71/c;->b:D

    .line 23
    .line 24
    iget-wide p0, p0, Lw71/c;->b:D

    .line 25
    .line 26
    sub-double/2addr v4, p0

    .line 27
    invoke-static {v4, v5, v2, v3}, Ljava/lang/Math;->pow(DD)D

    .line 28
    .line 29
    .line 30
    move-result-wide p0

    .line 31
    add-double/2addr p0, v0

    .line 32
    invoke-static {p0, p1}, Ljava/lang/Math;->sqrt(D)D

    .line 33
    .line 34
    .line 35
    move-result-wide p0

    .line 36
    return-wide p0
.end method

.method public static final c(DD)Lw71/c;
    .locals 3

    .line 1
    invoke-static {p0, p1}, Ljava/lang/Math;->cos(D)D

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    invoke-static {p0, p1}, Ljava/lang/Math;->sin(D)D

    .line 6
    .line 7
    .line 8
    move-result-wide p0

    .line 9
    new-instance v2, Lw71/c;

    .line 10
    .line 11
    mul-double/2addr v0, p2

    .line 12
    mul-double/2addr p0, p2

    .line 13
    invoke-direct {v2, v0, v1, p0, p1}, Lw71/c;-><init>(DD)V

    .line 14
    .line 15
    .line 16
    return-object v2
.end method

.method public static final d(Lw71/c;Lw71/c;)Z
    .locals 4

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "vector"

    .line 7
    .line 8
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    iget-wide v0, p0, Lw71/c;->a:D

    .line 12
    .line 13
    iget-wide v2, p1, Lw71/c;->a:D

    .line 14
    .line 15
    sub-double/2addr v0, v2

    .line 16
    invoke-static {v0, v1}, Ljava/lang/Math;->abs(D)D

    .line 17
    .line 18
    .line 19
    move-result-wide v0

    .line 20
    const-wide v2, 0x3eb0c6f7a0b5ed8dL    # 1.0E-6

    .line 21
    .line 22
    .line 23
    .line 24
    .line 25
    cmpg-double v0, v0, v2

    .line 26
    .line 27
    if-gez v0, :cond_0

    .line 28
    .line 29
    iget-wide v0, p0, Lw71/c;->b:D

    .line 30
    .line 31
    iget-wide p0, p1, Lw71/c;->b:D

    .line 32
    .line 33
    sub-double/2addr v0, p0

    .line 34
    invoke-static {v0, v1}, Ljava/lang/Math;->abs(D)D

    .line 35
    .line 36
    .line 37
    move-result-wide p0

    .line 38
    cmpg-double p0, p0, v2

    .line 39
    .line 40
    if-gez p0, :cond_0

    .line 41
    .line 42
    const/4 p0, 0x1

    .line 43
    return p0

    .line 44
    :cond_0
    const/4 p0, 0x0

    .line 45
    return p0
.end method

.method public static final e(Lw71/c;Ljava/util/Collection;D)Z
    .locals 9

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    mul-double v0, p2, p2

    .line 7
    .line 8
    invoke-interface {p1}, Ljava/util/Collection;->iterator()Ljava/util/Iterator;

    .line 9
    .line 10
    .line 11
    move-result-object p1

    .line 12
    :cond_0
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    .line 13
    .line 14
    .line 15
    move-result v2

    .line 16
    if-eqz v2, :cond_1

    .line 17
    .line 18
    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object v2

    .line 22
    check-cast v2, Lw71/c;

    .line 23
    .line 24
    iget-wide v3, p0, Lw71/c;->a:D

    .line 25
    .line 26
    iget-wide v5, v2, Lw71/c;->a:D

    .line 27
    .line 28
    sub-double/2addr v3, v5

    .line 29
    invoke-static {v3, v4}, Ljava/lang/Math;->abs(D)D

    .line 30
    .line 31
    .line 32
    move-result-wide v5

    .line 33
    cmpl-double v5, v5, p2

    .line 34
    .line 35
    if-gtz v5, :cond_0

    .line 36
    .line 37
    iget-wide v5, p0, Lw71/c;->b:D

    .line 38
    .line 39
    iget-wide v7, v2, Lw71/c;->b:D

    .line 40
    .line 41
    sub-double/2addr v5, v7

    .line 42
    invoke-static {v5, v6}, Ljava/lang/Math;->abs(D)D

    .line 43
    .line 44
    .line 45
    move-result-wide v7

    .line 46
    cmpl-double v2, v7, p2

    .line 47
    .line 48
    if-gtz v2, :cond_0

    .line 49
    .line 50
    mul-double/2addr v3, v3

    .line 51
    mul-double/2addr v5, v5

    .line 52
    add-double/2addr v5, v3

    .line 53
    cmpg-double v2, v5, v0

    .line 54
    .line 55
    if-gez v2, :cond_0

    .line 56
    .line 57
    const/4 p0, 0x1

    .line 58
    return p0

    .line 59
    :cond_1
    const/4 p0, 0x0

    .line 60
    return p0
.end method

.method public static final f(Lw71/c;Lw71/c;)Lw71/c;
    .locals 5

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "v"

    .line 7
    .line 8
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    new-instance v0, Lw71/c;

    .line 12
    .line 13
    iget-wide v1, p0, Lw71/c;->a:D

    .line 14
    .line 15
    iget-wide v3, p1, Lw71/c;->a:D

    .line 16
    .line 17
    sub-double/2addr v1, v3

    .line 18
    iget-wide v3, p0, Lw71/c;->b:D

    .line 19
    .line 20
    iget-wide p0, p1, Lw71/c;->b:D

    .line 21
    .line 22
    sub-double/2addr v3, p0

    .line 23
    invoke-direct {v0, v1, v2, v3, v4}, Lw71/c;-><init>(DD)V

    .line 24
    .line 25
    .line 26
    return-object v0
.end method

.method public static final g(Lw71/c;)Lw71/c;
    .locals 8

    .line 1
    iget-wide v0, p0, Lw71/c;->a:D

    .line 2
    .line 3
    mul-double v2, v0, v0

    .line 4
    .line 5
    iget-wide v4, p0, Lw71/c;->b:D

    .line 6
    .line 7
    mul-double v6, v4, v4

    .line 8
    .line 9
    add-double/2addr v6, v2

    .line 10
    invoke-static {v6, v7}, Ljava/lang/Math;->sqrt(D)D

    .line 11
    .line 12
    .line 13
    move-result-wide v2

    .line 14
    const-wide/16 v6, 0x0

    .line 15
    .line 16
    cmpg-double p0, v2, v6

    .line 17
    .line 18
    if-nez p0, :cond_0

    .line 19
    .line 20
    const/4 p0, 0x0

    .line 21
    return-object p0

    .line 22
    :cond_0
    new-instance p0, Lw71/c;

    .line 23
    .line 24
    div-double/2addr v0, v2

    .line 25
    div-double/2addr v4, v2

    .line 26
    invoke-direct {p0, v0, v1, v4, v5}, Lw71/c;-><init>(DD)V

    .line 27
    .line 28
    .line 29
    return-object p0
.end method

.method public static final h(Lw71/c;Lw71/c;)Lw71/c;
    .locals 5

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "v"

    .line 7
    .line 8
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    new-instance v0, Lw71/c;

    .line 12
    .line 13
    iget-wide v1, p0, Lw71/c;->a:D

    .line 14
    .line 15
    iget-wide v3, p1, Lw71/c;->a:D

    .line 16
    .line 17
    add-double/2addr v1, v3

    .line 18
    iget-wide v3, p0, Lw71/c;->b:D

    .line 19
    .line 20
    iget-wide p0, p1, Lw71/c;->b:D

    .line 21
    .line 22
    add-double/2addr v3, p0

    .line 23
    invoke-direct {v0, v1, v2, v3, v4}, Lw71/c;-><init>(DD)V

    .line 24
    .line 25
    .line 26
    return-object v0
.end method

.method public static final i(Lw71/c;I)Lw71/c;
    .locals 5

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    new-instance v0, Lw71/c;

    .line 7
    .line 8
    iget-wide v1, p0, Lw71/c;->a:D

    .line 9
    .line 10
    invoke-static {p1, v1, v2}, Llp/yc;->a(ID)D

    .line 11
    .line 12
    .line 13
    move-result-wide v1

    .line 14
    iget-wide v3, p0, Lw71/c;->b:D

    .line 15
    .line 16
    invoke-static {p1, v3, v4}, Llp/yc;->a(ID)D

    .line 17
    .line 18
    .line 19
    move-result-wide p0

    .line 20
    invoke-direct {v0, v1, v2, p0, p1}, Lw71/c;-><init>(DD)V

    .line 21
    .line 22
    .line 23
    return-object v0
.end method

.method public static final j(Lw71/c;D)Lw71/c;
    .locals 5

    .line 1
    new-instance v0, Lw71/c;

    .line 2
    .line 3
    iget-wide v1, p0, Lw71/c;->a:D

    .line 4
    .line 5
    mul-double/2addr v1, p1

    .line 6
    iget-wide v3, p0, Lw71/c;->b:D

    .line 7
    .line 8
    mul-double/2addr v3, p1

    .line 9
    invoke-direct {v0, v1, v2, v3, v4}, Lw71/c;-><init>(DD)V

    .line 10
    .line 11
    .line 12
    return-object v0
.end method
