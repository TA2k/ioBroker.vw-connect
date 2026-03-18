.class public final Lp1/g;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lo1/o;


# instance fields
.field public final a:Lp1/v;


# direct methods
.method public constructor <init>(Lp1/v;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lp1/g;->a:Lp1/v;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final a()I
    .locals 0

    .line 1
    iget-object p0, p0, Lp1/g;->a:Lp1/v;

    .line 2
    .line 3
    invoke-virtual {p0}, Lp1/v;->m()I

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method

.method public final b()I
    .locals 2

    .line 1
    iget-object p0, p0, Lp1/g;->a:Lp1/v;

    .line 2
    .line 3
    invoke-virtual {p0}, Lp1/v;->l()Lp1/o;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    iget-object v0, v0, Lp1/o;->a:Ljava/util/List;

    .line 8
    .line 9
    invoke-interface {v0}, Ljava/util/List;->size()I

    .line 10
    .line 11
    .line 12
    move-result v0

    .line 13
    if-nez v0, :cond_0

    .line 14
    .line 15
    const/4 p0, 0x0

    .line 16
    return p0

    .line 17
    :cond_0
    invoke-virtual {p0}, Lp1/v;->l()Lp1/o;

    .line 18
    .line 19
    .line 20
    move-result-object v0

    .line 21
    invoke-static {v0}, Ljp/bd;->b(Lp1/o;)I

    .line 22
    .line 23
    .line 24
    move-result v0

    .line 25
    invoke-virtual {p0}, Lp1/v;->l()Lp1/o;

    .line 26
    .line 27
    .line 28
    move-result-object v1

    .line 29
    iget v1, v1, Lp1/o;->b:I

    .line 30
    .line 31
    invoke-virtual {p0}, Lp1/v;->l()Lp1/o;

    .line 32
    .line 33
    .line 34
    move-result-object p0

    .line 35
    iget p0, p0, Lp1/o;->c:I

    .line 36
    .line 37
    add-int/2addr v1, p0

    .line 38
    const/4 p0, 0x1

    .line 39
    if-nez v1, :cond_1

    .line 40
    .line 41
    return p0

    .line 42
    :cond_1
    div-int/2addr v0, v1

    .line 43
    if-ge v0, p0, :cond_2

    .line 44
    .line 45
    return p0

    .line 46
    :cond_2
    return v0
.end method

.method public final c()Z
    .locals 0

    .line 1
    iget-object p0, p0, Lp1/g;->a:Lp1/v;

    .line 2
    .line 3
    invoke-virtual {p0}, Lp1/v;->l()Lp1/o;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    iget-object p0, p0, Lp1/o;->a:Ljava/util/List;

    .line 8
    .line 9
    check-cast p0, Ljava/util/Collection;

    .line 10
    .line 11
    invoke-interface {p0}, Ljava/util/Collection;->isEmpty()Z

    .line 12
    .line 13
    .line 14
    move-result p0

    .line 15
    xor-int/lit8 p0, p0, 0x1

    .line 16
    .line 17
    return p0
.end method

.method public final d()I
    .locals 1

    .line 1
    iget-object p0, p0, Lp1/g;->a:Lp1/v;

    .line 2
    .line 3
    iget p0, p0, Lp1/v;->e:I

    .line 4
    .line 5
    const/4 v0, 0x0

    .line 6
    invoke-static {v0, p0}, Ljava/lang/Math;->max(II)I

    .line 7
    .line 8
    .line 9
    move-result p0

    .line 10
    return p0
.end method

.method public final e()I
    .locals 1

    .line 1
    iget-object p0, p0, Lp1/g;->a:Lp1/v;

    .line 2
    .line 3
    invoke-virtual {p0}, Lp1/v;->m()I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    add-int/lit8 v0, v0, -0x1

    .line 8
    .line 9
    invoke-virtual {p0}, Lp1/v;->l()Lp1/o;

    .line 10
    .line 11
    .line 12
    move-result-object p0

    .line 13
    iget-object p0, p0, Lp1/o;->a:Ljava/util/List;

    .line 14
    .line 15
    invoke-static {p0}, Lmx0/q;->T(Ljava/util/List;)Ljava/lang/Object;

    .line 16
    .line 17
    .line 18
    move-result-object p0

    .line 19
    check-cast p0, Lp1/d;

    .line 20
    .line 21
    iget p0, p0, Lp1/d;->a:I

    .line 22
    .line 23
    invoke-static {v0, p0}, Ljava/lang/Math;->min(II)I

    .line 24
    .line 25
    .line 26
    move-result p0

    .line 27
    return p0
.end method
