.class public final Lda/g;
.super Llp/u0;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Lc2/k;

.field public b:I

.field public c:Ljava/lang/String;

.field public final d:Lwq/f;


# direct methods
.method public constructor <init>(Landroidx/lifecycle/s0;Ljava/util/LinkedHashMap;)V
    .locals 1

    .line 1
    const-string v0, "handle"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 7
    .line 8
    .line 9
    const/4 v0, -0x1

    .line 10
    iput v0, p0, Lda/g;->b:I

    .line 11
    .line 12
    const-string v0, ""

    .line 13
    .line 14
    iput-object v0, p0, Lda/g;->c:Ljava/lang/String;

    .line 15
    .line 16
    sget-object v0, Lxz0/a;->a:Lwq/f;

    .line 17
    .line 18
    iput-object v0, p0, Lda/g;->d:Lwq/f;

    .line 19
    .line 20
    new-instance v0, Lc2/k;

    .line 21
    .line 22
    invoke-direct {v0, p1, p2}, Lc2/k;-><init>(Landroidx/lifecycle/s0;Ljava/util/LinkedHashMap;)V

    .line 23
    .line 24
    .line 25
    iput-object v0, p0, Lda/g;->a:Lc2/k;

    .line 26
    .line 27
    return-void
.end method


# virtual methods
.method public final C(Lsz0/g;)Ltz0/c;
    .locals 1

    .line 1
    const-string v0, "descriptor"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-static {p1}, Lda/d;->f(Lsz0/g;)Z

    .line 7
    .line 8
    .line 9
    move-result v0

    .line 10
    if-eqz v0, :cond_0

    .line 11
    .line 12
    const/4 v0, 0x0

    .line 13
    invoke-interface {p1, v0}, Lsz0/g;->e(I)Ljava/lang/String;

    .line 14
    .line 15
    .line 16
    move-result-object p1

    .line 17
    iput-object p1, p0, Lda/g;->c:Ljava/lang/String;

    .line 18
    .line 19
    iput v0, p0, Lda/g;->b:I

    .line 20
    .line 21
    :cond_0
    return-object p0
.end method

.method public final E(Lsz0/g;)I
    .locals 4

    .line 1
    const-string v0, "descriptor"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget v0, p0, Lda/g;->b:I

    .line 7
    .line 8
    :cond_0
    add-int/lit8 v0, v0, 0x1

    .line 9
    .line 10
    invoke-interface {p1}, Lsz0/g;->d()I

    .line 11
    .line 12
    .line 13
    move-result v1

    .line 14
    if-lt v0, v1, :cond_1

    .line 15
    .line 16
    const/4 p0, -0x1

    .line 17
    return p0

    .line 18
    :cond_1
    invoke-interface {p1, v0}, Lsz0/g;->e(I)Ljava/lang/String;

    .line 19
    .line 20
    .line 21
    move-result-object v1

    .line 22
    iget-object v2, p0, Lda/g;->a:Lc2/k;

    .line 23
    .line 24
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 25
    .line 26
    .line 27
    const-string v3, "key"

    .line 28
    .line 29
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 30
    .line 31
    .line 32
    iget-object v2, v2, Lc2/k;->e:Ljava/lang/Object;

    .line 33
    .line 34
    check-cast v2, Landroidx/lifecycle/s0;

    .line 35
    .line 36
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 37
    .line 38
    .line 39
    iget-object v2, v2, Landroidx/lifecycle/s0;->b:Landroidx/lifecycle/c1;

    .line 40
    .line 41
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 42
    .line 43
    .line 44
    iget-object v2, v2, Landroidx/lifecycle/c1;->e:Ljava/lang/Object;

    .line 45
    .line 46
    check-cast v2, Ljava/util/LinkedHashMap;

    .line 47
    .line 48
    invoke-interface {v2, v1}, Ljava/util/Map;->containsKey(Ljava/lang/Object;)Z

    .line 49
    .line 50
    .line 51
    move-result v2

    .line 52
    if-eqz v2, :cond_0

    .line 53
    .line 54
    iput v0, p0, Lda/g;->b:I

    .line 55
    .line 56
    iput-object v1, p0, Lda/g;->c:Ljava/lang/String;

    .line 57
    .line 58
    return v0
.end method

.method public final G()Ljava/lang/Object;
    .locals 0

    .line 1
    invoke-virtual {p0}, Lda/g;->H()Ljava/lang/Object;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public final H()Ljava/lang/Object;
    .locals 2

    .line 1
    iget-object v0, p0, Lda/g;->a:Lc2/k;

    .line 2
    .line 3
    iget-object v1, p0, Lda/g;->c:Ljava/lang/String;

    .line 4
    .line 5
    invoke-virtual {v0, v1}, Lc2/k;->t(Ljava/lang/String;)Ljava/lang/Object;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    if-eqz v0, :cond_0

    .line 10
    .line 11
    return-object v0

    .line 12
    :cond_0
    new-instance v0, Ljava/lang/StringBuilder;

    .line 13
    .line 14
    const-string v1, "Unexpected null value for non-nullable argument "

    .line 15
    .line 16
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 17
    .line 18
    .line 19
    iget-object p0, p0, Lda/g;->c:Ljava/lang/String;

    .line 20
    .line 21
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 22
    .line 23
    .line 24
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 25
    .line 26
    .line 27
    move-result-object p0

    .line 28
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 29
    .line 30
    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 31
    .line 32
    .line 33
    move-result-object p0

    .line 34
    invoke-direct {v0, p0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 35
    .line 36
    .line 37
    throw v0
.end method

.method public final c()Lwq/f;
    .locals 0

    .line 1
    iget-object p0, p0, Lda/g;->d:Lwq/f;

    .line 2
    .line 3
    return-object p0
.end method

.method public final d(Lqz0/a;)Ljava/lang/Object;
    .locals 1

    .line 1
    const-string v0, "deserializer"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-virtual {p0}, Lda/g;->H()Ljava/lang/Object;

    .line 7
    .line 8
    .line 9
    move-result-object p0

    .line 10
    return-object p0
.end method

.method public final y()Z
    .locals 1

    .line 1
    iget-object v0, p0, Lda/g;->a:Lc2/k;

    .line 2
    .line 3
    iget-object p0, p0, Lda/g;->c:Ljava/lang/String;

    .line 4
    .line 5
    invoke-virtual {v0, p0}, Lc2/k;->t(Ljava/lang/String;)Ljava/lang/Object;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    if-eqz p0, :cond_0

    .line 10
    .line 11
    const/4 p0, 0x1

    .line 12
    return p0

    .line 13
    :cond_0
    const/4 p0, 0x0

    .line 14
    return p0
.end method
