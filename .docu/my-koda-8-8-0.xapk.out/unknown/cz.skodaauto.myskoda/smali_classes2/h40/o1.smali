.class public final Lh40/o1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lql0/h;


# instance fields
.field public final a:Lql0/g;

.field public final b:Z

.field public final c:Z

.field public final d:Z

.field public final e:Ljava/util/List;


# direct methods
.method public constructor <init>(Lql0/g;ZZZLjava/util/List;)V
    .locals 1

    .line 1
    const-string v0, "transactionsPerYear"

    .line 2
    .line 3
    invoke-static {p5, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 7
    .line 8
    .line 9
    iput-object p1, p0, Lh40/o1;->a:Lql0/g;

    .line 10
    .line 11
    iput-boolean p2, p0, Lh40/o1;->b:Z

    .line 12
    .line 13
    iput-boolean p3, p0, Lh40/o1;->c:Z

    .line 14
    .line 15
    iput-boolean p4, p0, Lh40/o1;->d:Z

    .line 16
    .line 17
    iput-object p5, p0, Lh40/o1;->e:Ljava/util/List;

    .line 18
    .line 19
    return-void
.end method

.method public static a(Lh40/o1;Lql0/g;ZZZLjava/util/ArrayList;I)Lh40/o1;
    .locals 6

    .line 1
    and-int/lit8 v0, p6, 0x1

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    iget-object p1, p0, Lh40/o1;->a:Lql0/g;

    .line 6
    .line 7
    :cond_0
    move-object v1, p1

    .line 8
    and-int/lit8 p1, p6, 0x2

    .line 9
    .line 10
    if-eqz p1, :cond_1

    .line 11
    .line 12
    iget-boolean p2, p0, Lh40/o1;->b:Z

    .line 13
    .line 14
    :cond_1
    move v2, p2

    .line 15
    and-int/lit8 p1, p6, 0x4

    .line 16
    .line 17
    if-eqz p1, :cond_2

    .line 18
    .line 19
    iget-boolean p3, p0, Lh40/o1;->c:Z

    .line 20
    .line 21
    :cond_2
    move v3, p3

    .line 22
    and-int/lit8 p1, p6, 0x8

    .line 23
    .line 24
    if-eqz p1, :cond_3

    .line 25
    .line 26
    iget-boolean p4, p0, Lh40/o1;->d:Z

    .line 27
    .line 28
    :cond_3
    move v4, p4

    .line 29
    and-int/lit8 p1, p6, 0x10

    .line 30
    .line 31
    if-eqz p1, :cond_4

    .line 32
    .line 33
    iget-object p5, p0, Lh40/o1;->e:Ljava/util/List;

    .line 34
    .line 35
    :cond_4
    move-object v5, p5

    .line 36
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 37
    .line 38
    .line 39
    const-string p0, "transactionsPerYear"

    .line 40
    .line 41
    invoke-static {v5, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 42
    .line 43
    .line 44
    new-instance v0, Lh40/o1;

    .line 45
    .line 46
    invoke-direct/range {v0 .. v5}, Lh40/o1;-><init>(Lql0/g;ZZZLjava/util/List;)V

    .line 47
    .line 48
    .line 49
    return-object v0
.end method


# virtual methods
.method public final equals(Ljava/lang/Object;)Z
    .locals 4

    .line 1
    const/4 v0, 0x1

    .line 2
    if-ne p0, p1, :cond_0

    .line 3
    .line 4
    return v0

    .line 5
    :cond_0
    instance-of v1, p1, Lh40/o1;

    .line 6
    .line 7
    const/4 v2, 0x0

    .line 8
    if-nez v1, :cond_1

    .line 9
    .line 10
    return v2

    .line 11
    :cond_1
    check-cast p1, Lh40/o1;

    .line 12
    .line 13
    iget-object v1, p0, Lh40/o1;->a:Lql0/g;

    .line 14
    .line 15
    iget-object v3, p1, Lh40/o1;->a:Lql0/g;

    .line 16
    .line 17
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 18
    .line 19
    .line 20
    move-result v1

    .line 21
    if-nez v1, :cond_2

    .line 22
    .line 23
    return v2

    .line 24
    :cond_2
    iget-boolean v1, p0, Lh40/o1;->b:Z

    .line 25
    .line 26
    iget-boolean v3, p1, Lh40/o1;->b:Z

    .line 27
    .line 28
    if-eq v1, v3, :cond_3

    .line 29
    .line 30
    return v2

    .line 31
    :cond_3
    iget-boolean v1, p0, Lh40/o1;->c:Z

    .line 32
    .line 33
    iget-boolean v3, p1, Lh40/o1;->c:Z

    .line 34
    .line 35
    if-eq v1, v3, :cond_4

    .line 36
    .line 37
    return v2

    .line 38
    :cond_4
    iget-boolean v1, p0, Lh40/o1;->d:Z

    .line 39
    .line 40
    iget-boolean v3, p1, Lh40/o1;->d:Z

    .line 41
    .line 42
    if-eq v1, v3, :cond_5

    .line 43
    .line 44
    return v2

    .line 45
    :cond_5
    iget-object p0, p0, Lh40/o1;->e:Ljava/util/List;

    .line 46
    .line 47
    iget-object p1, p1, Lh40/o1;->e:Ljava/util/List;

    .line 48
    .line 49
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 50
    .line 51
    .line 52
    move-result p0

    .line 53
    if-nez p0, :cond_6

    .line 54
    .line 55
    return v2

    .line 56
    :cond_6
    return v0
.end method

.method public final hashCode()I
    .locals 3

    .line 1
    iget-object v0, p0, Lh40/o1;->a:Lql0/g;

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    const/4 v0, 0x0

    .line 6
    goto :goto_0

    .line 7
    :cond_0
    invoke-virtual {v0}, Lql0/g;->hashCode()I

    .line 8
    .line 9
    .line 10
    move-result v0

    .line 11
    :goto_0
    const/16 v1, 0x1f

    .line 12
    .line 13
    mul-int/2addr v0, v1

    .line 14
    iget-boolean v2, p0, Lh40/o1;->b:Z

    .line 15
    .line 16
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 17
    .line 18
    .line 19
    move-result v0

    .line 20
    iget-boolean v2, p0, Lh40/o1;->c:Z

    .line 21
    .line 22
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 23
    .line 24
    .line 25
    move-result v0

    .line 26
    iget-boolean v2, p0, Lh40/o1;->d:Z

    .line 27
    .line 28
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 29
    .line 30
    .line 31
    move-result v0

    .line 32
    iget-object p0, p0, Lh40/o1;->e:Ljava/util/List;

    .line 33
    .line 34
    invoke-virtual {p0}, Ljava/lang/Object;->hashCode()I

    .line 35
    .line 36
    .line 37
    move-result p0

    .line 38
    add-int/2addr p0, v0

    .line 39
    return p0
.end method

.method public final toString()Ljava/lang/String;
    .locals 5

    .line 1
    const-string v0, ", isLoading="

    .line 2
    .line 3
    const-string v1, ", isRefreshing="

    .line 4
    .line 5
    const-string v2, "State(error="

    .line 6
    .line 7
    iget-object v3, p0, Lh40/o1;->a:Lql0/g;

    .line 8
    .line 9
    iget-boolean v4, p0, Lh40/o1;->b:Z

    .line 10
    .line 11
    invoke-static {v2, v3, v0, v4, v1}, Lp3/m;->s(Ljava/lang/String;Lql0/g;Ljava/lang/String;ZLjava/lang/String;)Ljava/lang/StringBuilder;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    const-string v1, ", isDataUnavailable="

    .line 16
    .line 17
    const-string v2, ", transactionsPerYear="

    .line 18
    .line 19
    iget-boolean v3, p0, Lh40/o1;->c:Z

    .line 20
    .line 21
    iget-boolean v4, p0, Lh40/o1;->d:Z

    .line 22
    .line 23
    invoke-static {v0, v3, v1, v4, v2}, Lkx/a;->y(Ljava/lang/StringBuilder;ZLjava/lang/String;ZLjava/lang/String;)V

    .line 24
    .line 25
    .line 26
    const-string v1, ")"

    .line 27
    .line 28
    iget-object p0, p0, Lh40/o1;->e:Ljava/util/List;

    .line 29
    .line 30
    invoke-static {v0, p0, v1}, Lu/w;->i(Ljava/lang/StringBuilder;Ljava/util/List;Ljava/lang/String;)Ljava/lang/String;

    .line 31
    .line 32
    .line 33
    move-result-object p0

    .line 34
    return-object p0
.end method
