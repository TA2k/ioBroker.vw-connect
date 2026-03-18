.class public final Lsz0/m;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lsz0/g;


# instance fields
.field public final a:Ljava/lang/String;

.field public final b:Lsz0/g;


# direct methods
.method public constructor <init>(Ljava/lang/String;Lsz0/g;)V
    .locals 1

    .line 1
    const-string v0, "original"

    .line 2
    .line 3
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 7
    .line 8
    .line 9
    iput-object p1, p0, Lsz0/m;->a:Ljava/lang/String;

    .line 10
    .line 11
    iput-object p2, p0, Lsz0/m;->b:Lsz0/g;

    .line 12
    .line 13
    return-void
.end method


# virtual methods
.method public final b()Z
    .locals 0

    .line 1
    iget-object p0, p0, Lsz0/m;->b:Lsz0/g;

    .line 2
    .line 3
    invoke-interface {p0}, Lsz0/g;->b()Z

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method

.method public final c(Ljava/lang/String;)I
    .locals 1

    .line 1
    const-string v0, "name"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lsz0/m;->b:Lsz0/g;

    .line 7
    .line 8
    invoke-interface {p0, p1}, Lsz0/g;->c(Ljava/lang/String;)I

    .line 9
    .line 10
    .line 11
    move-result p0

    .line 12
    return p0
.end method

.method public final d()I
    .locals 0

    .line 1
    iget-object p0, p0, Lsz0/m;->b:Lsz0/g;

    .line 2
    .line 3
    invoke-interface {p0}, Lsz0/g;->d()I

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method

.method public final e(I)Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lsz0/m;->b:Lsz0/g;

    .line 2
    .line 3
    invoke-interface {p0, p1}, Lsz0/g;->e(I)Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

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
    instance-of v1, p1, Lsz0/m;

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
    check-cast p1, Lsz0/m;

    .line 12
    .line 13
    iget-object v1, p1, Lsz0/m;->a:Ljava/lang/String;

    .line 14
    .line 15
    iget-object v3, p0, Lsz0/m;->a:Ljava/lang/String;

    .line 16
    .line 17
    invoke-static {v3, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 18
    .line 19
    .line 20
    move-result v1

    .line 21
    if-eqz v1, :cond_2

    .line 22
    .line 23
    iget-object p0, p0, Lsz0/m;->b:Lsz0/g;

    .line 24
    .line 25
    iget-object p1, p1, Lsz0/m;->b:Lsz0/g;

    .line 26
    .line 27
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 28
    .line 29
    .line 30
    move-result p0

    .line 31
    if-eqz p0, :cond_2

    .line 32
    .line 33
    return v0

    .line 34
    :cond_2
    return v2
.end method

.method public final f(I)Ljava/util/List;
    .locals 0

    .line 1
    iget-object p0, p0, Lsz0/m;->b:Lsz0/g;

    .line 2
    .line 3
    invoke-interface {p0, p1}, Lsz0/g;->f(I)Ljava/util/List;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public final g(I)Lsz0/g;
    .locals 0

    .line 1
    iget-object p0, p0, Lsz0/m;->b:Lsz0/g;

    .line 2
    .line 3
    invoke-interface {p0, p1}, Lsz0/g;->g(I)Lsz0/g;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public final getAnnotations()Ljava/util/List;
    .locals 0

    .line 1
    iget-object p0, p0, Lsz0/m;->b:Lsz0/g;

    .line 2
    .line 3
    invoke-interface {p0}, Lsz0/g;->getAnnotations()Ljava/util/List;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public final getKind()Lkp/y8;
    .locals 0

    .line 1
    iget-object p0, p0, Lsz0/m;->b:Lsz0/g;

    .line 2
    .line 3
    invoke-interface {p0}, Lsz0/g;->getKind()Lkp/y8;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public final h()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lsz0/m;->a:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final hashCode()I
    .locals 1

    .line 1
    iget-object v0, p0, Lsz0/m;->a:Ljava/lang/String;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/String;->hashCode()I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    mul-int/lit8 v0, v0, 0x1f

    .line 8
    .line 9
    iget-object p0, p0, Lsz0/m;->b:Lsz0/g;

    .line 10
    .line 11
    invoke-virtual {p0}, Ljava/lang/Object;->hashCode()I

    .line 12
    .line 13
    .line 14
    move-result p0

    .line 15
    add-int/2addr p0, v0

    .line 16
    return p0
.end method

.method public final i(I)Z
    .locals 0

    .line 1
    iget-object p0, p0, Lsz0/m;->b:Lsz0/g;

    .line 2
    .line 3
    invoke-interface {p0, p1}, Lsz0/g;->i(I)Z

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method

.method public final isInline()Z
    .locals 0

    .line 1
    iget-object p0, p0, Lsz0/m;->b:Lsz0/g;

    .line 2
    .line 3
    invoke-interface {p0}, Lsz0/g;->isInline()Z

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method

.method public final toString()Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p0}, Luz0/b1;->n(Lsz0/g;)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method
