.class public final Ljz0/s;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljz0/n;


# instance fields
.field public final a:Ljz0/c;

.field public final b:Ljava/util/Set;


# direct methods
.method public constructor <init>(Ljz0/c;)V
    .locals 3

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Ljz0/s;->a:Ljz0/c;

    .line 5
    .line 6
    invoke-static {}, Ljp/k1;->f()Lnx0/c;

    .line 7
    .line 8
    .line 9
    move-result-object v0

    .line 10
    invoke-static {v0, p1}, Llp/uc;->a(Lnx0/c;Ljz0/k;)V

    .line 11
    .line 12
    .line 13
    invoke-static {v0}, Ljp/k1;->d(Ljava/util/List;)Lnx0/c;

    .line 14
    .line 15
    .line 16
    move-result-object p1

    .line 17
    new-instance v0, Ljava/util/ArrayList;

    .line 18
    .line 19
    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    .line 20
    .line 21
    .line 22
    const/4 v1, 0x0

    .line 23
    invoke-virtual {p1, v1}, Lnx0/c;->listIterator(I)Ljava/util/ListIterator;

    .line 24
    .line 25
    .line 26
    move-result-object p1

    .line 27
    :cond_0
    :goto_0
    move-object v1, p1

    .line 28
    check-cast v1, Lnx0/a;

    .line 29
    .line 30
    invoke-virtual {v1}, Lnx0/a;->hasNext()Z

    .line 31
    .line 32
    .line 33
    move-result v2

    .line 34
    if-eqz v2, :cond_1

    .line 35
    .line 36
    invoke-virtual {v1}, Lnx0/a;->next()Ljava/lang/Object;

    .line 37
    .line 38
    .line 39
    move-result-object v1

    .line 40
    check-cast v1, Ljz0/j;

    .line 41
    .line 42
    invoke-interface {v1}, Ljz0/j;->c()Ljz0/a;

    .line 43
    .line 44
    .line 45
    move-result-object v1

    .line 46
    invoke-virtual {v1}, Ljz0/a;->d()Lhz0/d1;

    .line 47
    .line 48
    .line 49
    move-result-object v1

    .line 50
    if-eqz v1, :cond_0

    .line 51
    .line 52
    invoke-virtual {v0, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 53
    .line 54
    .line 55
    goto :goto_0

    .line 56
    :cond_1
    invoke-static {v0}, Lmx0/q;->C0(Ljava/lang/Iterable;)Ljava/util/Set;

    .line 57
    .line 58
    .line 59
    move-result-object p1

    .line 60
    iput-object p1, p0, Ljz0/s;->b:Ljava/util/Set;

    .line 61
    .line 62
    check-cast p1, Ljava/util/Collection;

    .line 63
    .line 64
    invoke-interface {p1}, Ljava/util/Collection;->isEmpty()Z

    .line 65
    .line 66
    .line 67
    move-result p0

    .line 68
    if-nez p0, :cond_2

    .line 69
    .line 70
    return-void

    .line 71
    :cond_2
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 72
    .line 73
    const-string p1, "Signed format must contain at least one field with a sign"

    .line 74
    .line 75
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 76
    .line 77
    .line 78
    throw p0
.end method


# virtual methods
.method public final a()Lkz0/c;
    .locals 1

    .line 1
    iget-object p0, p0, Ljz0/s;->a:Ljz0/c;

    .line 2
    .line 3
    iget-object p0, p0, Ljz0/c;->a:Ljz0/j;

    .line 4
    .line 5
    invoke-interface {p0}, Ljz0/j;->a()Lkz0/c;

    .line 6
    .line 7
    .line 8
    new-instance p0, Lkz0/a;

    .line 9
    .line 10
    new-instance v0, Lio/ktor/utils/io/g0;

    .line 11
    .line 12
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 13
    .line 14
    .line 15
    return-object p0
.end method

.method public final b()Llz0/n;
    .locals 5

    .line 1
    new-instance v0, Llz0/n;

    .line 2
    .line 3
    new-instance v1, Llz0/q;

    .line 4
    .line 5
    new-instance v2, Lh2/y5;

    .line 6
    .line 7
    const/16 v3, 0x13

    .line 8
    .line 9
    invoke-direct {v2, p0, v3}, Lh2/y5;-><init>(Ljava/lang/Object;I)V

    .line 10
    .line 11
    .line 12
    new-instance v3, Ljava/lang/StringBuilder;

    .line 13
    .line 14
    const-string v4, "sign for "

    .line 15
    .line 16
    invoke-direct {v3, v4}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 17
    .line 18
    .line 19
    iget-object v4, p0, Ljz0/s;->b:Ljava/util/Set;

    .line 20
    .line 21
    invoke-virtual {v3, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 22
    .line 23
    .line 24
    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 25
    .line 26
    .line 27
    move-result-object v3

    .line 28
    invoke-direct {v1, v2, v3}, Llz0/q;-><init>(Lh2/y5;Ljava/lang/String;)V

    .line 29
    .line 30
    .line 31
    invoke-static {v1}, Ljp/k1;->i(Ljava/lang/Object;)Ljava/util/List;

    .line 32
    .line 33
    .line 34
    move-result-object v1

    .line 35
    sget-object v2, Lmx0/s;->d:Lmx0/s;

    .line 36
    .line 37
    invoke-direct {v0, v1, v2}, Llz0/n;-><init>(Ljava/util/List;Ljava/util/List;)V

    .line 38
    .line 39
    .line 40
    iget-object p0, p0, Ljz0/s;->a:Ljz0/c;

    .line 41
    .line 42
    iget-object p0, p0, Ljz0/c;->a:Ljz0/j;

    .line 43
    .line 44
    invoke-interface {p0}, Ljz0/j;->b()Llz0/n;

    .line 45
    .line 46
    .line 47
    move-result-object p0

    .line 48
    filled-new-array {v0, p0}, [Llz0/n;

    .line 49
    .line 50
    .line 51
    move-result-object p0

    .line 52
    invoke-static {p0}, Ljp/k1;->j([Ljava/lang/Object;)Ljava/util/List;

    .line 53
    .line 54
    .line 55
    move-result-object p0

    .line 56
    invoke-static {p0}, Lvo/a;->b(Ljava/util/List;)Llz0/n;

    .line 57
    .line 58
    .line 59
    move-result-object p0

    .line 60
    return-object p0
.end method

.method public final equals(Ljava/lang/Object;)Z
    .locals 1

    .line 1
    instance-of v0, p1, Ljz0/s;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    check-cast p1, Ljz0/s;

    .line 6
    .line 7
    iget-object p1, p1, Ljz0/s;->a:Ljz0/c;

    .line 8
    .line 9
    iget-object p0, p0, Ljz0/s;->a:Ljz0/c;

    .line 10
    .line 11
    invoke-virtual {p0, p1}, Ljz0/c;->equals(Ljava/lang/Object;)Z

    .line 12
    .line 13
    .line 14
    move-result p0

    .line 15
    if-eqz p0, :cond_0

    .line 16
    .line 17
    const/4 p0, 0x1

    .line 18
    return p0

    .line 19
    :cond_0
    const/4 p0, 0x0

    .line 20
    return p0
.end method

.method public final hashCode()I
    .locals 1

    .line 1
    iget-object p0, p0, Ljz0/s;->a:Ljz0/c;

    .line 2
    .line 3
    iget-object p0, p0, Ljz0/c;->a:Ljz0/j;

    .line 4
    .line 5
    invoke-virtual {p0}, Ljava/lang/Object;->hashCode()I

    .line 6
    .line 7
    .line 8
    move-result p0

    .line 9
    mul-int/lit8 p0, p0, 0x1f

    .line 10
    .line 11
    const/4 v0, 0x1

    .line 12
    invoke-static {v0}, Ljava/lang/Boolean;->hashCode(Z)I

    .line 13
    .line 14
    .line 15
    move-result v0

    .line 16
    add-int/2addr v0, p0

    .line 17
    return v0
.end method

.method public final toString()Ljava/lang/String;
    .locals 2

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "SignedFormatStructure("

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    iget-object p0, p0, Ljz0/s;->a:Ljz0/c;

    .line 9
    .line 10
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 11
    .line 12
    .line 13
    const/16 p0, 0x29

    .line 14
    .line 15
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 16
    .line 17
    .line 18
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0
.end method
