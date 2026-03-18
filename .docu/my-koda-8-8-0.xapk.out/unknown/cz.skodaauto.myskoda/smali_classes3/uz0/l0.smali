.class public final Luz0/l0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lhy0/a0;


# instance fields
.field public final d:Lhy0/a0;


# direct methods
.method public constructor <init>(Lhy0/a0;)V
    .locals 1

    .line 1
    const-string v0, "origin"

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
    iput-object p1, p0, Luz0/l0;->d:Lhy0/a0;

    .line 10
    .line 11
    return-void
.end method


# virtual methods
.method public final equals(Ljava/lang/Object;)Z
    .locals 3

    .line 1
    const/4 v0, 0x0

    .line 2
    if-nez p1, :cond_0

    .line 3
    .line 4
    return v0

    .line 5
    :cond_0
    instance-of v1, p1, Luz0/l0;

    .line 6
    .line 7
    const/4 v2, 0x0

    .line 8
    if-eqz v1, :cond_1

    .line 9
    .line 10
    move-object v1, p1

    .line 11
    check-cast v1, Luz0/l0;

    .line 12
    .line 13
    goto :goto_0

    .line 14
    :cond_1
    move-object v1, v2

    .line 15
    :goto_0
    if-eqz v1, :cond_2

    .line 16
    .line 17
    iget-object v1, v1, Luz0/l0;->d:Lhy0/a0;

    .line 18
    .line 19
    goto :goto_1

    .line 20
    :cond_2
    move-object v1, v2

    .line 21
    :goto_1
    iget-object p0, p0, Luz0/l0;->d:Lhy0/a0;

    .line 22
    .line 23
    invoke-static {p0, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 24
    .line 25
    .line 26
    move-result v1

    .line 27
    if-nez v1, :cond_3

    .line 28
    .line 29
    return v0

    .line 30
    :cond_3
    invoke-interface {p0}, Lhy0/a0;->getClassifier()Lhy0/e;

    .line 31
    .line 32
    .line 33
    move-result-object p0

    .line 34
    instance-of v1, p0, Lhy0/d;

    .line 35
    .line 36
    if-eqz v1, :cond_7

    .line 37
    .line 38
    instance-of v1, p1, Lhy0/a0;

    .line 39
    .line 40
    if-eqz v1, :cond_4

    .line 41
    .line 42
    check-cast p1, Lhy0/a0;

    .line 43
    .line 44
    goto :goto_2

    .line 45
    :cond_4
    move-object p1, v2

    .line 46
    :goto_2
    if-eqz p1, :cond_5

    .line 47
    .line 48
    invoke-interface {p1}, Lhy0/a0;->getClassifier()Lhy0/e;

    .line 49
    .line 50
    .line 51
    move-result-object v2

    .line 52
    :cond_5
    if-eqz v2, :cond_7

    .line 53
    .line 54
    instance-of p1, v2, Lhy0/d;

    .line 55
    .line 56
    if-nez p1, :cond_6

    .line 57
    .line 58
    goto :goto_3

    .line 59
    :cond_6
    check-cast p0, Lhy0/d;

    .line 60
    .line 61
    invoke-static {p0}, Ljp/p1;->c(Lhy0/d;)Ljava/lang/Class;

    .line 62
    .line 63
    .line 64
    move-result-object p0

    .line 65
    check-cast v2, Lhy0/d;

    .line 66
    .line 67
    invoke-static {v2}, Ljp/p1;->c(Lhy0/d;)Ljava/lang/Class;

    .line 68
    .line 69
    .line 70
    move-result-object p1

    .line 71
    invoke-virtual {p0, p1}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 72
    .line 73
    .line 74
    move-result p0

    .line 75
    return p0

    .line 76
    :cond_7
    :goto_3
    return v0
.end method

.method public final getAnnotations()Ljava/util/List;
    .locals 0

    .line 1
    iget-object p0, p0, Luz0/l0;->d:Lhy0/a0;

    .line 2
    .line 3
    invoke-interface {p0}, Lhy0/b;->getAnnotations()Ljava/util/List;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public final getArguments()Ljava/util/List;
    .locals 0

    .line 1
    iget-object p0, p0, Luz0/l0;->d:Lhy0/a0;

    .line 2
    .line 3
    invoke-interface {p0}, Lhy0/a0;->getArguments()Ljava/util/List;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public final getClassifier()Lhy0/e;
    .locals 0

    .line 1
    iget-object p0, p0, Luz0/l0;->d:Lhy0/a0;

    .line 2
    .line 3
    invoke-interface {p0}, Lhy0/a0;->getClassifier()Lhy0/e;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public final hashCode()I
    .locals 0

    .line 1
    iget-object p0, p0, Luz0/l0;->d:Lhy0/a0;

    .line 2
    .line 3
    invoke-virtual {p0}, Ljava/lang/Object;->hashCode()I

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method

.method public final isMarkedNullable()Z
    .locals 0

    .line 1
    iget-object p0, p0, Luz0/l0;->d:Lhy0/a0;

    .line 2
    .line 3
    invoke-interface {p0}, Lhy0/a0;->isMarkedNullable()Z

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method

.method public final toString()Ljava/lang/String;
    .locals 2

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "KTypeWrapper: "

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    iget-object p0, p0, Luz0/l0;->d:Lhy0/a0;

    .line 9
    .line 10
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 11
    .line 12
    .line 13
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 14
    .line 15
    .line 16
    move-result-object p0

    .line 17
    return-object p0
.end method
