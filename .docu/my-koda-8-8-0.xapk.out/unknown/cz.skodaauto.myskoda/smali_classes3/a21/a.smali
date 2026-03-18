.class public final La21/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Lh21/a;

.field public final b:Lhy0/d;

.field public final c:Lh21/a;

.field public final d:Lay0/n;

.field public final e:La21/c;

.field public f:Ljava/lang/Object;


# direct methods
.method public constructor <init>(Lh21/a;Lhy0/d;Lh21/b;Lay0/n;La21/c;)V
    .locals 1

    .line 1
    const-string v0, "scopeQualifier"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "primaryType"

    .line 7
    .line 8
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 12
    .line 13
    .line 14
    iput-object p1, p0, La21/a;->a:Lh21/a;

    .line 15
    .line 16
    iput-object p2, p0, La21/a;->b:Lhy0/d;

    .line 17
    .line 18
    iput-object p3, p0, La21/a;->c:Lh21/a;

    .line 19
    .line 20
    iput-object p4, p0, La21/a;->d:Lay0/n;

    .line 21
    .line 22
    iput-object p5, p0, La21/a;->e:La21/c;

    .line 23
    .line 24
    sget-object p1, Lmx0/s;->d:Lmx0/s;

    .line 25
    .line 26
    iput-object p1, p0, La21/a;->f:Ljava/lang/Object;

    .line 27
    .line 28
    return-void
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
    const-string v1, "null cannot be cast to non-null type org.koin.core.definition.BeanDefinition<*>"

    .line 6
    .line 7
    invoke-static {p1, v1}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 8
    .line 9
    .line 10
    check-cast p1, La21/a;

    .line 11
    .line 12
    iget-object v1, p0, La21/a;->b:Lhy0/d;

    .line 13
    .line 14
    iget-object v2, p1, La21/a;->b:Lhy0/d;

    .line 15
    .line 16
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 17
    .line 18
    .line 19
    move-result v1

    .line 20
    const/4 v2, 0x0

    .line 21
    if-nez v1, :cond_1

    .line 22
    .line 23
    return v2

    .line 24
    :cond_1
    iget-object v1, p0, La21/a;->c:Lh21/a;

    .line 25
    .line 26
    iget-object v3, p1, La21/a;->c:Lh21/a;

    .line 27
    .line 28
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 29
    .line 30
    .line 31
    move-result v1

    .line 32
    if-nez v1, :cond_2

    .line 33
    .line 34
    return v2

    .line 35
    :cond_2
    iget-object p0, p0, La21/a;->a:Lh21/a;

    .line 36
    .line 37
    iget-object p1, p1, La21/a;->a:Lh21/a;

    .line 38
    .line 39
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 40
    .line 41
    .line 42
    move-result p0

    .line 43
    if-nez p0, :cond_3

    .line 44
    .line 45
    return v2

    .line 46
    :cond_3
    return v0
.end method

.method public final hashCode()I
    .locals 2

    .line 1
    iget-object v0, p0, La21/a;->c:Lh21/a;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    invoke-virtual {v0}, Ljava/lang/Object;->hashCode()I

    .line 6
    .line 7
    .line 8
    move-result v0

    .line 9
    goto :goto_0

    .line 10
    :cond_0
    const/4 v0, 0x0

    .line 11
    :goto_0
    mul-int/lit8 v0, v0, 0x1f

    .line 12
    .line 13
    iget-object v1, p0, La21/a;->b:Lhy0/d;

    .line 14
    .line 15
    invoke-interface {v1}, Lhy0/d;->hashCode()I

    .line 16
    .line 17
    .line 18
    move-result v1

    .line 19
    add-int/2addr v1, v0

    .line 20
    mul-int/lit8 v1, v1, 0x1f

    .line 21
    .line 22
    iget-object p0, p0, La21/a;->a:Lh21/a;

    .line 23
    .line 24
    invoke-virtual {p0}, Ljava/lang/Object;->hashCode()I

    .line 25
    .line 26
    .line 27
    move-result p0

    .line 28
    add-int/2addr p0, v1

    .line 29
    return p0
.end method

.method public final toString()Ljava/lang/String;
    .locals 7

    .line 1
    new-instance v1, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    invoke-direct {v1}, Ljava/lang/StringBuilder;-><init>()V

    .line 4
    .line 5
    .line 6
    const/16 v0, 0x5b

    .line 7
    .line 8
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 9
    .line 10
    .line 11
    iget-object v0, p0, La21/a;->e:La21/c;

    .line 12
    .line 13
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 14
    .line 15
    .line 16
    const-string v0, ": \'"

    .line 17
    .line 18
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 19
    .line 20
    .line 21
    iget-object v0, p0, La21/a;->b:Lhy0/d;

    .line 22
    .line 23
    const/16 v2, 0x27

    .line 24
    .line 25
    invoke-static {v0, v1, v2}, Lia/b;->s(Lhy0/d;Ljava/lang/StringBuilder;C)V

    .line 26
    .line 27
    .line 28
    iget-object v0, p0, La21/a;->c:Lh21/a;

    .line 29
    .line 30
    if-eqz v0, :cond_0

    .line 31
    .line 32
    const-string v2, ",qualifier:"

    .line 33
    .line 34
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 35
    .line 36
    .line 37
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 38
    .line 39
    .line 40
    :cond_0
    sget-object v0, Li21/b;->e:Lh21/b;

    .line 41
    .line 42
    iget-object v2, p0, La21/a;->a:Lh21/a;

    .line 43
    .line 44
    invoke-static {v2, v0}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 45
    .line 46
    .line 47
    move-result v0

    .line 48
    if-nez v0, :cond_1

    .line 49
    .line 50
    const-string v0, ",scope:"

    .line 51
    .line 52
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 53
    .line 54
    .line 55
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 56
    .line 57
    .line 58
    :cond_1
    iget-object v0, p0, La21/a;->f:Ljava/lang/Object;

    .line 59
    .line 60
    check-cast v0, Ljava/util/Collection;

    .line 61
    .line 62
    invoke-interface {v0}, Ljava/util/Collection;->isEmpty()Z

    .line 63
    .line 64
    .line 65
    move-result v0

    .line 66
    if-nez v0, :cond_2

    .line 67
    .line 68
    const-string v0, ",binds:"

    .line 69
    .line 70
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 71
    .line 72
    .line 73
    iget-object p0, p0, La21/a;->f:Ljava/lang/Object;

    .line 74
    .line 75
    move-object v0, p0

    .line 76
    check-cast v0, Ljava/lang/Iterable;

    .line 77
    .line 78
    new-instance v5, La00/a;

    .line 79
    .line 80
    const/4 p0, 0x2

    .line 81
    invoke-direct {v5, p0}, La00/a;-><init>(I)V

    .line 82
    .line 83
    .line 84
    const/16 v6, 0x3c

    .line 85
    .line 86
    const-string v2, ","

    .line 87
    .line 88
    const/4 v3, 0x0

    .line 89
    const/4 v4, 0x0

    .line 90
    invoke-static/range {v0 .. v6}, Lmx0/q;->Q(Ljava/lang/Iterable;Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lay0/k;I)V

    .line 91
    .line 92
    .line 93
    :cond_2
    const/16 p0, 0x5d

    .line 94
    .line 95
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 96
    .line 97
    .line 98
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 99
    .line 100
    .line 101
    move-result-object p0

    .line 102
    return-object p0
.end method
