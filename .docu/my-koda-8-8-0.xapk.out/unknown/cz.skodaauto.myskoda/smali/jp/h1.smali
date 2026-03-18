.class public abstract Ljp/h1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static a(Lzi/g;)Lzi/a;
    .locals 8

    .line 1
    const-string v0, "connectorDetails"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object v2, p0, Lzi/g;->a:Ljava/lang/String;

    .line 7
    .line 8
    iget-boolean v7, p0, Lzi/g;->f:Z

    .line 9
    .line 10
    iget-object v0, p0, Lzi/g;->b:Ljava/util/List;

    .line 11
    .line 12
    check-cast v0, Ljava/lang/Iterable;

    .line 13
    .line 14
    new-instance v3, Ljava/util/ArrayList;

    .line 15
    .line 16
    const/16 v1, 0xa

    .line 17
    .line 18
    invoke-static {v0, v1}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 19
    .line 20
    .line 21
    move-result v1

    .line 22
    invoke-direct {v3, v1}, Ljava/util/ArrayList;-><init>(I)V

    .line 23
    .line 24
    .line 25
    invoke-interface {v0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 26
    .line 27
    .line 28
    move-result-object v0

    .line 29
    :goto_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 30
    .line 31
    .line 32
    move-result v1

    .line 33
    if-eqz v1, :cond_0

    .line 34
    .line 35
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 36
    .line 37
    .line 38
    move-result-object v1

    .line 39
    check-cast v1, Lzi/d;

    .line 40
    .line 41
    new-instance v4, Lzi/h;

    .line 42
    .line 43
    iget-object v5, v1, Lzi/d;->a:Ljava/lang/String;

    .line 44
    .line 45
    iget-object v1, v1, Lzi/d;->b:Ljava/lang/String;

    .line 46
    .line 47
    invoke-direct {v4, v5, v1}, Lzi/h;-><init>(Ljava/lang/String;Ljava/lang/String;)V

    .line 48
    .line 49
    .line 50
    invoke-virtual {v3, v4}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 51
    .line 52
    .line 53
    goto :goto_0

    .line 54
    :cond_0
    iget-object v0, p0, Lzi/g;->c:Lgz0/p;

    .line 55
    .line 56
    if-eqz v0, :cond_1

    .line 57
    .line 58
    invoke-virtual {v0}, Lgz0/p;->a()J

    .line 59
    .line 60
    .line 61
    move-result-wide v0

    .line 62
    invoke-static {v0, v1}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 63
    .line 64
    .line 65
    move-result-object v0

    .line 66
    :goto_1
    move-object v4, v0

    .line 67
    goto :goto_2

    .line 68
    :cond_1
    const/4 v0, 0x0

    .line 69
    goto :goto_1

    .line 70
    :goto_2
    iget-object v5, p0, Lzi/g;->d:Ljava/lang/String;

    .line 71
    .line 72
    iget-object v6, p0, Lzi/g;->e:Ljava/lang/String;

    .line 73
    .line 74
    new-instance v1, Lzi/a;

    .line 75
    .line 76
    invoke-direct/range {v1 .. v7}, Lzi/a;-><init>(Ljava/lang/String;Ljava/util/ArrayList;Ljava/lang/Long;Ljava/lang/String;Ljava/lang/String;Z)V

    .line 77
    .line 78
    .line 79
    return-object v1
.end method


# virtual methods
.method public abstract b([BII)V
.end method
