.class public final Ldg/g;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method static constructor <clinit>()V
    .locals 0

    .line 1
    return-void
.end method

.method public static a(Leg/f;)Ldg/a;
    .locals 5

    .line 1
    const-string v0, "response"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Leg/f;->b:Ljava/lang/String;

    .line 7
    .line 8
    iget-object p0, p0, Leg/f;->a:Lzi/g;

    .line 9
    .line 10
    sget-object v1, Lkj/b;->g:Lsx0/b;

    .line 11
    .line 12
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 13
    .line 14
    .line 15
    new-instance v2, Landroidx/collection/d1;

    .line 16
    .line 17
    const/4 v3, 0x6

    .line 18
    invoke-direct {v2, v1, v3}, Landroidx/collection/d1;-><init>(Ljava/lang/Object;I)V

    .line 19
    .line 20
    .line 21
    :cond_0
    invoke-virtual {v2}, Landroidx/collection/d1;->hasNext()Z

    .line 22
    .line 23
    .line 24
    move-result v1

    .line 25
    const/4 v3, 0x0

    .line 26
    if-eqz v1, :cond_1

    .line 27
    .line 28
    invoke-virtual {v2}, Landroidx/collection/d1;->next()Ljava/lang/Object;

    .line 29
    .line 30
    .line 31
    move-result-object v1

    .line 32
    move-object v4, v1

    .line 33
    check-cast v4, Lkj/b;

    .line 34
    .line 35
    iget-object v4, v4, Lkj/b;->d:Ljava/lang/String;

    .line 36
    .line 37
    invoke-virtual {v4, v0}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 38
    .line 39
    .line 40
    move-result v4

    .line 41
    if-eqz v4, :cond_0

    .line 42
    .line 43
    goto :goto_0

    .line 44
    :cond_1
    move-object v1, v3

    .line 45
    :goto_0
    check-cast v1, Lkj/b;

    .line 46
    .line 47
    if-eqz v1, :cond_3

    .line 48
    .line 49
    sget-object v0, Lkj/b;->e:Lkj/b;

    .line 50
    .line 51
    if-ne v1, v0, :cond_2

    .line 52
    .line 53
    if-eqz p0, :cond_2

    .line 54
    .line 55
    invoke-static {p0}, Ljp/h1;->a(Lzi/g;)Lzi/a;

    .line 56
    .line 57
    .line 58
    move-result-object v3

    .line 59
    :cond_2
    new-instance p0, Ldg/a;

    .line 60
    .line 61
    invoke-direct {p0, v1, v3}, Ldg/a;-><init>(Lkj/b;Lzi/a;)V

    .line 62
    .line 63
    .line 64
    return-object p0

    .line 65
    :cond_3
    const-string p0, "Unknown status: "

    .line 66
    .line 67
    invoke-static {p0, v0}, La7/g0;->h(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 68
    .line 69
    .line 70
    move-result-object p0

    .line 71
    new-instance v0, Ljava/lang/IllegalArgumentException;

    .line 72
    .line 73
    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 74
    .line 75
    .line 76
    move-result-object p0

    .line 77
    invoke-direct {v0, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 78
    .line 79
    .line 80
    throw v0
.end method
