.class public final Lnn0/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/d;


# direct methods
.method public static a(Lon0/q;)Lon0/c;
    .locals 2

    .line 1
    const-string v0, "input"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lon0/q;->g:Ljava/util/List;

    .line 7
    .line 8
    iget-object p0, p0, Lon0/q;->f:Ljava/util/ArrayList;

    .line 9
    .line 10
    invoke-virtual {p0}, Ljava/util/ArrayList;->isEmpty()Z

    .line 11
    .line 12
    .line 13
    move-result v1

    .line 14
    if-nez v1, :cond_2

    .line 15
    .line 16
    invoke-static {p0}, Lmx0/q;->T(Ljava/util/List;)Ljava/lang/Object;

    .line 17
    .line 18
    .line 19
    move-result-object p0

    .line 20
    check-cast p0, Lon0/p;

    .line 21
    .line 22
    iget-object p0, p0, Lon0/p;->c:Ljava/lang/String;

    .line 23
    .line 24
    invoke-static {p0}, Lly0/p;->M(Ljava/lang/CharSequence;)Z

    .line 25
    .line 26
    .line 27
    move-result p0

    .line 28
    if-eqz p0, :cond_0

    .line 29
    .line 30
    goto :goto_0

    .line 31
    :cond_0
    invoke-interface {v0}, Ljava/util/List;->isEmpty()Z

    .line 32
    .line 33
    .line 34
    move-result p0

    .line 35
    if-eqz p0, :cond_1

    .line 36
    .line 37
    sget-object p0, Lon0/c;->h:Lon0/c;

    .line 38
    .line 39
    return-object p0

    .line 40
    :cond_1
    sget-object p0, Lon0/c;->e:Lon0/c;

    .line 41
    .line 42
    return-object p0

    .line 43
    :cond_2
    :goto_0
    invoke-interface {v0}, Ljava/util/List;->isEmpty()Z

    .line 44
    .line 45
    .line 46
    move-result p0

    .line 47
    if-eqz p0, :cond_3

    .line 48
    .line 49
    sget-object p0, Lon0/c;->f:Lon0/c;

    .line 50
    .line 51
    return-object p0

    .line 52
    :cond_3
    sget-object p0, Lon0/c;->g:Lon0/c;

    .line 53
    .line 54
    return-object p0
.end method


# virtual methods
.method public final bridge synthetic invoke()Ljava/lang/Object;
    .locals 0

    .line 1
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 2
    .line 3
    check-cast p0, Lon0/q;

    .line 4
    .line 5
    invoke-static {p0}, Lnn0/a;->a(Lon0/q;)Lon0/c;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    return-object p0
.end method
