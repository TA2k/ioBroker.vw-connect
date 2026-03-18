.class public abstract Llp/oa;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(Lzw0/a;)Lzw0/a;
    .locals 3

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lzw0/a;->b:Lhy0/a0;

    .line 7
    .line 8
    invoke-static {p0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 9
    .line 10
    .line 11
    invoke-interface {p0}, Lhy0/a0;->getArguments()Ljava/util/List;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    const/4 v0, 0x0

    .line 16
    invoke-interface {p0, v0}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 17
    .line 18
    .line 19
    move-result-object p0

    .line 20
    check-cast p0, Lhy0/d0;

    .line 21
    .line 22
    iget-object p0, p0, Lhy0/d0;->b:Lhy0/a0;

    .line 23
    .line 24
    invoke-static {p0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 25
    .line 26
    .line 27
    new-instance v0, Lzw0/a;

    .line 28
    .line 29
    invoke-interface {p0}, Lhy0/a0;->getClassifier()Lhy0/e;

    .line 30
    .line 31
    .line 32
    move-result-object v1

    .line 33
    const-string v2, "null cannot be cast to non-null type kotlin.reflect.KClass<*>"

    .line 34
    .line 35
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 36
    .line 37
    .line 38
    check-cast v1, Lhy0/d;

    .line 39
    .line 40
    invoke-direct {v0, v1, p0}, Lzw0/a;-><init>(Lhy0/d;Lhy0/a0;)V

    .line 41
    .line 42
    .line 43
    return-object v0
.end method

.method public static final b(Lu01/f;)Z
    .locals 7

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    new-instance v2, Lu01/f;

    .line 7
    .line 8
    invoke-direct {v2}, Ljava/lang/Object;-><init>()V

    .line 9
    .line 10
    .line 11
    iget-wide v0, p0, Lu01/f;->e:J

    .line 12
    .line 13
    const-wide/16 v3, 0x40

    .line 14
    .line 15
    cmp-long v5, v0, v3

    .line 16
    .line 17
    if-gez v5, :cond_0

    .line 18
    .line 19
    move-wide v5, v0

    .line 20
    goto :goto_0

    .line 21
    :cond_0
    move-wide v5, v3

    .line 22
    :goto_0
    const-wide/16 v3, 0x0

    .line 23
    .line 24
    move-object v1, p0

    .line 25
    invoke-virtual/range {v1 .. v6}, Lu01/f;->f(Lu01/f;JJ)V

    .line 26
    .line 27
    .line 28
    const/4 p0, 0x0

    .line 29
    const/4 v0, 0x1

    .line 30
    move v1, p0

    .line 31
    :goto_1
    if-eqz v0, :cond_2

    .line 32
    .line 33
    const/16 v3, 0x10

    .line 34
    .line 35
    if-ge v1, v3, :cond_2

    .line 36
    .line 37
    invoke-virtual {v2}, Lu01/f;->Z()Z

    .line 38
    .line 39
    .line 40
    move-result v3

    .line 41
    if-nez v3, :cond_2

    .line 42
    .line 43
    invoke-virtual {v2}, Lu01/f;->U()I

    .line 44
    .line 45
    .line 46
    move-result v3

    .line 47
    invoke-static {v3}, Ljava/lang/Character;->isISOControl(I)Z

    .line 48
    .line 49
    .line 50
    move-result v4

    .line 51
    if-eqz v4, :cond_1

    .line 52
    .line 53
    invoke-static {v3}, Ljava/lang/Character;->isWhitespace(I)Z

    .line 54
    .line 55
    .line 56
    move-result v3

    .line 57
    if-nez v3, :cond_1

    .line 58
    .line 59
    move v0, p0

    .line 60
    :cond_1
    add-int/lit8 v1, v1, 0x1

    .line 61
    .line 62
    goto :goto_1

    .line 63
    :cond_2
    return v0
.end method
