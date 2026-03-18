.class public abstract Lky0/l;
.super Llp/ke;


# direct methods
.method public static b(Ljava/util/Iterator;)Lky0/j;
    .locals 2

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    new-instance v0, Lky0/m;

    .line 7
    .line 8
    const/4 v1, 0x1

    .line 9
    invoke-direct {v0, p0, v1}, Lky0/m;-><init>(Ljava/lang/Object;I)V

    .line 10
    .line 11
    .line 12
    new-instance p0, Lky0/a;

    .line 13
    .line 14
    invoke-direct {p0, v0}, Lky0/a;-><init>(Lky0/j;)V

    .line 15
    .line 16
    .line 17
    return-object p0
.end method

.method public static c(Lky0/j;)I
    .locals 2

    .line 1
    invoke-interface {p0}, Lky0/j;->iterator()Ljava/util/Iterator;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    const/4 v0, 0x0

    .line 6
    :goto_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 7
    .line 8
    .line 9
    move-result v1

    .line 10
    if-eqz v1, :cond_1

    .line 11
    .line 12
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 13
    .line 14
    .line 15
    add-int/lit8 v0, v0, 0x1

    .line 16
    .line 17
    if-ltz v0, :cond_0

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    invoke-static {}, Ljp/k1;->q()V

    .line 21
    .line 22
    .line 23
    const/4 p0, 0x0

    .line 24
    throw p0

    .line 25
    :cond_1
    return v0
.end method

.method public static d(Lky0/j;I)Lky0/j;
    .locals 2

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    if-ltz p1, :cond_2

    .line 7
    .line 8
    if-nez p1, :cond_0

    .line 9
    .line 10
    return-object p0

    .line 11
    :cond_0
    instance-of v0, p0, Lky0/d;

    .line 12
    .line 13
    if-eqz v0, :cond_1

    .line 14
    .line 15
    check-cast p0, Lky0/d;

    .line 16
    .line 17
    invoke-interface {p0, p1}, Lky0/d;->a(I)Lky0/j;

    .line 18
    .line 19
    .line 20
    move-result-object p0

    .line 21
    return-object p0

    .line 22
    :cond_1
    new-instance v0, Lky0/c;

    .line 23
    .line 24
    const/4 v1, 0x0

    .line 25
    invoke-direct {v0, p0, p1, v1}, Lky0/c;-><init>(Lky0/j;II)V

    .line 26
    .line 27
    .line 28
    return-object v0

    .line 29
    :cond_2
    const-string p0, "Requested element count "

    .line 30
    .line 31
    const-string v0, " is less than zero."

    .line 32
    .line 33
    invoke-static {p0, p1, v0}, Lu/w;->e(Ljava/lang/String;ILjava/lang/String;)Ljava/lang/String;

    .line 34
    .line 35
    .line 36
    move-result-object p0

    .line 37
    new-instance p1, Ljava/lang/IllegalArgumentException;

    .line 38
    .line 39
    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 40
    .line 41
    .line 42
    move-result-object p0

    .line 43
    invoke-direct {p1, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 44
    .line 45
    .line 46
    throw p1
.end method

.method public static e(Lky0/j;Lay0/k;)Lky0/g;
    .locals 2

    .line 1
    const-string v0, "predicate"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    new-instance v0, Lky0/g;

    .line 7
    .line 8
    const/4 v1, 0x1

    .line 9
    invoke-direct {v0, p0, v1, p1}, Lky0/g;-><init>(Lky0/j;ZLay0/k;)V

    .line 10
    .line 11
    .line 12
    return-object v0
.end method

.method public static f(Lky0/j;Lay0/k;)Lky0/g;
    .locals 2

    .line 1
    const-string v0, "predicate"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    new-instance v0, Lky0/g;

    .line 7
    .line 8
    const/4 v1, 0x0

    .line 9
    invoke-direct {v0, p0, v1, p1}, Lky0/g;-><init>(Lky0/j;ZLay0/k;)V

    .line 10
    .line 11
    .line 12
    return-object v0
.end method

.method public static g(Lky0/g;)Ljava/lang/Object;
    .locals 1

    .line 1
    new-instance v0, Lky0/f;

    .line 2
    .line 3
    invoke-direct {v0, p0}, Lky0/f;-><init>(Lky0/g;)V

    .line 4
    .line 5
    .line 6
    invoke-virtual {v0}, Lky0/f;->hasNext()Z

    .line 7
    .line 8
    .line 9
    move-result p0

    .line 10
    if-nez p0, :cond_0

    .line 11
    .line 12
    const/4 p0, 0x0

    .line 13
    return-object p0

    .line 14
    :cond_0
    invoke-virtual {v0}, Lky0/f;->next()Ljava/lang/Object;

    .line 15
    .line 16
    .line 17
    move-result-object p0

    .line 18
    return-object p0
.end method

.method public static h(Lky0/j;Lay0/k;)Lky0/h;
    .locals 2

    .line 1
    const-string v0, "transform"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    new-instance v0, Lky0/h;

    .line 7
    .line 8
    sget-object v1, Lky0/q;->d:Lky0/q;

    .line 9
    .line 10
    invoke-direct {v0, p0, p1, v1}, Lky0/h;-><init>(Lky0/j;Lay0/k;Lay0/k;)V

    .line 11
    .line 12
    .line 13
    return-object v0
.end method

.method public static final i(Lky0/j;)Lky0/h;
    .locals 4

    .line 1
    new-instance v0, Lkq0/a;

    .line 2
    .line 3
    const/4 v1, 0x2

    .line 4
    invoke-direct {v0, v1}, Lkq0/a;-><init>(I)V

    .line 5
    .line 6
    .line 7
    instance-of v1, p0, Lky0/s;

    .line 8
    .line 9
    if-eqz v1, :cond_0

    .line 10
    .line 11
    check-cast p0, Lky0/s;

    .line 12
    .line 13
    new-instance v1, Lky0/h;

    .line 14
    .line 15
    iget-object v2, p0, Lky0/s;->a:Lky0/j;

    .line 16
    .line 17
    iget-object p0, p0, Lky0/s;->b:Lay0/k;

    .line 18
    .line 19
    invoke-direct {v1, v2, p0, v0}, Lky0/h;-><init>(Lky0/j;Lay0/k;Lay0/k;)V

    .line 20
    .line 21
    .line 22
    return-object v1

    .line 23
    :cond_0
    new-instance v1, Lky0/h;

    .line 24
    .line 25
    new-instance v2, Lu2/d;

    .line 26
    .line 27
    const/4 v3, 0x1

    .line 28
    invoke-direct {v2, v3}, Lu2/d;-><init>(I)V

    .line 29
    .line 30
    .line 31
    invoke-direct {v1, p0, v2, v0}, Lky0/h;-><init>(Lky0/j;Lay0/k;Lay0/k;)V

    .line 32
    .line 33
    .line 34
    return-object v1
.end method

.method public static j(Lay0/a;)Lky0/j;
    .locals 3

    .line 1
    new-instance v0, Lky0/i;

    .line 2
    .line 3
    new-instance v1, Li50/c0;

    .line 4
    .line 5
    const/16 v2, 0xa

    .line 6
    .line 7
    invoke-direct {v1, p0, v2}, Li50/c0;-><init>(Lay0/a;I)V

    .line 8
    .line 9
    .line 10
    invoke-direct {v0, p0, v1}, Lky0/i;-><init>(Lay0/a;Lay0/k;)V

    .line 11
    .line 12
    .line 13
    new-instance p0, Lky0/a;

    .line 14
    .line 15
    invoke-direct {p0, v0}, Lky0/a;-><init>(Lky0/j;)V

    .line 16
    .line 17
    .line 18
    return-object p0
.end method

.method public static k(Ljava/lang/Object;Lay0/k;)Lky0/j;
    .locals 3

    .line 1
    const-string v0, "nextFunction"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    if-nez p0, :cond_0

    .line 7
    .line 8
    sget-object p0, Lky0/e;->a:Lky0/e;

    .line 9
    .line 10
    return-object p0

    .line 11
    :cond_0
    new-instance v0, Lky0/i;

    .line 12
    .line 13
    new-instance v1, Lf91/a;

    .line 14
    .line 15
    const/4 v2, 0x1

    .line 16
    invoke-direct {v1, p0, v2}, Lf91/a;-><init>(Ljava/lang/Object;I)V

    .line 17
    .line 18
    .line 19
    invoke-direct {v0, v1, p1}, Lky0/i;-><init>(Lay0/a;Lay0/k;)V

    .line 20
    .line 21
    .line 22
    return-object v0
.end method

.method public static l(Lky0/j;Ljava/lang/String;)Ljava/lang/String;
    .locals 5

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    new-instance v0, Ljava/lang/StringBuilder;

    .line 7
    .line 8
    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    .line 9
    .line 10
    .line 11
    const-string v1, ""

    .line 12
    .line 13
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/CharSequence;)Ljava/lang/Appendable;

    .line 14
    .line 15
    .line 16
    invoke-interface {p0}, Lky0/j;->iterator()Ljava/util/Iterator;

    .line 17
    .line 18
    .line 19
    move-result-object p0

    .line 20
    const/4 v2, 0x0

    .line 21
    :goto_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 22
    .line 23
    .line 24
    move-result v3

    .line 25
    if-eqz v3, :cond_1

    .line 26
    .line 27
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 28
    .line 29
    .line 30
    move-result-object v3

    .line 31
    const/4 v4, 0x1

    .line 32
    add-int/2addr v2, v4

    .line 33
    if-le v2, v4, :cond_0

    .line 34
    .line 35
    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/CharSequence;)Ljava/lang/Appendable;

    .line 36
    .line 37
    .line 38
    :cond_0
    const/4 v4, 0x0

    .line 39
    invoke-static {v0, v3, v4}, Lly0/q;->a(Ljava/lang/Appendable;Ljava/lang/Object;Lay0/k;)V

    .line 40
    .line 41
    .line 42
    goto :goto_0

    .line 43
    :cond_1
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/CharSequence;)Ljava/lang/Appendable;

    .line 44
    .line 45
    .line 46
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 47
    .line 48
    .line 49
    move-result-object p0

    .line 50
    return-object p0
.end method

.method public static m(Lky0/j;)Ljava/lang/Object;
    .locals 2

    .line 1
    invoke-interface {p0}, Lky0/j;->iterator()Ljava/util/Iterator;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 6
    .line 7
    .line 8
    move-result v0

    .line 9
    if-eqz v0, :cond_1

    .line 10
    .line 11
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    :goto_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 16
    .line 17
    .line 18
    move-result v1

    .line 19
    if-eqz v1, :cond_0

    .line 20
    .line 21
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 22
    .line 23
    .line 24
    move-result-object v0

    .line 25
    goto :goto_0

    .line 26
    :cond_0
    return-object v0

    .line 27
    :cond_1
    new-instance p0, Ljava/util/NoSuchElementException;

    .line 28
    .line 29
    const-string v0, "Sequence is empty."

    .line 30
    .line 31
    invoke-direct {p0, v0}, Ljava/util/NoSuchElementException;-><init>(Ljava/lang/String;)V

    .line 32
    .line 33
    .line 34
    throw p0
.end method

.method public static n(Lky0/j;Lay0/k;)Lky0/s;
    .locals 1

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "transform"

    .line 7
    .line 8
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    new-instance v0, Lky0/s;

    .line 12
    .line 13
    invoke-direct {v0, p0, p1}, Lky0/s;-><init>(Lky0/j;Lay0/k;)V

    .line 14
    .line 15
    .line 16
    return-object v0
.end method

.method public static o(Lky0/j;Lay0/k;)Lky0/g;
    .locals 1

    .line 1
    const-string v0, "transform"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    new-instance v0, Lky0/s;

    .line 7
    .line 8
    invoke-direct {v0, p0, p1}, Lky0/s;-><init>(Lky0/j;Lay0/k;)V

    .line 9
    .line 10
    .line 11
    new-instance p0, Lkq0/a;

    .line 12
    .line 13
    const/4 p1, 0x3

    .line 14
    invoke-direct {p0, p1}, Lkq0/a;-><init>(I)V

    .line 15
    .line 16
    .line 17
    invoke-static {v0, p0}, Lky0/l;->f(Lky0/j;Lay0/k;)Lky0/g;

    .line 18
    .line 19
    .line 20
    move-result-object p0

    .line 21
    return-object p0
.end method

.method public static p(Lky0/j;)Ljava/util/List;
    .locals 2

    .line 1
    invoke-interface {p0}, Lky0/j;->iterator()Ljava/util/Iterator;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 6
    .line 7
    .line 8
    move-result v0

    .line 9
    if-nez v0, :cond_0

    .line 10
    .line 11
    sget-object p0, Lmx0/s;->d:Lmx0/s;

    .line 12
    .line 13
    return-object p0

    .line 14
    :cond_0
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 15
    .line 16
    .line 17
    move-result-object v0

    .line 18
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 19
    .line 20
    .line 21
    move-result v1

    .line 22
    if-nez v1, :cond_1

    .line 23
    .line 24
    invoke-static {v0}, Ljp/k1;->i(Ljava/lang/Object;)Ljava/util/List;

    .line 25
    .line 26
    .line 27
    move-result-object p0

    .line 28
    return-object p0

    .line 29
    :cond_1
    new-instance v1, Ljava/util/ArrayList;

    .line 30
    .line 31
    invoke-direct {v1}, Ljava/util/ArrayList;-><init>()V

    .line 32
    .line 33
    .line 34
    invoke-virtual {v1, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 35
    .line 36
    .line 37
    :goto_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 38
    .line 39
    .line 40
    move-result v0

    .line 41
    if-eqz v0, :cond_2

    .line 42
    .line 43
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 44
    .line 45
    .line 46
    move-result-object v0

    .line 47
    invoke-virtual {v1, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 48
    .line 49
    .line 50
    goto :goto_0

    .line 51
    :cond_2
    return-object v1
.end method
