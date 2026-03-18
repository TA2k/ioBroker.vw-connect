.class public abstract Ljp/s0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static a(Ljava/lang/Class;)Ljava/lang/String;
    .locals 3

    .line 1
    sget-object v0, Lz9/k0;->b:Ljava/util/LinkedHashMap;

    .line 2
    .line 3
    invoke-virtual {v0, p0}, Ljava/util/LinkedHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v1

    .line 7
    check-cast v1, Ljava/lang/String;

    .line 8
    .line 9
    if-nez v1, :cond_2

    .line 10
    .line 11
    const-class v1, Lz9/i0;

    .line 12
    .line 13
    invoke-virtual {p0, v1}, Ljava/lang/Class;->getAnnotation(Ljava/lang/Class;)Ljava/lang/annotation/Annotation;

    .line 14
    .line 15
    .line 16
    move-result-object v1

    .line 17
    check-cast v1, Lz9/i0;

    .line 18
    .line 19
    if-eqz v1, :cond_0

    .line 20
    .line 21
    invoke-interface {v1}, Lz9/i0;->value()Ljava/lang/String;

    .line 22
    .line 23
    .line 24
    move-result-object v1

    .line 25
    goto :goto_0

    .line 26
    :cond_0
    const/4 v1, 0x0

    .line 27
    :goto_0
    if-eqz v1, :cond_1

    .line 28
    .line 29
    invoke-virtual {v1}, Ljava/lang/String;->length()I

    .line 30
    .line 31
    .line 32
    move-result v2

    .line 33
    if-lez v2, :cond_1

    .line 34
    .line 35
    invoke-interface {v0, p0, v1}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 36
    .line 37
    .line 38
    goto :goto_1

    .line 39
    :cond_1
    invoke-virtual {p0}, Ljava/lang/Class;->getSimpleName()Ljava/lang/String;

    .line 40
    .line 41
    .line 42
    move-result-object p0

    .line 43
    const-string v0, "No @Navigator.Name annotation found for "

    .line 44
    .line 45
    invoke-virtual {v0, p0}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 46
    .line 47
    .line 48
    move-result-object p0

    .line 49
    new-instance v0, Ljava/lang/IllegalArgumentException;

    .line 50
    .line 51
    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 52
    .line 53
    .line 54
    move-result-object p0

    .line 55
    invoke-direct {v0, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 56
    .line 57
    .line 58
    throw v0

    .line 59
    :cond_2
    :goto_1
    invoke-static {v1}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 60
    .line 61
    .line 62
    return-object v1
.end method

.method public static final b([Lz9/j0;Ll2/o;)Lz9/y;
    .locals 7

    .line 1
    sget-object v0, Landroidx/compose/ui/platform/AndroidCompositionLocals_androidKt;->b:Ll2/u2;

    .line 2
    .line 3
    move-object v4, p1

    .line 4
    check-cast v4, Ll2/t;

    .line 5
    .line 6
    invoke-virtual {v4, v0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 7
    .line 8
    .line 9
    move-result-object p1

    .line 10
    check-cast p1, Landroid/content/Context;

    .line 11
    .line 12
    array-length v0, p0

    .line 13
    invoke-static {p0, v0}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    .line 14
    .line 15
    .line 16
    move-result-object v1

    .line 17
    new-instance v0, La00/b;

    .line 18
    .line 19
    const/4 v2, 0x3

    .line 20
    invoke-direct {v0, v2}, La00/b;-><init>(I)V

    .line 21
    .line 22
    .line 23
    new-instance v2, Laa/y;

    .line 24
    .line 25
    const/4 v3, 0x0

    .line 26
    invoke-direct {v2, p1, v3}, Laa/y;-><init>(Landroid/content/Context;I)V

    .line 27
    .line 28
    .line 29
    move-object v3, v2

    .line 30
    new-instance v2, Lu2/l;

    .line 31
    .line 32
    invoke-direct {v2, v0, v3}, Lu2/l;-><init>(Lay0/n;Lay0/k;)V

    .line 33
    .line 34
    .line 35
    invoke-virtual {v4, p1}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 36
    .line 37
    .line 38
    move-result v0

    .line 39
    invoke-virtual {v4}, Ll2/t;->L()Ljava/lang/Object;

    .line 40
    .line 41
    .line 42
    move-result-object v3

    .line 43
    if-nez v0, :cond_0

    .line 44
    .line 45
    sget-object v0, Ll2/n;->a:Ll2/x0;

    .line 46
    .line 47
    if-ne v3, v0, :cond_1

    .line 48
    .line 49
    :cond_0
    new-instance v3, Laa/x;

    .line 50
    .line 51
    const/4 v0, 0x0

    .line 52
    invoke-direct {v3, p1, v0}, Laa/x;-><init>(Landroid/content/Context;I)V

    .line 53
    .line 54
    .line 55
    invoke-virtual {v4, v3}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 56
    .line 57
    .line 58
    :cond_1
    check-cast v3, Lay0/a;

    .line 59
    .line 60
    const/4 v5, 0x0

    .line 61
    const/4 v6, 0x4

    .line 62
    invoke-static/range {v1 .. v6}, Lu2/m;->e([Ljava/lang/Object;Lu2/k;Lay0/a;Ll2/o;II)Ljava/lang/Object;

    .line 63
    .line 64
    .line 65
    move-result-object p1

    .line 66
    check-cast p1, Lz9/y;

    .line 67
    .line 68
    array-length v0, p0

    .line 69
    const/4 v1, 0x0

    .line 70
    :goto_0
    if-ge v1, v0, :cond_2

    .line 71
    .line 72
    aget-object v2, p0, v1

    .line 73
    .line 74
    iget-object v3, p1, Lz9/y;->b:Lca/g;

    .line 75
    .line 76
    iget-object v3, v3, Lca/g;->s:Lz9/k0;

    .line 77
    .line 78
    invoke-virtual {v3, v2}, Lz9/k0;->a(Lz9/j0;)V

    .line 79
    .line 80
    .line 81
    add-int/lit8 v1, v1, 0x1

    .line 82
    .line 83
    goto :goto_0

    .line 84
    :cond_2
    return-object p1
.end method


# virtual methods
.method public abstract c(Ljava/util/ArrayList;)V
.end method
