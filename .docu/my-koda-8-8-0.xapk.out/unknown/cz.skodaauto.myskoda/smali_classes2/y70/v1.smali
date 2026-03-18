.class public abstract Ly70/v1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Ljava/util/List;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    const-string v0, "winterreifen_kmh"

    .line 2
    .line 3
    invoke-static {v0}, Ljp/k1;->i(Ljava/lang/Object;)Ljava/util/List;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    sput-object v0, Ly70/v1;->a:Ljava/util/List;

    .line 8
    .line 9
    return-void
.end method

.method public static final a(Lcq0/r;)Ljava/lang/String;
    .locals 1

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lcq0/r;->a:Ljava/lang/String;

    .line 7
    .line 8
    if-eqz p0, :cond_0

    .line 9
    .line 10
    sget-object v0, Ljava/util/Locale;->ROOT:Ljava/util/Locale;

    .line 11
    .line 12
    invoke-virtual {p0, v0}, Ljava/lang/String;->toLowerCase(Ljava/util/Locale;)Ljava/lang/String;

    .line 13
    .line 14
    .line 15
    move-result-object p0

    .line 16
    const-string v0, "toLowerCase(...)"

    .line 17
    .line 18
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 19
    .line 20
    .line 21
    goto :goto_0

    .line 22
    :cond_0
    const/4 p0, 0x0

    .line 23
    :goto_0
    const-string v0, "ic_service_"

    .line 24
    .line 25
    invoke-static {v0, p0}, La7/g0;->h(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 26
    .line 27
    .line 28
    move-result-object p0

    .line 29
    return-object p0
.end method

.method public static final b(Lcq0/r;Lxf0/a;Z)Ly70/m0;
    .locals 7

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "drawableResource"

    .line 7
    .line 8
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    new-instance v0, Ly70/m0;

    .line 12
    .line 13
    invoke-static {p0}, Ly70/v1;->a(Lcq0/r;)Ljava/lang/String;

    .line 14
    .line 15
    .line 16
    move-result-object v1

    .line 17
    const-string v2, "drawableName"

    .line 18
    .line 19
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 20
    .line 21
    .line 22
    iget-object v2, p1, Lxf0/a;->a:Landroid/content/res/Resources;

    .line 23
    .line 24
    const-string v3, "@drawable/"

    .line 25
    .line 26
    invoke-virtual {v3, v1}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 27
    .line 28
    .line 29
    move-result-object v1

    .line 30
    const-string v3, "drawable"

    .line 31
    .line 32
    iget-object p1, p1, Lxf0/a;->b:Ljava/lang/String;

    .line 33
    .line 34
    invoke-virtual {v2, v1, v3, p1}, Landroid/content/res/Resources;->getIdentifier(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)I

    .line 35
    .line 36
    .line 37
    move-result p1

    .line 38
    if-nez p1, :cond_0

    .line 39
    .line 40
    new-instance v1, Lne0/c;

    .line 41
    .line 42
    new-instance v2, Ljava/lang/Exception;

    .line 43
    .line 44
    invoke-static {p0}, Ly70/v1;->a(Lcq0/r;)Ljava/lang/String;

    .line 45
    .line 46
    .line 47
    move-result-object p1

    .line 48
    const-string v3, "Resource "

    .line 49
    .line 50
    const-string v4, " not found"

    .line 51
    .line 52
    invoke-static {v3, p1, v4}, Lp3/m;->j(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 53
    .line 54
    .line 55
    move-result-object p1

    .line 56
    invoke-direct {v2, p1}, Ljava/lang/Exception;-><init>(Ljava/lang/String;)V

    .line 57
    .line 58
    .line 59
    const/4 v5, 0x0

    .line 60
    const/16 v6, 0x1e

    .line 61
    .line 62
    const/4 v3, 0x0

    .line 63
    const/4 v4, 0x0

    .line 64
    invoke-direct/range {v1 .. v6}, Lne0/c;-><init>(Ljava/lang/Throwable;Lne0/c;Lne0/a;Lne0/b;I)V

    .line 65
    .line 66
    .line 67
    new-instance p1, La60/a;

    .line 68
    .line 69
    const/4 v2, 0x1

    .line 70
    invoke-direct {p1, v1, v2}, La60/a;-><init>(Lne0/c;I)V

    .line 71
    .line 72
    .line 73
    invoke-static {p0, p1}, Llp/nd;->e(Ljava/lang/Object;Lay0/a;)V

    .line 74
    .line 75
    .line 76
    const p1, 0x7f0801d3

    .line 77
    .line 78
    .line 79
    :cond_0
    sget-object v1, Ly70/v1;->a:Ljava/util/List;

    .line 80
    .line 81
    check-cast v1, Ljava/lang/Iterable;

    .line 82
    .line 83
    iget-object v2, p0, Lcq0/r;->a:Ljava/lang/String;

    .line 84
    .line 85
    invoke-static {v1, v2}, Lmx0/q;->A(Ljava/lang/Iterable;Ljava/lang/Object;)Z

    .line 86
    .line 87
    .line 88
    move-result v1

    .line 89
    if-eqz v1, :cond_1

    .line 90
    .line 91
    const/4 p2, 0x0

    .line 92
    goto :goto_0

    .line 93
    :cond_1
    if-nez p2, :cond_2

    .line 94
    .line 95
    sget-object p2, Lcq0/s;->d:Lcq0/s;

    .line 96
    .line 97
    goto :goto_0

    .line 98
    :cond_2
    iget-object p2, p0, Lcq0/r;->b:Lcq0/s;

    .line 99
    .line 100
    :goto_0
    iget-object p0, p0, Lcq0/r;->c:Ljava/lang/String;

    .line 101
    .line 102
    invoke-direct {v0, p1, p2, p0}, Ly70/m0;-><init>(ILcq0/s;Ljava/lang/String;)V

    .line 103
    .line 104
    .line 105
    return-object v0
.end method
