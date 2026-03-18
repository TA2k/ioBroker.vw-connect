.class public final Lkf0/q;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/d;


# static fields
.field public static final a:Ljava/util/List;


# direct methods
.method static constructor <clinit>()V
    .locals 24

    .line 1
    const-string v22, "-"

    .line 2
    .line 3
    const-string v23, "%"

    .line 4
    .line 5
    const-string v1, "^"

    .line 6
    .line 7
    const-string v2, "$"

    .line 8
    .line 9
    const-string v3, "|"

    .line 10
    .line 11
    const-string v4, "]"

    .line 12
    .line 13
    const-string v5, "["

    .line 14
    .line 15
    const-string v6, "}"

    .line 16
    .line 17
    const-string v7, "{"

    .line 18
    .line 19
    const-string v8, "@"

    .line 20
    .line 21
    const-string v9, "&"

    .line 22
    .line 23
    const-string v10, "#"

    .line 24
    .line 25
    const-string v11, ":"

    .line 26
    .line 27
    const-string v12, ")"

    .line 28
    .line 29
    const-string v13, "("

    .line 30
    .line 31
    const-string v14, "/"

    .line 32
    .line 33
    const-string v15, "\\"

    .line 34
    .line 35
    const-string v16, "*"

    .line 36
    .line 37
    const-string v17, ";"

    .line 38
    .line 39
    const-string v18, " "

    .line 40
    .line 41
    const-string v19, "<"

    .line 42
    .line 43
    const-string v20, ">"

    .line 44
    .line 45
    const-string v21, "."

    .line 46
    .line 47
    filled-new-array/range {v1 .. v23}, [Ljava/lang/String;

    .line 48
    .line 49
    .line 50
    move-result-object v0

    .line 51
    invoke-static {v0}, Ljp/k1;->j([Ljava/lang/Object;)Ljava/util/List;

    .line 52
    .line 53
    .line 54
    move-result-object v0

    .line 55
    sput-object v0, Lkf0/q;->a:Ljava/util/List;

    .line 56
    .line 57
    return-void
.end method


# virtual methods
.method public final a(Ljava/lang/String;)Ljava/lang/Boolean;
    .locals 2

    .line 1
    const-string p0, "input"

    .line 2
    .line 3
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-virtual {p1}, Ljava/lang/String;->length()I

    .line 7
    .line 8
    .line 9
    move-result p0

    .line 10
    const/16 v0, 0x9

    .line 11
    .line 12
    const/4 v1, 0x0

    .line 13
    if-le p0, v0, :cond_0

    .line 14
    .line 15
    goto :goto_1

    .line 16
    :cond_0
    sget-object p0, Lkf0/q;->a:Ljava/util/List;

    .line 17
    .line 18
    check-cast p0, Ljava/lang/Iterable;

    .line 19
    .line 20
    instance-of v0, p0, Ljava/util/Collection;

    .line 21
    .line 22
    if-eqz v0, :cond_1

    .line 23
    .line 24
    move-object v0, p0

    .line 25
    check-cast v0, Ljava/util/Collection;

    .line 26
    .line 27
    invoke-interface {v0}, Ljava/util/Collection;->isEmpty()Z

    .line 28
    .line 29
    .line 30
    move-result v0

    .line 31
    if-eqz v0, :cond_1

    .line 32
    .line 33
    goto :goto_0

    .line 34
    :cond_1
    invoke-interface {p0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 35
    .line 36
    .line 37
    move-result-object p0

    .line 38
    :cond_2
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 39
    .line 40
    .line 41
    move-result v0

    .line 42
    if-eqz v0, :cond_3

    .line 43
    .line 44
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 45
    .line 46
    .line 47
    move-result-object v0

    .line 48
    check-cast v0, Ljava/lang/String;

    .line 49
    .line 50
    invoke-static {p1, v0, v1}, Lly0/p;->A(Ljava/lang/CharSequence;Ljava/lang/CharSequence;Z)Z

    .line 51
    .line 52
    .line 53
    move-result v0

    .line 54
    if-eqz v0, :cond_2

    .line 55
    .line 56
    goto :goto_1

    .line 57
    :cond_3
    :goto_0
    const/4 v1, 0x1

    .line 58
    :goto_1
    invoke-static {v1}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 59
    .line 60
    .line 61
    move-result-object p0

    .line 62
    return-object p0
.end method

.method public final bridge synthetic invoke()Ljava/lang/Object;
    .locals 1

    .line 1
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 2
    .line 3
    check-cast v0, Ljava/lang/String;

    .line 4
    .line 5
    invoke-virtual {p0, v0}, Lkf0/q;->a(Ljava/lang/String;)Ljava/lang/Boolean;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    return-object p0
.end method
