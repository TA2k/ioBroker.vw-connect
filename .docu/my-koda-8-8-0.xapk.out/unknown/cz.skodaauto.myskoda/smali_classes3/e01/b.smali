.class public final Le01/b;
.super Ljp/ng;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Lhy0/d;

.field public final b:Ljava/lang/Object;

.field public final c:Ljp/ng;


# direct methods
.method public constructor <init>(Lhy0/d;Ljava/lang/Object;Ljp/ng;)V
    .locals 1

    .line 1
    const-string v0, "key"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "value"

    .line 7
    .line 8
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    const-string v0, "next"

    .line 12
    .line 13
    invoke-static {p3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 17
    .line 18
    .line 19
    iput-object p1, p0, Le01/b;->a:Lhy0/d;

    .line 20
    .line 21
    iput-object p2, p0, Le01/b;->b:Ljava/lang/Object;

    .line 22
    .line 23
    iput-object p3, p0, Le01/b;->c:Ljp/ng;

    .line 24
    .line 25
    return-void
.end method


# virtual methods
.method public final a(Lhy0/d;)Ljava/lang/Object;
    .locals 1

    .line 1
    const-string v0, "key"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Le01/b;->a:Lhy0/d;

    .line 7
    .line 8
    invoke-virtual {p1, v0}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 9
    .line 10
    .line 11
    move-result v0

    .line 12
    if-eqz v0, :cond_0

    .line 13
    .line 14
    invoke-static {p1}, Ljp/p1;->c(Lhy0/d;)Ljava/lang/Class;

    .line 15
    .line 16
    .line 17
    move-result-object p1

    .line 18
    iget-object p0, p0, Le01/b;->b:Ljava/lang/Object;

    .line 19
    .line 20
    invoke-virtual {p1, p0}, Ljava/lang/Class;->cast(Ljava/lang/Object;)Ljava/lang/Object;

    .line 21
    .line 22
    .line 23
    move-result-object p0

    .line 24
    return-object p0

    .line 25
    :cond_0
    iget-object p0, p0, Le01/b;->c:Ljp/ng;

    .line 26
    .line 27
    invoke-virtual {p0, p1}, Ljp/ng;->a(Lhy0/d;)Ljava/lang/Object;

    .line 28
    .line 29
    .line 30
    move-result-object p0

    .line 31
    return-object p0
.end method

.method public final b(Lhy0/d;Ljava/lang/Object;)Ljp/ng;
    .locals 3

    .line 1
    const-string v0, "key"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Le01/b;->a:Lhy0/d;

    .line 7
    .line 8
    invoke-virtual {p1, v0}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 9
    .line 10
    .line 11
    move-result v1

    .line 12
    iget-object v2, p0, Le01/b;->c:Ljp/ng;

    .line 13
    .line 14
    if-eqz v1, :cond_0

    .line 15
    .line 16
    goto :goto_1

    .line 17
    :cond_0
    const/4 v1, 0x0

    .line 18
    invoke-virtual {v2, p1, v1}, Ljp/ng;->b(Lhy0/d;Ljava/lang/Object;)Ljp/ng;

    .line 19
    .line 20
    .line 21
    move-result-object v1

    .line 22
    if-ne v1, v2, :cond_1

    .line 23
    .line 24
    goto :goto_0

    .line 25
    :cond_1
    new-instance v2, Le01/b;

    .line 26
    .line 27
    iget-object p0, p0, Le01/b;->b:Ljava/lang/Object;

    .line 28
    .line 29
    invoke-direct {v2, v0, p0, v1}, Le01/b;-><init>(Lhy0/d;Ljava/lang/Object;Ljp/ng;)V

    .line 30
    .line 31
    .line 32
    move-object p0, v2

    .line 33
    :goto_0
    move-object v2, p0

    .line 34
    :goto_1
    if-eqz p2, :cond_2

    .line 35
    .line 36
    new-instance p0, Le01/b;

    .line 37
    .line 38
    invoke-direct {p0, p1, p2, v2}, Le01/b;-><init>(Lhy0/d;Ljava/lang/Object;Ljp/ng;)V

    .line 39
    .line 40
    .line 41
    return-object p0

    .line 42
    :cond_2
    return-object v2
.end method

.method public final toString()Ljava/lang/String;
    .locals 6

    .line 1
    new-instance v0, Ldj/a;

    .line 2
    .line 3
    const/16 v1, 0xb

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ldj/a;-><init>(I)V

    .line 6
    .line 7
    .line 8
    invoke-static {p0, v0}, Lky0/l;->k(Ljava/lang/Object;Lay0/k;)Lky0/j;

    .line 9
    .line 10
    .line 11
    move-result-object p0

    .line 12
    invoke-static {p0}, Lky0/l;->p(Lky0/j;)Ljava/util/List;

    .line 13
    .line 14
    .line 15
    move-result-object p0

    .line 16
    check-cast p0, Ljava/lang/Iterable;

    .line 17
    .line 18
    invoke-static {p0}, Lmx0/q;->g0(Ljava/lang/Iterable;)Ljava/util/List;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    move-object v0, p0

    .line 23
    check-cast v0, Ljava/lang/Iterable;

    .line 24
    .line 25
    new-instance v4, Ldj/a;

    .line 26
    .line 27
    const/16 p0, 0xc

    .line 28
    .line 29
    invoke-direct {v4, p0}, Ldj/a;-><init>(I)V

    .line 30
    .line 31
    .line 32
    const/16 v5, 0x19

    .line 33
    .line 34
    const/4 v1, 0x0

    .line 35
    const-string v2, "{"

    .line 36
    .line 37
    const-string v3, "}"

    .line 38
    .line 39
    invoke-static/range {v0 .. v5}, Lmx0/q;->R(Ljava/lang/Iterable;Ljava/lang/CharSequence;Ljava/lang/String;Ljava/lang/String;Lay0/k;I)Ljava/lang/String;

    .line 40
    .line 41
    .line 42
    move-result-object p0

    .line 43
    return-object p0
.end method
