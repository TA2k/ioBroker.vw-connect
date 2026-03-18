.class public final Lh40/l0;
.super Lql0/j;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final h:Lij0/a;

.field public final i:Ltr0/b;

.field public final j:Lf40/h1;

.field public final k:Lf40/v1;


# direct methods
.method public constructor <init>(Lij0/a;Ltr0/b;Lf40/h1;Lf40/v1;)V
    .locals 8

    .line 1
    new-instance v0, Lh40/k0;

    .line 2
    .line 3
    const/16 v1, 0x3f

    .line 4
    .line 5
    and-int/lit8 v2, v1, 0x4

    .line 6
    .line 7
    const/4 v7, 0x0

    .line 8
    if-eqz v2, :cond_0

    .line 9
    .line 10
    sget-object v2, Lmx0/s;->d:Lmx0/s;

    .line 11
    .line 12
    move-object v3, v2

    .line 13
    goto :goto_0

    .line 14
    :cond_0
    move-object v3, v7

    .line 15
    :goto_0
    and-int/lit8 v2, v1, 0x8

    .line 16
    .line 17
    const/4 v4, 0x1

    .line 18
    const/4 v5, 0x0

    .line 19
    if-eqz v2, :cond_1

    .line 20
    .line 21
    move v2, v4

    .line 22
    move v4, v5

    .line 23
    goto :goto_1

    .line 24
    :cond_1
    move v2, v4

    .line 25
    :goto_1
    and-int/lit8 v6, v1, 0x10

    .line 26
    .line 27
    if-eqz v6, :cond_2

    .line 28
    .line 29
    move v6, v5

    .line 30
    goto :goto_2

    .line 31
    :cond_2
    move v6, v5

    .line 32
    move v5, v2

    .line 33
    :goto_2
    and-int/lit8 v1, v1, 0x20

    .line 34
    .line 35
    if-eqz v1, :cond_3

    .line 36
    .line 37
    goto :goto_3

    .line 38
    :cond_3
    move v6, v2

    .line 39
    :goto_3
    const/4 v1, 0x0

    .line 40
    const/4 v2, 0x0

    .line 41
    invoke-direct/range {v0 .. v6}, Lh40/k0;-><init>(Lql0/g;ZLjava/util/List;IZZ)V

    .line 42
    .line 43
    .line 44
    invoke-direct {p0, v0}, Lql0/j;-><init>(Lql0/h;)V

    .line 45
    .line 46
    .line 47
    iput-object p1, p0, Lh40/l0;->h:Lij0/a;

    .line 48
    .line 49
    iput-object p2, p0, Lh40/l0;->i:Ltr0/b;

    .line 50
    .line 51
    iput-object p3, p0, Lh40/l0;->j:Lf40/h1;

    .line 52
    .line 53
    iput-object p4, p0, Lh40/l0;->k:Lf40/v1;

    .line 54
    .line 55
    new-instance p1, Lh40/h;

    .line 56
    .line 57
    const/4 p2, 0x3

    .line 58
    invoke-direct {p1, p0, v7, p2}, Lh40/h;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 59
    .line 60
    .line 61
    invoke-virtual {p0, p1}, Lql0/j;->b(Lay0/n;)V

    .line 62
    .line 63
    .line 64
    return-void
.end method


# virtual methods
.method public final h(I)V
    .locals 9

    .line 1
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    move-object v1, v0

    .line 6
    check-cast v1, Lh40/k0;

    .line 7
    .line 8
    const/4 v0, 0x0

    .line 9
    const/4 v2, 0x1

    .line 10
    if-lez p1, :cond_0

    .line 11
    .line 12
    move v6, v2

    .line 13
    goto :goto_0

    .line 14
    :cond_0
    move v6, v0

    .line 15
    :goto_0
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 16
    .line 17
    .line 18
    move-result-object v3

    .line 19
    check-cast v3, Lh40/k0;

    .line 20
    .line 21
    iget-object v3, v3, Lh40/k0;->c:Ljava/util/List;

    .line 22
    .line 23
    invoke-interface {v3}, Ljava/util/List;->size()I

    .line 24
    .line 25
    .line 26
    move-result v3

    .line 27
    sub-int/2addr v3, v2

    .line 28
    if-ge p1, v3, :cond_1

    .line 29
    .line 30
    move v7, v2

    .line 31
    goto :goto_1

    .line 32
    :cond_1
    move v7, v0

    .line 33
    :goto_1
    const/4 v8, 0x7

    .line 34
    const/4 v2, 0x0

    .line 35
    const/4 v3, 0x0

    .line 36
    const/4 v4, 0x0

    .line 37
    move v5, p1

    .line 38
    invoke-static/range {v1 .. v8}, Lh40/k0;->a(Lh40/k0;Lql0/g;ZLjava/util/ArrayList;IZZI)Lh40/k0;

    .line 39
    .line 40
    .line 41
    move-result-object p1

    .line 42
    invoke-virtual {p0, p1}, Lql0/j;->g(Lql0/h;)V

    .line 43
    .line 44
    .line 45
    return-void
.end method
