.class public final Lh40/p1;
.super Lql0/j;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final h:Ltr0/b;

.field public final i:Lf40/o1;

.field public final j:Lf40/x;

.field public final k:Lij0/a;


# direct methods
.method public constructor <init>(Ltr0/b;Lf40/o1;Lf40/x;Lij0/a;)V
    .locals 7

    .line 1
    new-instance v0, Lh40/o1;

    .line 2
    .line 3
    const/16 v1, 0x1f

    .line 4
    .line 5
    and-int/lit8 v2, v1, 0x2

    .line 6
    .line 7
    const/4 v3, 0x1

    .line 8
    const/4 v4, 0x0

    .line 9
    if-eqz v2, :cond_0

    .line 10
    .line 11
    move v2, v4

    .line 12
    goto :goto_0

    .line 13
    :cond_0
    move v2, v3

    .line 14
    :goto_0
    and-int/lit8 v5, v1, 0x8

    .line 15
    .line 16
    if-eqz v5, :cond_1

    .line 17
    .line 18
    goto :goto_1

    .line 19
    :cond_1
    move v4, v3

    .line 20
    :goto_1
    and-int/lit8 v1, v1, 0x10

    .line 21
    .line 22
    const/4 v6, 0x0

    .line 23
    if-eqz v1, :cond_2

    .line 24
    .line 25
    sget-object v1, Lmx0/s;->d:Lmx0/s;

    .line 26
    .line 27
    move-object v5, v1

    .line 28
    goto :goto_2

    .line 29
    :cond_2
    move-object v5, v6

    .line 30
    :goto_2
    const/4 v1, 0x0

    .line 31
    const/4 v3, 0x0

    .line 32
    invoke-direct/range {v0 .. v5}, Lh40/o1;-><init>(Lql0/g;ZZZLjava/util/List;)V

    .line 33
    .line 34
    .line 35
    invoke-direct {p0, v0}, Lql0/j;-><init>(Lql0/h;)V

    .line 36
    .line 37
    .line 38
    iput-object p1, p0, Lh40/p1;->h:Ltr0/b;

    .line 39
    .line 40
    iput-object p2, p0, Lh40/p1;->i:Lf40/o1;

    .line 41
    .line 42
    iput-object p3, p0, Lh40/p1;->j:Lf40/x;

    .line 43
    .line 44
    iput-object p4, p0, Lh40/p1;->k:Lij0/a;

    .line 45
    .line 46
    new-instance p1, Lh40/m1;

    .line 47
    .line 48
    const/4 p2, 0x0

    .line 49
    invoke-direct {p1, p0, v6, p2}, Lh40/m1;-><init>(Lh40/p1;Lkotlin/coroutines/Continuation;I)V

    .line 50
    .line 51
    .line 52
    invoke-virtual {p0, p1}, Lql0/j;->b(Lay0/n;)V

    .line 53
    .line 54
    .line 55
    return-void
.end method
