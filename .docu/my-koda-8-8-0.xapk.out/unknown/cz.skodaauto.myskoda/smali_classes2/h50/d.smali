.class public final Lh50/d;
.super Lql0/j;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final h:Ltr0/b;

.field public final i:Lpp0/f0;

.field public final j:Lij0/a;

.field public final k:Lpp0/p1;

.field public final l:Lrq0/d;


# direct methods
.method public constructor <init>(Ltr0/b;Lpp0/f0;Lij0/a;Lpp0/p1;Lrq0/d;)V
    .locals 7

    .line 1
    new-instance v0, Lh50/c;

    .line 2
    .line 3
    const/16 v1, 0x1f

    .line 4
    .line 5
    and-int/lit8 v2, v1, 0x2

    .line 6
    .line 7
    const/4 v6, 0x0

    .line 8
    if-eqz v2, :cond_0

    .line 9
    .line 10
    sget-object v2, Lmx0/s;->d:Lmx0/s;

    .line 11
    .line 12
    goto :goto_0

    .line 13
    :cond_0
    move-object v2, v6

    .line 14
    :goto_0
    and-int/lit8 v1, v1, 0x4

    .line 15
    .line 16
    if-eqz v1, :cond_1

    .line 17
    .line 18
    const/4 v1, 0x0

    .line 19
    :goto_1
    move v3, v1

    .line 20
    goto :goto_2

    .line 21
    :cond_1
    const/4 v1, 0x3

    .line 22
    goto :goto_1

    .line 23
    :goto_2
    const/4 v4, 0x0

    .line 24
    const/4 v5, 0x0

    .line 25
    const/4 v1, 0x0

    .line 26
    invoke-direct/range {v0 .. v5}, Lh50/c;-><init>(Ljava/util/UUID;Ljava/util/List;IZZ)V

    .line 27
    .line 28
    .line 29
    invoke-direct {p0, v0}, Lql0/j;-><init>(Lql0/h;)V

    .line 30
    .line 31
    .line 32
    iput-object p1, p0, Lh50/d;->h:Ltr0/b;

    .line 33
    .line 34
    iput-object p2, p0, Lh50/d;->i:Lpp0/f0;

    .line 35
    .line 36
    iput-object p3, p0, Lh50/d;->j:Lij0/a;

    .line 37
    .line 38
    iput-object p4, p0, Lh50/d;->k:Lpp0/p1;

    .line 39
    .line 40
    iput-object p5, p0, Lh50/d;->l:Lrq0/d;

    .line 41
    .line 42
    new-instance p1, Lh50/b;

    .line 43
    .line 44
    const/4 p2, 0x0

    .line 45
    invoke-direct {p1, p0, v6, p2}, Lh50/b;-><init>(Lh50/d;Lkotlin/coroutines/Continuation;I)V

    .line 46
    .line 47
    .line 48
    invoke-virtual {p0, p1}, Lql0/j;->b(Lay0/n;)V

    .line 49
    .line 50
    .line 51
    return-void
.end method
