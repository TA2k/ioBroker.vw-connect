.class public final Lh40/i2;
.super Lql0/j;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final h:Ltr0/b;

.field public final i:Lij0/a;

.field public final j:Lf40/j1;

.field public final k:Lf40/s;

.field public final l:Lf40/h2;

.field public final m:Lf40/i4;


# direct methods
.method public constructor <init>(Ltr0/b;Lij0/a;Lf40/j1;Lf40/s;Lf40/h2;Lf40/i4;)V
    .locals 7

    .line 1
    new-instance v0, Lh40/h2;

    .line 2
    .line 3
    sget-object v5, Lmx0/s;->d:Lmx0/s;

    .line 4
    .line 5
    sget-object v6, Lh40/l3;->e:Lh40/l3;

    .line 6
    .line 7
    const/4 v1, 0x0

    .line 8
    const/4 v2, 0x0

    .line 9
    const/4 v3, 0x0

    .line 10
    const/4 v4, 0x0

    .line 11
    invoke-direct/range {v0 .. v6}, Lh40/h2;-><init>(ZLql0/g;ZZLjava/util/List;Lh40/l3;)V

    .line 12
    .line 13
    .line 14
    invoke-direct {p0, v0}, Lql0/j;-><init>(Lql0/h;)V

    .line 15
    .line 16
    .line 17
    iput-object p1, p0, Lh40/i2;->h:Ltr0/b;

    .line 18
    .line 19
    iput-object p2, p0, Lh40/i2;->i:Lij0/a;

    .line 20
    .line 21
    iput-object p3, p0, Lh40/i2;->j:Lf40/j1;

    .line 22
    .line 23
    iput-object p4, p0, Lh40/i2;->k:Lf40/s;

    .line 24
    .line 25
    iput-object p5, p0, Lh40/i2;->l:Lf40/h2;

    .line 26
    .line 27
    iput-object p6, p0, Lh40/i2;->m:Lf40/i4;

    .line 28
    .line 29
    new-instance p1, Lh40/g2;

    .line 30
    .line 31
    const/4 p2, 0x0

    .line 32
    const/4 p3, 0x0

    .line 33
    invoke-direct {p1, p0, p2, p3}, Lh40/g2;-><init>(Lh40/i2;Lkotlin/coroutines/Continuation;I)V

    .line 34
    .line 35
    .line 36
    invoke-virtual {p0, p1}, Lql0/j;->b(Lay0/n;)V

    .line 37
    .line 38
    .line 39
    return-void
.end method
