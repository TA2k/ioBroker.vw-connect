.class public final Lh40/s0;
.super Lql0/j;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final h:Ltr0/b;

.field public final i:Lf40/h1;

.field public final j:Lf40/q;

.field public final k:Lij0/a;

.field public final l:Lf40/r1;


# direct methods
.method public constructor <init>(Ltr0/b;Lf40/h1;Lf40/q;Lij0/a;Lf40/r1;)V
    .locals 7

    .line 1
    new-instance v0, Lh40/r0;

    .line 2
    .line 3
    sget-object v5, Lh40/b;->e:Lh40/b;

    .line 4
    .line 5
    sget-object v6, Lmx0/s;->d:Lmx0/s;

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
    invoke-direct/range {v0 .. v6}, Lh40/r0;-><init>(ZLql0/g;ZZLh40/b;Ljava/util/List;)V

    .line 12
    .line 13
    .line 14
    invoke-direct {p0, v0}, Lql0/j;-><init>(Lql0/h;)V

    .line 15
    .line 16
    .line 17
    iput-object p1, p0, Lh40/s0;->h:Ltr0/b;

    .line 18
    .line 19
    iput-object p2, p0, Lh40/s0;->i:Lf40/h1;

    .line 20
    .line 21
    iput-object p3, p0, Lh40/s0;->j:Lf40/q;

    .line 22
    .line 23
    iput-object p4, p0, Lh40/s0;->k:Lij0/a;

    .line 24
    .line 25
    iput-object p5, p0, Lh40/s0;->l:Lf40/r1;

    .line 26
    .line 27
    new-instance p1, Lh40/q0;

    .line 28
    .line 29
    const/4 p2, 0x0

    .line 30
    const/4 p3, 0x0

    .line 31
    invoke-direct {p1, p0, p2, p3}, Lh40/q0;-><init>(Lh40/s0;Lkotlin/coroutines/Continuation;I)V

    .line 32
    .line 33
    .line 34
    invoke-virtual {p0, p1}, Lql0/j;->b(Lay0/n;)V

    .line 35
    .line 36
    .line 37
    return-void
.end method
