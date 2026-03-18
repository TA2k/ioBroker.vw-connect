.class public final Lma0/g;
.super Lql0/j;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final h:Ltr0/b;

.field public final i:Lgn0/f;

.field public final j:Lka0/a;

.field public final k:Lka0/c;

.field public final l:Lbh0/i;

.field public final m:Lij0/a;


# direct methods
.method public constructor <init>(Ltr0/b;Lgn0/f;Lka0/a;Lka0/c;Lbh0/i;Lij0/a;)V
    .locals 7

    .line 1
    new-instance v0, Lma0/f;

    .line 2
    .line 3
    const/4 v5, 0x0

    .line 4
    const/4 v6, 0x0

    .line 5
    sget-object v1, Lmx0/s;->d:Lmx0/s;

    .line 6
    .line 7
    const/4 v3, 0x0

    .line 8
    const/4 v4, 0x0

    .line 9
    move-object v2, v1

    .line 10
    invoke-direct/range {v0 .. v6}, Lma0/f;-><init>(Ljava/util/List;Ljava/util/List;Lql0/g;ZZZ)V

    .line 11
    .line 12
    .line 13
    invoke-direct {p0, v0}, Lql0/j;-><init>(Lql0/h;)V

    .line 14
    .line 15
    .line 16
    iput-object p1, p0, Lma0/g;->h:Ltr0/b;

    .line 17
    .line 18
    iput-object p2, p0, Lma0/g;->i:Lgn0/f;

    .line 19
    .line 20
    iput-object p3, p0, Lma0/g;->j:Lka0/a;

    .line 21
    .line 22
    iput-object p4, p0, Lma0/g;->k:Lka0/c;

    .line 23
    .line 24
    iput-object p5, p0, Lma0/g;->l:Lbh0/i;

    .line 25
    .line 26
    iput-object p6, p0, Lma0/g;->m:Lij0/a;

    .line 27
    .line 28
    new-instance p1, Lk20/a;

    .line 29
    .line 30
    const/4 p2, 0x0

    .line 31
    const/16 p3, 0x15

    .line 32
    .line 33
    invoke-direct {p1, p0, p2, p3}, Lk20/a;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 34
    .line 35
    .line 36
    invoke-virtual {p0, p1}, Lql0/j;->b(Lay0/n;)V

    .line 37
    .line 38
    .line 39
    return-void
.end method
