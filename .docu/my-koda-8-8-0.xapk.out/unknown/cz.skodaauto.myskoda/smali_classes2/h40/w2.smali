.class public final Lh40/w2;
.super Lql0/j;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final h:Lf40/l1;

.field public final i:Lf40/o2;

.field public final j:Lf40/f2;

.field public final k:Lwr0/l;

.field public final l:Lf40/f0;

.field public final m:Lf40/u;

.field public final n:Lij0/a;


# direct methods
.method public constructor <init>(Lf40/l1;Lf40/o2;Lf40/f2;Lwr0/l;Lf40/f0;Lf40/u;Lij0/a;)V
    .locals 3

    .line 1
    new-instance v0, Lh40/v2;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    const/16 v2, 0x3f

    .line 5
    .line 6
    invoke-direct {v0, v2, v1}, Lh40/v2;-><init>(IZ)V

    .line 7
    .line 8
    .line 9
    invoke-direct {p0, v0}, Lql0/j;-><init>(Lql0/h;)V

    .line 10
    .line 11
    .line 12
    iput-object p1, p0, Lh40/w2;->h:Lf40/l1;

    .line 13
    .line 14
    iput-object p2, p0, Lh40/w2;->i:Lf40/o2;

    .line 15
    .line 16
    iput-object p3, p0, Lh40/w2;->j:Lf40/f2;

    .line 17
    .line 18
    iput-object p4, p0, Lh40/w2;->k:Lwr0/l;

    .line 19
    .line 20
    iput-object p5, p0, Lh40/w2;->l:Lf40/f0;

    .line 21
    .line 22
    iput-object p6, p0, Lh40/w2;->m:Lf40/u;

    .line 23
    .line 24
    iput-object p7, p0, Lh40/w2;->n:Lij0/a;

    .line 25
    .line 26
    new-instance p1, Lg60/w;

    .line 27
    .line 28
    const/4 p2, 0x0

    .line 29
    const/16 p3, 0x1a

    .line 30
    .line 31
    invoke-direct {p1, p0, p2, p3}, Lg60/w;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 32
    .line 33
    .line 34
    invoke-virtual {p0, p1}, Lql0/j;->b(Lay0/n;)V

    .line 35
    .line 36
    .line 37
    return-void
.end method
