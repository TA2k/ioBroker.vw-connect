.class public final Lq30/d;
.super Lql0/j;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final h:Lhh0/a;

.field public final i:Lo30/l;

.field public final j:Lo30/m;

.field public final k:Lo30/f;

.field public final l:Lwr0/e;


# direct methods
.method public constructor <init>(Lhh0/a;Lo30/l;Lo30/m;Lo30/f;Lwr0/e;)V
    .locals 2

    .line 1
    new-instance v0, Lq30/c;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-direct {v0, v1, v1}, Lq30/c;-><init>(ZZ)V

    .line 5
    .line 6
    .line 7
    invoke-direct {p0, v0}, Lql0/j;-><init>(Lql0/h;)V

    .line 8
    .line 9
    .line 10
    iput-object p1, p0, Lq30/d;->h:Lhh0/a;

    .line 11
    .line 12
    iput-object p2, p0, Lq30/d;->i:Lo30/l;

    .line 13
    .line 14
    iput-object p3, p0, Lq30/d;->j:Lo30/m;

    .line 15
    .line 16
    iput-object p4, p0, Lq30/d;->k:Lo30/f;

    .line 17
    .line 18
    iput-object p5, p0, Lq30/d;->l:Lwr0/e;

    .line 19
    .line 20
    new-instance p1, Lac0/m;

    .line 21
    .line 22
    const/4 p2, 0x0

    .line 23
    const/16 p3, 0xa

    .line 24
    .line 25
    invoke-direct {p1, p0, p2, p3}, Lac0/m;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 26
    .line 27
    .line 28
    invoke-virtual {p0, p1}, Lql0/j;->b(Lay0/n;)V

    .line 29
    .line 30
    .line 31
    return-void
.end method
