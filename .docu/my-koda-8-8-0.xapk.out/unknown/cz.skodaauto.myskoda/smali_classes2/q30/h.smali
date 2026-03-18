.class public final Lq30/h;
.super Lql0/j;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final h:Ltr0/b;

.field public final i:Lwr0/i;

.field public final j:Lo30/n;

.field public final k:Lo30/j;

.field public final l:Lo30/d;


# direct methods
.method public constructor <init>(Ltr0/b;Lwr0/i;Lo30/n;Lo30/j;Lo30/d;)V
    .locals 6

    .line 1
    new-instance v0, Lq30/g;

    .line 2
    .line 3
    sget-object v3, Lmx0/s;->d:Lmx0/s;

    .line 4
    .line 5
    const/4 v5, 0x0

    .line 6
    const/4 v1, 0x0

    .line 7
    const-string v2, ""

    .line 8
    .line 9
    const/4 v4, 0x0

    .line 10
    invoke-direct/range {v0 .. v5}, Lq30/g;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/util/List;ZZ)V

    .line 11
    .line 12
    .line 13
    invoke-direct {p0, v0}, Lql0/j;-><init>(Lql0/h;)V

    .line 14
    .line 15
    .line 16
    iput-object p1, p0, Lq30/h;->h:Ltr0/b;

    .line 17
    .line 18
    iput-object p2, p0, Lq30/h;->i:Lwr0/i;

    .line 19
    .line 20
    iput-object p3, p0, Lq30/h;->j:Lo30/n;

    .line 21
    .line 22
    iput-object p4, p0, Lq30/h;->k:Lo30/j;

    .line 23
    .line 24
    iput-object p5, p0, Lq30/h;->l:Lo30/d;

    .line 25
    .line 26
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 27
    .line 28
    .line 29
    move-result-object p1

    .line 30
    new-instance p2, Lq30/f;

    .line 31
    .line 32
    const/4 p3, 0x0

    .line 33
    const/4 p4, 0x0

    .line 34
    invoke-direct {p2, p0, p4, p3}, Lq30/f;-><init>(Lq30/h;Lkotlin/coroutines/Continuation;I)V

    .line 35
    .line 36
    .line 37
    const/4 p3, 0x3

    .line 38
    invoke-static {p1, p4, p4, p2, p3}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 39
    .line 40
    .line 41
    new-instance p1, Lq30/f;

    .line 42
    .line 43
    const/4 p2, 0x1

    .line 44
    invoke-direct {p1, p0, p4, p2}, Lq30/f;-><init>(Lq30/h;Lkotlin/coroutines/Continuation;I)V

    .line 45
    .line 46
    .line 47
    invoke-virtual {p0, p1}, Lql0/j;->b(Lay0/n;)V

    .line 48
    .line 49
    .line 50
    return-void
.end method
