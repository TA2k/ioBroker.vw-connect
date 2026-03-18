.class public final Ly70/l0;
.super Lql0/j;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final h:Lxf0/a;

.field public final i:Lij0/a;

.field public final j:Ltr0/b;

.field public final k:Lw70/p;

.field public final l:Lw70/e0;


# direct methods
.method public constructor <init>(Lxf0/a;Lij0/a;Ltr0/b;Lw70/p;Lw70/e0;)V
    .locals 3

    .line 1
    new-instance v0, Ly70/k0;

    .line 2
    .line 3
    sget-object v1, Lmx0/s;->d:Lmx0/s;

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    invoke-direct {v0, v2, v1}, Ly70/k0;-><init>(Lql0/g;Ljava/util/List;)V

    .line 7
    .line 8
    .line 9
    invoke-direct {p0, v0}, Lql0/j;-><init>(Lql0/h;)V

    .line 10
    .line 11
    .line 12
    iput-object p1, p0, Ly70/l0;->h:Lxf0/a;

    .line 13
    .line 14
    iput-object p2, p0, Ly70/l0;->i:Lij0/a;

    .line 15
    .line 16
    iput-object p3, p0, Ly70/l0;->j:Ltr0/b;

    .line 17
    .line 18
    iput-object p4, p0, Ly70/l0;->k:Lw70/p;

    .line 19
    .line 20
    iput-object p5, p0, Ly70/l0;->l:Lw70/e0;

    .line 21
    .line 22
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 23
    .line 24
    .line 25
    move-result-object p1

    .line 26
    new-instance p2, Lxm0/g;

    .line 27
    .line 28
    const/4 p3, 0x6

    .line 29
    invoke-direct {p2, p0, v2, p3}, Lxm0/g;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 30
    .line 31
    .line 32
    const/4 p0, 0x3

    .line 33
    invoke-static {p1, v2, v2, p2, p0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 34
    .line 35
    .line 36
    return-void
.end method
