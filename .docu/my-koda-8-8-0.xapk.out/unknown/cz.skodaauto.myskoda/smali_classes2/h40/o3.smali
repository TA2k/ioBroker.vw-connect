.class public final Lh40/o3;
.super Lql0/j;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final h:Lij0/a;

.field public final i:Lf40/j1;


# direct methods
.method public constructor <init>(Lij0/a;Lf40/j1;)V
    .locals 4

    .line 1
    new-instance v0, Lh40/n3;

    .line 2
    .line 3
    const/4 v1, 0x7

    .line 4
    const/4 v2, 0x0

    .line 5
    const/4 v3, 0x0

    .line 6
    invoke-direct {v0, v1, v2, v3}, Lh40/n3;-><init>(ILjava/util/List;Z)V

    .line 7
    .line 8
    .line 9
    invoke-direct {p0, v0}, Lql0/j;-><init>(Lql0/h;)V

    .line 10
    .line 11
    .line 12
    iput-object p1, p0, Lh40/o3;->h:Lij0/a;

    .line 13
    .line 14
    iput-object p2, p0, Lh40/o3;->i:Lf40/j1;

    .line 15
    .line 16
    new-instance p1, Lh40/h;

    .line 17
    .line 18
    const/4 p2, 0x7

    .line 19
    invoke-direct {p1, p0, v2, p2}, Lh40/h;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 20
    .line 21
    .line 22
    invoke-virtual {p0, p1}, Lql0/j;->b(Lay0/n;)V

    .line 23
    .line 24
    .line 25
    return-void
.end method
