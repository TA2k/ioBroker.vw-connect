.class public final Le20/d;
.super Lql0/j;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final h:Ltr0/b;

.field public final i:Lbd0/c;

.field public final j:Lrq0/d;


# direct methods
.method public constructor <init>(Ltr0/b;Lbd0/c;Lrq0/d;Lc20/d;)V
    .locals 3

    .line 1
    new-instance v0, Le20/c;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    sget-object v2, Lmx0/s;->d:Lmx0/s;

    .line 5
    .line 6
    invoke-direct {v0, v2, v1, v1}, Le20/c;-><init>(Ljava/util/List;ZZ)V

    .line 7
    .line 8
    .line 9
    invoke-direct {p0, v0}, Lql0/j;-><init>(Lql0/h;)V

    .line 10
    .line 11
    .line 12
    iput-object p1, p0, Le20/d;->h:Ltr0/b;

    .line 13
    .line 14
    iput-object p2, p0, Le20/d;->i:Lbd0/c;

    .line 15
    .line 16
    iput-object p3, p0, Le20/d;->j:Lrq0/d;

    .line 17
    .line 18
    new-instance p1, Lc80/l;

    .line 19
    .line 20
    const/4 p2, 0x0

    .line 21
    const/16 p3, 0x19

    .line 22
    .line 23
    invoke-direct {p1, p3, p4, p0, p2}, Lc80/l;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 24
    .line 25
    .line 26
    invoke-virtual {p0, p1}, Lql0/j;->b(Lay0/n;)V

    .line 27
    .line 28
    .line 29
    return-void
.end method
