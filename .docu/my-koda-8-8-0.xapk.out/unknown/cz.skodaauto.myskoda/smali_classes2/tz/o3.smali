.class public final Ltz/o3;
.super Lql0/j;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final h:Ltr0/b;

.field public final i:Lbd0/c;


# direct methods
.method public constructor <init>(Lro0/i;Ltr0/b;Lbd0/c;)V
    .locals 3

    .line 1
    new-instance v0, Ltz/n3;

    .line 2
    .line 3
    const/4 v1, 0x1

    .line 4
    sget-object v2, Lmx0/s;->d:Lmx0/s;

    .line 5
    .line 6
    invoke-direct {v0, v1, v2}, Ltz/n3;-><init>(ZLjava/util/List;)V

    .line 7
    .line 8
    .line 9
    invoke-direct {p0, v0}, Lql0/j;-><init>(Lql0/h;)V

    .line 10
    .line 11
    .line 12
    iput-object p2, p0, Ltz/o3;->h:Ltr0/b;

    .line 13
    .line 14
    iput-object p3, p0, Ltz/o3;->i:Lbd0/c;

    .line 15
    .line 16
    new-instance p2, Ltz/o2;

    .line 17
    .line 18
    const/4 p3, 0x0

    .line 19
    const/4 v0, 0x4

    .line 20
    invoke-direct {p2, v0, p1, p0, p3}, Ltz/o2;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 21
    .line 22
    .line 23
    invoke-virtual {p0, p2}, Lql0/j;->b(Lay0/n;)V

    .line 24
    .line 25
    .line 26
    return-void
.end method
