.class public final Lhk0/c;
.super Lql0/j;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public constructor <init>(Lgk0/a;Lwj0/k;Lal0/s0;)V
    .locals 10

    .line 1
    new-instance v0, Lhk0/b;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    const/4 v2, 0x0

    .line 5
    invoke-direct {v0, v1, v2, v1, v1}, Lhk0/b;-><init>(ZFII)V

    .line 6
    .line 7
    .line 8
    invoke-direct {p0, v0}, Lql0/j;-><init>(Lql0/h;)V

    .line 9
    .line 10
    .line 11
    new-instance v3, Lh7/z;

    .line 12
    .line 13
    const/4 v8, 0x0

    .line 14
    const/4 v9, 0x1

    .line 15
    move-object v5, p0

    .line 16
    move-object v4, p1

    .line 17
    move-object v7, p2

    .line 18
    move-object v6, p3

    .line 19
    invoke-direct/range {v3 .. v9}, Lh7/z;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 20
    .line 21
    .line 22
    invoke-virtual {v5, v3}, Lql0/j;->b(Lay0/n;)V

    .line 23
    .line 24
    .line 25
    return-void
.end method
