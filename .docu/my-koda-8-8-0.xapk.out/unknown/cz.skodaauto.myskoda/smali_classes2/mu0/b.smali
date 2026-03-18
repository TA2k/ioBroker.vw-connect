.class public final Lmu0/b;
.super Lql0/j;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final h:Lku0/b;


# direct methods
.method public constructor <init>(Lku0/b;)V
    .locals 3

    .line 1
    new-instance v0, Lmu0/a;

    .line 2
    .line 3
    sget-object v1, Lmx0/s;->d:Lmx0/s;

    .line 4
    .line 5
    const/4 v2, 0x1

    .line 6
    invoke-direct {v0, v1, v2}, Lmu0/a;-><init>(Ljava/util/List;Z)V

    .line 7
    .line 8
    .line 9
    invoke-direct {p0, v0}, Lql0/j;-><init>(Lql0/h;)V

    .line 10
    .line 11
    .line 12
    iput-object p1, p0, Lmu0/b;->h:Lku0/b;

    .line 13
    .line 14
    new-instance p1, Lk20/a;

    .line 15
    .line 16
    const/4 v0, 0x0

    .line 17
    const/16 v1, 0x1c

    .line 18
    .line 19
    invoke-direct {p1, p0, v0, v1}, Lk20/a;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 20
    .line 21
    .line 22
    invoke-virtual {p0, p1}, Lql0/j;->b(Lay0/n;)V

    .line 23
    .line 24
    .line 25
    return-void
.end method
