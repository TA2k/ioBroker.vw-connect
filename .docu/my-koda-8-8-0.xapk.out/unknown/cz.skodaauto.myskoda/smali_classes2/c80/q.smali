.class public final Lc80/q;
.super Lql0/j;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final h:Lwq0/v;


# direct methods
.method public constructor <init>(Lwq0/v;)V
    .locals 2

    .line 1
    new-instance v0, Lc80/p;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-direct {v0, v1}, Lc80/p;-><init>(Lyq0/m;)V

    .line 5
    .line 6
    .line 7
    invoke-direct {p0, v0}, Lql0/j;-><init>(Lql0/h;)V

    .line 8
    .line 9
    .line 10
    iput-object p1, p0, Lc80/q;->h:Lwq0/v;

    .line 11
    .line 12
    new-instance p1, La50/a;

    .line 13
    .line 14
    const/16 v0, 0x13

    .line 15
    .line 16
    invoke-direct {p1, p0, v1, v0}, La50/a;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 17
    .line 18
    .line 19
    invoke-virtual {p0, p1}, Lql0/j;->b(Lay0/n;)V

    .line 20
    .line 21
    .line 22
    return-void
.end method
