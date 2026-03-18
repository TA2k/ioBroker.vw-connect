.class public final Lsa0/k;
.super Lql0/j;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final h:Lcs0/d0;

.field public final i:Lcs0/t;

.field public final j:Lqa0/e;

.field public final k:Ltr0/b;


# direct methods
.method public constructor <init>(Lcs0/d0;Lcs0/t;Lqa0/e;Ltr0/b;)V
    .locals 3

    .line 1
    new-instance v0, Lsa0/j;

    .line 2
    .line 3
    sget-object v1, Lmx0/s;->d:Lmx0/s;

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    invoke-direct {v0, v1, v2}, Lsa0/j;-><init>(Ljava/util/List;Z)V

    .line 7
    .line 8
    .line 9
    invoke-direct {p0, v0}, Lql0/j;-><init>(Lql0/h;)V

    .line 10
    .line 11
    .line 12
    iput-object p1, p0, Lsa0/k;->h:Lcs0/d0;

    .line 13
    .line 14
    iput-object p2, p0, Lsa0/k;->i:Lcs0/t;

    .line 15
    .line 16
    iput-object p3, p0, Lsa0/k;->j:Lqa0/e;

    .line 17
    .line 18
    iput-object p4, p0, Lsa0/k;->k:Ltr0/b;

    .line 19
    .line 20
    new-instance p1, Lsa0/i;

    .line 21
    .line 22
    const/4 p2, 0x0

    .line 23
    const/4 p3, 0x0

    .line 24
    invoke-direct {p1, p0, p3, p2}, Lsa0/i;-><init>(Lsa0/k;Lkotlin/coroutines/Continuation;I)V

    .line 25
    .line 26
    .line 27
    invoke-virtual {p0, p1}, Lql0/j;->b(Lay0/n;)V

    .line 28
    .line 29
    .line 30
    new-instance p1, Lsa0/i;

    .line 31
    .line 32
    const/4 p2, 0x1

    .line 33
    invoke-direct {p1, p0, p3, p2}, Lsa0/i;-><init>(Lsa0/k;Lkotlin/coroutines/Continuation;I)V

    .line 34
    .line 35
    .line 36
    invoke-virtual {p0, p1}, Lql0/j;->b(Lay0/n;)V

    .line 37
    .line 38
    .line 39
    return-void
.end method
