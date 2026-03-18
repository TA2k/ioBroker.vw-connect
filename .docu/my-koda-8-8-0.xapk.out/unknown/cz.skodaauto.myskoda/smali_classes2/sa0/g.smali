.class public final Lsa0/g;
.super Lql0/j;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final h:Ltr0/b;

.field public final i:Lbq0/j;

.field public final j:Lqa0/e;

.field public final k:Lbh0/g;

.field public final l:Lbh0/j;


# direct methods
.method public constructor <init>(Ltr0/b;Lbq0/j;Lqa0/e;Lbh0/g;Lbh0/j;)V
    .locals 3

    .line 1
    new-instance v0, Lsa0/e;

    .line 2
    .line 3
    sget-object v1, Lra0/b;->d:Lra0/b;

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    invoke-direct {v0, v1, v2}, Lsa0/e;-><init>(Lra0/b;Lcq0/x;)V

    .line 7
    .line 8
    .line 9
    invoke-direct {p0, v0}, Lql0/j;-><init>(Lql0/h;)V

    .line 10
    .line 11
    .line 12
    iput-object p1, p0, Lsa0/g;->h:Ltr0/b;

    .line 13
    .line 14
    iput-object p2, p0, Lsa0/g;->i:Lbq0/j;

    .line 15
    .line 16
    iput-object p3, p0, Lsa0/g;->j:Lqa0/e;

    .line 17
    .line 18
    iput-object p4, p0, Lsa0/g;->k:Lbh0/g;

    .line 19
    .line 20
    iput-object p5, p0, Lsa0/g;->l:Lbh0/j;

    .line 21
    .line 22
    new-instance p1, Lsa0/d;

    .line 23
    .line 24
    const/4 p2, 0x0

    .line 25
    invoke-direct {p1, p0, v2, p2}, Lsa0/d;-><init>(Lsa0/g;Lkotlin/coroutines/Continuation;I)V

    .line 26
    .line 27
    .line 28
    invoke-virtual {p0, p1}, Lql0/j;->b(Lay0/n;)V

    .line 29
    .line 30
    .line 31
    new-instance p1, Lsa0/d;

    .line 32
    .line 33
    const/4 p2, 0x1

    .line 34
    invoke-direct {p1, p0, v2, p2}, Lsa0/d;-><init>(Lsa0/g;Lkotlin/coroutines/Continuation;I)V

    .line 35
    .line 36
    .line 37
    invoke-virtual {p0, p1}, Lql0/j;->b(Lay0/n;)V

    .line 38
    .line 39
    .line 40
    return-void
.end method
