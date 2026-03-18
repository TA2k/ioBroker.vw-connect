.class public final La60/j;
.super Lql0/j;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final h:Ltr0/b;

.field public final i:Lbd0/c;

.field public final j:Lgf0/e;


# direct methods
.method public constructor <init>(Ly50/d;Ltr0/b;Lbd0/c;Lgf0/e;)V
    .locals 2

    .line 1
    new-instance v0, La60/i;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-direct {v0, v1}, La60/i;-><init>(La60/h;)V

    .line 5
    .line 6
    .line 7
    invoke-direct {p0, v0}, Lql0/j;-><init>(Lql0/h;)V

    .line 8
    .line 9
    .line 10
    iput-object p2, p0, La60/j;->h:Ltr0/b;

    .line 11
    .line 12
    iput-object p3, p0, La60/j;->i:Lbd0/c;

    .line 13
    .line 14
    iput-object p4, p0, La60/j;->j:Lgf0/e;

    .line 15
    .line 16
    new-instance p2, La60/f;

    .line 17
    .line 18
    const/4 p3, 0x0

    .line 19
    invoke-direct {p2, p3, p0, p1, v1}, La60/f;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 20
    .line 21
    .line 22
    invoke-virtual {p0, p2}, Lql0/j;->b(Lay0/n;)V

    .line 23
    .line 24
    .line 25
    return-void
.end method
