.class public final Ls90/d;
.super Lql0/j;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final h:Lgn0/i;

.field public final i:Lq90/a;

.field public final j:Lij0/a;


# direct methods
.method public constructor <init>(Lgn0/i;Lq90/a;Lij0/a;)V
    .locals 4

    .line 1
    new-instance v0, Ls90/c;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    sget-object v2, Lmx0/s;->d:Lmx0/s;

    .line 5
    .line 6
    const-string v3, ""

    .line 7
    .line 8
    invoke-direct {v0, v3, v3, v1, v2}, Ls90/c;-><init>(Ljava/lang/String;Ljava/lang/String;ZLjava/util/List;)V

    .line 9
    .line 10
    .line 11
    invoke-direct {p0, v0}, Lql0/j;-><init>(Lql0/h;)V

    .line 12
    .line 13
    .line 14
    iput-object p1, p0, Ls90/d;->h:Lgn0/i;

    .line 15
    .line 16
    iput-object p2, p0, Ls90/d;->i:Lq90/a;

    .line 17
    .line 18
    iput-object p3, p0, Ls90/d;->j:Lij0/a;

    .line 19
    .line 20
    new-instance p1, Lrp0/a;

    .line 21
    .line 22
    const/4 p2, 0x0

    .line 23
    const/4 p3, 0x6

    .line 24
    invoke-direct {p1, p0, p2, p3}, Lrp0/a;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 25
    .line 26
    .line 27
    invoke-virtual {p0, p1}, Lql0/j;->b(Lay0/n;)V

    .line 28
    .line 29
    .line 30
    return-void
.end method
