.class public final Lqk0/c;
.super Lql0/j;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final h:Lfg0/a;

.field public final i:Ltn0/e;

.field public final j:Lok0/l;


# direct methods
.method public constructor <init>(Lok0/e;Ltn0/b;Lfg0/a;Ltn0/e;Lok0/l;)V
    .locals 3

    .line 1
    new-instance v0, Lqk0/a;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    const/4 v2, 0x3

    .line 5
    invoke-direct {v0, v1, v2}, Lqk0/a;-><init>(Ljava/util/List;I)V

    .line 6
    .line 7
    .line 8
    invoke-direct {p0, v0}, Lql0/j;-><init>(Lql0/h;)V

    .line 9
    .line 10
    .line 11
    iput-object p3, p0, Lqk0/c;->h:Lfg0/a;

    .line 12
    .line 13
    iput-object p4, p0, Lqk0/c;->i:Ltn0/e;

    .line 14
    .line 15
    iput-object p5, p0, Lqk0/c;->j:Lok0/l;

    .line 16
    .line 17
    new-instance p3, Lna/e;

    .line 18
    .line 19
    const/16 p4, 0x1a

    .line 20
    .line 21
    invoke-direct {p3, p4, p1, p0, v1}, Lna/e;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 22
    .line 23
    .line 24
    invoke-virtual {p0, p3}, Lql0/j;->b(Lay0/n;)V

    .line 25
    .line 26
    .line 27
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 28
    .line 29
    .line 30
    move-result-object p1

    .line 31
    new-instance p3, Lny/f0;

    .line 32
    .line 33
    const/16 p4, 0x12

    .line 34
    .line 35
    invoke-direct {p3, p4, p0, p2, v1}, Lny/f0;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 36
    .line 37
    .line 38
    invoke-static {p1, v1, v1, p3, v2}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 39
    .line 40
    .line 41
    return-void
.end method
