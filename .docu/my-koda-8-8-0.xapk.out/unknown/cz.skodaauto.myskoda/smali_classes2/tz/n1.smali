.class public final Ltz/n1;
.super Lql0/j;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final h:Lkf0/b0;

.field public final i:Lrz/x;

.field public final j:Lij0/a;


# direct methods
.method public constructor <init>(Lqd0/k0;Lkf0/e0;Lkf0/b0;Lrz/x;Lij0/a;)V
    .locals 3

    .line 1
    new-instance v0, Ltz/m1;

    .line 2
    .line 3
    const/16 v1, 0x1f

    .line 4
    .line 5
    move-object v2, p5

    .line 6
    const/4 p5, 0x0

    .line 7
    invoke-direct {v0, p5, v1}, Ltz/m1;-><init>(Llf0/i;I)V

    .line 8
    .line 9
    .line 10
    invoke-direct {p0, v0}, Lql0/j;-><init>(Lql0/h;)V

    .line 11
    .line 12
    .line 13
    iput-object p3, p0, Ltz/n1;->h:Lkf0/b0;

    .line 14
    .line 15
    iput-object p4, p0, Ltz/n1;->i:Lrz/x;

    .line 16
    .line 17
    iput-object v2, p0, Ltz/n1;->j:Lij0/a;

    .line 18
    .line 19
    move-object p4, p0

    .line 20
    new-instance p0, Ltr0/e;

    .line 21
    .line 22
    move-object p3, p1

    .line 23
    const/4 p1, 0x5

    .line 24
    invoke-direct/range {p0 .. p5}, Ltr0/e;-><init>(ILjava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 25
    .line 26
    .line 27
    invoke-virtual {p4, p0}, Lql0/j;->b(Lay0/n;)V

    .line 28
    .line 29
    .line 30
    invoke-static {p4}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 31
    .line 32
    .line 33
    move-result-object p0

    .line 34
    new-instance p1, Lrp0/a;

    .line 35
    .line 36
    const/16 p2, 0x12

    .line 37
    .line 38
    invoke-direct {p1, p4, p5, p2}, Lrp0/a;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 39
    .line 40
    .line 41
    const/4 p2, 0x3

    .line 42
    invoke-static {p0, p5, p5, p1, p2}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 43
    .line 44
    .line 45
    return-void
.end method
