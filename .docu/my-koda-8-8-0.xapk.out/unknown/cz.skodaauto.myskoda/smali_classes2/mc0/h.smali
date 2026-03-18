.class public final Lmc0/h;
.super Lql0/j;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final h:Lkc0/t0;


# direct methods
.method public constructor <init>(Lkc0/t0;)V
    .locals 3

    .line 1
    sget-object v0, Lmc0/g;->a:Lmc0/g;

    .line 2
    .line 3
    invoke-direct {p0, v0}, Lql0/j;-><init>(Lql0/h;)V

    .line 4
    .line 5
    .line 6
    iput-object p1, p0, Lmc0/h;->h:Lkc0/t0;

    .line 7
    .line 8
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 9
    .line 10
    .line 11
    move-result-object p1

    .line 12
    new-instance v0, Lk20/a;

    .line 13
    .line 14
    const/16 v1, 0x17

    .line 15
    .line 16
    const/4 v2, 0x0

    .line 17
    invoke-direct {v0, p0, v2, v1}, Lk20/a;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 18
    .line 19
    .line 20
    const/4 p0, 0x3

    .line 21
    invoke-static {p1, v2, v2, v0, p0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 22
    .line 23
    .line 24
    return-void
.end method
