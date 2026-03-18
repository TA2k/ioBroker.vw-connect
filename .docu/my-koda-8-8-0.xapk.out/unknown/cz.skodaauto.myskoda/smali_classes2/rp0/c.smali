.class public final Lrp0/c;
.super Lql0/j;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final h:Lpp0/h0;


# direct methods
.method public constructor <init>(Lpp0/h0;)V
    .locals 3

    .line 1
    new-instance v0, Lrp0/b;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-direct {v0, v1}, Lrp0/b;-><init>(Z)V

    .line 5
    .line 6
    .line 7
    invoke-direct {p0, v0}, Lql0/j;-><init>(Lql0/h;)V

    .line 8
    .line 9
    .line 10
    iput-object p1, p0, Lrp0/c;->h:Lpp0/h0;

    .line 11
    .line 12
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 13
    .line 14
    .line 15
    move-result-object p1

    .line 16
    new-instance v0, Lrp0/a;

    .line 17
    .line 18
    const/4 v2, 0x0

    .line 19
    invoke-direct {v0, p0, v2, v1}, Lrp0/a;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 20
    .line 21
    .line 22
    const/4 p0, 0x3

    .line 23
    invoke-static {p1, v2, v2, v0, p0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 24
    .line 25
    .line 26
    return-void
.end method
