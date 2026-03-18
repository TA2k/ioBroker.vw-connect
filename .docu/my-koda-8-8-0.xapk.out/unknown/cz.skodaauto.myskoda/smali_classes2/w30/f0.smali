.class public final Lw30/f0;
.super Lql0/j;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final h:Ltr0/b;

.field public final i:Lag0/b;


# direct methods
.method public constructor <init>(Ltr0/b;Lag0/b;)V
    .locals 2

    .line 1
    new-instance v0, Lw30/e0;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-direct {v0, v1}, Lw30/e0;-><init>(Z)V

    .line 5
    .line 6
    .line 7
    invoke-direct {p0, v0}, Lql0/j;-><init>(Lql0/h;)V

    .line 8
    .line 9
    .line 10
    iput-object p1, p0, Lw30/f0;->h:Ltr0/b;

    .line 11
    .line 12
    iput-object p2, p0, Lw30/f0;->i:Lag0/b;

    .line 13
    .line 14
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 15
    .line 16
    .line 17
    move-result-object p1

    .line 18
    new-instance p2, Lvo0/e;

    .line 19
    .line 20
    const/4 v0, 0x5

    .line 21
    const/4 v1, 0x0

    .line 22
    invoke-direct {p2, p0, v1, v0}, Lvo0/e;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 23
    .line 24
    .line 25
    const/4 p0, 0x3

    .line 26
    invoke-static {p1, v1, v1, p2, p0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 27
    .line 28
    .line 29
    return-void
.end method
