.class public final Lx60/b;
.super Lql0/j;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final h:Lzd0/a;

.field public final i:Lwr0/a;

.field public final j:Lkc0/j;

.field public final k:Lij0/a;


# direct methods
.method public constructor <init>(Lzd0/a;Lwr0/a;Lkc0/j;Lij0/a;)V
    .locals 2

    .line 1
    new-instance v0, Lx60/a;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-direct {v0, v1}, Lx60/a;-><init>(Lql0/g;)V

    .line 5
    .line 6
    .line 7
    invoke-direct {p0, v0}, Lql0/j;-><init>(Lql0/h;)V

    .line 8
    .line 9
    .line 10
    iput-object p1, p0, Lx60/b;->h:Lzd0/a;

    .line 11
    .line 12
    iput-object p2, p0, Lx60/b;->i:Lwr0/a;

    .line 13
    .line 14
    iput-object p3, p0, Lx60/b;->j:Lkc0/j;

    .line 15
    .line 16
    iput-object p4, p0, Lx60/b;->k:Lij0/a;

    .line 17
    .line 18
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 19
    .line 20
    .line 21
    move-result-object p1

    .line 22
    new-instance p2, Lvo0/e;

    .line 23
    .line 24
    const/16 p3, 0x14

    .line 25
    .line 26
    invoke-direct {p2, p0, v1, p3}, Lvo0/e;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 27
    .line 28
    .line 29
    const/4 p0, 0x3

    .line 30
    invoke-static {p1, v1, v1, p2, p0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 31
    .line 32
    .line 33
    return-void
.end method
