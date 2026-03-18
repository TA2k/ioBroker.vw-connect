.class public final Ltz/k2;
.super Lql0/j;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final h:Lrz/c;

.field public final i:Lqd0/r0;

.field public final j:Lqd0/y0;

.field public final k:Ltr0/b;

.field public l:Lrd0/r;


# direct methods
.method public constructor <init>(Lrz/c;Lqd0/r0;Lqd0/y0;Ltr0/b;)V
    .locals 3

    .line 1
    new-instance v0, Ltz/j2;

    .line 2
    .line 3
    const-string v1, ""

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    invoke-direct {v0, v1, v2, v2}, Ltz/j2;-><init>(Ljava/lang/String;ZZ)V

    .line 7
    .line 8
    .line 9
    invoke-direct {p0, v0}, Lql0/j;-><init>(Lql0/h;)V

    .line 10
    .line 11
    .line 12
    iput-object p1, p0, Ltz/k2;->h:Lrz/c;

    .line 13
    .line 14
    iput-object p2, p0, Ltz/k2;->i:Lqd0/r0;

    .line 15
    .line 16
    iput-object p3, p0, Ltz/k2;->j:Lqd0/y0;

    .line 17
    .line 18
    iput-object p4, p0, Ltz/k2;->k:Ltr0/b;

    .line 19
    .line 20
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 21
    .line 22
    .line 23
    move-result-object p1

    .line 24
    new-instance p2, Lrp0/a;

    .line 25
    .line 26
    const/16 p3, 0x13

    .line 27
    .line 28
    const/4 p4, 0x0

    .line 29
    invoke-direct {p2, p0, p4, p3}, Lrp0/a;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 30
    .line 31
    .line 32
    const/4 p0, 0x3

    .line 33
    invoke-static {p1, p4, p4, p2, p0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 34
    .line 35
    .line 36
    return-void
.end method
