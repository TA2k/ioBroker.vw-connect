.class public final Lm80/o;
.super Lql0/j;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final h:Ltr0/b;

.field public final i:Lbd0/c;

.field public final j:Lam0/c;


# direct methods
.method public constructor <init>(Ltr0/b;Lbd0/c;Lam0/c;)V
    .locals 2

    .line 1
    new-instance v0, Lm80/n;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-direct {v0, v1}, Lm80/n;-><init>(Ljava/lang/String;)V

    .line 5
    .line 6
    .line 7
    invoke-direct {p0, v0}, Lql0/j;-><init>(Lql0/h;)V

    .line 8
    .line 9
    .line 10
    iput-object p1, p0, Lm80/o;->h:Ltr0/b;

    .line 11
    .line 12
    iput-object p2, p0, Lm80/o;->i:Lbd0/c;

    .line 13
    .line 14
    iput-object p3, p0, Lm80/o;->j:Lam0/c;

    .line 15
    .line 16
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 17
    .line 18
    .line 19
    move-result-object p1

    .line 20
    new-instance p2, Lk20/a;

    .line 21
    .line 22
    const/16 p3, 0x14

    .line 23
    .line 24
    invoke-direct {p2, p0, v1, p3}, Lk20/a;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 25
    .line 26
    .line 27
    const/4 p0, 0x3

    .line 28
    invoke-static {p1, v1, v1, p2, p0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 29
    .line 30
    .line 31
    return-void
.end method
