.class public final Lw30/h;
.super Lql0/j;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final h:Lu30/d;

.field public final i:Ltr0/b;

.field public final j:Lbd0/c;

.field public final k:Lij0/a;


# direct methods
.method public constructor <init>(Lu30/d;Ltr0/b;Lbd0/c;Lij0/a;)V
    .locals 4

    .line 1
    new-instance v0, Lw30/g;

    .line 2
    .line 3
    const-string v1, ""

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    const/4 v3, 0x0

    .line 7
    invoke-direct {v0, v1, v1, v3, v2}, Lw30/g;-><init>(Ljava/lang/String;Ljava/lang/String;Lql0/g;Z)V

    .line 8
    .line 9
    .line 10
    invoke-direct {p0, v0}, Lql0/j;-><init>(Lql0/h;)V

    .line 11
    .line 12
    .line 13
    iput-object p1, p0, Lw30/h;->h:Lu30/d;

    .line 14
    .line 15
    iput-object p2, p0, Lw30/h;->i:Ltr0/b;

    .line 16
    .line 17
    iput-object p3, p0, Lw30/h;->j:Lbd0/c;

    .line 18
    .line 19
    iput-object p4, p0, Lw30/h;->k:Lij0/a;

    .line 20
    .line 21
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 22
    .line 23
    .line 24
    move-result-object p1

    .line 25
    new-instance p2, Lvo0/e;

    .line 26
    .line 27
    const/4 p3, 0x2

    .line 28
    invoke-direct {p2, p0, v3, p3}, Lvo0/e;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 29
    .line 30
    .line 31
    const/4 p0, 0x3

    .line 32
    invoke-static {p1, v3, v3, p2, p0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 33
    .line 34
    .line 35
    return-void
.end method
