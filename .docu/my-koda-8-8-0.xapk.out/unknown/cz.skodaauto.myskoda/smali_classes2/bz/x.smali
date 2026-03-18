.class public final Lbz/x;
.super Lql0/j;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final h:Luk0/e0;

.field public final i:Ltr0/b;


# direct methods
.method public constructor <init>(Luk0/e0;Ltr0/b;)V
    .locals 2

    .line 1
    sget-object v0, Lbz/f;->b:Lbz/f;

    .line 2
    .line 3
    invoke-direct {p0, v0}, Lql0/j;-><init>(Lql0/h;)V

    .line 4
    .line 5
    .line 6
    iput-object p1, p0, Lbz/x;->h:Luk0/e0;

    .line 7
    .line 8
    iput-object p2, p0, Lbz/x;->i:Ltr0/b;

    .line 9
    .line 10
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 11
    .line 12
    .line 13
    move-result-object p1

    .line 14
    new-instance p2, La50/a;

    .line 15
    .line 16
    const/16 v0, 0xe

    .line 17
    .line 18
    const/4 v1, 0x0

    .line 19
    invoke-direct {p2, p0, v1, v0}, La50/a;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 20
    .line 21
    .line 22
    const/4 p0, 0x3

    .line 23
    invoke-static {p1, v1, v1, p2, p0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 24
    .line 25
    .line 26
    return-void
.end method
