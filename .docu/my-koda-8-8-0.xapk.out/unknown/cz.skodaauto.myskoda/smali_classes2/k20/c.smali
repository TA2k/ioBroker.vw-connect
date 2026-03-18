.class public final Lk20/c;
.super Lql0/j;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final h:Lzd0/b;

.field public final i:Li20/r;

.field public final j:Ltr0/b;

.field public final k:Lij0/a;


# direct methods
.method public constructor <init>(Lzd0/b;Li20/r;Ltr0/b;Lij0/a;)V
    .locals 2

    .line 1
    new-instance v0, Lk20/b;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-direct {v0, v1, v1}, Lk20/b;-><init>(Lae0/a;Lql0/g;)V

    .line 5
    .line 6
    .line 7
    invoke-direct {p0, v0}, Lql0/j;-><init>(Lql0/h;)V

    .line 8
    .line 9
    .line 10
    iput-object p1, p0, Lk20/c;->h:Lzd0/b;

    .line 11
    .line 12
    iput-object p2, p0, Lk20/c;->i:Li20/r;

    .line 13
    .line 14
    iput-object p3, p0, Lk20/c;->j:Ltr0/b;

    .line 15
    .line 16
    iput-object p4, p0, Lk20/c;->k:Lij0/a;

    .line 17
    .line 18
    new-instance p1, Lk20/a;

    .line 19
    .line 20
    const/4 p2, 0x0

    .line 21
    invoke-direct {p1, p0, v1, p2}, Lk20/a;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 22
    .line 23
    .line 24
    invoke-virtual {p0, p1}, Lql0/j;->b(Lay0/n;)V

    .line 25
    .line 26
    .line 27
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 28
    .line 29
    .line 30
    move-result-object p1

    .line 31
    new-instance p2, Lif0/d0;

    .line 32
    .line 33
    const/16 p3, 0x16

    .line 34
    .line 35
    invoke-direct {p2, p0, v1, p3}, Lif0/d0;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 36
    .line 37
    .line 38
    const/4 p0, 0x3

    .line 39
    invoke-static {p1, v1, v1, p2, p0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 40
    .line 41
    .line 42
    return-void
.end method
