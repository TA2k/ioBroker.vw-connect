.class public final Lvy0/q1;
.super Lvy0/i0;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final g:Lkotlin/coroutines/Continuation;


# direct methods
.method public constructor <init>(Lpx0/g;Lay0/n;)V
    .locals 2

    .line 1
    const/4 v0, 0x0

    .line 2
    const/4 v1, 0x1

    .line 3
    invoke-direct {p0, p1, v1, v0}, Lvy0/a;-><init>(Lpx0/g;ZZ)V

    .line 4
    .line 5
    .line 6
    invoke-static {p2, p0, p0}, Ljp/hg;->a(Lay0/n;Lkotlin/coroutines/Continuation;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 7
    .line 8
    .line 9
    move-result-object p1

    .line 10
    iput-object p1, p0, Lvy0/q1;->g:Lkotlin/coroutines/Continuation;

    .line 11
    .line 12
    return-void
.end method


# virtual methods
.method public final e0()V
    .locals 1

    .line 1
    iget-object v0, p0, Lvy0/q1;->g:Lkotlin/coroutines/Continuation;

    .line 2
    .line 3
    invoke-static {v0, p0}, Ljp/qb;->b(Lkotlin/coroutines/Continuation;Lvy0/a;)V

    .line 4
    .line 5
    .line 6
    return-void
.end method
