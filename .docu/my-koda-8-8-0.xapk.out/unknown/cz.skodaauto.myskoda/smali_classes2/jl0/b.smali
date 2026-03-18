.class public final Ljl0/b;
.super Lql0/j;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final h:Lwj0/h0;


# direct methods
.method public constructor <init>(Lwj0/s;Lwj0/h0;)V
    .locals 2

    .line 1
    new-instance v0, Ljl0/a;

    .line 2
    .line 3
    invoke-direct {v0}, Ljl0/a;-><init>()V

    .line 4
    .line 5
    .line 6
    invoke-direct {p0, v0}, Lql0/j;-><init>(Lql0/h;)V

    .line 7
    .line 8
    .line 9
    iput-object p2, p0, Ljl0/b;->h:Lwj0/h0;

    .line 10
    .line 11
    new-instance p2, Lif0/d0;

    .line 12
    .line 13
    const/16 v0, 0x8

    .line 14
    .line 15
    const/4 v1, 0x0

    .line 16
    invoke-direct {p2, v0, p1, p0, v1}, Lif0/d0;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 17
    .line 18
    .line 19
    invoke-virtual {p0, p2}, Lql0/j;->b(Lay0/n;)V

    .line 20
    .line 21
    .line 22
    return-void
.end method
