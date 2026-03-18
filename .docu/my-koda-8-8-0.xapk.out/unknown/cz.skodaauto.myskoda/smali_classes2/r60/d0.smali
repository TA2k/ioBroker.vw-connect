.class public final Lr60/d0;
.super Lql0/j;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final h:Lkf0/v;

.field public final i:Lp60/c0;

.field public final j:Lij0/a;


# direct methods
.method public constructor <init>(Lkf0/v;Lp60/c0;Lij0/a;)V
    .locals 3

    .line 1
    new-instance v0, Lr60/c0;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    const-string v2, ""

    .line 5
    .line 6
    invoke-direct {v0, v1, v2}, Lr60/c0;-><init>(ZLjava/lang/String;)V

    .line 7
    .line 8
    .line 9
    invoke-direct {p0, v0}, Lql0/j;-><init>(Lql0/h;)V

    .line 10
    .line 11
    .line 12
    iput-object p1, p0, Lr60/d0;->h:Lkf0/v;

    .line 13
    .line 14
    iput-object p2, p0, Lr60/d0;->i:Lp60/c0;

    .line 15
    .line 16
    iput-object p3, p0, Lr60/d0;->j:Lij0/a;

    .line 17
    .line 18
    new-instance p1, Ln00/f;

    .line 19
    .line 20
    const/4 p2, 0x0

    .line 21
    const/16 p3, 0x19

    .line 22
    .line 23
    invoke-direct {p1, p0, p2, p3}, Ln00/f;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 24
    .line 25
    .line 26
    invoke-virtual {p0, p1}, Lql0/j;->b(Lay0/n;)V

    .line 27
    .line 28
    .line 29
    return-void
.end method
