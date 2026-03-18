.class public final Lcl0/l;
.super Lql0/j;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final h:Lal0/o1;


# direct methods
.method public constructor <init>(Lal0/x0;Lal0/o1;)V
    .locals 2

    .line 1
    new-instance v0, Lcl0/k;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-direct {v0, v1}, Lcl0/k;-><init>(Z)V

    .line 5
    .line 6
    .line 7
    invoke-direct {p0, v0}, Lql0/j;-><init>(Lql0/h;)V

    .line 8
    .line 9
    .line 10
    iput-object p2, p0, Lcl0/l;->h:Lal0/o1;

    .line 11
    .line 12
    new-instance p2, Lc80/l;

    .line 13
    .line 14
    const/4 v0, 0x0

    .line 15
    const/16 v1, 0xd

    .line 16
    .line 17
    invoke-direct {p2, v1, p1, p0, v0}, Lc80/l;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 18
    .line 19
    .line 20
    invoke-virtual {p0, p2}, Lql0/j;->b(Lay0/n;)V

    .line 21
    .line 22
    .line 23
    return-void
.end method
