.class public final Lm80/k;
.super Lql0/j;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final h:Lk80/d;

.field public final i:Lkf0/k;

.field public final j:Lhh0/a;


# direct methods
.method public constructor <init>(Lk80/d;Lkf0/k;Lhh0/a;)V
    .locals 2

    .line 1
    new-instance v0, Lm80/j;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-direct {v0, v1, v1}, Lm80/j;-><init>(ZZ)V

    .line 5
    .line 6
    .line 7
    invoke-direct {p0, v0}, Lql0/j;-><init>(Lql0/h;)V

    .line 8
    .line 9
    .line 10
    iput-object p1, p0, Lm80/k;->h:Lk80/d;

    .line 11
    .line 12
    iput-object p2, p0, Lm80/k;->i:Lkf0/k;

    .line 13
    .line 14
    iput-object p3, p0, Lm80/k;->j:Lhh0/a;

    .line 15
    .line 16
    new-instance p1, Lm80/i;

    .line 17
    .line 18
    const/4 p2, 0x0

    .line 19
    invoke-direct {p1, p0, p2}, Lm80/i;-><init>(Lm80/k;Lkotlin/coroutines/Continuation;)V

    .line 20
    .line 21
    .line 22
    invoke-virtual {p0, p1}, Lql0/j;->b(Lay0/n;)V

    .line 23
    .line 24
    .line 25
    return-void
.end method
