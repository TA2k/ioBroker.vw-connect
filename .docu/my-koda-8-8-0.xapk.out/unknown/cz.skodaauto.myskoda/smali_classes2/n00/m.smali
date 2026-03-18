.class public final Ln00/m;
.super Lql0/j;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final h:Ll00/i;

.field public final i:Ll00/k;

.field public final j:Lhh0/a;


# direct methods
.method public constructor <init>(Ll00/i;Ll00/k;Lhh0/a;)V
    .locals 2

    .line 1
    new-instance v0, Ln00/l;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-direct {v0, v1}, Ln00/l;-><init>(Z)V

    .line 5
    .line 6
    .line 7
    invoke-direct {p0, v0}, Lql0/j;-><init>(Lql0/h;)V

    .line 8
    .line 9
    .line 10
    iput-object p1, p0, Ln00/m;->h:Ll00/i;

    .line 11
    .line 12
    iput-object p2, p0, Ln00/m;->i:Ll00/k;

    .line 13
    .line 14
    iput-object p3, p0, Ln00/m;->j:Lhh0/a;

    .line 15
    .line 16
    new-instance p1, Ln00/f;

    .line 17
    .line 18
    const/4 p2, 0x0

    .line 19
    const/4 p3, 0x1

    .line 20
    invoke-direct {p1, p0, p2, p3}, Ln00/f;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 21
    .line 22
    .line 23
    invoke-virtual {p0, p1}, Lql0/j;->b(Lay0/n;)V

    .line 24
    .line 25
    .line 26
    return-void
.end method
