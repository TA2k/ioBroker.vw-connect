.class public final Lor0/b;
.super Lql0/j;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final h:Lfo0/b;

.field public final i:Lfo0/c;

.field public final j:Lnr0/e;


# direct methods
.method public constructor <init>(Lfo0/b;Lfo0/c;Lnr0/e;)V
    .locals 2

    .line 1
    new-instance v0, Lor0/a;

    .line 2
    .line 3
    const/4 v1, 0x1

    .line 4
    invoke-direct {v0, v1}, Lor0/a;-><init>(Z)V

    .line 5
    .line 6
    .line 7
    invoke-direct {p0, v0}, Lql0/j;-><init>(Lql0/h;)V

    .line 8
    .line 9
    .line 10
    iput-object p1, p0, Lor0/b;->h:Lfo0/b;

    .line 11
    .line 12
    iput-object p2, p0, Lor0/b;->i:Lfo0/c;

    .line 13
    .line 14
    iput-object p3, p0, Lor0/b;->j:Lnr0/e;

    .line 15
    .line 16
    new-instance p1, Ln00/f;

    .line 17
    .line 18
    const/4 p2, 0x0

    .line 19
    const/16 p3, 0x8

    .line 20
    .line 21
    invoke-direct {p1, p0, p2, p3}, Ln00/f;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 22
    .line 23
    .line 24
    invoke-virtual {p0, p1}, Lql0/j;->b(Lay0/n;)V

    .line 25
    .line 26
    .line 27
    return-void
.end method
