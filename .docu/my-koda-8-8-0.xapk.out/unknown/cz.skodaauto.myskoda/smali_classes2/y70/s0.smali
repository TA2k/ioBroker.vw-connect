.class public final Ly70/s0;
.super Lql0/j;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final h:Lw70/i0;

.field public final i:Lkf0/k;

.field public final j:Lbq0/o;

.field public final k:Lij0/a;


# direct methods
.method public constructor <init>(Lw70/i0;Lkf0/k;Lbq0/o;Lij0/a;)V
    .locals 2

    .line 1
    new-instance v0, Ly70/r0;

    .line 2
    .line 3
    const/4 v1, 0x3

    .line 4
    invoke-direct {v0, v1}, Ly70/r0;-><init>(I)V

    .line 5
    .line 6
    .line 7
    invoke-direct {p0, v0}, Lql0/j;-><init>(Lql0/h;)V

    .line 8
    .line 9
    .line 10
    iput-object p1, p0, Ly70/s0;->h:Lw70/i0;

    .line 11
    .line 12
    iput-object p2, p0, Ly70/s0;->i:Lkf0/k;

    .line 13
    .line 14
    iput-object p3, p0, Ly70/s0;->j:Lbq0/o;

    .line 15
    .line 16
    iput-object p4, p0, Ly70/s0;->k:Lij0/a;

    .line 17
    .line 18
    new-instance p1, Lvo0/e;

    .line 19
    .line 20
    const/16 p2, 0x1c

    .line 21
    .line 22
    const/4 p3, 0x0

    .line 23
    invoke-direct {p1, p0, p3, p2}, Lvo0/e;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 24
    .line 25
    .line 26
    invoke-virtual {p0, p1}, Lql0/j;->b(Lay0/n;)V

    .line 27
    .line 28
    .line 29
    return-void
.end method
