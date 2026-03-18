.class public final Lc90/j0;
.super Lql0/j;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final h:Lfo0/b;

.field public final i:Lfo0/c;

.field public final j:Lnr0/a;

.field public final k:Lfj0/i;


# direct methods
.method public constructor <init>(Lfo0/b;Lfo0/c;Lnr0/a;Lfj0/i;)V
    .locals 2

    .line 1
    new-instance v0, Lc90/i0;

    .line 2
    .line 3
    const/4 v1, 0x1

    .line 4
    invoke-direct {v0, v1}, Lc90/i0;-><init>(Z)V

    .line 5
    .line 6
    .line 7
    invoke-direct {p0, v0}, Lql0/j;-><init>(Lql0/h;)V

    .line 8
    .line 9
    .line 10
    iput-object p1, p0, Lc90/j0;->h:Lfo0/b;

    .line 11
    .line 12
    iput-object p2, p0, Lc90/j0;->i:Lfo0/c;

    .line 13
    .line 14
    iput-object p3, p0, Lc90/j0;->j:Lnr0/a;

    .line 15
    .line 16
    iput-object p4, p0, Lc90/j0;->k:Lfj0/i;

    .line 17
    .line 18
    new-instance p1, Lc90/h0;

    .line 19
    .line 20
    const/4 p2, 0x0

    .line 21
    const/4 p3, 0x0

    .line 22
    invoke-direct {p1, p0, p2, p3}, Lc90/h0;-><init>(Lc90/j0;Lkotlin/coroutines/Continuation;I)V

    .line 23
    .line 24
    .line 25
    invoke-virtual {p0, p1}, Lql0/j;->b(Lay0/n;)V

    .line 26
    .line 27
    .line 28
    return-void
.end method
