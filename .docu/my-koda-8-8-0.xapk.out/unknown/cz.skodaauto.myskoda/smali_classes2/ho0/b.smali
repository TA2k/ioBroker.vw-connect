.class public final Lho0/b;
.super Lql0/j;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final h:Lfo0/a;

.field public final i:Lfo0/d;


# direct methods
.method public constructor <init>(Lfo0/a;Lfo0/d;)V
    .locals 2

    .line 1
    new-instance v0, Lho0/a;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-direct {v0, v1}, Lho0/a;-><init>(Lgo0/b;)V

    .line 5
    .line 6
    .line 7
    invoke-direct {p0, v0}, Lql0/j;-><init>(Lql0/h;)V

    .line 8
    .line 9
    .line 10
    iput-object p1, p0, Lho0/b;->h:Lfo0/a;

    .line 11
    .line 12
    iput-object p2, p0, Lho0/b;->i:Lfo0/d;

    .line 13
    .line 14
    new-instance p1, Lh40/h;

    .line 15
    .line 16
    const/16 p2, 0xd

    .line 17
    .line 18
    invoke-direct {p1, p0, v1, p2}, Lh40/h;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 19
    .line 20
    .line 21
    invoke-virtual {p0, p1}, Lql0/j;->b(Lay0/n;)V

    .line 22
    .line 23
    .line 24
    return-void
.end method
