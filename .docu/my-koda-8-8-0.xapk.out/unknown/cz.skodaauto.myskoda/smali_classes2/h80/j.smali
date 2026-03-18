.class public final Lh80/j;
.super Lql0/j;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final h:Lq80/h;

.field public final i:Lf80/i;

.field public final j:Lf80/h;

.field public k:Ljava/util/ArrayList;


# direct methods
.method public constructor <init>(Lf80/g;Lq80/h;Lf80/i;Lf80/h;)V
    .locals 3

    .line 1
    new-instance v0, Lh80/i;

    .line 2
    .line 3
    const/4 v1, 0x3

    .line 4
    const/4 v2, 0x0

    .line 5
    invoke-direct {v0, v2, v1}, Lh80/i;-><init>(Ljava/util/List;I)V

    .line 6
    .line 7
    .line 8
    invoke-direct {p0, v0}, Lql0/j;-><init>(Lql0/h;)V

    .line 9
    .line 10
    .line 11
    iput-object p2, p0, Lh80/j;->h:Lq80/h;

    .line 12
    .line 13
    iput-object p3, p0, Lh80/j;->i:Lf80/i;

    .line 14
    .line 15
    iput-object p4, p0, Lh80/j;->j:Lf80/h;

    .line 16
    .line 17
    new-instance p2, Lh40/w3;

    .line 18
    .line 19
    const/16 p3, 0xf

    .line 20
    .line 21
    invoke-direct {p2, p3, p1, p0, v2}, Lh40/w3;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 22
    .line 23
    .line 24
    invoke-virtual {p0, p2}, Lql0/j;->b(Lay0/n;)V

    .line 25
    .line 26
    .line 27
    return-void
.end method
