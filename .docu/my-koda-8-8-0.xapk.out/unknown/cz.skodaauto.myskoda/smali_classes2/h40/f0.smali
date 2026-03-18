.class public final Lh40/f0;
.super Lql0/j;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final h:Lud0/b;

.field public final i:Lhq0/f;


# direct methods
.method public constructor <init>(Lf40/e0;Lud0/b;Lhq0/f;)V
    .locals 6

    .line 1
    new-instance v0, Lh40/e0;

    .line 2
    .line 3
    const-string v1, ""

    .line 4
    .line 5
    const/4 v5, 0x0

    .line 6
    move-object v2, v1

    .line 7
    move-object v3, v1

    .line 8
    move-object v4, v1

    .line 9
    invoke-direct/range {v0 .. v5}, Lh40/e0;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lh40/d0;)V

    .line 10
    .line 11
    .line 12
    invoke-direct {p0, v0}, Lql0/j;-><init>(Lql0/h;)V

    .line 13
    .line 14
    .line 15
    iput-object p2, p0, Lh40/f0;->h:Lud0/b;

    .line 16
    .line 17
    iput-object p3, p0, Lh40/f0;->i:Lhq0/f;

    .line 18
    .line 19
    new-instance p2, Le30/p;

    .line 20
    .line 21
    const/4 p3, 0x0

    .line 22
    const/16 v0, 0x13

    .line 23
    .line 24
    invoke-direct {p2, v0, p1, p0, p3}, Le30/p;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 25
    .line 26
    .line 27
    invoke-virtual {p0, p2}, Lql0/j;->b(Lay0/n;)V

    .line 28
    .line 29
    .line 30
    return-void
.end method
