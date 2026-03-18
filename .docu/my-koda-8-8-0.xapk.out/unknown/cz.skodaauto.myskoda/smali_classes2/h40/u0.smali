.class public final Lh40/u0;
.super Lql0/j;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final h:Ltr0/b;

.field public final i:Lf40/l4;


# direct methods
.method public constructor <init>(Ltr0/b;Lf40/l4;Lf40/u;Lij0/a;)V
    .locals 9

    .line 1
    new-instance v0, Lh40/t0;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    const-string v2, ""

    .line 5
    .line 6
    const/4 v8, 0x0

    .line 7
    invoke-direct {v0, v1, v8, v8, v2}, Lh40/t0;-><init>(ZLg40/i0;Lql0/g;Ljava/lang/String;)V

    .line 8
    .line 9
    .line 10
    invoke-direct {p0, v0}, Lql0/j;-><init>(Lql0/h;)V

    .line 11
    .line 12
    .line 13
    iput-object p1, p0, Lh40/u0;->h:Ltr0/b;

    .line 14
    .line 15
    iput-object p2, p0, Lh40/u0;->i:Lf40/l4;

    .line 16
    .line 17
    new-instance v3, Lg1/y2;

    .line 18
    .line 19
    const/4 v4, 0x6

    .line 20
    move-object v6, p0

    .line 21
    move-object v5, p3

    .line 22
    move-object v7, p4

    .line 23
    invoke-direct/range {v3 .. v8}, Lg1/y2;-><init>(ILjava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 24
    .line 25
    .line 26
    invoke-virtual {v6, v3}, Lql0/j;->b(Lay0/n;)V

    .line 27
    .line 28
    .line 29
    sget-object p0, Lg40/u0;->e:Lg40/u0;

    .line 30
    .line 31
    iget-object p1, p2, Lf40/l4;->a:Lf40/c1;

    .line 32
    .line 33
    check-cast p1, Ld40/e;

    .line 34
    .line 35
    iput-object p0, p1, Ld40/e;->b:Lg40/u0;

    .line 36
    .line 37
    return-void
.end method
