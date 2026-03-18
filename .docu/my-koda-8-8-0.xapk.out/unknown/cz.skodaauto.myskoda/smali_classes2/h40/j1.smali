.class public final Lh40/j1;
.super Lql0/j;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final h:Ltr0/b;

.field public final i:Lf40/l4;


# direct methods
.method public constructor <init>(Lf40/c3;Ltr0/b;Lf40/l4;Lf40/u;Lij0/a;)V
    .locals 8

    .line 1
    new-instance v0, Lh40/i1;

    .line 2
    .line 3
    const/4 v4, 0x0

    .line 4
    const-string v5, ""

    .line 5
    .line 6
    const/4 v1, 0x0

    .line 7
    const/4 v2, 0x0

    .line 8
    const/4 v3, 0x0

    .line 9
    invoke-direct/range {v0 .. v5}, Lh40/i1;-><init>(ZLg40/i0;Lql0/g;ILjava/lang/String;)V

    .line 10
    .line 11
    .line 12
    invoke-direct {p0, v0}, Lql0/j;-><init>(Lql0/h;)V

    .line 13
    .line 14
    .line 15
    iput-object p2, p0, Lh40/j1;->h:Ltr0/b;

    .line 16
    .line 17
    iput-object p3, p0, Lh40/j1;->i:Lf40/l4;

    .line 18
    .line 19
    new-instance v1, La7/k;

    .line 20
    .line 21
    const/4 v6, 0x0

    .line 22
    const/16 v7, 0x1b

    .line 23
    .line 24
    move-object v3, p0

    .line 25
    move-object v4, p1

    .line 26
    move-object v2, p4

    .line 27
    move-object v5, p5

    .line 28
    invoke-direct/range {v1 .. v7}, La7/k;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 29
    .line 30
    .line 31
    invoke-virtual {v3, v1}, Lql0/j;->b(Lay0/n;)V

    .line 32
    .line 33
    .line 34
    sget-object p0, Lg40/u0;->e:Lg40/u0;

    .line 35
    .line 36
    iget-object p1, p3, Lf40/l4;->a:Lf40/c1;

    .line 37
    .line 38
    check-cast p1, Ld40/e;

    .line 39
    .line 40
    iput-object p0, p1, Ld40/e;->b:Lg40/u0;

    .line 41
    .line 42
    return-void
.end method
