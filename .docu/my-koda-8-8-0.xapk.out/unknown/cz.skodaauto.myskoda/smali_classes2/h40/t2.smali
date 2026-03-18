.class public final Lh40/t2;
.super Lql0/j;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final h:Lbq0/k;

.field public final i:Ltr0/b;

.field public final j:Lbh0/g;

.field public final k:Lbh0/j;

.field public final l:Lbd0/c;


# direct methods
.method public constructor <init>(Lbq0/k;Ltr0/b;Lbh0/g;Lbh0/j;Lbd0/c;Lij0/a;)V
    .locals 7

    .line 1
    new-instance v0, Lh40/r2;

    .line 2
    .line 3
    const-string v1, ""

    .line 4
    .line 5
    sget-object v6, Lmx0/s;->d:Lmx0/s;

    .line 6
    .line 7
    const/4 v2, 0x0

    .line 8
    const/4 v3, 0x0

    .line 9
    const/4 v4, 0x0

    .line 10
    const/4 v5, 0x0

    .line 11
    invoke-direct/range {v0 .. v6}, Lh40/r2;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/util/List;)V

    .line 12
    .line 13
    .line 14
    invoke-direct {p0, v0}, Lql0/j;-><init>(Lql0/h;)V

    .line 15
    .line 16
    .line 17
    iput-object p1, p0, Lh40/t2;->h:Lbq0/k;

    .line 18
    .line 19
    iput-object p2, p0, Lh40/t2;->i:Ltr0/b;

    .line 20
    .line 21
    iput-object p3, p0, Lh40/t2;->j:Lbh0/g;

    .line 22
    .line 23
    iput-object p4, p0, Lh40/t2;->k:Lbh0/j;

    .line 24
    .line 25
    iput-object p5, p0, Lh40/t2;->l:Lbd0/c;

    .line 26
    .line 27
    new-instance p1, Lg60/w;

    .line 28
    .line 29
    const/4 p2, 0x0

    .line 30
    const/16 p3, 0x19

    .line 31
    .line 32
    invoke-direct {p1, p3, p0, p6, p2}, Lg60/w;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 33
    .line 34
    .line 35
    invoke-virtual {p0, p1}, Lql0/j;->b(Lay0/n;)V

    .line 36
    .line 37
    .line 38
    return-void
.end method
