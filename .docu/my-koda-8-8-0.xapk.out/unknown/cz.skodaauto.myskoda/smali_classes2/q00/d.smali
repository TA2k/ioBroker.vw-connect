.class public final Lq00/d;
.super Lql0/j;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final h:Lbh0/j;

.field public final i:Lbh0/g;

.field public final j:Lp00/b;

.field public final k:Ltr0/b;

.field public final l:Lij0/a;

.field public final m:Lcf0/h;


# direct methods
.method public constructor <init>(Lwr0/e;Lid0/c;Lbh0/j;Lbh0/g;Lp00/b;Ltr0/b;Lij0/a;Lcf0/h;)V
    .locals 6

    .line 1
    new-instance v0, Lq00/a;

    .line 2
    .line 3
    sget-object v3, Lmx0/s;->d:Lmx0/s;

    .line 4
    .line 5
    const/4 v5, 0x0

    .line 6
    const-string v1, ""

    .line 7
    .line 8
    const/4 v4, 0x0

    .line 9
    move-object v2, v1

    .line 10
    invoke-direct/range {v0 .. v5}, Lq00/a;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/util/List;ZZ)V

    .line 11
    .line 12
    .line 13
    invoke-direct {p0, v0}, Lql0/j;-><init>(Lql0/h;)V

    .line 14
    .line 15
    .line 16
    iput-object p3, p0, Lq00/d;->h:Lbh0/j;

    .line 17
    .line 18
    iput-object p4, p0, Lq00/d;->i:Lbh0/g;

    .line 19
    .line 20
    iput-object p5, p0, Lq00/d;->j:Lp00/b;

    .line 21
    .line 22
    iput-object p6, p0, Lq00/d;->k:Ltr0/b;

    .line 23
    .line 24
    iput-object p7, p0, Lq00/d;->l:Lij0/a;

    .line 25
    .line 26
    iput-object p8, p0, Lq00/d;->m:Lcf0/h;

    .line 27
    .line 28
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 29
    .line 30
    .line 31
    move-result-object p3

    .line 32
    new-instance v0, Lh7/z;

    .line 33
    .line 34
    const/16 v1, 0x14

    .line 35
    .line 36
    const/4 v5, 0x0

    .line 37
    move-object v3, p0

    .line 38
    move-object v2, p1

    .line 39
    move-object v4, p2

    .line 40
    invoke-direct/range {v0 .. v5}, Lh7/z;-><init>(ILjava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 41
    .line 42
    .line 43
    const/4 p0, 0x3

    .line 44
    invoke-static {p3, v5, v5, v0, p0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 45
    .line 46
    .line 47
    return-void
.end method

.method public static h(Ljd0/b;)Ljava/lang/String;
    .locals 2

    .line 1
    iget-object v0, p0, Ljd0/b;->a:Ljava/time/LocalTime;

    .line 2
    .line 3
    invoke-static {v0}, Lua0/g;->b(Ljava/time/LocalTime;)Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    iget-object p0, p0, Ljd0/b;->b:Ljava/time/LocalTime;

    .line 8
    .line 9
    invoke-static {p0}, Lua0/g;->b(Ljava/time/LocalTime;)Ljava/lang/String;

    .line 10
    .line 11
    .line 12
    move-result-object p0

    .line 13
    const-string v1, " - "

    .line 14
    .line 15
    invoke-static {v0, v1, p0}, Lf2/m0;->i(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 16
    .line 17
    .line 18
    move-result-object p0

    .line 19
    return-object p0
.end method
