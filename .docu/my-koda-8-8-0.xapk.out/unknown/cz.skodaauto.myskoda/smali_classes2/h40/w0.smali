.class public final Lh40/w0;
.super Lql0/j;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final h:Lf40/a2;

.field public final i:Ltr0/b;


# direct methods
.method public constructor <init>(Lbq0/s;Lf40/h0;Lf40/a2;Ltr0/b;)V
    .locals 4

    .line 1
    new-instance v0, Lh40/v0;

    .line 2
    .line 3
    const-string v1, ""

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    const/4 v3, 0x0

    .line 7
    invoke-direct {v0, v1, v1, v3, v2}, Lh40/v0;-><init>(Ljava/lang/String;Ljava/lang/String;Landroid/net/Uri;I)V

    .line 8
    .line 9
    .line 10
    invoke-direct {p0, v0}, Lql0/j;-><init>(Lql0/h;)V

    .line 11
    .line 12
    .line 13
    iput-object p3, p0, Lh40/w0;->h:Lf40/a2;

    .line 14
    .line 15
    iput-object p4, p0, Lh40/w0;->i:Ltr0/b;

    .line 16
    .line 17
    invoke-virtual {p1, v3}, Lbq0/s;->a(Lcq0/n;)V

    .line 18
    .line 19
    .line 20
    invoke-virtual {p2}, Lf40/h0;->invoke()Ljava/lang/Object;

    .line 21
    .line 22
    .line 23
    move-result-object p1

    .line 24
    check-cast p1, Lg40/f;

    .line 25
    .line 26
    if-eqz p1, :cond_1

    .line 27
    .line 28
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 29
    .line 30
    .line 31
    move-result-object p2

    .line 32
    check-cast p2, Lh40/v0;

    .line 33
    .line 34
    iget-object p3, p1, Lg40/f;->b:Ljava/lang/String;

    .line 35
    .line 36
    iget-object p4, p1, Lg40/f;->c:Ljava/lang/String;

    .line 37
    .line 38
    iget-object v0, p1, Lg40/f;->f:Ljava/util/List;

    .line 39
    .line 40
    invoke-static {v0}, Lmx0/q;->L(Ljava/util/List;)Ljava/lang/Object;

    .line 41
    .line 42
    .line 43
    move-result-object v0

    .line 44
    check-cast v0, Ljava/lang/String;

    .line 45
    .line 46
    if-eqz v0, :cond_0

    .line 47
    .line 48
    invoke-static {v0}, Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;

    .line 49
    .line 50
    .line 51
    move-result-object v3

    .line 52
    :cond_0
    iget p1, p1, Lg40/f;->e:I

    .line 53
    .line 54
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 55
    .line 56
    .line 57
    const-string p2, "rewardName"

    .line 58
    .line 59
    invoke-static {p3, p2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 60
    .line 61
    .line 62
    const-string p2, "description"

    .line 63
    .line 64
    invoke-static {p4, p2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 65
    .line 66
    .line 67
    new-instance p2, Lh40/v0;

    .line 68
    .line 69
    invoke-direct {p2, p3, p4, v3, p1}, Lh40/v0;-><init>(Ljava/lang/String;Ljava/lang/String;Landroid/net/Uri;I)V

    .line 70
    .line 71
    .line 72
    invoke-virtual {p0, p2}, Lql0/j;->g(Lql0/h;)V

    .line 73
    .line 74
    .line 75
    :cond_1
    return-void
.end method
