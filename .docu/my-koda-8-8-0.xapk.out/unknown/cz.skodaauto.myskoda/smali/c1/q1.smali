.class public final Lc1/q1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Lc1/b2;

.field public final b:Ll2/j1;

.field public final synthetic c:Lc1/w1;


# direct methods
.method public constructor <init>(Lc1/w1;Lc1/b2;Ljava/lang/String;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lc1/q1;->c:Lc1/w1;

    .line 5
    .line 6
    iput-object p2, p0, Lc1/q1;->a:Lc1/b2;

    .line 7
    .line 8
    const/4 p1, 0x0

    .line 9
    invoke-static {p1}, Ll2/b;->n(Ljava/lang/Object;)Ll2/j1;

    .line 10
    .line 11
    .line 12
    move-result-object p1

    .line 13
    iput-object p1, p0, Lc1/q1;->b:Ll2/j1;

    .line 14
    .line 15
    return-void
.end method


# virtual methods
.method public final a(Lay0/k;Lay0/k;)Lc1/p1;
    .locals 8

    .line 1
    iget-object v0, p0, Lc1/q1;->b:Ll2/j1;

    .line 2
    .line 3
    invoke-virtual {v0}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v1

    .line 7
    check-cast v1, Lc1/p1;

    .line 8
    .line 9
    iget-object v2, p0, Lc1/q1;->c:Lc1/w1;

    .line 10
    .line 11
    if-nez v1, :cond_0

    .line 12
    .line 13
    new-instance v1, Lc1/p1;

    .line 14
    .line 15
    new-instance v3, Lc1/t1;

    .line 16
    .line 17
    iget-object v4, v2, Lc1/w1;->a:Lap0/o;

    .line 18
    .line 19
    invoke-virtual {v4}, Lap0/o;->D()Ljava/lang/Object;

    .line 20
    .line 21
    .line 22
    move-result-object v4

    .line 23
    invoke-interface {p2, v4}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 24
    .line 25
    .line 26
    move-result-object v4

    .line 27
    iget-object v5, v2, Lc1/w1;->a:Lap0/o;

    .line 28
    .line 29
    invoke-virtual {v5}, Lap0/o;->D()Ljava/lang/Object;

    .line 30
    .line 31
    .line 32
    move-result-object v5

    .line 33
    invoke-interface {p2, v5}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 34
    .line 35
    .line 36
    move-result-object v5

    .line 37
    iget-object v6, p0, Lc1/q1;->a:Lc1/b2;

    .line 38
    .line 39
    iget-object v7, v6, Lc1/b2;->a:Lay0/k;

    .line 40
    .line 41
    invoke-interface {v7, v5}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 42
    .line 43
    .line 44
    move-result-object v5

    .line 45
    check-cast v5, Lc1/p;

    .line 46
    .line 47
    invoke-virtual {v5}, Lc1/p;->d()V

    .line 48
    .line 49
    .line 50
    invoke-direct {v3, v2, v4, v5, v6}, Lc1/t1;-><init>(Lc1/w1;Ljava/lang/Object;Lc1/p;Lc1/b2;)V

    .line 51
    .line 52
    .line 53
    invoke-direct {v1, p0, v3, p1, p2}, Lc1/p1;-><init>(Lc1/q1;Lc1/t1;Lay0/k;Lay0/k;)V

    .line 54
    .line 55
    .line 56
    invoke-virtual {v0, v1}, Ll2/j1;->setValue(Ljava/lang/Object;)V

    .line 57
    .line 58
    .line 59
    iget-object p0, v2, Lc1/w1;->i:Lv2/o;

    .line 60
    .line 61
    invoke-virtual {p0, v3}, Lv2/o;->add(Ljava/lang/Object;)Z

    .line 62
    .line 63
    .line 64
    :cond_0
    check-cast p2, Lkotlin/jvm/internal/n;

    .line 65
    .line 66
    iput-object p2, v1, Lc1/p1;->f:Lkotlin/jvm/internal/n;

    .line 67
    .line 68
    iput-object p1, v1, Lc1/p1;->e:Lay0/k;

    .line 69
    .line 70
    invoke-virtual {v2}, Lc1/w1;->f()Lc1/r1;

    .line 71
    .line 72
    .line 73
    move-result-object p0

    .line 74
    invoke-virtual {v1, p0}, Lc1/p1;->a(Lc1/r1;)V

    .line 75
    .line 76
    .line 77
    return-object v1
.end method
