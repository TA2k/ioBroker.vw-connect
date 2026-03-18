.class public final Lh40/l1;
.super Lql0/j;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final h:Lf40/l4;

.field public final i:Lf40/o2;


# direct methods
.method public constructor <init>(Lf40/l4;Lf40/o2;Lf40/d0;Lf40/x0;Lij0/a;)V
    .locals 3

    .line 1
    new-instance v0, Lh40/k1;

    .line 2
    .line 3
    const-string v1, ""

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    invoke-direct {v0, v1, v2, v2}, Lh40/k1;-><init>(Ljava/lang/String;IZ)V

    .line 7
    .line 8
    .line 9
    invoke-direct {p0, v0}, Lql0/j;-><init>(Lql0/h;)V

    .line 10
    .line 11
    .line 12
    iput-object p1, p0, Lh40/l1;->h:Lf40/l4;

    .line 13
    .line 14
    iput-object p2, p0, Lh40/l1;->i:Lf40/o2;

    .line 15
    .line 16
    invoke-virtual {p4}, Lf40/x0;->invoke()Ljava/lang/Object;

    .line 17
    .line 18
    .line 19
    move-result-object p1

    .line 20
    check-cast p1, Ljava/lang/Boolean;

    .line 21
    .line 22
    if-eqz p1, :cond_0

    .line 23
    .line 24
    invoke-virtual {p1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 25
    .line 26
    .line 27
    move-result p1

    .line 28
    goto :goto_0

    .line 29
    :cond_0
    move p1, v2

    .line 30
    :goto_0
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 31
    .line 32
    .line 33
    move-result-object p2

    .line 34
    check-cast p2, Lh40/k1;

    .line 35
    .line 36
    if-eqz p1, :cond_1

    .line 37
    .line 38
    const p4, 0x7f120c82

    .line 39
    .line 40
    .line 41
    goto :goto_1

    .line 42
    :cond_1
    const p4, 0x7f120c83

    .line 43
    .line 44
    .line 45
    :goto_1
    new-array v0, v2, [Ljava/lang/Object;

    .line 46
    .line 47
    check-cast p5, Ljj0/f;

    .line 48
    .line 49
    invoke-virtual {p5, p4, v0}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 50
    .line 51
    .line 52
    move-result-object p4

    .line 53
    const/4 p5, 0x1

    .line 54
    invoke-static {p2, v2, p1, p4, p5}, Lh40/k1;->a(Lh40/k1;IZLjava/lang/String;I)Lh40/k1;

    .line 55
    .line 56
    .line 57
    move-result-object p1

    .line 58
    invoke-virtual {p0, p1}, Lql0/j;->g(Lql0/h;)V

    .line 59
    .line 60
    .line 61
    invoke-virtual {p3}, Lf40/d0;->invoke()Ljava/lang/Object;

    .line 62
    .line 63
    .line 64
    move-result-object p1

    .line 65
    check-cast p1, Lg40/k0;

    .line 66
    .line 67
    if-eqz p1, :cond_2

    .line 68
    .line 69
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 70
    .line 71
    .line 72
    move-result-object p2

    .line 73
    check-cast p2, Lh40/k1;

    .line 74
    .line 75
    iget p1, p1, Lg40/k0;->a:I

    .line 76
    .line 77
    const/4 p3, 0x0

    .line 78
    const/4 p4, 0x6

    .line 79
    invoke-static {p2, p1, v2, p3, p4}, Lh40/k1;->a(Lh40/k1;IZLjava/lang/String;I)Lh40/k1;

    .line 80
    .line 81
    .line 82
    move-result-object p1

    .line 83
    invoke-virtual {p0, p1}, Lql0/j;->g(Lql0/h;)V

    .line 84
    .line 85
    .line 86
    :cond_2
    return-void
.end method
