.class public final Lh80/d;
.super Lql0/j;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final h:Ltr0/b;


# direct methods
.method public constructor <init>(Ltr0/b;Lf80/e;Lij0/a;)V
    .locals 4

    .line 1
    new-instance v0, Lh80/c;

    .line 2
    .line 3
    const-string v1, ""

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    invoke-direct {v0, v2, v1, v1}, Lh80/c;-><init>(Lql0/g;Ljava/lang/String;Ljava/lang/String;)V

    .line 7
    .line 8
    .line 9
    invoke-direct {p0, v0}, Lql0/j;-><init>(Lql0/h;)V

    .line 10
    .line 11
    .line 12
    iput-object p1, p0, Lh80/d;->h:Ltr0/b;

    .line 13
    .line 14
    invoke-virtual {p2}, Lf80/e;->invoke()Ljava/lang/Object;

    .line 15
    .line 16
    .line 17
    move-result-object p1

    .line 18
    check-cast p1, Lne0/t;

    .line 19
    .line 20
    instance-of p2, p1, Lne0/e;

    .line 21
    .line 22
    if-eqz p2, :cond_0

    .line 23
    .line 24
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 25
    .line 26
    .line 27
    move-result-object p2

    .line 28
    check-cast p2, Lh80/c;

    .line 29
    .line 30
    check-cast p1, Lne0/e;

    .line 31
    .line 32
    iget-object p1, p1, Lne0/e;->a:Ljava/lang/Object;

    .line 33
    .line 34
    check-cast p1, Lg80/a;

    .line 35
    .line 36
    iget-object p3, p1, Lg80/a;->b:Ljava/lang/String;

    .line 37
    .line 38
    iget-object p1, p1, Lg80/a;->g:Ljava/lang/String;

    .line 39
    .line 40
    const-string v0, "\n"

    .line 41
    .line 42
    const/4 v1, 0x0

    .line 43
    const-string v3, "<br>"

    .line 44
    .line 45
    invoke-static {v1, p1, v3, v0}, Lly0/w;->t(ZLjava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 46
    .line 47
    .line 48
    move-result-object p1

    .line 49
    const/4 v0, 0x1

    .line 50
    invoke-static {p2, v2, p3, p1, v0}, Lh80/c;->a(Lh80/c;Lql0/g;Ljava/lang/String;Ljava/lang/String;I)Lh80/c;

    .line 51
    .line 52
    .line 53
    move-result-object p1

    .line 54
    goto :goto_0

    .line 55
    :cond_0
    instance-of p2, p1, Lne0/c;

    .line 56
    .line 57
    if-eqz p2, :cond_1

    .line 58
    .line 59
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 60
    .line 61
    .line 62
    move-result-object p2

    .line 63
    check-cast p2, Lh80/c;

    .line 64
    .line 65
    check-cast p1, Lne0/c;

    .line 66
    .line 67
    invoke-static {p1, p3}, Ljp/rf;->e(Lne0/c;Lij0/a;)Lql0/g;

    .line 68
    .line 69
    .line 70
    move-result-object p1

    .line 71
    const/4 p3, 0x6

    .line 72
    invoke-static {p2, p1, v2, v2, p3}, Lh80/c;->a(Lh80/c;Lql0/g;Ljava/lang/String;Ljava/lang/String;I)Lh80/c;

    .line 73
    .line 74
    .line 75
    move-result-object p1

    .line 76
    :goto_0
    invoke-virtual {p0, p1}, Lql0/j;->g(Lql0/h;)V

    .line 77
    .line 78
    .line 79
    return-void

    .line 80
    :cond_1
    new-instance p0, La8/r0;

    .line 81
    .line 82
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 83
    .line 84
    .line 85
    throw p0
.end method
