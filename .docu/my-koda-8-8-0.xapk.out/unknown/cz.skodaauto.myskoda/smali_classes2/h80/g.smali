.class public final Lh80/g;
.super Lql0/j;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final h:Ltr0/b;

.field public final i:Lq80/g;

.field public final j:Lq80/f;


# direct methods
.method public constructor <init>(Ltr0/b;Lq80/g;Lq80/f;Lij0/a;Lf80/e;)V
    .locals 10

    .line 1
    new-instance v0, Lh80/f;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    const/4 v2, 0x1

    .line 5
    invoke-direct {v0, v1, v1, v2}, Lh80/f;-><init>(Lql0/g;Lh80/e;Z)V

    .line 6
    .line 7
    .line 8
    invoke-direct {p0, v0}, Lql0/j;-><init>(Lql0/h;)V

    .line 9
    .line 10
    .line 11
    iput-object p1, p0, Lh80/g;->h:Ltr0/b;

    .line 12
    .line 13
    iput-object p2, p0, Lh80/g;->i:Lq80/g;

    .line 14
    .line 15
    iput-object p3, p0, Lh80/g;->j:Lq80/f;

    .line 16
    .line 17
    invoke-virtual {p5}, Lf80/e;->invoke()Ljava/lang/Object;

    .line 18
    .line 19
    .line 20
    move-result-object p1

    .line 21
    check-cast p1, Lne0/t;

    .line 22
    .line 23
    instance-of p2, p1, Lne0/e;

    .line 24
    .line 25
    const/4 p3, 0x0

    .line 26
    if-eqz p2, :cond_1

    .line 27
    .line 28
    check-cast p1, Lne0/e;

    .line 29
    .line 30
    iget-object p1, p1, Lne0/e;->a:Ljava/lang/Object;

    .line 31
    .line 32
    check-cast p1, Lg80/a;

    .line 33
    .line 34
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 35
    .line 36
    .line 37
    move-result-object p2

    .line 38
    check-cast p2, Lh80/f;

    .line 39
    .line 40
    const-string p4, "<this>"

    .line 41
    .line 42
    invoke-static {p1, p4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 43
    .line 44
    .line 45
    new-instance v3, Lh80/e;

    .line 46
    .line 47
    iget-object v4, p1, Lg80/a;->b:Ljava/lang/String;

    .line 48
    .line 49
    iget-object v5, p1, Lg80/a;->a:Ljava/lang/String;

    .line 50
    .line 51
    iget-object v6, p1, Lg80/a;->c:Ljava/lang/String;

    .line 52
    .line 53
    iget-object v9, p1, Lg80/a;->d:Ljava/util/List;

    .line 54
    .line 55
    iget-object v7, p1, Lg80/a;->e:Ljava/lang/String;

    .line 56
    .line 57
    iget-object v8, p1, Lg80/a;->h:Ljava/lang/String;

    .line 58
    .line 59
    invoke-direct/range {v3 .. v9}, Lh80/e;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/util/List;)V

    .line 60
    .line 61
    .line 62
    iget-object p1, p1, Lg80/a;->g:Ljava/lang/String;

    .line 63
    .line 64
    invoke-virtual {p1}, Ljava/lang/String;->length()I

    .line 65
    .line 66
    .line 67
    move-result p1

    .line 68
    if-lez p1, :cond_0

    .line 69
    .line 70
    move p3, v2

    .line 71
    :cond_0
    invoke-static {p2, v1, v3, p3, v2}, Lh80/f;->a(Lh80/f;Lql0/g;Lh80/e;ZI)Lh80/f;

    .line 72
    .line 73
    .line 74
    move-result-object p1

    .line 75
    goto :goto_0

    .line 76
    :cond_1
    instance-of p2, p1, Lne0/c;

    .line 77
    .line 78
    if-eqz p2, :cond_2

    .line 79
    .line 80
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 81
    .line 82
    .line 83
    move-result-object p2

    .line 84
    check-cast p2, Lh80/f;

    .line 85
    .line 86
    check-cast p1, Lne0/c;

    .line 87
    .line 88
    invoke-static {p1, p4}, Ljp/rf;->e(Lne0/c;Lij0/a;)Lql0/g;

    .line 89
    .line 90
    .line 91
    move-result-object p1

    .line 92
    const/4 p4, 0x6

    .line 93
    invoke-static {p2, p1, v1, p3, p4}, Lh80/f;->a(Lh80/f;Lql0/g;Lh80/e;ZI)Lh80/f;

    .line 94
    .line 95
    .line 96
    move-result-object p1

    .line 97
    :goto_0
    invoke-virtual {p0, p1}, Lql0/j;->g(Lql0/h;)V

    .line 98
    .line 99
    .line 100
    return-void

    .line 101
    :cond_2
    new-instance p0, La8/r0;

    .line 102
    .line 103
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 104
    .line 105
    .line 106
    throw p0
.end method
