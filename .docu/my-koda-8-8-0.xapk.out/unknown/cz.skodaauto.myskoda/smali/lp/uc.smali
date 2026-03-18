.class public abstract Llp/uc;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(Lnx0/c;Ljz0/k;)V
    .locals 1

    .line 1
    instance-of v0, p1, Ljz0/c;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    check-cast p1, Ljz0/c;

    .line 6
    .line 7
    iget-object p1, p1, Ljz0/c;->a:Ljz0/j;

    .line 8
    .line 9
    invoke-virtual {p0, p1}, Lnx0/c;->add(Ljava/lang/Object;)Z

    .line 10
    .line 11
    .line 12
    return-void

    .line 13
    :cond_0
    instance-of v0, p1, Ljz0/f;

    .line 14
    .line 15
    if-eqz v0, :cond_1

    .line 16
    .line 17
    check-cast p1, Ljz0/f;

    .line 18
    .line 19
    iget-object p1, p1, Ljz0/f;->a:Ljava/util/List;

    .line 20
    .line 21
    check-cast p1, Ljava/lang/Iterable;

    .line 22
    .line 23
    invoke-interface {p1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 24
    .line 25
    .line 26
    move-result-object p1

    .line 27
    :goto_0
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    .line 28
    .line 29
    .line 30
    move-result v0

    .line 31
    if-eqz v0, :cond_3

    .line 32
    .line 33
    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 34
    .line 35
    .line 36
    move-result-object v0

    .line 37
    check-cast v0, Ljz0/n;

    .line 38
    .line 39
    invoke-static {p0, v0}, Llp/uc;->a(Lnx0/c;Ljz0/k;)V

    .line 40
    .line 41
    .line 42
    goto :goto_0

    .line 43
    :cond_1
    instance-of v0, p1, Ljz0/h;

    .line 44
    .line 45
    if-nez v0, :cond_6

    .line 46
    .line 47
    instance-of v0, p1, Ljz0/s;

    .line 48
    .line 49
    if-eqz v0, :cond_2

    .line 50
    .line 51
    check-cast p1, Ljz0/s;

    .line 52
    .line 53
    iget-object p1, p1, Ljz0/s;->a:Ljz0/c;

    .line 54
    .line 55
    invoke-static {p0, p1}, Llp/uc;->a(Lnx0/c;Ljz0/k;)V

    .line 56
    .line 57
    .line 58
    return-void

    .line 59
    :cond_2
    instance-of v0, p1, Ljz0/b;

    .line 60
    .line 61
    if-eqz v0, :cond_4

    .line 62
    .line 63
    check-cast p1, Ljz0/b;

    .line 64
    .line 65
    iget-object v0, p1, Ljz0/b;->a:Ljz0/f;

    .line 66
    .line 67
    invoke-static {p0, v0}, Llp/uc;->a(Lnx0/c;Ljz0/k;)V

    .line 68
    .line 69
    .line 70
    iget-object p1, p1, Ljz0/b;->b:Ljava/util/ArrayList;

    .line 71
    .line 72
    invoke-interface {p1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 73
    .line 74
    .line 75
    move-result-object p1

    .line 76
    :goto_1
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    .line 77
    .line 78
    .line 79
    move-result v0

    .line 80
    if-eqz v0, :cond_3

    .line 81
    .line 82
    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 83
    .line 84
    .line 85
    move-result-object v0

    .line 86
    check-cast v0, Ljz0/k;

    .line 87
    .line 88
    invoke-static {p0, v0}, Llp/uc;->a(Lnx0/c;Ljz0/k;)V

    .line 89
    .line 90
    .line 91
    goto :goto_1

    .line 92
    :cond_3
    return-void

    .line 93
    :cond_4
    instance-of v0, p1, Ljz0/p;

    .line 94
    .line 95
    if-eqz v0, :cond_5

    .line 96
    .line 97
    check-cast p1, Ljz0/p;

    .line 98
    .line 99
    iget-object p1, p1, Ljz0/p;->b:Ljz0/f;

    .line 100
    .line 101
    invoke-static {p0, p1}, Llp/uc;->a(Lnx0/c;Ljz0/k;)V

    .line 102
    .line 103
    .line 104
    return-void

    .line 105
    :cond_5
    new-instance p0, La8/r0;

    .line 106
    .line 107
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 108
    .line 109
    .line 110
    throw p0

    .line 111
    :cond_6
    return-void
.end method
