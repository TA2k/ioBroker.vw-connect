.class public abstract Ljp/nb;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(Lo41/c;Lay0/k;Lay0/k;)V
    .locals 1

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    instance-of v0, p0, Lo41/a;

    .line 7
    .line 8
    if-eqz v0, :cond_0

    .line 9
    .line 10
    check-cast p0, Lo41/a;

    .line 11
    .line 12
    iget-object p0, p0, Lo41/a;->a:Ljava/lang/Throwable;

    .line 13
    .line 14
    invoke-interface {p1, p0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 15
    .line 16
    .line 17
    return-void

    .line 18
    :cond_0
    instance-of p1, p0, Lo41/b;

    .line 19
    .line 20
    if-eqz p1, :cond_1

    .line 21
    .line 22
    check-cast p0, Lo41/b;

    .line 23
    .line 24
    iget-object p0, p0, Lo41/b;->a:Ljava/lang/Object;

    .line 25
    .line 26
    invoke-interface {p2, p0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 27
    .line 28
    .line 29
    return-void

    .line 30
    :cond_1
    new-instance p0, La8/r0;

    .line 31
    .line 32
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 33
    .line 34
    .line 35
    throw p0
.end method

.method public static final b(Lo41/c;)Ljava/lang/Object;
    .locals 1

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    instance-of v0, p0, Lo41/b;

    .line 7
    .line 8
    if-eqz v0, :cond_1

    .line 9
    .line 10
    if-eqz v0, :cond_0

    .line 11
    .line 12
    check-cast p0, Lo41/b;

    .line 13
    .line 14
    iget-object p0, p0, Lo41/b;->a:Ljava/lang/Object;

    .line 15
    .line 16
    return-object p0

    .line 17
    :cond_0
    new-instance p0, Ljava/util/NoSuchElementException;

    .line 18
    .line 19
    invoke-direct {p0}, Ljava/util/NoSuchElementException;-><init>()V

    .line 20
    .line 21
    .line 22
    throw p0

    .line 23
    :cond_1
    const/4 p0, 0x0

    .line 24
    return-object p0
.end method

.method public static final c(Lo41/c;Lay0/k;)Lo41/c;
    .locals 1

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    instance-of v0, p0, Lo41/a;

    .line 7
    .line 8
    if-eqz v0, :cond_0

    .line 9
    .line 10
    new-instance p1, Lo41/a;

    .line 11
    .line 12
    check-cast p0, Lo41/a;

    .line 13
    .line 14
    iget-object p0, p0, Lo41/a;->a:Ljava/lang/Throwable;

    .line 15
    .line 16
    invoke-direct {p1, p0}, Lo41/a;-><init>(Ljava/lang/Throwable;)V

    .line 17
    .line 18
    .line 19
    return-object p1

    .line 20
    :cond_0
    instance-of v0, p0, Lo41/b;

    .line 21
    .line 22
    if-eqz v0, :cond_1

    .line 23
    .line 24
    new-instance v0, Lo41/b;

    .line 25
    .line 26
    check-cast p0, Lo41/b;

    .line 27
    .line 28
    iget-object p0, p0, Lo41/b;->a:Ljava/lang/Object;

    .line 29
    .line 30
    invoke-interface {p1, p0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 31
    .line 32
    .line 33
    move-result-object p0

    .line 34
    invoke-direct {v0, p0}, Lo41/b;-><init>(Ljava/lang/Object;)V

    .line 35
    .line 36
    .line 37
    return-object v0

    .line 38
    :cond_1
    new-instance p0, La8/r0;

    .line 39
    .line 40
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 41
    .line 42
    .line 43
    throw p0
.end method

.method public static final d(Laz/c;)I
    .locals 1

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-virtual {p0}, Ljava/lang/Enum;->ordinal()I

    .line 7
    .line 8
    .line 9
    move-result p0

    .line 10
    packed-switch p0, :pswitch_data_0

    .line 11
    .line 12
    .line 13
    new-instance p0, La8/r0;

    .line 14
    .line 15
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 16
    .line 17
    .line 18
    throw p0

    .line 19
    :pswitch_0
    const p0, 0x7f08051e

    .line 20
    .line 21
    .line 22
    return p0

    .line 23
    :pswitch_1
    const p0, 0x7f0804be

    .line 24
    .line 25
    .line 26
    return p0

    .line 27
    :pswitch_2
    const p0, 0x7f0803a1

    .line 28
    .line 29
    .line 30
    return p0

    .line 31
    :pswitch_3
    const p0, 0x7f080363

    .line 32
    .line 33
    .line 34
    return p0

    .line 35
    :pswitch_4
    const p0, 0x7f08037f

    .line 36
    .line 37
    .line 38
    return p0

    .line 39
    :pswitch_5
    const p0, 0x7f0804d0

    .line 40
    .line 41
    .line 42
    return p0

    .line 43
    :pswitch_6
    const p0, 0x7f0802fb

    .line 44
    .line 45
    .line 46
    return p0

    .line 47
    :pswitch_7
    const p0, 0x7f0803c5

    .line 48
    .line 49
    .line 50
    return p0

    .line 51
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_7
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public static final e(Laz/c;Lij0/a;)Ljava/lang/String;
    .locals 1

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "stringResource"

    .line 7
    .line 8
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    invoke-virtual {p0}, Ljava/lang/Enum;->ordinal()I

    .line 12
    .line 13
    .line 14
    move-result p0

    .line 15
    const/4 v0, 0x0

    .line 16
    packed-switch p0, :pswitch_data_0

    .line 17
    .line 18
    .line 19
    new-instance p0, La8/r0;

    .line 20
    .line 21
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 22
    .line 23
    .line 24
    throw p0

    .line 25
    :pswitch_0
    new-array p0, v0, [Ljava/lang/Object;

    .line 26
    .line 27
    check-cast p1, Ljj0/f;

    .line 28
    .line 29
    const v0, 0x7f12004b

    .line 30
    .line 31
    .line 32
    invoke-virtual {p1, v0, p0}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 33
    .line 34
    .line 35
    move-result-object p0

    .line 36
    return-object p0

    .line 37
    :pswitch_1
    new-array p0, v0, [Ljava/lang/Object;

    .line 38
    .line 39
    check-cast p1, Ljj0/f;

    .line 40
    .line 41
    const v0, 0x7f12004a

    .line 42
    .line 43
    .line 44
    invoke-virtual {p1, v0, p0}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 45
    .line 46
    .line 47
    move-result-object p0

    .line 48
    return-object p0

    .line 49
    :pswitch_2
    new-array p0, v0, [Ljava/lang/Object;

    .line 50
    .line 51
    check-cast p1, Ljj0/f;

    .line 52
    .line 53
    const v0, 0x7f12003d

    .line 54
    .line 55
    .line 56
    invoke-virtual {p1, v0, p0}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 57
    .line 58
    .line 59
    move-result-object p0

    .line 60
    return-object p0

    .line 61
    :pswitch_3
    new-array p0, v0, [Ljava/lang/Object;

    .line 62
    .line 63
    check-cast p1, Ljj0/f;

    .line 64
    .line 65
    const v0, 0x7f12003b

    .line 66
    .line 67
    .line 68
    invoke-virtual {p1, v0, p0}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 69
    .line 70
    .line 71
    move-result-object p0

    .line 72
    return-object p0

    .line 73
    :pswitch_4
    new-array p0, v0, [Ljava/lang/Object;

    .line 74
    .line 75
    check-cast p1, Ljj0/f;

    .line 76
    .line 77
    const v0, 0x7f120047

    .line 78
    .line 79
    .line 80
    invoke-virtual {p1, v0, p0}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 81
    .line 82
    .line 83
    move-result-object p0

    .line 84
    return-object p0

    .line 85
    :pswitch_5
    new-array p0, v0, [Ljava/lang/Object;

    .line 86
    .line 87
    check-cast p1, Ljj0/f;

    .line 88
    .line 89
    const v0, 0x7f12004c

    .line 90
    .line 91
    .line 92
    invoke-virtual {p1, v0, p0}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 93
    .line 94
    .line 95
    move-result-object p0

    .line 96
    return-object p0

    .line 97
    :pswitch_6
    new-array p0, v0, [Ljava/lang/Object;

    .line 98
    .line 99
    check-cast p1, Ljj0/f;

    .line 100
    .line 101
    const v0, 0x7f120048

    .line 102
    .line 103
    .line 104
    invoke-virtual {p1, v0, p0}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 105
    .line 106
    .line 107
    move-result-object p0

    .line 108
    return-object p0

    .line 109
    :pswitch_7
    new-array p0, v0, [Ljava/lang/Object;

    .line 110
    .line 111
    check-cast p1, Ljj0/f;

    .line 112
    .line 113
    const v0, 0x7f12003e

    .line 114
    .line 115
    .line 116
    invoke-virtual {p1, v0, p0}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 117
    .line 118
    .line 119
    move-result-object p0

    .line 120
    return-object p0

    .line 121
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_7
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
