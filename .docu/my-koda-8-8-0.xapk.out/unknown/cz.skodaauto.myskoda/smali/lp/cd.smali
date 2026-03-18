.class public abstract Llp/cd;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(Ler0/j;Lij0/a;)Ljava/lang/String;
    .locals 4

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Ler0/j;->b:Ljava/lang/Integer;

    .line 7
    .line 8
    const-string v1, "stringResource"

    .line 9
    .line 10
    invoke-static {p1, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 11
    .line 12
    .line 13
    iget-object p0, p0, Ler0/j;->a:Ler0/k;

    .line 14
    .line 15
    invoke-virtual {p0}, Ljava/lang/Enum;->ordinal()I

    .line 16
    .line 17
    .line 18
    move-result p0

    .line 19
    const-string v1, ""

    .line 20
    .line 21
    const/4 v2, 0x0

    .line 22
    if-eqz p0, :cond_5

    .line 23
    .line 24
    const/4 v3, 0x1

    .line 25
    if-eq p0, v3, :cond_3

    .line 26
    .line 27
    const/4 v3, 0x2

    .line 28
    if-eq p0, v3, :cond_1

    .line 29
    .line 30
    const/4 v0, 0x3

    .line 31
    if-ne p0, v0, :cond_0

    .line 32
    .line 33
    new-array p0, v2, [Ljava/lang/Object;

    .line 34
    .line 35
    check-cast p1, Ljj0/f;

    .line 36
    .line 37
    const v0, 0x7f121271

    .line 38
    .line 39
    .line 40
    invoke-virtual {p1, v0, p0}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 41
    .line 42
    .line 43
    move-result-object p0

    .line 44
    return-object p0

    .line 45
    :cond_0
    new-instance p0, La8/r0;

    .line 46
    .line 47
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 48
    .line 49
    .line 50
    throw p0

    .line 51
    :cond_1
    if-eqz v0, :cond_2

    .line 52
    .line 53
    invoke-virtual {v0}, Ljava/lang/Integer;->intValue()I

    .line 54
    .line 55
    .line 56
    move-result p0

    .line 57
    new-array v0, v2, [Ljava/lang/Object;

    .line 58
    .line 59
    check-cast p1, Ljj0/f;

    .line 60
    .line 61
    const v1, 0x7f100004

    .line 62
    .line 63
    .line 64
    invoke-virtual {p1, v1, p0, v0}, Ljj0/f;->a(II[Ljava/lang/Object;)Ljava/lang/String;

    .line 65
    .line 66
    .line 67
    move-result-object p0

    .line 68
    return-object p0

    .line 69
    :cond_2
    return-object v1

    .line 70
    :cond_3
    if-eqz v0, :cond_4

    .line 71
    .line 72
    invoke-virtual {v0}, Ljava/lang/Integer;->intValue()I

    .line 73
    .line 74
    .line 75
    move-result p0

    .line 76
    new-array v0, v2, [Ljava/lang/Object;

    .line 77
    .line 78
    check-cast p1, Ljj0/f;

    .line 79
    .line 80
    const v1, 0x7f100003

    .line 81
    .line 82
    .line 83
    invoke-virtual {p1, v1, p0, v0}, Ljj0/f;->a(II[Ljava/lang/Object;)Ljava/lang/String;

    .line 84
    .line 85
    .line 86
    move-result-object p0

    .line 87
    return-object p0

    .line 88
    :cond_4
    return-object v1

    .line 89
    :cond_5
    if-eqz v0, :cond_6

    .line 90
    .line 91
    invoke-virtual {v0}, Ljava/lang/Integer;->intValue()I

    .line 92
    .line 93
    .line 94
    move-result p0

    .line 95
    new-array v0, v2, [Ljava/lang/Object;

    .line 96
    .line 97
    check-cast p1, Ljj0/f;

    .line 98
    .line 99
    const v1, 0x7f100002

    .line 100
    .line 101
    .line 102
    invoke-virtual {p1, v1, p0, v0}, Ljj0/f;->a(II[Ljava/lang/Object;)Ljava/lang/String;

    .line 103
    .line 104
    .line 105
    move-result-object p0

    .line 106
    return-object p0

    .line 107
    :cond_6
    return-object v1
.end method

.method public static final b(Ler0/j;Lij0/a;)Ljava/lang/String;
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
    iget-boolean v0, p0, Ler0/j;->c:Z

    .line 12
    .line 13
    if-eqz v0, :cond_0

    .line 14
    .line 15
    const/4 p0, 0x0

    .line 16
    new-array p0, p0, [Ljava/lang/Object;

    .line 17
    .line 18
    check-cast p1, Ljj0/f;

    .line 19
    .line 20
    const v0, 0x7f121270

    .line 21
    .line 22
    .line 23
    invoke-virtual {p1, v0, p0}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    return-object p0

    .line 28
    :cond_0
    invoke-static {p0, p1}, Llp/cd;->a(Ler0/j;Lij0/a;)Ljava/lang/String;

    .line 29
    .line 30
    .line 31
    move-result-object p0

    .line 32
    return-object p0
.end method

.method public static final c(I)Ljava/lang/String;
    .locals 2

    .line 1
    packed-switch p0, :pswitch_data_0

    .line 2
    .line 3
    .line 4
    const-string v0, "Unknown("

    .line 5
    .line 6
    const-string v1, ")"

    .line 7
    .line 8
    invoke-static {v0, p0, v1}, Lu/w;->e(Ljava/lang/String;ILjava/lang/String;)Ljava/lang/String;

    .line 9
    .line 10
    .line 11
    move-result-object p0

    .line 12
    return-object p0

    .line 13
    :pswitch_0
    const-string p0, "BLE_TURNING_OFF"

    .line 14
    .line 15
    return-object p0

    .line 16
    :pswitch_1
    const-string p0, "BLE_ON"

    .line 17
    .line 18
    return-object p0

    .line 19
    :pswitch_2
    const-string p0, "BLE_TURNING_ON"

    .line 20
    .line 21
    return-object p0

    .line 22
    :pswitch_3
    const-string p0, "TURNING_OFF"

    .line 23
    .line 24
    return-object p0

    .line 25
    :pswitch_4
    const-string p0, "ON"

    .line 26
    .line 27
    return-object p0

    .line 28
    :pswitch_5
    const-string p0, "TURNING_ON"

    .line 29
    .line 30
    return-object p0

    .line 31
    :pswitch_6
    const-string p0, "OFF"

    .line 32
    .line 33
    return-object p0

    .line 34
    nop

    .line 35
    :pswitch_data_0
    .packed-switch 0xa
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public static final d(Ler0/d;)I
    .locals 2

    .line 1
    invoke-virtual {p0}, Ljava/lang/Enum;->ordinal()I

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    if-eqz p0, :cond_4

    .line 6
    .line 7
    const/4 v0, 0x1

    .line 8
    if-eq p0, v0, :cond_3

    .line 9
    .line 10
    const/4 v0, 0x2

    .line 11
    if-eq p0, v0, :cond_2

    .line 12
    .line 13
    const/4 v0, 0x3

    .line 14
    const v1, 0x7f080348

    .line 15
    .line 16
    .line 17
    if-eq p0, v0, :cond_1

    .line 18
    .line 19
    const/4 v0, 0x4

    .line 20
    if-eq p0, v0, :cond_1

    .line 21
    .line 22
    const/4 v0, 0x5

    .line 23
    if-ne p0, v0, :cond_0

    .line 24
    .line 25
    return v1

    .line 26
    :cond_0
    new-instance p0, La8/r0;

    .line 27
    .line 28
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 29
    .line 30
    .line 31
    throw p0

    .line 32
    :cond_1
    return v1

    .line 33
    :cond_2
    const p0, 0x7f080342

    .line 34
    .line 35
    .line 36
    return p0

    .line 37
    :cond_3
    const p0, 0x7f080358

    .line 38
    .line 39
    .line 40
    return p0

    .line 41
    :cond_4
    const p0, 0x7f0804bd

    .line 42
    .line 43
    .line 44
    return p0
.end method

.method public static final e(Ler0/c;Lij0/a;)Ljava/lang/String;
    .locals 4

    .line 1
    iget-object v0, p0, Ler0/c;->j:Ljava/time/LocalDate;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    invoke-static {v0}, Lu7/b;->c(Ljava/time/LocalDate;)Ljava/lang/String;

    .line 6
    .line 7
    .line 8
    move-result-object v1

    .line 9
    goto :goto_0

    .line 10
    :cond_0
    const-string v1, ""

    .line 11
    .line 12
    :goto_0
    iget-object p0, p0, Ler0/c;->e:Ler0/d;

    .line 13
    .line 14
    invoke-virtual {p0}, Ljava/lang/Enum;->ordinal()I

    .line 15
    .line 16
    .line 17
    move-result p0

    .line 18
    const/4 v2, 0x0

    .line 19
    if-eqz p0, :cond_8

    .line 20
    .line 21
    const/4 v3, 0x1

    .line 22
    if-eq p0, v3, :cond_7

    .line 23
    .line 24
    const/4 v3, 0x2

    .line 25
    if-eq p0, v3, :cond_4

    .line 26
    .line 27
    const/4 v0, 0x3

    .line 28
    if-eq p0, v0, :cond_3

    .line 29
    .line 30
    const/4 v0, 0x4

    .line 31
    if-eq p0, v0, :cond_2

    .line 32
    .line 33
    const/4 v0, 0x5

    .line 34
    if-ne p0, v0, :cond_1

    .line 35
    .line 36
    new-array p0, v2, [Ljava/lang/Object;

    .line 37
    .line 38
    check-cast p1, Ljj0/f;

    .line 39
    .line 40
    const v0, 0x7f12127d

    .line 41
    .line 42
    .line 43
    invoke-virtual {p1, v0, p0}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 44
    .line 45
    .line 46
    move-result-object p0

    .line 47
    return-object p0

    .line 48
    :cond_1
    new-instance p0, La8/r0;

    .line 49
    .line 50
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 51
    .line 52
    .line 53
    throw p0

    .line 54
    :cond_2
    filled-new-array {v1}, [Ljava/lang/Object;

    .line 55
    .line 56
    .line 57
    move-result-object p0

    .line 58
    check-cast p1, Ljj0/f;

    .line 59
    .line 60
    const v0, 0x7f12127e

    .line 61
    .line 62
    .line 63
    invoke-virtual {p1, v0, p0}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 64
    .line 65
    .line 66
    move-result-object p0

    .line 67
    return-object p0

    .line 68
    :cond_3
    filled-new-array {v1}, [Ljava/lang/Object;

    .line 69
    .line 70
    .line 71
    move-result-object p0

    .line 72
    check-cast p1, Ljj0/f;

    .line 73
    .line 74
    const v0, 0x7f12127f

    .line 75
    .line 76
    .line 77
    invoke-virtual {p1, v0, p0}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 78
    .line 79
    .line 80
    move-result-object p0

    .line 81
    return-object p0

    .line 82
    :cond_4
    if-eqz v0, :cond_6

    .line 83
    .line 84
    invoke-virtual {v0}, Ljava/time/LocalDate;->getYear()I

    .line 85
    .line 86
    .line 87
    move-result p0

    .line 88
    invoke-static {}, Ljava/time/LocalDate;->now()Ljava/time/LocalDate;

    .line 89
    .line 90
    .line 91
    move-result-object v0

    .line 92
    invoke-virtual {v0}, Ljava/time/LocalDate;->getYear()I

    .line 93
    .line 94
    .line 95
    move-result v0

    .line 96
    sub-int/2addr p0, v0

    .line 97
    const/16 v0, 0x1e

    .line 98
    .line 99
    if-le p0, v0, :cond_5

    .line 100
    .line 101
    goto :goto_1

    .line 102
    :cond_5
    filled-new-array {v1}, [Ljava/lang/Object;

    .line 103
    .line 104
    .line 105
    move-result-object p0

    .line 106
    check-cast p1, Ljj0/f;

    .line 107
    .line 108
    const v0, 0x7f121284

    .line 109
    .line 110
    .line 111
    invoke-virtual {p1, v0, p0}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 112
    .line 113
    .line 114
    move-result-object p0

    .line 115
    return-object p0

    .line 116
    :cond_6
    :goto_1
    new-array p0, v2, [Ljava/lang/Object;

    .line 117
    .line 118
    check-cast p1, Ljj0/f;

    .line 119
    .line 120
    const v0, 0x7f121283

    .line 121
    .line 122
    .line 123
    invoke-virtual {p1, v0, p0}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 124
    .line 125
    .line 126
    move-result-object p0

    .line 127
    return-object p0

    .line 128
    :cond_7
    new-array p0, v2, [Ljava/lang/Object;

    .line 129
    .line 130
    check-cast p1, Ljj0/f;

    .line 131
    .line 132
    const v0, 0x7f121281

    .line 133
    .line 134
    .line 135
    invoke-virtual {p1, v0, p0}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 136
    .line 137
    .line 138
    move-result-object p0

    .line 139
    return-object p0

    .line 140
    :cond_8
    new-array p0, v2, [Ljava/lang/Object;

    .line 141
    .line 142
    check-cast p1, Ljj0/f;

    .line 143
    .line 144
    const v0, 0x7f12127c

    .line 145
    .line 146
    .line 147
    invoke-virtual {p1, v0, p0}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 148
    .line 149
    .line 150
    move-result-object p0

    .line 151
    return-object p0
.end method

.method public static final f(Ler0/b;)I
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
    if-eqz p0, :cond_2

    .line 11
    .line 12
    const/4 v0, 0x1

    .line 13
    if-eq p0, v0, :cond_1

    .line 14
    .line 15
    const/4 v0, 0x2

    .line 16
    if-ne p0, v0, :cond_0

    .line 17
    .line 18
    const p0, 0x7f121278

    .line 19
    .line 20
    .line 21
    return p0

    .line 22
    :cond_0
    new-instance p0, La8/r0;

    .line 23
    .line 24
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 25
    .line 26
    .line 27
    throw p0

    .line 28
    :cond_1
    const p0, 0x7f12127b

    .line 29
    .line 30
    .line 31
    return p0

    .line 32
    :cond_2
    const p0, 0x7f121279

    .line 33
    .line 34
    .line 35
    return p0
.end method
