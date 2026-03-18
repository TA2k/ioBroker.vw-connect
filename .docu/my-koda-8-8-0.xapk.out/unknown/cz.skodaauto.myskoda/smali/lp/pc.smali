.class public abstract Llp/pc;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static a(JJ)J
    .locals 9

    .line 1
    add-long v0, p0, p2

    .line 2
    .line 3
    xor-long v2, p0, p2

    .line 4
    .line 5
    const-wide/16 v4, 0x0

    .line 6
    .line 7
    cmp-long v2, v2, v4

    .line 8
    .line 9
    const/4 v3, 0x0

    .line 10
    const/4 v6, 0x1

    .line 11
    if-gez v2, :cond_0

    .line 12
    .line 13
    move v2, v6

    .line 14
    goto :goto_0

    .line 15
    :cond_0
    move v2, v3

    .line 16
    :goto_0
    xor-long v7, p0, v0

    .line 17
    .line 18
    cmp-long v4, v7, v4

    .line 19
    .line 20
    if-ltz v4, :cond_1

    .line 21
    .line 22
    move v3, v6

    .line 23
    :cond_1
    or-int/2addr v2, v3

    .line 24
    if-eqz v2, :cond_2

    .line 25
    .line 26
    return-wide v0

    .line 27
    :cond_2
    new-instance v0, Ljava/lang/ArithmeticException;

    .line 28
    .line 29
    const-string v1, "overflow: checkedAdd("

    .line 30
    .line 31
    const-string v2, ", "

    .line 32
    .line 33
    invoke-static {p0, p1, v1, v2}, Lp3/m;->o(JLjava/lang/String;Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 34
    .line 35
    .line 36
    move-result-object p0

    .line 37
    const-string p1, ")"

    .line 38
    .line 39
    invoke-static {p2, p3, p1, p0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->k(JLjava/lang/String;Ljava/lang/StringBuilder;)Ljava/lang/String;

    .line 40
    .line 41
    .line 42
    move-result-object p0

    .line 43
    invoke-direct {v0, p0}, Ljava/lang/ArithmeticException;-><init>(Ljava/lang/String;)V

    .line 44
    .line 45
    .line 46
    throw v0
.end method

.method public static b(JJLjava/math/RoundingMode;)J
    .locals 8

    .line 1
    invoke-virtual {p4}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 2
    .line 3
    .line 4
    div-long v0, p0, p2

    .line 5
    .line 6
    mul-long v2, p2, v0

    .line 7
    .line 8
    sub-long v2, p0, v2

    .line 9
    .line 10
    const-wide/16 v4, 0x0

    .line 11
    .line 12
    cmp-long v6, v2, v4

    .line 13
    .line 14
    if-nez v6, :cond_0

    .line 15
    .line 16
    goto :goto_1

    .line 17
    :cond_0
    xor-long/2addr p0, p2

    .line 18
    const/16 v7, 0x3f

    .line 19
    .line 20
    shr-long/2addr p0, v7

    .line 21
    long-to-int p0, p0

    .line 22
    or-int/lit8 p0, p0, 0x1

    .line 23
    .line 24
    sget-object p1, Ljr/d;->a:[I

    .line 25
    .line 26
    invoke-virtual {p4}, Ljava/lang/Enum;->ordinal()I

    .line 27
    .line 28
    .line 29
    move-result v7

    .line 30
    aget p1, p1, v7

    .line 31
    .line 32
    packed-switch p1, :pswitch_data_0

    .line 33
    .line 34
    .line 35
    new-instance p0, Ljava/lang/AssertionError;

    .line 36
    .line 37
    invoke-direct {p0}, Ljava/lang/AssertionError;-><init>()V

    .line 38
    .line 39
    .line 40
    throw p0

    .line 41
    :pswitch_0
    invoke-static {v2, v3}, Ljava/lang/Math;->abs(J)J

    .line 42
    .line 43
    .line 44
    move-result-wide v2

    .line 45
    invoke-static {p2, p3}, Ljava/lang/Math;->abs(J)J

    .line 46
    .line 47
    .line 48
    move-result-wide p1

    .line 49
    sub-long/2addr p1, v2

    .line 50
    sub-long/2addr v2, p1

    .line 51
    cmp-long p1, v2, v4

    .line 52
    .line 53
    if-nez p1, :cond_1

    .line 54
    .line 55
    sget-object p1, Ljava/math/RoundingMode;->HALF_UP:Ljava/math/RoundingMode;

    .line 56
    .line 57
    if-eq p4, p1, :cond_2

    .line 58
    .line 59
    sget-object p1, Ljava/math/RoundingMode;->HALF_EVEN:Ljava/math/RoundingMode;

    .line 60
    .line 61
    if-ne p4, p1, :cond_3

    .line 62
    .line 63
    const-wide/16 p1, 0x1

    .line 64
    .line 65
    and-long/2addr p1, v0

    .line 66
    cmp-long p1, p1, v4

    .line 67
    .line 68
    if-eqz p1, :cond_3

    .line 69
    .line 70
    goto :goto_0

    .line 71
    :cond_1
    if-lez p1, :cond_3

    .line 72
    .line 73
    goto :goto_0

    .line 74
    :pswitch_1
    if-lez p0, :cond_3

    .line 75
    .line 76
    goto :goto_0

    .line 77
    :pswitch_2
    if-gez p0, :cond_3

    .line 78
    .line 79
    :cond_2
    :goto_0
    :pswitch_3
    int-to-long p0, p0

    .line 80
    add-long/2addr v0, p0

    .line 81
    return-wide v0

    .line 82
    :pswitch_4
    if-nez v6, :cond_4

    .line 83
    .line 84
    :cond_3
    :goto_1
    :pswitch_5
    return-wide v0

    .line 85
    :cond_4
    new-instance p0, Ljava/lang/ArithmeticException;

    .line 86
    .line 87
    const-string p1, "mode was UNNECESSARY, but rounding was necessary"

    .line 88
    .line 89
    invoke-direct {p0, p1}, Ljava/lang/ArithmeticException;-><init>(Ljava/lang/String;)V

    .line 90
    .line 91
    .line 92
    throw p0

    .line 93
    :pswitch_data_0
    .packed-switch 0x1
        :pswitch_4
        :pswitch_5
        :pswitch_2
        :pswitch_3
        :pswitch_1
        :pswitch_0
        :pswitch_0
        :pswitch_0
    .end packed-switch
.end method

.method public static c(JJ)J
    .locals 4

    .line 1
    const-string v0, "a"

    .line 2
    .line 3
    invoke-static {p0, p1, v0}, Llp/qc;->c(JLjava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "b"

    .line 7
    .line 8
    invoke-static {p2, p3, v0}, Llp/qc;->c(JLjava/lang/String;)V

    .line 9
    .line 10
    .line 11
    const-wide/16 v0, 0x0

    .line 12
    .line 13
    cmp-long v2, p0, v0

    .line 14
    .line 15
    if-nez v2, :cond_0

    .line 16
    .line 17
    return-wide p2

    .line 18
    :cond_0
    cmp-long v0, p2, v0

    .line 19
    .line 20
    if-nez v0, :cond_1

    .line 21
    .line 22
    return-wide p0

    .line 23
    :cond_1
    invoke-static {p0, p1}, Ljava/lang/Long;->numberOfTrailingZeros(J)I

    .line 24
    .line 25
    .line 26
    move-result v0

    .line 27
    shr-long/2addr p0, v0

    .line 28
    invoke-static {p2, p3}, Ljava/lang/Long;->numberOfTrailingZeros(J)I

    .line 29
    .line 30
    .line 31
    move-result v1

    .line 32
    shr-long/2addr p2, v1

    .line 33
    :goto_0
    cmp-long v2, p0, p2

    .line 34
    .line 35
    if-eqz v2, :cond_2

    .line 36
    .line 37
    sub-long/2addr p0, p2

    .line 38
    const/16 v2, 0x3f

    .line 39
    .line 40
    shr-long v2, p0, v2

    .line 41
    .line 42
    and-long/2addr v2, p0

    .line 43
    sub-long/2addr p0, v2

    .line 44
    sub-long/2addr p0, v2

    .line 45
    add-long/2addr p2, v2

    .line 46
    invoke-static {p0, p1}, Ljava/lang/Long;->numberOfTrailingZeros(J)I

    .line 47
    .line 48
    .line 49
    move-result v2

    .line 50
    shr-long/2addr p0, v2

    .line 51
    goto :goto_0

    .line 52
    :cond_2
    invoke-static {v0, v1}, Ljava/lang/Math;->min(II)I

    .line 53
    .line 54
    .line 55
    move-result p2

    .line 56
    shl-long/2addr p0, p2

    .line 57
    return-wide p0
.end method

.method public static final d(Lij0/a;)Lvy/n;
    .locals 11

    .line 1
    const/4 v0, 0x0

    .line 2
    new-array v1, v0, [Ljava/lang/Object;

    .line 3
    .line 4
    check-cast p0, Ljj0/f;

    .line 5
    .line 6
    const v2, 0x7f12002a

    .line 7
    .line 8
    .line 9
    invoke-virtual {p0, v2, v1}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 10
    .line 11
    .line 12
    move-result-object v4

    .line 13
    const v1, 0x7f1201aa

    .line 14
    .line 15
    .line 16
    new-array v0, v0, [Ljava/lang/Object;

    .line 17
    .line 18
    invoke-virtual {p0, v1, v0}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 19
    .line 20
    .line 21
    move-result-object v5

    .line 22
    new-instance v3, Lvy/n;

    .line 23
    .line 24
    const/4 v9, 0x0

    .line 25
    const/16 v10, 0x48

    .line 26
    .line 27
    const/4 v6, 0x0

    .line 28
    const/4 v7, 0x0

    .line 29
    const/4 v8, 0x0

    .line 30
    invoke-direct/range {v3 .. v10}, Lvy/n;-><init>(Ljava/lang/String;Ljava/lang/String;FZZLvf0/g;I)V

    .line 31
    .line 32
    .line 33
    return-object v3
.end method

.method public static final e(ZZLmy0/c;Lij0/a;Lvf0/g;)Lvy/n;
    .locals 9

    .line 1
    if-eqz p0, :cond_0

    .line 2
    .line 3
    const v0, 0x7f120028

    .line 4
    .line 5
    .line 6
    goto :goto_0

    .line 7
    :cond_0
    const v0, 0x7f120029

    .line 8
    .line 9
    .line 10
    :goto_0
    new-instance v1, Lvy/n;

    .line 11
    .line 12
    const/4 v2, 0x0

    .line 13
    new-array v3, v2, [Ljava/lang/Object;

    .line 14
    .line 15
    check-cast p3, Ljj0/f;

    .line 16
    .line 17
    invoke-virtual {p3, v0, v3}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 18
    .line 19
    .line 20
    move-result-object v0

    .line 21
    if-eqz p2, :cond_1

    .line 22
    .line 23
    iget-wide v3, p2, Lmy0/c;->d:J

    .line 24
    .line 25
    invoke-static {v3, v4, p3}, Ljp/d1;->f(JLij0/a;)Ljava/lang/String;

    .line 26
    .line 27
    .line 28
    move-result-object v3

    .line 29
    if-nez v3, :cond_2

    .line 30
    .line 31
    :cond_1
    const v3, 0x7f1201aa

    .line 32
    .line 33
    .line 34
    new-array v4, v2, [Ljava/lang/Object;

    .line 35
    .line 36
    invoke-virtual {p3, v3, v4}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 37
    .line 38
    .line 39
    move-result-object v3

    .line 40
    :cond_2
    if-eqz p2, :cond_3

    .line 41
    .line 42
    iget-wide p2, p2, Lmy0/c;->d:J

    .line 43
    .line 44
    sget-object v4, Lmy0/e;->i:Lmy0/e;

    .line 45
    .line 46
    invoke-static {p2, p3, v4}, Lmy0/c;->n(JLmy0/e;)J

    .line 47
    .line 48
    .line 49
    move-result-wide p2

    .line 50
    invoke-static {p2, p3}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 51
    .line 52
    .line 53
    move-result-object p2

    .line 54
    goto :goto_1

    .line 55
    :cond_3
    const/16 p2, 0xa

    .line 56
    .line 57
    invoke-static {p2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 58
    .line 59
    .line 60
    move-result-object p2

    .line 61
    :goto_1
    invoke-virtual {p2}, Ljava/lang/Number;->floatValue()F

    .line 62
    .line 63
    .line 64
    move-result v4

    .line 65
    if-nez p0, :cond_5

    .line 66
    .line 67
    if-eqz p1, :cond_4

    .line 68
    .line 69
    goto :goto_3

    .line 70
    :cond_4
    :goto_2
    move v6, v2

    .line 71
    goto :goto_4

    .line 72
    :cond_5
    :goto_3
    const/4 v2, 0x1

    .line 73
    goto :goto_2

    .line 74
    :goto_4
    const/16 v8, 0x8

    .line 75
    .line 76
    const/4 v5, 0x1

    .line 77
    move-object v7, p4

    .line 78
    move-object v2, v0

    .line 79
    invoke-direct/range {v1 .. v8}, Lvy/n;-><init>(Ljava/lang/String;Ljava/lang/String;FZZLvf0/g;I)V

    .line 80
    .line 81
    .line 82
    return-object v1
.end method

.method public static final f(Lss0/b;Lij0/a;)Lvy/p;
    .locals 17

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    const-string v2, "<this>"

    .line 6
    .line 7
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 8
    .line 9
    .line 10
    const-string v2, "stringResource"

    .line 11
    .line 12
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 13
    .line 14
    .line 15
    sget-object v6, Lvy/o;->d:Lvy/o;

    .line 16
    .line 17
    sget v2, Lmy0/c;->g:I

    .line 18
    .line 19
    const/16 v2, 0xa

    .line 20
    .line 21
    sget-object v3, Lmy0/e;->i:Lmy0/e;

    .line 22
    .line 23
    invoke-static {v2, v3}, Lmy0/h;->s(ILmy0/e;)J

    .line 24
    .line 25
    .line 26
    move-result-wide v2

    .line 27
    new-instance v4, Lmy0/c;

    .line 28
    .line 29
    invoke-direct {v4, v2, v3}, Lmy0/c;-><init>(J)V

    .line 30
    .line 31
    .line 32
    const/4 v2, 0x0

    .line 33
    const/4 v3, 0x0

    .line 34
    invoke-static {v2, v2, v4, v1, v3}, Llp/pc;->e(ZZLmy0/c;Lij0/a;Lvf0/g;)Lvy/n;

    .line 35
    .line 36
    .line 37
    move-result-object v8

    .line 38
    new-instance v9, Lao0/c;

    .line 39
    .line 40
    const/16 v3, 0x8

    .line 41
    .line 42
    invoke-static {v3, v2}, Ljava/time/LocalTime;->of(II)Ljava/time/LocalTime;

    .line 43
    .line 44
    .line 45
    move-result-object v13

    .line 46
    const-string v2, "of(...)"

    .line 47
    .line 48
    invoke-static {v13, v2}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 49
    .line 50
    .line 51
    sget-object v14, Lao0/f;->d:Lao0/f;

    .line 52
    .line 53
    sget-object v2, Ljava/time/DayOfWeek;->MONDAY:Ljava/time/DayOfWeek;

    .line 54
    .line 55
    invoke-static {v2}, Ljp/m1;->k(Ljava/lang/Object;)Ljava/util/Set;

    .line 56
    .line 57
    .line 58
    move-result-object v15

    .line 59
    const/16 v16, 0x0

    .line 60
    .line 61
    const-wide/16 v10, 0x1

    .line 62
    .line 63
    const/4 v12, 0x1

    .line 64
    invoke-direct/range {v9 .. v16}, Lao0/c;-><init>(JZLjava/time/LocalTime;Lao0/f;Ljava/util/Set;Z)V

    .line 65
    .line 66
    .line 67
    invoke-static {v9}, Ljp/k1;->i(Ljava/lang/Object;)Ljava/util/List;

    .line 68
    .line 69
    .line 70
    move-result-object v2

    .line 71
    invoke-static {v1, v2}, Ljp/za;->c(Lij0/a;Ljava/util/List;)Lbo0/l;

    .line 72
    .line 73
    .line 74
    move-result-object v7

    .line 75
    sget-object v1, Lss0/e;->f:Lss0/e;

    .line 76
    .line 77
    invoke-static {v0, v1}, Lkp/u6;->d(Lss0/b;Lss0/e;)Ler0/g;

    .line 78
    .line 79
    .line 80
    move-result-object v4

    .line 81
    invoke-static {v0, v1}, Llp/pf;->i(Lss0/b;Lss0/e;)Llf0/i;

    .line 82
    .line 83
    .line 84
    move-result-object v5

    .line 85
    new-instance v3, Lvy/p;

    .line 86
    .line 87
    const/16 v9, 0x100

    .line 88
    .line 89
    invoke-direct/range {v3 .. v9}, Lvy/p;-><init>(Ler0/g;Llf0/i;Lvy/o;Lbo0/l;Lvy/n;I)V

    .line 90
    .line 91
    .line 92
    return-object v3
.end method

.method public static g(JJ)J
    .locals 9

    .line 1
    invoke-static {p0, p1}, Ljava/lang/Long;->numberOfLeadingZeros(J)I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    not-long v1, p0

    .line 6
    invoke-static {v1, v2}, Ljava/lang/Long;->numberOfLeadingZeros(J)I

    .line 7
    .line 8
    .line 9
    move-result v1

    .line 10
    add-int/2addr v1, v0

    .line 11
    invoke-static {p2, p3}, Ljava/lang/Long;->numberOfLeadingZeros(J)I

    .line 12
    .line 13
    .line 14
    move-result v0

    .line 15
    add-int/2addr v0, v1

    .line 16
    not-long v1, p2

    .line 17
    invoke-static {v1, v2}, Ljava/lang/Long;->numberOfLeadingZeros(J)I

    .line 18
    .line 19
    .line 20
    move-result v1

    .line 21
    add-int/2addr v1, v0

    .line 22
    const/16 v0, 0x41

    .line 23
    .line 24
    if-le v1, v0, :cond_0

    .line 25
    .line 26
    mul-long/2addr p0, p2

    .line 27
    return-wide p0

    .line 28
    :cond_0
    xor-long v2, p0, p2

    .line 29
    .line 30
    const/16 v0, 0x3f

    .line 31
    .line 32
    ushr-long/2addr v2, v0

    .line 33
    const-wide v4, 0x7fffffffffffffffL

    .line 34
    .line 35
    .line 36
    .line 37
    .line 38
    add-long/2addr v2, v4

    .line 39
    const/16 v0, 0x40

    .line 40
    .line 41
    const/4 v4, 0x0

    .line 42
    const/4 v5, 0x1

    .line 43
    if-ge v1, v0, :cond_1

    .line 44
    .line 45
    move v0, v5

    .line 46
    goto :goto_0

    .line 47
    :cond_1
    move v0, v4

    .line 48
    :goto_0
    const-wide/16 v6, 0x0

    .line 49
    .line 50
    cmp-long v1, p0, v6

    .line 51
    .line 52
    if-gez v1, :cond_2

    .line 53
    .line 54
    move v6, v5

    .line 55
    goto :goto_1

    .line 56
    :cond_2
    move v6, v4

    .line 57
    :goto_1
    const-wide/high16 v7, -0x8000000000000000L

    .line 58
    .line 59
    cmp-long v7, p2, v7

    .line 60
    .line 61
    if-nez v7, :cond_3

    .line 62
    .line 63
    move v4, v5

    .line 64
    :cond_3
    and-int/2addr v4, v6

    .line 65
    or-int/2addr v0, v4

    .line 66
    if-eqz v0, :cond_4

    .line 67
    .line 68
    goto :goto_2

    .line 69
    :cond_4
    mul-long v4, p0, p2

    .line 70
    .line 71
    if-eqz v1, :cond_6

    .line 72
    .line 73
    div-long p0, v4, p0

    .line 74
    .line 75
    cmp-long p0, p0, p2

    .line 76
    .line 77
    if-nez p0, :cond_5

    .line 78
    .line 79
    goto :goto_3

    .line 80
    :cond_5
    :goto_2
    return-wide v2

    .line 81
    :cond_6
    :goto_3
    return-wide v4
.end method

.method public static final h(Lvy/p;Lvy/o;)Lvy/p;
    .locals 10

    .line 1
    const-string v1, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object v1, p0, Lvy/p;->h:Lvy/n;

    .line 7
    .line 8
    iget-object v3, v1, Lvy/n;->a:Ljava/lang/String;

    .line 9
    .line 10
    iget-object v4, v1, Lvy/n;->b:Ljava/lang/String;

    .line 11
    .line 12
    iget v5, v1, Lvy/n;->c:F

    .line 13
    .line 14
    iget v6, v1, Lvy/n;->d:F

    .line 15
    .line 16
    iget-boolean v7, v1, Lvy/n;->e:Z

    .line 17
    .line 18
    iget-object v9, v1, Lvy/n;->g:Lvf0/g;

    .line 19
    .line 20
    const-string v1, "title"

    .line 21
    .line 22
    invoke-static {v3, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 23
    .line 24
    .line 25
    const-string v1, "text"

    .line 26
    .line 27
    invoke-static {v4, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 28
    .line 29
    .line 30
    new-instance v2, Lvy/n;

    .line 31
    .line 32
    const/4 v8, 0x1

    .line 33
    invoke-direct/range {v2 .. v9}, Lvy/n;-><init>(Ljava/lang/String;Ljava/lang/String;FFZZLvf0/g;)V

    .line 34
    .line 35
    .line 36
    const/4 v6, 0x0

    .line 37
    const/16 v7, 0x15f

    .line 38
    .line 39
    const/4 v1, 0x0

    .line 40
    move-object v5, v2

    .line 41
    const/4 v2, 0x0

    .line 42
    const/4 v4, 0x0

    .line 43
    move-object v0, p0

    .line 44
    move-object v3, p1

    .line 45
    invoke-static/range {v0 .. v7}, Lvy/p;->a(Lvy/p;ZZLvy/o;Lbo0/l;Lvy/n;ZI)Lvy/p;

    .line 46
    .line 47
    .line 48
    move-result-object v0

    .line 49
    return-object v0
.end method

.method public static final i(Lvy/p;Luy/b;Lij0/a;Lcn0/c;)Lvy/p;
    .locals 11

    .line 1
    const-string v4, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v4, "status"

    .line 7
    .line 8
    invoke-static {p1, v4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    const-string v4, "stringResource"

    .line 12
    .line 13
    invoke-static {p2, v4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    iget-object v4, p1, Luy/b;->b:Luy/a;

    .line 17
    .line 18
    invoke-static {v4}, Llp/pa;->b(Luy/a;)Z

    .line 19
    .line 20
    .line 21
    move-result v5

    .line 22
    iget-object v6, p1, Luy/b;->a:Ljava/time/OffsetDateTime;

    .line 23
    .line 24
    const/4 v7, 0x0

    .line 25
    if-eqz v6, :cond_0

    .line 26
    .line 27
    invoke-static {v6}, Lvo/a;->a(Ljava/time/OffsetDateTime;)J

    .line 28
    .line 29
    .line 30
    move-result-wide v8

    .line 31
    new-instance v6, Lmy0/c;

    .line 32
    .line 33
    invoke-direct {v6, v8, v9}, Lmy0/c;-><init>(J)V

    .line 34
    .line 35
    .line 36
    if-eqz v5, :cond_0

    .line 37
    .line 38
    invoke-static {v8, v9}, Lmy0/c;->i(J)Z

    .line 39
    .line 40
    .line 41
    move-result v8

    .line 42
    if-eqz v8, :cond_0

    .line 43
    .line 44
    goto :goto_0

    .line 45
    :cond_0
    move-object v6, v7

    .line 46
    :goto_0
    if-eqz v5, :cond_1

    .line 47
    .line 48
    move-object v10, v6

    .line 49
    goto :goto_1

    .line 50
    :cond_1
    iget-wide v8, p1, Luy/b;->c:J

    .line 51
    .line 52
    new-instance v10, Lmy0/c;

    .line 53
    .line 54
    invoke-direct {v10, v8, v9}, Lmy0/c;-><init>(J)V

    .line 55
    .line 56
    .line 57
    :goto_1
    iget-object v8, p1, Luy/b;->f:Lmb0/c;

    .line 58
    .line 59
    iget-boolean v9, p0, Lvy/p;->i:Z

    .line 60
    .line 61
    invoke-static {v8, v9, p2}, Ljp/ia;->b(Lmb0/c;ZLij0/a;)Lvf0/g;

    .line 62
    .line 63
    .line 64
    move-result-object v8

    .line 65
    invoke-static {v4}, Llp/pa;->c(Luy/a;)Z

    .line 66
    .line 67
    .line 68
    move-result v9

    .line 69
    if-eqz v9, :cond_2

    .line 70
    .line 71
    invoke-static {p3}, Ljp/sd;->c(Lcn0/c;)Z

    .line 72
    .line 73
    .line 74
    move-result v9

    .line 75
    invoke-static {v5, v9, v10, p2, v8}, Llp/pc;->e(ZZLmy0/c;Lij0/a;Lvf0/g;)Lvy/n;

    .line 76
    .line 77
    .line 78
    move-result-object v8

    .line 79
    goto :goto_2

    .line 80
    :cond_2
    invoke-static {p2}, Llp/pc;->d(Lij0/a;)Lvy/n;

    .line 81
    .line 82
    .line 83
    move-result-object v8

    .line 84
    :goto_2
    invoke-static {p3}, Ljp/sd;->c(Lcn0/c;)Z

    .line 85
    .line 86
    .line 87
    move-result v9

    .line 88
    if-eqz v9, :cond_5

    .line 89
    .line 90
    if-eqz p3, :cond_3

    .line 91
    .line 92
    iget-object v7, p3, Lcn0/c;->e:Lcn0/a;

    .line 93
    .line 94
    :cond_3
    sget-object v3, Lcn0/a;->t:Lcn0/a;

    .line 95
    .line 96
    if-ne v7, v3, :cond_4

    .line 97
    .line 98
    sget-object v3, Lvy/o;->h:Lvy/o;

    .line 99
    .line 100
    goto :goto_3

    .line 101
    :cond_4
    sget-object v3, Lvy/o;->g:Lvy/o;

    .line 102
    .line 103
    goto :goto_3

    .line 104
    :cond_5
    sget-object v3, Luy/a;->d:Luy/a;

    .line 105
    .line 106
    if-ne v4, v3, :cond_6

    .line 107
    .line 108
    sget-object v3, Lvy/o;->d:Lvy/o;

    .line 109
    .line 110
    goto :goto_3

    .line 111
    :cond_6
    if-eqz v5, :cond_7

    .line 112
    .line 113
    if-nez v6, :cond_7

    .line 114
    .line 115
    sget-object v3, Lvy/o;->f:Lvy/o;

    .line 116
    .line 117
    goto :goto_3

    .line 118
    :cond_7
    sget-object v3, Luy/a;->e:Luy/a;

    .line 119
    .line 120
    if-ne v4, v3, :cond_8

    .line 121
    .line 122
    sget-object v3, Lvy/o;->i:Lvy/o;

    .line 123
    .line 124
    goto :goto_3

    .line 125
    :cond_8
    sget-object v3, Lvy/o;->e:Lvy/o;

    .line 126
    .line 127
    :goto_3
    iget-object v1, p1, Luy/b;->d:Ljava/util/ArrayList;

    .line 128
    .line 129
    invoke-static {p2, v1}, Ljp/za;->c(Lij0/a;Ljava/util/List;)Lbo0/l;

    .line 130
    .line 131
    .line 132
    move-result-object v4

    .line 133
    const/4 v6, 0x0

    .line 134
    const/16 v7, 0x10b

    .line 135
    .line 136
    const/4 v1, 0x0

    .line 137
    const/4 v2, 0x0

    .line 138
    move-object v0, p0

    .line 139
    move-object v5, v8

    .line 140
    invoke-static/range {v0 .. v7}, Lvy/p;->a(Lvy/p;ZZLvy/o;Lbo0/l;Lvy/n;ZI)Lvy/p;

    .line 141
    .line 142
    .line 143
    move-result-object v0

    .line 144
    return-object v0
.end method
