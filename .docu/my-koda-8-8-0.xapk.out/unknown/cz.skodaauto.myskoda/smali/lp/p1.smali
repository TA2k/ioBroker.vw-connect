.class public abstract Llp/p1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static a(CLjava/lang/CharSequence;I)I
    .locals 2

    .line 1
    invoke-interface {p1}, Ljava/lang/CharSequence;->length()I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    :goto_0
    if-ge p2, v0, :cond_1

    .line 6
    .line 7
    invoke-interface {p1, p2}, Ljava/lang/CharSequence;->charAt(I)C

    .line 8
    .line 9
    .line 10
    move-result v1

    .line 11
    if-ne v1, p0, :cond_0

    .line 12
    .line 13
    return p2

    .line 14
    :cond_0
    add-int/lit8 p2, p2, 0x1

    .line 15
    .line 16
    goto :goto_0

    .line 17
    :cond_1
    const/4 p0, -0x1

    .line 18
    return p0
.end method

.method public static b(I)Z
    .locals 3

    .line 1
    invoke-static {p0}, Ljava/lang/Character;->getType(I)I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    const/16 v1, 0x1d

    .line 6
    .line 7
    const/4 v2, 0x1

    .line 8
    if-eq v0, v1, :cond_0

    .line 9
    .line 10
    const/16 v1, 0x1e

    .line 11
    .line 12
    if-eq v0, v1, :cond_0

    .line 13
    .line 14
    packed-switch v0, :pswitch_data_0

    .line 15
    .line 16
    .line 17
    const/16 v0, 0x24

    .line 18
    .line 19
    if-eq p0, v0, :cond_0

    .line 20
    .line 21
    const/16 v0, 0x2b

    .line 22
    .line 23
    if-eq p0, v0, :cond_0

    .line 24
    .line 25
    const/16 v0, 0x5e

    .line 26
    .line 27
    if-eq p0, v0, :cond_0

    .line 28
    .line 29
    const/16 v0, 0x60

    .line 30
    .line 31
    if-eq p0, v0, :cond_0

    .line 32
    .line 33
    const/16 v0, 0x7c

    .line 34
    .line 35
    if-eq p0, v0, :cond_0

    .line 36
    .line 37
    const/16 v0, 0x7e

    .line 38
    .line 39
    if-eq p0, v0, :cond_0

    .line 40
    .line 41
    packed-switch p0, :pswitch_data_1

    .line 42
    .line 43
    .line 44
    const/4 p0, 0x0

    .line 45
    return p0

    .line 46
    :cond_0
    :pswitch_0
    return v2

    .line 47
    :pswitch_data_0
    .packed-switch 0x14
        :pswitch_0
        :pswitch_0
        :pswitch_0
        :pswitch_0
        :pswitch_0
    .end packed-switch

    .line 48
    .line 49
    .line 50
    .line 51
    .line 52
    .line 53
    .line 54
    .line 55
    .line 56
    .line 57
    .line 58
    .line 59
    .line 60
    .line 61
    :pswitch_data_1
    .packed-switch 0x3c
        :pswitch_0
        :pswitch_0
        :pswitch_0
    .end packed-switch
.end method

.method public static c(I)Z
    .locals 3

    .line 1
    const/16 v0, 0x9

    .line 2
    .line 3
    const/4 v1, 0x1

    .line 4
    if-eq p0, v0, :cond_1

    .line 5
    .line 6
    const/16 v0, 0xa

    .line 7
    .line 8
    if-eq p0, v0, :cond_1

    .line 9
    .line 10
    const/16 v0, 0xc

    .line 11
    .line 12
    if-eq p0, v0, :cond_1

    .line 13
    .line 14
    const/16 v2, 0xd

    .line 15
    .line 16
    if-eq p0, v2, :cond_1

    .line 17
    .line 18
    const/16 v2, 0x20

    .line 19
    .line 20
    if-eq p0, v2, :cond_1

    .line 21
    .line 22
    invoke-static {p0}, Ljava/lang/Character;->getType(I)I

    .line 23
    .line 24
    .line 25
    move-result p0

    .line 26
    if-ne p0, v0, :cond_0

    .line 27
    .line 28
    return v1

    .line 29
    :cond_0
    const/4 p0, 0x0

    .line 30
    return p0

    .line 31
    :cond_1
    return v1
.end method

.method public static d(Lkg/p0;Z)Lug/b;
    .locals 10

    .line 1
    const-string v0, "tariff"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lkg/p0;->g:Lkg/o;

    .line 7
    .line 8
    iget-object v2, v0, Lkg/o;->d:Ljava/lang/String;

    .line 9
    .line 10
    iget-object v3, v0, Lkg/o;->e:Ljava/lang/String;

    .line 11
    .line 12
    iget-object v4, p0, Lkg/p0;->e:Ljava/lang/String;

    .line 13
    .line 14
    iget-object v0, p0, Lkg/p0;->n:Ljava/lang/String;

    .line 15
    .line 16
    if-nez v0, :cond_0

    .line 17
    .line 18
    const-string v1, ""

    .line 19
    .line 20
    move-object v5, v1

    .line 21
    goto :goto_0

    .line 22
    :cond_0
    move-object v5, v0

    .line 23
    :goto_0
    const/4 v1, 0x1

    .line 24
    if-eqz v0, :cond_2

    .line 25
    .line 26
    invoke-static {v0}, Lly0/p;->M(Ljava/lang/CharSequence;)Z

    .line 27
    .line 28
    .line 29
    move-result v0

    .line 30
    if-eqz v0, :cond_1

    .line 31
    .line 32
    goto :goto_1

    .line 33
    :cond_1
    const/4 v0, 0x0

    .line 34
    goto :goto_2

    .line 35
    :cond_2
    :goto_1
    move v0, v1

    .line 36
    :goto_2
    xor-int/lit8 v6, v0, 0x1

    .line 37
    .line 38
    iget-object v0, p0, Lkg/p0;->i:Ljava/util/List;

    .line 39
    .line 40
    check-cast v0, Ljava/lang/Iterable;

    .line 41
    .line 42
    new-instance v7, Ljava/util/ArrayList;

    .line 43
    .line 44
    invoke-direct {v7}, Ljava/util/ArrayList;-><init>()V

    .line 45
    .line 46
    .line 47
    invoke-interface {v0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 48
    .line 49
    .line 50
    move-result-object v0

    .line 51
    :cond_3
    :goto_3
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 52
    .line 53
    .line 54
    move-result v1

    .line 55
    if-eqz v1, :cond_6

    .line 56
    .line 57
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 58
    .line 59
    .line 60
    move-result-object v1

    .line 61
    check-cast v1, Lkg/i;

    .line 62
    .line 63
    iget-boolean v8, v1, Lkg/i;->f:Z

    .line 64
    .line 65
    if-nez v8, :cond_5

    .line 66
    .line 67
    if-eqz p1, :cond_4

    .line 68
    .line 69
    goto :goto_4

    .line 70
    :cond_4
    const/4 v1, 0x0

    .line 71
    goto :goto_5

    .line 72
    :cond_5
    :goto_4
    invoke-static {v1}, Llp/q1;->b(Lkg/i;)Lug/d;

    .line 73
    .line 74
    .line 75
    move-result-object v1

    .line 76
    :goto_5
    if-eqz v1, :cond_3

    .line 77
    .line 78
    invoke-virtual {v7, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 79
    .line 80
    .line 81
    goto :goto_3

    .line 82
    :cond_6
    iget-object v8, p0, Lkg/p0;->f:Ljava/util/List;

    .line 83
    .line 84
    iget-object v9, p0, Lkg/p0;->l:Ljava/lang/String;

    .line 85
    .line 86
    new-instance v1, Lug/b;

    .line 87
    .line 88
    invoke-direct/range {v1 .. v9}, Lug/b;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ZLjava/util/ArrayList;Ljava/util/List;Ljava/lang/String;)V

    .line 89
    .line 90
    .line 91
    return-object v1
.end method

.method public static e(Ljava/lang/CharSequence;II)I
    .locals 2

    .line 1
    :goto_0
    if-ge p1, p2, :cond_1

    .line 2
    .line 3
    invoke-interface {p0, p1}, Ljava/lang/CharSequence;->charAt(I)C

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    const/16 v1, 0x9

    .line 8
    .line 9
    if-eq v0, v1, :cond_0

    .line 10
    .line 11
    const/16 v1, 0x20

    .line 12
    .line 13
    if-eq v0, v1, :cond_0

    .line 14
    .line 15
    return p1

    .line 16
    :cond_0
    add-int/lit8 p1, p1, 0x1

    .line 17
    .line 18
    goto :goto_0

    .line 19
    :cond_1
    return p2
.end method

.method public static f(Ljava/lang/CharSequence;II)I
    .locals 2

    .line 1
    :goto_0
    if-lt p1, p2, :cond_1

    .line 2
    .line 3
    invoke-interface {p0, p1}, Ljava/lang/CharSequence;->charAt(I)C

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    const/16 v1, 0x9

    .line 8
    .line 9
    if-eq v0, v1, :cond_0

    .line 10
    .line 11
    const/16 v1, 0x20

    .line 12
    .line 13
    if-eq v0, v1, :cond_0

    .line 14
    .line 15
    return p1

    .line 16
    :cond_0
    add-int/lit8 p1, p1, -0x1

    .line 17
    .line 18
    goto :goto_0

    .line 19
    :cond_1
    add-int/lit8 p2, p2, -0x1

    .line 20
    .line 21
    return p2
.end method
