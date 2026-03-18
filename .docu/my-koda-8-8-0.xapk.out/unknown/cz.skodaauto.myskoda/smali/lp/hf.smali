.class public abstract Llp/hf;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(Lla/o;Ljava/lang/String;Lrx0/c;)Ljava/lang/Object;
    .locals 2

    .line 1
    new-instance v0, Lkq0/a;

    .line 2
    .line 3
    const/16 v1, 0x9

    .line 4
    .line 5
    invoke-direct {v0, v1}, Lkq0/a;-><init>(I)V

    .line 6
    .line 7
    .line 8
    invoke-interface {p0, p1, v0, p2}, Lla/o;->a(Ljava/lang/String;Lay0/k;Lrx0/c;)Ljava/lang/Object;

    .line 9
    .line 10
    .line 11
    move-result-object p0

    .line 12
    sget-object p1, Lqx0/a;->d:Lqx0/a;

    .line 13
    .line 14
    if-ne p0, p1, :cond_0

    .line 15
    .line 16
    return-object p0

    .line 17
    :cond_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 18
    .line 19
    return-object p0
.end method

.method public static final b(Laz/a;)Ljava/lang/String;
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
    const-string p0, "VEGETARIAN_VEGAN"

    .line 20
    .line 21
    return-object p0

    .line 22
    :pswitch_1
    const-string p0, "LATIN_AMERICAN_CUISINE"

    .line 23
    .line 24
    return-object p0

    .line 25
    :pswitch_2
    const-string p0, "EUROPEAN_AND_MEDITERRANEAN"

    .line 26
    .line 27
    return-object p0

    .line 28
    :pswitch_3
    const-string p0, "CAFES_BRUNCH"

    .line 29
    .line 30
    return-object p0

    .line 31
    :pswitch_4
    const-string p0, "BAKERIES_DESSERTS"

    .line 32
    .line 33
    return-object p0

    .line 34
    :pswitch_5
    const-string p0, "ASIAN_CUISINE"

    .line 35
    .line 36
    return-object p0

    .line 37
    :pswitch_6
    const-string p0, "AMERICAN_AND_FAST_FOOD"

    .line 38
    .line 39
    return-object p0

    .line 40
    nop

    .line 41
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public static final c(Laz/c;)Ljava/lang/String;
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
    const-string p0, "RELAXATION"

    .line 20
    .line 21
    return-object p0

    .line 22
    :pswitch_1
    const-string p0, "SHOPPING"

    .line 23
    .line 24
    return-object p0

    .line 25
    :pswitch_2
    const-string p0, "AMUSEMENTS"

    .line 26
    .line 27
    return-object p0

    .line 28
    :pswitch_3
    const-string p0, "CULTURE"

    .line 29
    .line 30
    return-object p0

    .line 31
    :pswitch_4
    const-string p0, "HISTORY"

    .line 32
    .line 33
    return-object p0

    .line 34
    :pswitch_5
    const-string p0, "SPORT"

    .line 35
    .line 36
    return-object p0

    .line 37
    :pswitch_6
    const-string p0, "OUTDOOR"

    .line 38
    .line 39
    return-object p0

    .line 40
    :pswitch_7
    const-string p0, "FOOD"

    .line 41
    .line 42
    return-object p0

    .line 43
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

.method public static final d(Laz/h;)Ljava/lang/String;
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
    if-eqz p0, :cond_4

    .line 11
    .line 12
    const/4 v0, 0x1

    .line 13
    if-eq p0, v0, :cond_3

    .line 14
    .line 15
    const/4 v0, 0x2

    .line 16
    if-eq p0, v0, :cond_2

    .line 17
    .line 18
    const/4 v0, 0x3

    .line 19
    if-eq p0, v0, :cond_1

    .line 20
    .line 21
    const/4 v0, 0x4

    .line 22
    if-ne p0, v0, :cond_0

    .line 23
    .line 24
    const-string p0, "SENIOR"

    .line 25
    .line 26
    return-object p0

    .line 27
    :cond_0
    new-instance p0, La8/r0;

    .line 28
    .line 29
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 30
    .line 31
    .line 32
    throw p0

    .line 33
    :cond_1
    const-string p0, "FRIENDS"

    .line 34
    .line 35
    return-object p0

    .line 36
    :cond_2
    const-string p0, "FAMILY"

    .line 37
    .line 38
    return-object p0

    .line 39
    :cond_3
    const-string p0, "COUPLE"

    .line 40
    .line 41
    return-object p0

    .line 42
    :cond_4
    const-string p0, "INDIVIDUAL"

    .line 43
    .line 44
    return-object p0
.end method
