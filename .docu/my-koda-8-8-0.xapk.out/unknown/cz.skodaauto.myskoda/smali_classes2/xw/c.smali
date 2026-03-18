.class public final Lxw/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lxw/p;


# instance fields
.field public final synthetic a:I


# direct methods
.method public synthetic constructor <init>(I)V
    .locals 0

    .line 1
    iput p1, p0, Lxw/c;->a:I

    .line 2
    .line 3
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final get(Ljava/lang/Object;Ljava/lang/String;)Ljava/lang/Object;
    .locals 0

    .line 1
    iget p0, p0, Lxw/c;->a:I

    .line 2
    .line 3
    packed-switch p0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    sget-object p0, Lxw/v;->d:Ljava/lang/String;

    .line 7
    .line 8
    return-object p0

    .line 9
    :pswitch_0
    return-object p1

    .line 10
    :pswitch_1
    :try_start_0
    check-cast p1, Ljava/util/Iterator;

    .line 11
    .line 12
    invoke-static {p2}, Ljava/lang/Integer;->parseInt(Ljava/lang/String;)I

    .line 13
    .line 14
    .line 15
    move-result p0

    .line 16
    const/4 p2, 0x0

    .line 17
    :goto_0
    if-ge p2, p0, :cond_0

    .line 18
    .line 19
    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 20
    .line 21
    .line 22
    add-int/lit8 p2, p2, 0x1

    .line 23
    .line 24
    goto :goto_0

    .line 25
    :cond_0
    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 26
    .line 27
    .line 28
    move-result-object p0
    :try_end_0
    .catch Ljava/lang/NumberFormatException; {:try_start_0 .. :try_end_0} :catch_1
    .catch Ljava/util/NoSuchElementException; {:try_start_0 .. :try_end_0} :catch_0

    .line 29
    goto :goto_1

    .line 30
    :catch_0
    sget-object p0, Lxw/v;->d:Ljava/lang/String;

    .line 31
    .line 32
    goto :goto_1

    .line 33
    :catch_1
    sget-object p0, Lxw/v;->d:Ljava/lang/String;

    .line 34
    .line 35
    :goto_1
    return-object p0

    .line 36
    :pswitch_2
    :try_start_1
    check-cast p1, Ljava/util/List;

    .line 37
    .line 38
    invoke-static {p2}, Ljava/lang/Integer;->parseInt(Ljava/lang/String;)I

    .line 39
    .line 40
    .line 41
    move-result p0

    .line 42
    invoke-interface {p1, p0}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 43
    .line 44
    .line 45
    move-result-object p0
    :try_end_1
    .catch Ljava/lang/NumberFormatException; {:try_start_1 .. :try_end_1} :catch_3
    .catch Ljava/lang/IndexOutOfBoundsException; {:try_start_1 .. :try_end_1} :catch_2

    .line 46
    goto :goto_2

    .line 47
    :catch_2
    sget-object p0, Lxw/v;->d:Ljava/lang/String;

    .line 48
    .line 49
    goto :goto_2

    .line 50
    :catch_3
    sget-object p0, Lxw/v;->d:Ljava/lang/String;

    .line 51
    .line 52
    :goto_2
    return-object p0

    .line 53
    :pswitch_3
    check-cast p1, Ljava/util/Map;

    .line 54
    .line 55
    invoke-interface {p1, p2}, Ljava/util/Map;->containsKey(Ljava/lang/Object;)Z

    .line 56
    .line 57
    .line 58
    move-result p0

    .line 59
    if-eqz p0, :cond_1

    .line 60
    .line 61
    invoke-interface {p1, p2}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 62
    .line 63
    .line 64
    move-result-object p0

    .line 65
    goto :goto_3

    .line 66
    :cond_1
    const-string p0, "entrySet"

    .line 67
    .line 68
    if-ne p2, p0, :cond_2

    .line 69
    .line 70
    invoke-interface {p1}, Ljava/util/Map;->entrySet()Ljava/util/Set;

    .line 71
    .line 72
    .line 73
    move-result-object p0

    .line 74
    goto :goto_3

    .line 75
    :cond_2
    sget-object p0, Lxw/v;->d:Ljava/lang/String;

    .line 76
    .line 77
    :goto_3
    return-object p0

    .line 78
    nop

    .line 79
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public toString()Ljava/lang/String;
    .locals 1

    .line 1
    iget v0, p0, Lxw/c;->a:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    invoke-super {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 7
    .line 8
    .line 9
    move-result-object p0

    .line 10
    return-object p0

    .line 11
    :pswitch_0
    const-string p0, "THIS_FETCHER"

    .line 12
    .line 13
    return-object p0

    .line 14
    :pswitch_1
    const-string p0, "ITER_FETCHER"

    .line 15
    .line 16
    return-object p0

    .line 17
    :pswitch_2
    const-string p0, "LIST_FETCHER"

    .line 18
    .line 19
    return-object p0

    .line 20
    :pswitch_3
    const-string p0, "MAP_FETCHER"

    .line 21
    .line 22
    return-object p0

    .line 23
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
