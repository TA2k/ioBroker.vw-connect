.class public final Ljv0/g;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lyy0/j;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ljv0/i;


# direct methods
.method public synthetic constructor <init>(Ljv0/i;I)V
    .locals 0

    .line 1
    iput p2, p0, Ljv0/g;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Ljv0/g;->e:Ljv0/i;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final emit(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 11

    .line 1
    iget p2, p0, Ljv0/g;->d:I

    .line 2
    .line 3
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 4
    .line 5
    iget-object p0, p0, Ljv0/g;->e:Ljv0/i;

    .line 6
    .line 7
    packed-switch p2, :pswitch_data_0

    .line 8
    .line 9
    .line 10
    check-cast p1, Lxj0/r;

    .line 11
    .line 12
    sget-object p1, Ljv0/i;->D:Lhl0/b;

    .line 13
    .line 14
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 15
    .line 16
    .line 17
    move-result-object p1

    .line 18
    move-object v1, p1

    .line 19
    check-cast v1, Ljv0/h;

    .line 20
    .line 21
    const/4 v9, 0x0

    .line 22
    const/16 v10, 0xdf

    .line 23
    .line 24
    const/4 v2, 0x0

    .line 25
    const/4 v3, 0x0

    .line 26
    const/4 v4, 0x0

    .line 27
    const/4 v5, 0x0

    .line 28
    const/4 v6, 0x0

    .line 29
    const/4 v7, 0x1

    .line 30
    const/4 v8, 0x0

    .line 31
    invoke-static/range {v1 .. v10}, Ljv0/h;->a(Ljv0/h;Ljava/lang/String;Ljava/util/List;Liv0/f;ZZZZZI)Ljv0/h;

    .line 32
    .line 33
    .line 34
    move-result-object p1

    .line 35
    invoke-virtual {p0, p1}, Lql0/j;->g(Lql0/h;)V

    .line 36
    .line 37
    .line 38
    return-object v0

    .line 39
    :pswitch_0
    check-cast p1, Lbl0/g0;

    .line 40
    .line 41
    sget-object p2, Ljv0/i;->D:Lhl0/b;

    .line 42
    .line 43
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 44
    .line 45
    .line 46
    move-result-object p2

    .line 47
    move-object v1, p2

    .line 48
    check-cast v1, Ljv0/h;

    .line 49
    .line 50
    if-eqz p1, :cond_0

    .line 51
    .line 52
    const/4 p2, 0x1

    .line 53
    :goto_0
    move v5, p2

    .line 54
    goto :goto_1

    .line 55
    :cond_0
    const/4 p2, 0x0

    .line 56
    goto :goto_0

    .line 57
    :goto_1
    instance-of v6, p1, Lbl0/w;

    .line 58
    .line 59
    const/4 v9, 0x0

    .line 60
    const/16 v10, 0xe7

    .line 61
    .line 62
    const/4 v2, 0x0

    .line 63
    const/4 v3, 0x0

    .line 64
    const/4 v4, 0x0

    .line 65
    const/4 v7, 0x0

    .line 66
    const/4 v8, 0x0

    .line 67
    invoke-static/range {v1 .. v10}, Ljv0/h;->a(Ljv0/h;Ljava/lang/String;Ljava/util/List;Liv0/f;ZZZZZI)Ljv0/h;

    .line 68
    .line 69
    .line 70
    move-result-object p1

    .line 71
    invoke-virtual {p0, p1}, Lql0/j;->g(Lql0/h;)V

    .line 72
    .line 73
    .line 74
    return-object v0

    .line 75
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
