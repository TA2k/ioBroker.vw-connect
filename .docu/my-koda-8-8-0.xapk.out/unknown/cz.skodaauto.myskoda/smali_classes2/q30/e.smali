.class public final Lq30/e;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lyy0/j;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lq30/h;


# direct methods
.method public synthetic constructor <init>(Lq30/h;I)V
    .locals 0

    .line 1
    iput p2, p0, Lq30/e;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lq30/e;->e:Lq30/h;

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
    .locals 6

    .line 1
    iget p2, p0, Lq30/e;->d:I

    .line 2
    .line 3
    packed-switch p2, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Lne0/s;

    .line 7
    .line 8
    instance-of p2, p1, Lne0/e;

    .line 9
    .line 10
    iget-object p0, p0, Lq30/e;->e:Lq30/h;

    .line 11
    .line 12
    if-eqz p2, :cond_0

    .line 13
    .line 14
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 15
    .line 16
    .line 17
    move-result-object p1

    .line 18
    move-object v0, p1

    .line 19
    check-cast v0, Lq30/g;

    .line 20
    .line 21
    const/4 v4, 0x0

    .line 22
    const/16 v5, 0xf

    .line 23
    .line 24
    const/4 v1, 0x0

    .line 25
    const/4 v2, 0x0

    .line 26
    const/4 v3, 0x0

    .line 27
    invoke-static/range {v0 .. v5}, Lq30/g;->a(Lq30/g;Ljava/lang/String;Ljava/lang/String;Ljava/util/List;ZI)Lq30/g;

    .line 28
    .line 29
    .line 30
    move-result-object p1

    .line 31
    goto :goto_0

    .line 32
    :cond_0
    instance-of p2, p1, Lne0/d;

    .line 33
    .line 34
    if-eqz p2, :cond_1

    .line 35
    .line 36
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 37
    .line 38
    .line 39
    move-result-object p1

    .line 40
    move-object v0, p1

    .line 41
    check-cast v0, Lq30/g;

    .line 42
    .line 43
    const/4 v4, 0x1

    .line 44
    const/16 v5, 0xf

    .line 45
    .line 46
    const/4 v1, 0x0

    .line 47
    const/4 v2, 0x0

    .line 48
    const/4 v3, 0x0

    .line 49
    invoke-static/range {v0 .. v5}, Lq30/g;->a(Lq30/g;Ljava/lang/String;Ljava/lang/String;Ljava/util/List;ZI)Lq30/g;

    .line 50
    .line 51
    .line 52
    move-result-object p1

    .line 53
    goto :goto_0

    .line 54
    :cond_1
    instance-of p1, p1, Lne0/c;

    .line 55
    .line 56
    if-eqz p1, :cond_2

    .line 57
    .line 58
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 59
    .line 60
    .line 61
    move-result-object p1

    .line 62
    move-object v0, p1

    .line 63
    check-cast v0, Lq30/g;

    .line 64
    .line 65
    const/4 v4, 0x0

    .line 66
    const/16 v5, 0xf

    .line 67
    .line 68
    const/4 v1, 0x0

    .line 69
    const/4 v2, 0x0

    .line 70
    const/4 v3, 0x0

    .line 71
    invoke-static/range {v0 .. v5}, Lq30/g;->a(Lq30/g;Ljava/lang/String;Ljava/lang/String;Ljava/util/List;ZI)Lq30/g;

    .line 72
    .line 73
    .line 74
    move-result-object p1

    .line 75
    :goto_0
    invoke-virtual {p0, p1}, Lql0/j;->g(Lql0/h;)V

    .line 76
    .line 77
    .line 78
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 79
    .line 80
    return-object p0

    .line 81
    :cond_2
    new-instance p0, La8/r0;

    .line 82
    .line 83
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 84
    .line 85
    .line 86
    throw p0

    .line 87
    :pswitch_0
    move-object v3, p1

    .line 88
    check-cast v3, Ljava/util/List;

    .line 89
    .line 90
    iget-object p0, p0, Lq30/e;->e:Lq30/h;

    .line 91
    .line 92
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 93
    .line 94
    .line 95
    move-result-object p1

    .line 96
    move-object v0, p1

    .line 97
    check-cast v0, Lq30/g;

    .line 98
    .line 99
    const/4 v4, 0x0

    .line 100
    const/16 v5, 0x17

    .line 101
    .line 102
    const/4 v1, 0x0

    .line 103
    const/4 v2, 0x0

    .line 104
    invoke-static/range {v0 .. v5}, Lq30/g;->a(Lq30/g;Ljava/lang/String;Ljava/lang/String;Ljava/util/List;ZI)Lq30/g;

    .line 105
    .line 106
    .line 107
    move-result-object p1

    .line 108
    invoke-virtual {p0, p1}, Lql0/j;->g(Lql0/h;)V

    .line 109
    .line 110
    .line 111
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 112
    .line 113
    return-object p0

    .line 114
    nop

    .line 115
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
