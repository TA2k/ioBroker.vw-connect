.class public final Lct0/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lyy0/j;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lct0/h;


# direct methods
.method public synthetic constructor <init>(Lct0/h;I)V
    .locals 0

    .line 1
    iput p2, p0, Lct0/a;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lct0/a;->e:Lct0/h;

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
    .locals 7

    .line 1
    iget p2, p0, Lct0/a;->d:I

    .line 2
    .line 3
    packed-switch p2, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Llx0/b0;

    .line 7
    .line 8
    iget-object p0, p0, Lct0/a;->e:Lct0/h;

    .line 9
    .line 10
    iget-object p0, p0, Lct0/h;->i:Lat0/a;

    .line 11
    .line 12
    invoke-static {p0}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 13
    .line 14
    .line 15
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 16
    .line 17
    return-object p0

    .line 18
    :pswitch_0
    check-cast p1, Lbt0/a;

    .line 19
    .line 20
    iget-object p0, p0, Lct0/a;->e:Lct0/h;

    .line 21
    .line 22
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 23
    .line 24
    .line 25
    move-result-object p2

    .line 26
    move-object v0, p2

    .line 27
    check-cast v0, Lct0/g;

    .line 28
    .line 29
    if-eqz p1, :cond_0

    .line 30
    .line 31
    const/4 p2, 0x1

    .line 32
    :goto_0
    move v3, p2

    .line 33
    goto :goto_1

    .line 34
    :cond_0
    const/4 p2, 0x0

    .line 35
    goto :goto_0

    .line 36
    :goto_1
    if-eqz p1, :cond_1

    .line 37
    .line 38
    iget-object p2, p1, Lbt0/a;->a:Lbt0/b;

    .line 39
    .line 40
    :goto_2
    move-object v4, p2

    .line 41
    goto :goto_3

    .line 42
    :cond_1
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 43
    .line 44
    .line 45
    move-result-object p2

    .line 46
    check-cast p2, Lct0/g;

    .line 47
    .line 48
    iget-object p2, p2, Lct0/g;->d:Lbt0/b;

    .line 49
    .line 50
    goto :goto_2

    .line 51
    :goto_3
    const/4 v5, 0x0

    .line 52
    const/16 v6, 0x13

    .line 53
    .line 54
    const/4 v1, 0x0

    .line 55
    const/4 v2, 0x0

    .line 56
    invoke-static/range {v0 .. v6}, Lct0/g;->a(Lct0/g;ZZZLbt0/b;Lct0/f;I)Lct0/g;

    .line 57
    .line 58
    .line 59
    move-result-object p2

    .line 60
    invoke-virtual {p0, p2}, Lql0/j;->g(Lql0/h;)V

    .line 61
    .line 62
    .line 63
    if-eqz p1, :cond_2

    .line 64
    .line 65
    iget-object p1, p1, Lbt0/a;->b:Ljava/lang/Long;

    .line 66
    .line 67
    if-nez p1, :cond_2

    .line 68
    .line 69
    iget-object p0, p0, Lct0/h;->k:Lat0/l;

    .line 70
    .line 71
    invoke-static {p0}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 72
    .line 73
    .line 74
    :cond_2
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 75
    .line 76
    return-object p0

    .line 77
    :pswitch_1
    check-cast p1, Ljava/lang/Boolean;

    .line 78
    .line 79
    invoke-virtual {p1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 80
    .line 81
    .line 82
    move-result v2

    .line 83
    iget-object p0, p0, Lct0/a;->e:Lct0/h;

    .line 84
    .line 85
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 86
    .line 87
    .line 88
    move-result-object p1

    .line 89
    move-object v0, p1

    .line 90
    check-cast v0, Lct0/g;

    .line 91
    .line 92
    const/4 v5, 0x0

    .line 93
    const/16 v6, 0x1d

    .line 94
    .line 95
    const/4 v1, 0x0

    .line 96
    const/4 v3, 0x0

    .line 97
    const/4 v4, 0x0

    .line 98
    invoke-static/range {v0 .. v6}, Lct0/g;->a(Lct0/g;ZZZLbt0/b;Lct0/f;I)Lct0/g;

    .line 99
    .line 100
    .line 101
    move-result-object p1

    .line 102
    invoke-virtual {p0, p1}, Lql0/j;->g(Lql0/h;)V

    .line 103
    .line 104
    .line 105
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 106
    .line 107
    return-object p0

    .line 108
    nop

    .line 109
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
