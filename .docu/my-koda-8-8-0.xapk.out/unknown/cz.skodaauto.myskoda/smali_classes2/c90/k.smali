.class public final Lc90/k;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lyy0/j;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lc90/x;


# direct methods
.method public synthetic constructor <init>(Lc90/x;I)V
    .locals 0

    .line 1
    iput p2, p0, Lc90/k;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lc90/k;->e:Lc90/x;

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
    .locals 12

    .line 1
    iget v0, p0, Lc90/k;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Lne0/s;

    .line 7
    .line 8
    iget-object p0, p0, Lc90/k;->e:Lc90/x;

    .line 9
    .line 10
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 11
    .line 12
    .line 13
    move-result-object v0

    .line 14
    check-cast v0, Lc90/t;

    .line 15
    .line 16
    iget-object v0, v0, Lc90/t;->e:Ljava/lang/String;

    .line 17
    .line 18
    invoke-virtual {v0}, Ljava/lang/String;->length()I

    .line 19
    .line 20
    .line 21
    move-result v0

    .line 22
    sget-object v1, Llx0/b0;->a:Llx0/b0;

    .line 23
    .line 24
    if-nez v0, :cond_1

    .line 25
    .line 26
    instance-of v0, p1, Lne0/e;

    .line 27
    .line 28
    if-eqz v0, :cond_0

    .line 29
    .line 30
    check-cast p1, Lne0/e;

    .line 31
    .line 32
    iget-object p1, p1, Lne0/e;->a:Ljava/lang/Object;

    .line 33
    .line 34
    check-cast p1, Ljava/util/List;

    .line 35
    .line 36
    invoke-static {p0, p1, p2}, Lc90/x;->j(Lc90/x;Ljava/util/List;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 37
    .line 38
    .line 39
    move-result-object p0

    .line 40
    sget-object p1, Lqx0/a;->d:Lqx0/a;

    .line 41
    .line 42
    if-ne p0, p1, :cond_1

    .line 43
    .line 44
    move-object v1, p0

    .line 45
    goto :goto_0

    .line 46
    :cond_0
    instance-of p2, p1, Lne0/c;

    .line 47
    .line 48
    if-eqz p2, :cond_1

    .line 49
    .line 50
    check-cast p1, Lne0/c;

    .line 51
    .line 52
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 53
    .line 54
    .line 55
    move-result-object p2

    .line 56
    move-object v2, p2

    .line 57
    check-cast v2, Lc90/t;

    .line 58
    .line 59
    iget-object p2, p0, Lc90/x;->u:Lij0/a;

    .line 60
    .line 61
    invoke-static {p1, p2}, Ljp/rf;->e(Lne0/c;Lij0/a;)Lql0/g;

    .line 62
    .line 63
    .line 64
    move-result-object v8

    .line 65
    const/4 v10, 0x0

    .line 66
    const/16 v11, 0x1d6

    .line 67
    .line 68
    const/4 v3, 0x0

    .line 69
    const/4 v4, 0x0

    .line 70
    const/4 v5, 0x0

    .line 71
    const/4 v6, 0x0

    .line 72
    const/4 v7, 0x0

    .line 73
    const/4 v9, 0x0

    .line 74
    invoke-static/range {v2 .. v11}, Lc90/t;->a(Lc90/t;ZZLjava/lang/Boolean;Ljava/util/List;Ljava/lang/String;Lql0/g;ZLb90/e;I)Lc90/t;

    .line 75
    .line 76
    .line 77
    move-result-object p1

    .line 78
    invoke-virtual {p0, p1}, Lql0/j;->g(Lql0/h;)V

    .line 79
    .line 80
    .line 81
    :cond_1
    :goto_0
    return-object v1

    .line 82
    :pswitch_0
    check-cast p1, Lgg0/a;

    .line 83
    .line 84
    iget-object p0, p0, Lc90/k;->e:Lc90/x;

    .line 85
    .line 86
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 87
    .line 88
    .line 89
    move-result-object v0

    .line 90
    move-object v1, v0

    .line 91
    check-cast v1, Lc90/t;

    .line 92
    .line 93
    if-eqz p1, :cond_2

    .line 94
    .line 95
    const/4 p1, 0x1

    .line 96
    :goto_1
    move v3, p1

    .line 97
    goto :goto_2

    .line 98
    :cond_2
    const/4 p1, 0x0

    .line 99
    goto :goto_1

    .line 100
    :goto_2
    const/4 v9, 0x0

    .line 101
    const/16 v10, 0x1fd

    .line 102
    .line 103
    const/4 v2, 0x0

    .line 104
    const/4 v4, 0x0

    .line 105
    const/4 v5, 0x0

    .line 106
    const/4 v6, 0x0

    .line 107
    const/4 v7, 0x0

    .line 108
    const/4 v8, 0x0

    .line 109
    invoke-static/range {v1 .. v10}, Lc90/t;->a(Lc90/t;ZZLjava/lang/Boolean;Ljava/util/List;Ljava/lang/String;Lql0/g;ZLb90/e;I)Lc90/t;

    .line 110
    .line 111
    .line 112
    move-result-object p1

    .line 113
    invoke-virtual {p0, p1}, Lql0/j;->g(Lql0/h;)V

    .line 114
    .line 115
    .line 116
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 117
    .line 118
    .line 119
    move-result-object p1

    .line 120
    check-cast p1, Lc90/t;

    .line 121
    .line 122
    iget-boolean p1, p1, Lc90/t;->i:Z

    .line 123
    .line 124
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 125
    .line 126
    if-eqz p1, :cond_3

    .line 127
    .line 128
    invoke-virtual {p0, p2}, Lc90/x;->k(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 129
    .line 130
    .line 131
    move-result-object p0

    .line 132
    sget-object p1, Lqx0/a;->d:Lqx0/a;

    .line 133
    .line 134
    if-ne p0, p1, :cond_3

    .line 135
    .line 136
    goto :goto_3

    .line 137
    :cond_3
    move-object p0, v0

    .line 138
    :goto_3
    sget-object p1, Lqx0/a;->d:Lqx0/a;

    .line 139
    .line 140
    if-ne p0, p1, :cond_4

    .line 141
    .line 142
    move-object v0, p0

    .line 143
    :cond_4
    return-object v0

    .line 144
    nop

    .line 145
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
