.class public final Ltz/s0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lyy0/j;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ltz/u0;


# direct methods
.method public synthetic constructor <init>(Ltz/u0;I)V
    .locals 0

    .line 1
    iput p2, p0, Ltz/s0;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Ltz/s0;->e:Ltz/u0;

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
    iget p2, p0, Ltz/s0;->d:I

    .line 2
    .line 3
    packed-switch p2, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Lne0/t;

    .line 7
    .line 8
    instance-of p2, p1, Lne0/c;

    .line 9
    .line 10
    if-eqz p2, :cond_0

    .line 11
    .line 12
    check-cast p1, Lne0/c;

    .line 13
    .line 14
    iget-object p0, p0, Ltz/s0;->e:Ltz/u0;

    .line 15
    .line 16
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 17
    .line 18
    .line 19
    move-result-object p2

    .line 20
    move-object v0, p2

    .line 21
    check-cast v0, Ltz/r0;

    .line 22
    .line 23
    iget-object p2, p0, Ltz/u0;->m:Lij0/a;

    .line 24
    .line 25
    invoke-static {p1, p2}, Ljp/rf;->e(Lne0/c;Lij0/a;)Lql0/g;

    .line 26
    .line 27
    .line 28
    move-result-object v9

    .line 29
    const/16 v10, 0xff

    .line 30
    .line 31
    const/4 v1, 0x0

    .line 32
    const/4 v2, 0x0

    .line 33
    const/4 v3, 0x0

    .line 34
    const/4 v4, 0x0

    .line 35
    const/4 v5, 0x0

    .line 36
    const/4 v6, 0x0

    .line 37
    const/4 v7, 0x0

    .line 38
    const/4 v8, 0x0

    .line 39
    invoke-static/range {v0 .. v10}, Ltz/r0;->a(Ltz/r0;Ljava/lang/Integer;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ZZLtz/q0;ZLql0/g;I)Ltz/r0;

    .line 40
    .line 41
    .line 42
    move-result-object p1

    .line 43
    invoke-virtual {p0, p1}, Lql0/j;->g(Lql0/h;)V

    .line 44
    .line 45
    .line 46
    :cond_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 47
    .line 48
    return-object p0

    .line 49
    :pswitch_0
    check-cast p1, Lne0/t;

    .line 50
    .line 51
    instance-of p2, p1, Lne0/c;

    .line 52
    .line 53
    iget-object p0, p0, Ltz/s0;->e:Ltz/u0;

    .line 54
    .line 55
    if-eqz p2, :cond_1

    .line 56
    .line 57
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 58
    .line 59
    .line 60
    move-result-object p2

    .line 61
    move-object v0, p2

    .line 62
    check-cast v0, Ltz/r0;

    .line 63
    .line 64
    check-cast p1, Lne0/c;

    .line 65
    .line 66
    iget-object p2, p0, Ltz/u0;->m:Lij0/a;

    .line 67
    .line 68
    invoke-static {p1, p2}, Ljp/rf;->e(Lne0/c;Lij0/a;)Lql0/g;

    .line 69
    .line 70
    .line 71
    move-result-object v9

    .line 72
    const/16 v10, 0xff

    .line 73
    .line 74
    const/4 v1, 0x0

    .line 75
    const/4 v2, 0x0

    .line 76
    const/4 v3, 0x0

    .line 77
    const/4 v4, 0x0

    .line 78
    const/4 v5, 0x0

    .line 79
    const/4 v6, 0x0

    .line 80
    const/4 v7, 0x0

    .line 81
    const/4 v8, 0x0

    .line 82
    invoke-static/range {v0 .. v10}, Ltz/r0;->a(Ltz/r0;Ljava/lang/Integer;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ZZLtz/q0;ZLql0/g;I)Ltz/r0;

    .line 83
    .line 84
    .line 85
    move-result-object p1

    .line 86
    goto :goto_0

    .line 87
    :cond_1
    instance-of p1, p1, Lne0/e;

    .line 88
    .line 89
    if-eqz p1, :cond_2

    .line 90
    .line 91
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 92
    .line 93
    .line 94
    move-result-object p1

    .line 95
    move-object v0, p1

    .line 96
    check-cast v0, Ltz/r0;

    .line 97
    .line 98
    const/4 v9, 0x0

    .line 99
    const/16 v10, 0x17f

    .line 100
    .line 101
    const/4 v1, 0x0

    .line 102
    const/4 v2, 0x0

    .line 103
    const/4 v3, 0x0

    .line 104
    const/4 v4, 0x0

    .line 105
    const/4 v5, 0x0

    .line 106
    const/4 v6, 0x0

    .line 107
    const/4 v7, 0x0

    .line 108
    const/4 v8, 0x1

    .line 109
    invoke-static/range {v0 .. v10}, Ltz/r0;->a(Ltz/r0;Ljava/lang/Integer;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ZZLtz/q0;ZLql0/g;I)Ltz/r0;

    .line 110
    .line 111
    .line 112
    move-result-object p1

    .line 113
    :goto_0
    invoke-virtual {p0, p1}, Lql0/j;->g(Lql0/h;)V

    .line 114
    .line 115
    .line 116
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 117
    .line 118
    return-object p0

    .line 119
    :cond_2
    new-instance p0, La8/r0;

    .line 120
    .line 121
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 122
    .line 123
    .line 124
    throw p0

    .line 125
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
