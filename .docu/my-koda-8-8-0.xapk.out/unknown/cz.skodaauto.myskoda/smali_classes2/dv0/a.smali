.class public final Ldv0/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lyy0/j;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ldv0/e;


# direct methods
.method public synthetic constructor <init>(Ldv0/e;I)V
    .locals 0

    .line 1
    iput p2, p0, Ldv0/a;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Ldv0/a;->e:Ldv0/e;

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
    .locals 4

    .line 1
    iget v0, p0, Ldv0/a;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Ljava/lang/Boolean;

    .line 7
    .line 8
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 9
    .line 10
    .line 11
    iget-object p0, p0, Ldv0/a;->e:Ldv0/e;

    .line 12
    .line 13
    iget-object p0, p0, Ldv0/e;->t:Lee0/d;

    .line 14
    .line 15
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 16
    .line 17
    .line 18
    invoke-virtual {p0, p2}, Lee0/d;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    sget-object p1, Lqx0/a;->d:Lqx0/a;

    .line 23
    .line 24
    if-ne p0, p1, :cond_0

    .line 25
    .line 26
    goto :goto_0

    .line 27
    :cond_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 28
    .line 29
    :goto_0
    return-object p0

    .line 30
    :pswitch_0
    check-cast p1, Ljava/lang/Boolean;

    .line 31
    .line 32
    invoke-virtual {p1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 33
    .line 34
    .line 35
    move-result p1

    .line 36
    iget-object p0, p0, Ldv0/a;->e:Ldv0/e;

    .line 37
    .line 38
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 39
    .line 40
    .line 41
    move-result-object p2

    .line 42
    check-cast p2, Ldv0/d;

    .line 43
    .line 44
    const/4 v0, 0x0

    .line 45
    const/4 v1, 0x3

    .line 46
    const/4 v2, 0x0

    .line 47
    invoke-static {p2, v2, v0, p1, v1}, Ldv0/d;->a(Ldv0/d;ZLhb0/a;ZI)Ldv0/d;

    .line 48
    .line 49
    .line 50
    move-result-object p1

    .line 51
    invoke-virtual {p0, p1}, Lql0/j;->g(Lql0/h;)V

    .line 52
    .line 53
    .line 54
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 55
    .line 56
    return-object p0

    .line 57
    :pswitch_1
    check-cast p1, Lmp0/a;

    .line 58
    .line 59
    sget-object p2, Lmp0/a;->f:Lmp0/a;

    .line 60
    .line 61
    if-ne p1, p2, :cond_1

    .line 62
    .line 63
    iget-object p0, p0, Ldv0/a;->e:Ldv0/e;

    .line 64
    .line 65
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 66
    .line 67
    .line 68
    move-result-object p1

    .line 69
    check-cast p1, Ldv0/d;

    .line 70
    .line 71
    const/4 p2, 0x0

    .line 72
    const/4 v0, 0x6

    .line 73
    const/4 v1, 0x1

    .line 74
    const/4 v2, 0x0

    .line 75
    invoke-static {p1, v1, v2, p2, v0}, Ldv0/d;->a(Ldv0/d;ZLhb0/a;ZI)Ldv0/d;

    .line 76
    .line 77
    .line 78
    move-result-object p1

    .line 79
    invoke-virtual {p0, p1}, Lql0/j;->g(Lql0/h;)V

    .line 80
    .line 81
    .line 82
    :cond_1
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 83
    .line 84
    return-object p0

    .line 85
    :pswitch_2
    check-cast p1, Lss0/d0;

    .line 86
    .line 87
    iget-object p0, p0, Ldv0/a;->e:Ldv0/e;

    .line 88
    .line 89
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 90
    .line 91
    .line 92
    move-result-object v0

    .line 93
    check-cast v0, Ldv0/d;

    .line 94
    .line 95
    instance-of v1, p1, Lss0/g;

    .line 96
    .line 97
    if-eqz v1, :cond_2

    .line 98
    .line 99
    sget-object v1, Lhb0/a;->e:Lhb0/a;

    .line 100
    .line 101
    goto :goto_1

    .line 102
    :cond_2
    sget-object v1, Lhb0/a;->d:Lhb0/a;

    .line 103
    .line 104
    :goto_1
    const/4 v2, 0x5

    .line 105
    const/4 v3, 0x0

    .line 106
    invoke-static {v0, v3, v1, v3, v2}, Ldv0/d;->a(Ldv0/d;ZLhb0/a;ZI)Ldv0/d;

    .line 107
    .line 108
    .line 109
    move-result-object v0

    .line 110
    invoke-virtual {p0, v0}, Lql0/j;->g(Lql0/h;)V

    .line 111
    .line 112
    .line 113
    if-nez p1, :cond_3

    .line 114
    .line 115
    iget-object p0, p0, Ldv0/e;->i:Lgb0/l;

    .line 116
    .line 117
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 118
    .line 119
    .line 120
    invoke-virtual {p0, p2}, Lgb0/l;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 121
    .line 122
    .line 123
    move-result-object p0

    .line 124
    sget-object p1, Lqx0/a;->d:Lqx0/a;

    .line 125
    .line 126
    if-ne p0, p1, :cond_3

    .line 127
    .line 128
    goto :goto_2

    .line 129
    :cond_3
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 130
    .line 131
    :goto_2
    return-object p0

    .line 132
    nop

    .line 133
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
