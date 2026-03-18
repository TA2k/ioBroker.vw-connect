.class public final Ln50/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lyy0/j;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ln50/e;


# direct methods
.method public synthetic constructor <init>(Ln50/e;I)V
    .locals 0

    .line 1
    iput p2, p0, Ln50/a;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Ln50/a;->e:Ln50/e;

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
    iget p2, p0, Ln50/a;->d:I

    .line 2
    .line 3
    packed-switch p2, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Llx0/l;

    .line 7
    .line 8
    iget-object p0, p0, Ln50/a;->e:Ln50/e;

    .line 9
    .line 10
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 11
    .line 12
    .line 13
    move-result-object p2

    .line 14
    check-cast p2, Ln50/d;

    .line 15
    .line 16
    const/4 v0, 0x0

    .line 17
    const/4 v1, 0x3

    .line 18
    const/4 v2, 0x0

    .line 19
    invoke-static {p2, v2, v0, p1, v1}, Ln50/d;->a(Ln50/d;Ljava/lang/String;ZLlx0/l;I)Ln50/d;

    .line 20
    .line 21
    .line 22
    move-result-object p1

    .line 23
    invoke-virtual {p0, p1}, Lql0/j;->g(Lql0/h;)V

    .line 24
    .line 25
    .line 26
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 27
    .line 28
    return-object p0

    .line 29
    :pswitch_0
    check-cast p1, Ljava/lang/Boolean;

    .line 30
    .line 31
    invoke-virtual {p1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 32
    .line 33
    .line 34
    move-result p1

    .line 35
    iget-object p0, p0, Ln50/a;->e:Ln50/e;

    .line 36
    .line 37
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 38
    .line 39
    .line 40
    move-result-object p2

    .line 41
    check-cast p2, Ln50/d;

    .line 42
    .line 43
    const/4 v0, 0x0

    .line 44
    const/4 v1, 0x5

    .line 45
    invoke-static {p2, v0, p1, v0, v1}, Ln50/d;->a(Ln50/d;Ljava/lang/String;ZLlx0/l;I)Ln50/d;

    .line 46
    .line 47
    .line 48
    move-result-object p1

    .line 49
    invoke-virtual {p0, p1}, Lql0/j;->g(Lql0/h;)V

    .line 50
    .line 51
    .line 52
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 53
    .line 54
    return-object p0

    .line 55
    :pswitch_1
    check-cast p1, Lne0/s;

    .line 56
    .line 57
    instance-of p2, p1, Lne0/c;

    .line 58
    .line 59
    const/4 v0, 0x6

    .line 60
    const/4 v1, 0x0

    .line 61
    const/4 v2, 0x0

    .line 62
    const-string v3, ""

    .line 63
    .line 64
    iget-object p0, p0, Ln50/a;->e:Ln50/e;

    .line 65
    .line 66
    if-eqz p2, :cond_0

    .line 67
    .line 68
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 69
    .line 70
    .line 71
    move-result-object p1

    .line 72
    check-cast p1, Ln50/d;

    .line 73
    .line 74
    invoke-static {p1, v3, v2, v1, v0}, Ln50/d;->a(Ln50/d;Ljava/lang/String;ZLlx0/l;I)Ln50/d;

    .line 75
    .line 76
    .line 77
    move-result-object p1

    .line 78
    invoke-virtual {p0, p1}, Lql0/j;->g(Lql0/h;)V

    .line 79
    .line 80
    .line 81
    goto :goto_1

    .line 82
    :cond_0
    instance-of p2, p1, Lne0/d;

    .line 83
    .line 84
    if-nez p2, :cond_3

    .line 85
    .line 86
    instance-of p2, p1, Lne0/e;

    .line 87
    .line 88
    if-eqz p2, :cond_2

    .line 89
    .line 90
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 91
    .line 92
    .line 93
    move-result-object p2

    .line 94
    check-cast p2, Ln50/d;

    .line 95
    .line 96
    check-cast p1, Lne0/e;

    .line 97
    .line 98
    iget-object p1, p1, Lne0/e;->a:Ljava/lang/Object;

    .line 99
    .line 100
    check-cast p1, Lyr0/e;

    .line 101
    .line 102
    iget-object p1, p1, Lyr0/e;->c:Ljava/lang/String;

    .line 103
    .line 104
    if-nez p1, :cond_1

    .line 105
    .line 106
    goto :goto_0

    .line 107
    :cond_1
    move-object v3, p1

    .line 108
    :goto_0
    invoke-static {p2, v3, v2, v1, v0}, Ln50/d;->a(Ln50/d;Ljava/lang/String;ZLlx0/l;I)Ln50/d;

    .line 109
    .line 110
    .line 111
    move-result-object p1

    .line 112
    invoke-virtual {p0, p1}, Lql0/j;->g(Lql0/h;)V

    .line 113
    .line 114
    .line 115
    goto :goto_1

    .line 116
    :cond_2
    new-instance p0, La8/r0;

    .line 117
    .line 118
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 119
    .line 120
    .line 121
    throw p0

    .line 122
    :cond_3
    :goto_1
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 123
    .line 124
    return-object p0

    .line 125
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
