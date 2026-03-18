.class public final Lfk/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lay0/k;


# direct methods
.method public synthetic constructor <init>(ILay0/k;)V
    .locals 0

    .line 1
    iput p1, p0, Lfk/b;->d:I

    .line 2
    .line 3
    iput-object p2, p0, Lfk/b;->e:Lay0/k;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 5

    .line 1
    iget v0, p0, Lfk/b;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Ljava/lang/Boolean;

    .line 7
    .line 8
    invoke-virtual {p1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 9
    .line 10
    .line 11
    move-result p1

    .line 12
    iget-object p0, p0, Lfk/b;->e:Lay0/k;

    .line 13
    .line 14
    new-instance v0, Lfh/c;

    .line 15
    .line 16
    invoke-direct {v0, p1}, Lfh/c;-><init>(Z)V

    .line 17
    .line 18
    .line 19
    invoke-interface {p0, v0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 20
    .line 21
    .line 22
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 23
    .line 24
    return-object p0

    .line 25
    :pswitch_0
    check-cast p1, Lv2/j;

    .line 26
    .line 27
    sget-object v0, Lv2/l;->c:Ljava/lang/Object;

    .line 28
    .line 29
    monitor-enter v0

    .line 30
    :try_start_0
    sget-wide v1, Lv2/l;->e:J

    .line 31
    .line 32
    const/4 v3, 0x1

    .line 33
    int-to-long v3, v3

    .line 34
    add-long/2addr v3, v1

    .line 35
    sput-wide v3, Lv2/l;->e:J
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 36
    .line 37
    monitor-exit v0

    .line 38
    iget-object p0, p0, Lfk/b;->e:Lay0/k;

    .line 39
    .line 40
    new-instance v0, Lv2/e;

    .line 41
    .line 42
    invoke-direct {v0, v1, v2, p1, p0}, Lv2/e;-><init>(JLv2/j;Lay0/k;)V

    .line 43
    .line 44
    .line 45
    return-object v0

    .line 46
    :catchall_0
    move-exception p0

    .line 47
    monitor-exit v0

    .line 48
    throw p0

    .line 49
    :pswitch_1
    check-cast p1, Ljava/lang/Number;

    .line 50
    .line 51
    invoke-virtual {p1}, Ljava/lang/Number;->longValue()J

    .line 52
    .line 53
    .line 54
    move-result-wide v0

    .line 55
    iget-object p0, p0, Lfk/b;->e:Lay0/k;

    .line 56
    .line 57
    const-wide/32 v2, 0xf4240

    .line 58
    .line 59
    .line 60
    div-long/2addr v0, v2

    .line 61
    invoke-static {v0, v1}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 62
    .line 63
    .line 64
    move-result-object p1

    .line 65
    invoke-interface {p0, p1}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 66
    .line 67
    .line 68
    move-result-object p0

    .line 69
    return-object p0

    .line 70
    :pswitch_2
    check-cast p1, Ljava/lang/String;

    .line 71
    .line 72
    const-string v0, "it"

    .line 73
    .line 74
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 75
    .line 76
    .line 77
    iget-object p0, p0, Lfk/b;->e:Lay0/k;

    .line 78
    .line 79
    invoke-interface {p0, p1}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 80
    .line 81
    .line 82
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 83
    .line 84
    return-object p0

    .line 85
    :pswitch_3
    check-cast p1, Ljava/lang/String;

    .line 86
    .line 87
    const-string v0, "it"

    .line 88
    .line 89
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 90
    .line 91
    .line 92
    iget-object p0, p0, Lfk/b;->e:Lay0/k;

    .line 93
    .line 94
    invoke-interface {p0, p1}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 95
    .line 96
    .line 97
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 98
    .line 99
    return-object p0

    .line 100
    :pswitch_4
    check-cast p1, Ljava/lang/String;

    .line 101
    .line 102
    const-string v0, "it"

    .line 103
    .line 104
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 105
    .line 106
    .line 107
    iget-object p0, p0, Lfk/b;->e:Lay0/k;

    .line 108
    .line 109
    invoke-interface {p0, p1}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 110
    .line 111
    .line 112
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 113
    .line 114
    return-object p0

    .line 115
    :pswitch_5
    check-cast p1, Ljava/lang/String;

    .line 116
    .line 117
    const-string v0, "it"

    .line 118
    .line 119
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 120
    .line 121
    .line 122
    iget-object p0, p0, Lfk/b;->e:Lay0/k;

    .line 123
    .line 124
    invoke-interface {p0, p1}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 125
    .line 126
    .line 127
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 128
    .line 129
    return-object p0

    .line 130
    nop

    .line 131
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
