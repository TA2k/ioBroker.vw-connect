.class public final synthetic Lqf/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ll2/b1;


# direct methods
.method public synthetic constructor <init>(Ll2/b1;I)V
    .locals 0

    .line 1
    iput p2, p0, Lqf/c;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lqf/c;->e:Ll2/b1;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, Lqf/c;->d:I

    .line 2
    .line 3
    check-cast p1, Lz9/y;

    .line 4
    .line 5
    packed-switch v0, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    check-cast p2, Ljava/lang/String;

    .line 9
    .line 10
    const-string v0, "$this$navigator"

    .line 11
    .line 12
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 13
    .line 14
    .line 15
    const-string v0, "id"

    .line 16
    .line 17
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 18
    .line 19
    .line 20
    iget-object p0, p0, Lqf/c;->e:Ll2/b1;

    .line 21
    .line 22
    invoke-interface {p0, p2}, Ll2/b1;->setValue(Ljava/lang/Object;)V

    .line 23
    .line 24
    .line 25
    const/4 p0, 0x0

    .line 26
    const/4 p2, 0x6

    .line 27
    const-string v0, "/order_charging_card_warning"

    .line 28
    .line 29
    invoke-static {p1, v0, p0, p2}, Lz9/y;->f(Lz9/y;Ljava/lang/String;Lz9/b0;I)V

    .line 30
    .line 31
    .line 32
    :goto_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 33
    .line 34
    return-object p0

    .line 35
    :pswitch_0
    check-cast p2, Ltc/q;

    .line 36
    .line 37
    const-string v0, "$this$navigator"

    .line 38
    .line 39
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 40
    .line 41
    .line 42
    const-string v0, "response"

    .line 43
    .line 44
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 45
    .line 46
    .line 47
    iget-object p0, p0, Lqf/c;->e:Ll2/b1;

    .line 48
    .line 49
    invoke-interface {p0, p2}, Ll2/b1;->setValue(Ljava/lang/Object;)V

    .line 50
    .line 51
    .line 52
    const/4 p0, 0x0

    .line 53
    const/4 p2, 0x6

    .line 54
    const-string v0, "/add_charging_card"

    .line 55
    .line 56
    invoke-static {p1, v0, p0, p2}, Lz9/y;->f(Lz9/y;Ljava/lang/String;Lz9/b0;I)V

    .line 57
    .line 58
    .line 59
    goto :goto_0

    .line 60
    :pswitch_1
    check-cast p2, Lrd/a;

    .line 61
    .line 62
    const-string v0, "$this$navigator"

    .line 63
    .line 64
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 65
    .line 66
    .line 67
    const-string v0, "sessionDetails"

    .line 68
    .line 69
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 70
    .line 71
    .line 72
    iget-object p0, p0, Lqf/c;->e:Ll2/b1;

    .line 73
    .line 74
    invoke-interface {p0, p2}, Ll2/b1;->setValue(Ljava/lang/Object;)V

    .line 75
    .line 76
    .line 77
    const/4 p0, 0x0

    .line 78
    const/4 p2, 0x6

    .line 79
    const-string v0, "/details"

    .line 80
    .line 81
    invoke-static {p1, v0, p0, p2}, Lz9/y;->f(Lz9/y;Ljava/lang/String;Lz9/b0;I)V

    .line 82
    .line 83
    .line 84
    goto :goto_0

    .line 85
    :pswitch_2
    check-cast p2, Luf/n;

    .line 86
    .line 87
    const-string v0, "$this$navigator"

    .line 88
    .line 89
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 90
    .line 91
    .line 92
    const-string v0, "param"

    .line 93
    .line 94
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 95
    .line 96
    .line 97
    iget-object p0, p0, Lqf/c;->e:Ll2/b1;

    .line 98
    .line 99
    invoke-interface {p0, p2}, Ll2/b1;->setValue(Ljava/lang/Object;)V

    .line 100
    .line 101
    .line 102
    const/4 p0, 0x0

    .line 103
    const/4 p2, 0x6

    .line 104
    const-string v0, "/activation_deactivation"

    .line 105
    .line 106
    invoke-static {p1, v0, p0, p2}, Lz9/y;->f(Lz9/y;Ljava/lang/String;Lz9/b0;I)V

    .line 107
    .line 108
    .line 109
    goto :goto_0

    .line 110
    :pswitch_3
    check-cast p2, Luf/p;

    .line 111
    .line 112
    const-string v0, "$this$navigator"

    .line 113
    .line 114
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 115
    .line 116
    .line 117
    const-string v0, "param"

    .line 118
    .line 119
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 120
    .line 121
    .line 122
    iget-object p0, p0, Lqf/c;->e:Ll2/b1;

    .line 123
    .line 124
    invoke-interface {p0, p2}, Ll2/b1;->setValue(Ljava/lang/Object;)V

    .line 125
    .line 126
    .line 127
    new-instance p0, Lqe/b;

    .line 128
    .line 129
    const/4 p2, 0x7

    .line 130
    invoke-direct {p0, p2}, Lqe/b;-><init>(I)V

    .line 131
    .line 132
    .line 133
    const-string p2, "/installation_uninstallation"

    .line 134
    .line 135
    invoke-virtual {p1, p2, p0}, Lz9/y;->d(Ljava/lang/String;Lay0/k;)V

    .line 136
    .line 137
    .line 138
    goto :goto_0

    .line 139
    :pswitch_4
    check-cast p2, Ljava/lang/String;

    .line 140
    .line 141
    const-string v0, "$this$navigator"

    .line 142
    .line 143
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 144
    .line 145
    .line 146
    const-string v0, "param"

    .line 147
    .line 148
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 149
    .line 150
    .line 151
    iget-object p0, p0, Lqf/c;->e:Ll2/b1;

    .line 152
    .line 153
    invoke-interface {p0, p2}, Ll2/b1;->setValue(Ljava/lang/Object;)V

    .line 154
    .line 155
    .line 156
    const/4 p0, 0x0

    .line 157
    const/4 p2, 0x6

    .line 158
    const-string v0, "/confirm_uninstallation"

    .line 159
    .line 160
    invoke-static {p1, v0, p0, p2}, Lz9/y;->f(Lz9/y;Ljava/lang/String;Lz9/b0;I)V

    .line 161
    .line 162
    .line 163
    goto/16 :goto_0

    .line 164
    .line 165
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
