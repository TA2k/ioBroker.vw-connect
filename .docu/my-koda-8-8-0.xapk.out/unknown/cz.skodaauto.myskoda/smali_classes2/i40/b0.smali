.class public final Li40/b0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lyy0/j;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lay0/k;


# direct methods
.method public synthetic constructor <init>(ILay0/k;)V
    .locals 0

    .line 1
    iput p1, p0, Li40/b0;->d:I

    .line 2
    .line 3
    iput-object p2, p0, Li40/b0;->e:Lay0/k;

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
    .locals 1

    .line 1
    iget p2, p0, Li40/b0;->d:I

    .line 2
    .line 3
    packed-switch p2, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Ljava/util/List;

    .line 7
    .line 8
    check-cast p1, Ljava/lang/Iterable;

    .line 9
    .line 10
    invoke-interface {p1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 11
    .line 12
    .line 13
    move-result-object p1

    .line 14
    :goto_0
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    .line 15
    .line 16
    .line 17
    move-result p2

    .line 18
    if-eqz p2, :cond_0

    .line 19
    .line 20
    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 21
    .line 22
    .line 23
    move-result-object p2

    .line 24
    check-cast p2, Lxj0/r;

    .line 25
    .line 26
    iget-object v0, p0, Li40/b0;->e:Lay0/k;

    .line 27
    .line 28
    invoke-interface {v0, p2}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 29
    .line 30
    .line 31
    goto :goto_0

    .line 32
    :cond_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 33
    .line 34
    return-object p0

    .line 35
    :pswitch_0
    check-cast p1, Ljava/lang/Number;

    .line 36
    .line 37
    invoke-virtual {p1}, Ljava/lang/Number;->intValue()I

    .line 38
    .line 39
    .line 40
    move-result p1

    .line 41
    new-instance p2, Ljava/lang/Integer;

    .line 42
    .line 43
    invoke-direct {p2, p1}, Ljava/lang/Integer;-><init>(I)V

    .line 44
    .line 45
    .line 46
    iget-object p0, p0, Li40/b0;->e:Lay0/k;

    .line 47
    .line 48
    invoke-interface {p0, p2}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 49
    .line 50
    .line 51
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 52
    .line 53
    return-object p0

    .line 54
    :pswitch_1
    check-cast p1, Landroid/content/Intent;

    .line 55
    .line 56
    if-eqz p1, :cond_1

    .line 57
    .line 58
    invoke-virtual {p1}, Landroid/content/Intent;->getData()Landroid/net/Uri;

    .line 59
    .line 60
    .line 61
    move-result-object p1

    .line 62
    if-eqz p1, :cond_1

    .line 63
    .line 64
    invoke-virtual {p1}, Landroid/net/Uri;->toString()Ljava/lang/String;

    .line 65
    .line 66
    .line 67
    move-result-object p1

    .line 68
    if-eqz p1, :cond_1

    .line 69
    .line 70
    new-instance p2, Ljava/net/URI;

    .line 71
    .line 72
    invoke-direct {p2, p1}, Ljava/net/URI;-><init>(Ljava/lang/String;)V

    .line 73
    .line 74
    .line 75
    goto :goto_1

    .line 76
    :cond_1
    const/4 p2, 0x0

    .line 77
    :goto_1
    iget-object p0, p0, Li40/b0;->e:Lay0/k;

    .line 78
    .line 79
    invoke-interface {p0, p2}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 80
    .line 81
    .line 82
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 83
    .line 84
    return-object p0

    .line 85
    :pswitch_2
    check-cast p1, Ljava/lang/Number;

    .line 86
    .line 87
    invoke-virtual {p1}, Ljava/lang/Number;->intValue()I

    .line 88
    .line 89
    .line 90
    move-result p1

    .line 91
    new-instance p2, Ljava/lang/Integer;

    .line 92
    .line 93
    invoke-direct {p2, p1}, Ljava/lang/Integer;-><init>(I)V

    .line 94
    .line 95
    .line 96
    iget-object p0, p0, Li40/b0;->e:Lay0/k;

    .line 97
    .line 98
    invoke-interface {p0, p2}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 99
    .line 100
    .line 101
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 102
    .line 103
    return-object p0

    .line 104
    :pswitch_3
    check-cast p1, Landroid/content/Intent;

    .line 105
    .line 106
    invoke-virtual {p1}, Landroid/content/Intent;->getData()Landroid/net/Uri;

    .line 107
    .line 108
    .line 109
    move-result-object p1

    .line 110
    if-eqz p1, :cond_2

    .line 111
    .line 112
    invoke-virtual {p1}, Landroid/net/Uri;->toString()Ljava/lang/String;

    .line 113
    .line 114
    .line 115
    move-result-object p1

    .line 116
    goto :goto_2

    .line 117
    :cond_2
    const/4 p1, 0x0

    .line 118
    :goto_2
    iget-object p0, p0, Li40/b0;->e:Lay0/k;

    .line 119
    .line 120
    invoke-interface {p0, p1}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 121
    .line 122
    .line 123
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 124
    .line 125
    return-object p0

    .line 126
    :pswitch_4
    check-cast p1, Ljava/lang/Number;

    .line 127
    .line 128
    invoke-virtual {p1}, Ljava/lang/Number;->intValue()I

    .line 129
    .line 130
    .line 131
    move-result p1

    .line 132
    new-instance p2, Ljava/lang/Integer;

    .line 133
    .line 134
    invoke-direct {p2, p1}, Ljava/lang/Integer;-><init>(I)V

    .line 135
    .line 136
    .line 137
    iget-object p0, p0, Li40/b0;->e:Lay0/k;

    .line 138
    .line 139
    invoke-interface {p0, p2}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 140
    .line 141
    .line 142
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 143
    .line 144
    return-object p0

    .line 145
    :pswitch_5
    check-cast p1, Ljava/lang/Number;

    .line 146
    .line 147
    invoke-virtual {p1}, Ljava/lang/Number;->intValue()I

    .line 148
    .line 149
    .line 150
    move-result p1

    .line 151
    new-instance p2, Ljava/lang/Integer;

    .line 152
    .line 153
    invoke-direct {p2, p1}, Ljava/lang/Integer;-><init>(I)V

    .line 154
    .line 155
    .line 156
    iget-object p0, p0, Li40/b0;->e:Lay0/k;

    .line 157
    .line 158
    invoke-interface {p0, p2}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 159
    .line 160
    .line 161
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 162
    .line 163
    return-object p0

    .line 164
    :pswitch_6
    check-cast p1, Ljava/lang/Number;

    .line 165
    .line 166
    invoke-virtual {p1}, Ljava/lang/Number;->intValue()I

    .line 167
    .line 168
    .line 169
    move-result p1

    .line 170
    new-instance p2, Ljava/lang/Integer;

    .line 171
    .line 172
    invoke-direct {p2, p1}, Ljava/lang/Integer;-><init>(I)V

    .line 173
    .line 174
    .line 175
    iget-object p0, p0, Li40/b0;->e:Lay0/k;

    .line 176
    .line 177
    invoke-interface {p0, p2}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 178
    .line 179
    .line 180
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 181
    .line 182
    return-object p0

    .line 183
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
