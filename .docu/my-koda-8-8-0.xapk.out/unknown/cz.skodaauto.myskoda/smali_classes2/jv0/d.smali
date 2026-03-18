.class public final synthetic Ljv0/d;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/a;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Liv0/f;


# direct methods
.method public synthetic constructor <init>(Liv0/f;I)V
    .locals 0

    .line 1
    iput p2, p0, Ljv0/d;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Ljv0/d;->e:Liv0/f;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 2

    .line 1
    iget v0, p0, Ljv0/d;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance v0, Ljava/lang/StringBuilder;

    .line 7
    .line 8
    const-string v1, "Destination "

    .line 9
    .line 10
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 11
    .line 12
    .line 13
    iget-object p0, p0, Ljv0/d;->e:Liv0/f;

    .line 14
    .line 15
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 16
    .line 17
    .line 18
    const-string p0, " cant be casted as Route"

    .line 19
    .line 20
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 21
    .line 22
    .line 23
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    return-object p0

    .line 28
    :pswitch_0
    const-string v0, "<this>"

    .line 29
    .line 30
    iget-object p0, p0, Ljv0/d;->e:Liv0/f;

    .line 31
    .line 32
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 33
    .line 34
    .line 35
    sget-object v0, Liv0/g;->a:Liv0/g;

    .line 36
    .line 37
    invoke-virtual {p0, v0}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 38
    .line 39
    .line 40
    move-result v0

    .line 41
    if-eqz v0, :cond_0

    .line 42
    .line 43
    const-string p0, "Maps - My car"

    .line 44
    .line 45
    goto/16 :goto_2

    .line 46
    .line 47
    :cond_0
    sget-object v0, Liv0/a;->a:Liv0/a;

    .line 48
    .line 49
    invoke-virtual {p0, v0}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 50
    .line 51
    .line 52
    move-result v0

    .line 53
    if-eqz v0, :cond_1

    .line 54
    .line 55
    const-string p0, "Maps - Charging stations - list"

    .line 56
    .line 57
    goto :goto_2

    .line 58
    :cond_1
    sget-object v0, Liv0/j;->a:Liv0/j;

    .line 59
    .line 60
    invoke-virtual {p0, v0}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 61
    .line 62
    .line 63
    move-result v0

    .line 64
    if-nez v0, :cond_9

    .line 65
    .line 66
    sget-object v0, Liv0/c;->a:Liv0/c;

    .line 67
    .line 68
    invoke-virtual {p0, v0}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 69
    .line 70
    .line 71
    move-result v0

    .line 72
    if-eqz v0, :cond_2

    .line 73
    .line 74
    goto :goto_1

    .line 75
    :cond_2
    sget-object v0, Liv0/i;->a:Liv0/i;

    .line 76
    .line 77
    invoke-virtual {p0, v0}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 78
    .line 79
    .line 80
    move-result v0

    .line 81
    if-eqz v0, :cond_3

    .line 82
    .line 83
    const-string p0, "Maps - Parking - list"

    .line 84
    .line 85
    goto :goto_2

    .line 86
    :cond_3
    sget-object v0, Liv0/h;->a:Liv0/h;

    .line 87
    .line 88
    invoke-virtual {p0, v0}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 89
    .line 90
    .line 91
    move-result v0

    .line 92
    if-nez v0, :cond_8

    .line 93
    .line 94
    sget-object v0, Liv0/m;->a:Liv0/m;

    .line 95
    .line 96
    invoke-virtual {p0, v0}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 97
    .line 98
    .line 99
    move-result v0

    .line 100
    if-eqz v0, :cond_4

    .line 101
    .line 102
    goto :goto_0

    .line 103
    :cond_4
    sget-object v0, Liv0/n;->a:Liv0/n;

    .line 104
    .line 105
    invoke-virtual {p0, v0}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 106
    .line 107
    .line 108
    move-result v0

    .line 109
    if-eqz v0, :cond_5

    .line 110
    .line 111
    const-string p0, "Maps - Search detail"

    .line 112
    .line 113
    goto :goto_2

    .line 114
    :cond_5
    sget-object v0, Liv0/u;->a:Liv0/u;

    .line 115
    .line 116
    invoke-virtual {p0, v0}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 117
    .line 118
    .line 119
    move-result v0

    .line 120
    if-eqz v0, :cond_6

    .line 121
    .line 122
    const-string p0, "Maps - Services - list"

    .line 123
    .line 124
    goto :goto_2

    .line 125
    :cond_6
    sget-object v0, Liv0/d;->a:Liv0/d;

    .line 126
    .line 127
    invoke-virtual {p0, v0}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 128
    .line 129
    .line 130
    move-result p0

    .line 131
    if-eqz p0, :cond_7

    .line 132
    .line 133
    const-string p0, "Maps - Hotels - list"

    .line 134
    .line 135
    goto :goto_2

    .line 136
    :cond_7
    new-instance p0, La8/r0;

    .line 137
    .line 138
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 139
    .line 140
    .line 141
    throw p0

    .line 142
    :cond_8
    :goto_0
    const-string p0, "Maps - Restaurants - list"

    .line 143
    .line 144
    goto :goto_2

    .line 145
    :cond_9
    :goto_1
    const-string p0, "Maps - Gas stations - list"

    .line 146
    .line 147
    :goto_2
    new-instance v0, Lkj0/h;

    .line 148
    .line 149
    invoke-direct {v0, p0}, Lkj0/h;-><init>(Ljava/lang/String;)V

    .line 150
    .line 151
    .line 152
    return-object v0

    .line 153
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
