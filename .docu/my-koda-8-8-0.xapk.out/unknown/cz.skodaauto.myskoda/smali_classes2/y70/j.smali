.class public final Ly70/j;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lyy0/j;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ly70/o;


# direct methods
.method public synthetic constructor <init>(Ly70/o;I)V
    .locals 0

    .line 1
    iput p2, p0, Ly70/j;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Ly70/j;->e:Ly70/o;

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
    .locals 9

    .line 1
    iget p2, p0, Ly70/j;->d:I

    .line 2
    .line 3
    packed-switch p2, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Lne0/s;

    .line 7
    .line 8
    instance-of p2, p1, Lne0/c;

    .line 9
    .line 10
    iget-object p0, p0, Ly70/j;->e:Ly70/o;

    .line 11
    .line 12
    if-eqz p2, :cond_0

    .line 13
    .line 14
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 15
    .line 16
    .line 17
    move-result-object p2

    .line 18
    move-object v0, p2

    .line 19
    check-cast v0, Ly70/k;

    .line 20
    .line 21
    check-cast p1, Lne0/c;

    .line 22
    .line 23
    iget-object p2, p0, Ly70/o;->n:Lij0/a;

    .line 24
    .line 25
    invoke-static {p1, p2}, Ljp/rf;->e(Lne0/c;Lij0/a;)Lql0/g;

    .line 26
    .line 27
    .line 28
    move-result-object v1

    .line 29
    const/4 v7, 0x0

    .line 30
    const/16 v8, 0x7a

    .line 31
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
    invoke-static/range {v0 .. v8}, Ly70/k;->a(Ly70/k;Lql0/g;ZZZLjava/lang/String;Ljava/lang/String;Ly70/w1;I)Ly70/k;

    .line 38
    .line 39
    .line 40
    move-result-object p1

    .line 41
    goto :goto_0

    .line 42
    :cond_0
    instance-of p2, p1, Lne0/e;

    .line 43
    .line 44
    if-eqz p2, :cond_1

    .line 45
    .line 46
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 47
    .line 48
    .line 49
    move-result-object p1

    .line 50
    move-object v0, p1

    .line 51
    check-cast v0, Ly70/k;

    .line 52
    .line 53
    const/4 v7, 0x0

    .line 54
    const/16 v8, 0x7b

    .line 55
    .line 56
    const/4 v1, 0x0

    .line 57
    const/4 v2, 0x0

    .line 58
    const/4 v3, 0x0

    .line 59
    const/4 v4, 0x0

    .line 60
    const/4 v5, 0x0

    .line 61
    const/4 v6, 0x0

    .line 62
    invoke-static/range {v0 .. v8}, Ly70/k;->a(Ly70/k;Lql0/g;ZZZLjava/lang/String;Ljava/lang/String;Ly70/w1;I)Ly70/k;

    .line 63
    .line 64
    .line 65
    move-result-object p1

    .line 66
    goto :goto_0

    .line 67
    :cond_1
    instance-of p1, p1, Lne0/d;

    .line 68
    .line 69
    if-eqz p1, :cond_2

    .line 70
    .line 71
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 72
    .line 73
    .line 74
    move-result-object p1

    .line 75
    move-object v0, p1

    .line 76
    check-cast v0, Ly70/k;

    .line 77
    .line 78
    const/4 v7, 0x0

    .line 79
    const/16 v8, 0x7b

    .line 80
    .line 81
    const/4 v1, 0x0

    .line 82
    const/4 v2, 0x0

    .line 83
    const/4 v3, 0x1

    .line 84
    const/4 v4, 0x0

    .line 85
    const/4 v5, 0x0

    .line 86
    const/4 v6, 0x0

    .line 87
    invoke-static/range {v0 .. v8}, Ly70/k;->a(Ly70/k;Lql0/g;ZZZLjava/lang/String;Ljava/lang/String;Ly70/w1;I)Ly70/k;

    .line 88
    .line 89
    .line 90
    move-result-object p1

    .line 91
    :goto_0
    invoke-virtual {p0, p1}, Lql0/j;->g(Lql0/h;)V

    .line 92
    .line 93
    .line 94
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 95
    .line 96
    return-object p0

    .line 97
    :cond_2
    new-instance p0, La8/r0;

    .line 98
    .line 99
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 100
    .line 101
    .line 102
    throw p0

    .line 103
    :pswitch_0
    check-cast p1, Lne0/s;

    .line 104
    .line 105
    iget-object p0, p0, Ly70/j;->e:Ly70/o;

    .line 106
    .line 107
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 108
    .line 109
    .line 110
    move-result-object p2

    .line 111
    move-object v0, p2

    .line 112
    check-cast v0, Ly70/k;

    .line 113
    .line 114
    instance-of p2, p1, Lne0/e;

    .line 115
    .line 116
    const/4 v1, 0x0

    .line 117
    if-eqz p2, :cond_3

    .line 118
    .line 119
    move-object v2, p1

    .line 120
    check-cast v2, Lne0/e;

    .line 121
    .line 122
    goto :goto_1

    .line 123
    :cond_3
    move-object v2, v1

    .line 124
    :goto_1
    if-eqz v2, :cond_5

    .line 125
    .line 126
    iget-object v2, v2, Lne0/e;->a:Ljava/lang/Object;

    .line 127
    .line 128
    check-cast v2, Lyr0/e;

    .line 129
    .line 130
    if-eqz v2, :cond_5

    .line 131
    .line 132
    iget-object v2, v2, Lyr0/e;->f:Ljava/lang/String;

    .line 133
    .line 134
    if-nez v2, :cond_4

    .line 135
    .line 136
    goto :goto_2

    .line 137
    :cond_4
    move-object v5, v2

    .line 138
    goto :goto_3

    .line 139
    :cond_5
    :goto_2
    move-object v5, v1

    .line 140
    :goto_3
    if-eqz p2, :cond_6

    .line 141
    .line 142
    check-cast p1, Lne0/e;

    .line 143
    .line 144
    goto :goto_4

    .line 145
    :cond_6
    move-object p1, v1

    .line 146
    :goto_4
    if-eqz p1, :cond_7

    .line 147
    .line 148
    iget-object p1, p1, Lne0/e;->a:Ljava/lang/Object;

    .line 149
    .line 150
    check-cast p1, Lyr0/e;

    .line 151
    .line 152
    if-eqz p1, :cond_7

    .line 153
    .line 154
    iget-object p1, p1, Lyr0/e;->f:Ljava/lang/String;

    .line 155
    .line 156
    if-eqz p1, :cond_7

    .line 157
    .line 158
    invoke-static {p1}, Lcom/google/android/gms/internal/measurement/j4;->a(Ljava/lang/String;)Ljava/lang/String;

    .line 159
    .line 160
    .line 161
    move-result-object v1

    .line 162
    :cond_7
    move-object v6, v1

    .line 163
    const/4 v7, 0x0

    .line 164
    const/16 v8, 0x4f

    .line 165
    .line 166
    const/4 v1, 0x0

    .line 167
    const/4 v2, 0x0

    .line 168
    const/4 v3, 0x0

    .line 169
    const/4 v4, 0x0

    .line 170
    invoke-static/range {v0 .. v8}, Ly70/k;->a(Ly70/k;Lql0/g;ZZZLjava/lang/String;Ljava/lang/String;Ly70/w1;I)Ly70/k;

    .line 171
    .line 172
    .line 173
    move-result-object p1

    .line 174
    invoke-virtual {p0, p1}, Lql0/j;->g(Lql0/h;)V

    .line 175
    .line 176
    .line 177
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 178
    .line 179
    return-object p0

    .line 180
    nop

    .line 181
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
