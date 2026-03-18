.class public final synthetic Lh2/a6;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/a;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lh2/r8;

.field public final synthetic f:Lay0/a;

.field public final synthetic g:Lvy0/b0;


# direct methods
.method public synthetic constructor <init>(Lh2/r8;Lay0/a;Lvy0/b0;)V
    .locals 1

    .line 1
    const/4 v0, 0x1

    iput v0, p0, Lh2/a6;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lh2/a6;->e:Lh2/r8;

    iput-object p2, p0, Lh2/a6;->f:Lay0/a;

    iput-object p3, p0, Lh2/a6;->g:Lvy0/b0;

    return-void
.end method

.method public synthetic constructor <init>(Lh2/r8;Lvy0/b0;Lay0/a;)V
    .locals 1

    .line 2
    const/4 v0, 0x0

    iput v0, p0, Lh2/a6;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lh2/a6;->e:Lh2/r8;

    iput-object p2, p0, Lh2/a6;->g:Lvy0/b0;

    iput-object p3, p0, Lh2/a6;->f:Lay0/a;

    return-void
.end method

.method public synthetic constructor <init>(Lvy0/b0;Lh2/r8;Lay0/a;I)V
    .locals 0

    .line 3
    iput p4, p0, Lh2/a6;->d:I

    iput-object p1, p0, Lh2/a6;->g:Lvy0/b0;

    iput-object p2, p0, Lh2/a6;->e:Lh2/r8;

    iput-object p3, p0, Lh2/a6;->f:Lay0/a;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 5

    .line 1
    iget v0, p0, Lh2/a6;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance v0, Lz20/k;

    .line 7
    .line 8
    const/4 v1, 0x3

    .line 9
    iget-object v2, p0, Lh2/a6;->e:Lh2/r8;

    .line 10
    .line 11
    iget-object v3, p0, Lh2/a6;->f:Lay0/a;

    .line 12
    .line 13
    const/4 v4, 0x0

    .line 14
    invoke-direct {v0, v2, v3, v4, v1}, Lz20/k;-><init>(Lh2/r8;Lay0/a;Lkotlin/coroutines/Continuation;I)V

    .line 15
    .line 16
    .line 17
    iget-object p0, p0, Lh2/a6;->g:Lvy0/b0;

    .line 18
    .line 19
    invoke-static {p0, v4, v4, v0, v1}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 20
    .line 21
    .line 22
    :goto_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 23
    .line 24
    return-object p0

    .line 25
    :pswitch_0
    new-instance v0, Lz20/k;

    .line 26
    .line 27
    const/4 v1, 0x2

    .line 28
    iget-object v2, p0, Lh2/a6;->e:Lh2/r8;

    .line 29
    .line 30
    iget-object v3, p0, Lh2/a6;->f:Lay0/a;

    .line 31
    .line 32
    const/4 v4, 0x0

    .line 33
    invoke-direct {v0, v2, v3, v4, v1}, Lz20/k;-><init>(Lh2/r8;Lay0/a;Lkotlin/coroutines/Continuation;I)V

    .line 34
    .line 35
    .line 36
    const/4 v1, 0x3

    .line 37
    iget-object p0, p0, Lh2/a6;->g:Lvy0/b0;

    .line 38
    .line 39
    invoke-static {p0, v4, v4, v0, v1}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 40
    .line 41
    .line 42
    goto :goto_0

    .line 43
    :pswitch_1
    new-instance v0, Lz20/k;

    .line 44
    .line 45
    const/4 v1, 0x1

    .line 46
    iget-object v2, p0, Lh2/a6;->e:Lh2/r8;

    .line 47
    .line 48
    iget-object v3, p0, Lh2/a6;->f:Lay0/a;

    .line 49
    .line 50
    const/4 v4, 0x0

    .line 51
    invoke-direct {v0, v2, v3, v4, v1}, Lz20/k;-><init>(Lh2/r8;Lay0/a;Lkotlin/coroutines/Continuation;I)V

    .line 52
    .line 53
    .line 54
    const/4 v1, 0x3

    .line 55
    iget-object p0, p0, Lh2/a6;->g:Lvy0/b0;

    .line 56
    .line 57
    invoke-static {p0, v4, v4, v0, v1}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 58
    .line 59
    .line 60
    goto :goto_0

    .line 61
    :pswitch_2
    new-instance v0, Lz20/k;

    .line 62
    .line 63
    const/4 v1, 0x0

    .line 64
    iget-object v2, p0, Lh2/a6;->e:Lh2/r8;

    .line 65
    .line 66
    iget-object v3, p0, Lh2/a6;->f:Lay0/a;

    .line 67
    .line 68
    const/4 v4, 0x0

    .line 69
    invoke-direct {v0, v2, v3, v4, v1}, Lz20/k;-><init>(Lh2/r8;Lay0/a;Lkotlin/coroutines/Continuation;I)V

    .line 70
    .line 71
    .line 72
    const/4 v1, 0x3

    .line 73
    iget-object p0, p0, Lh2/a6;->g:Lvy0/b0;

    .line 74
    .line 75
    invoke-static {p0, v4, v4, v0, v1}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 76
    .line 77
    .line 78
    goto :goto_0

    .line 79
    :pswitch_3
    iget-object v0, p0, Lh2/a6;->e:Lh2/r8;

    .line 80
    .line 81
    invoke-virtual {v0}, Lh2/r8;->c()Lh2/s8;

    .line 82
    .line 83
    .line 84
    move-result-object v1

    .line 85
    invoke-virtual {v1}, Ljava/lang/Enum;->ordinal()I

    .line 86
    .line 87
    .line 88
    move-result v1

    .line 89
    const/4 v2, 0x1

    .line 90
    if-eq v1, v2, :cond_1

    .line 91
    .line 92
    const/4 v2, 0x2

    .line 93
    const/4 v3, 0x3

    .line 94
    iget-object p0, p0, Lh2/a6;->g:Lvy0/b0;

    .line 95
    .line 96
    const/4 v4, 0x0

    .line 97
    if-eq v1, v2, :cond_0

    .line 98
    .line 99
    new-instance v1, Lh2/i0;

    .line 100
    .line 101
    const/16 v2, 0xb

    .line 102
    .line 103
    invoke-direct {v1, v0, v4, v2}, Lh2/i0;-><init>(Lh2/r8;Lkotlin/coroutines/Continuation;I)V

    .line 104
    .line 105
    .line 106
    invoke-static {p0, v4, v4, v1, v3}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 107
    .line 108
    .line 109
    goto :goto_1

    .line 110
    :cond_0
    new-instance v1, Lh2/i0;

    .line 111
    .line 112
    const/16 v2, 0xa

    .line 113
    .line 114
    invoke-direct {v1, v0, v4, v2}, Lh2/i0;-><init>(Lh2/r8;Lkotlin/coroutines/Continuation;I)V

    .line 115
    .line 116
    .line 117
    invoke-static {p0, v4, v4, v1, v3}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 118
    .line 119
    .line 120
    goto :goto_1

    .line 121
    :cond_1
    iget-object p0, p0, Lh2/a6;->f:Lay0/a;

    .line 122
    .line 123
    invoke-interface {p0}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 124
    .line 125
    .line 126
    :goto_1
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 127
    .line 128
    return-object p0

    .line 129
    :pswitch_4
    iget-object v0, p0, Lh2/a6;->e:Lh2/r8;

    .line 130
    .line 131
    iget-object v1, v0, Lh2/r8;->e:Li2/p;

    .line 132
    .line 133
    iget-object v1, v1, Li2/p;->d:Lay0/k;

    .line 134
    .line 135
    sget-object v2, Lh2/s8;->d:Lh2/s8;

    .line 136
    .line 137
    invoke-interface {v1, v2}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 138
    .line 139
    .line 140
    move-result-object v1

    .line 141
    check-cast v1, Ljava/lang/Boolean;

    .line 142
    .line 143
    invoke-virtual {v1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 144
    .line 145
    .line 146
    move-result v1

    .line 147
    if-eqz v1, :cond_2

    .line 148
    .line 149
    new-instance v1, Lh2/i0;

    .line 150
    .line 151
    const/16 v2, 0x9

    .line 152
    .line 153
    const/4 v3, 0x0

    .line 154
    invoke-direct {v1, v0, v3, v2}, Lh2/i0;-><init>(Lh2/r8;Lkotlin/coroutines/Continuation;I)V

    .line 155
    .line 156
    .line 157
    const/4 v2, 0x3

    .line 158
    iget-object v4, p0, Lh2/a6;->g:Lvy0/b0;

    .line 159
    .line 160
    invoke-static {v4, v3, v3, v1, v2}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 161
    .line 162
    .line 163
    move-result-object v1

    .line 164
    new-instance v2, Lh2/c6;

    .line 165
    .line 166
    const/4 v3, 0x0

    .line 167
    iget-object p0, p0, Lh2/a6;->f:Lay0/a;

    .line 168
    .line 169
    invoke-direct {v2, v0, p0, v3}, Lh2/c6;-><init>(Lh2/r8;Lay0/a;I)V

    .line 170
    .line 171
    .line 172
    invoke-virtual {v1, v2}, Lvy0/p1;->E(Lay0/k;)Lvy0/r0;

    .line 173
    .line 174
    .line 175
    :cond_2
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 176
    .line 177
    return-object p0

    .line 178
    nop

    .line 179
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
