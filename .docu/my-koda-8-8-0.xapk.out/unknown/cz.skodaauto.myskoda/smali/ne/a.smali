.class public final synthetic Lne/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ljava/lang/String;

.field public final synthetic f:Ljava/lang/String;

.field public final synthetic g:Lay0/a;


# direct methods
.method public synthetic constructor <init>(Ljava/lang/String;Ljava/lang/String;Lay0/a;I)V
    .locals 0

    .line 1
    iput p4, p0, Lne/a;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lne/a;->e:Ljava/lang/String;

    .line 4
    .line 5
    iput-object p2, p0, Lne/a;->f:Ljava/lang/String;

    .line 6
    .line 7
    iput-object p3, p0, Lne/a;->g:Lay0/a;

    .line 8
    .line 9
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 10
    .line 11
    .line 12
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 8

    .line 1
    iget v0, p0, Lne/a;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Lhi/a;

    .line 7
    .line 8
    const-string v0, "$this$sdkViewModel"

    .line 9
    .line 10
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 11
    .line 12
    .line 13
    const-class v0, Lke/f;

    .line 14
    .line 15
    sget-object v1, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 16
    .line 17
    invoke-virtual {v1, v0}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 18
    .line 19
    .line 20
    move-result-object v0

    .line 21
    check-cast p1, Lii/a;

    .line 22
    .line 23
    invoke-virtual {p1, v0}, Lii/a;->b(Lhy0/d;)Ljava/lang/Object;

    .line 24
    .line 25
    .line 26
    move-result-object p1

    .line 27
    move-object v2, p1

    .line 28
    check-cast v2, Lke/f;

    .line 29
    .line 30
    new-instance p1, Lue/b;

    .line 31
    .line 32
    new-instance v0, Lt10/k;

    .line 33
    .line 34
    const/4 v6, 0x0

    .line 35
    const/16 v7, 0x11

    .line 36
    .line 37
    const/4 v1, 0x1

    .line 38
    const-class v3, Lke/f;

    .line 39
    .line 40
    const-string v4, "getKolaCountries"

    .line 41
    .line 42
    const-string v5, "getKolaCountries-IoAF18A(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;"

    .line 43
    .line 44
    invoke-direct/range {v0 .. v7}, Lt10/k;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 45
    .line 46
    .line 47
    new-instance v1, Lne/b;

    .line 48
    .line 49
    const/4 v3, 0x0

    .line 50
    const/4 v4, 0x1

    .line 51
    iget-object v5, p0, Lne/a;->e:Ljava/lang/String;

    .line 52
    .line 53
    invoke-direct {v1, v2, v5, v3, v4}, Lne/b;-><init>(Lke/f;Ljava/lang/String;Lkotlin/coroutines/Continuation;I)V

    .line 54
    .line 55
    .line 56
    iget-object v2, p0, Lne/a;->f:Ljava/lang/String;

    .line 57
    .line 58
    iget-object p0, p0, Lne/a;->g:Lay0/a;

    .line 59
    .line 60
    invoke-direct {p1, v0, v1, v2, p0}, Lue/b;-><init>(Lt10/k;Lne/b;Ljava/lang/String;Lay0/a;)V

    .line 61
    .line 62
    .line 63
    return-object p1

    .line 64
    :pswitch_0
    check-cast p1, Lz9/w;

    .line 65
    .line 66
    const-string v0, "$this$navigation"

    .line 67
    .line 68
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 69
    .line 70
    .line 71
    new-instance v0, Lak/k;

    .line 72
    .line 73
    iget-object v1, p0, Lne/a;->e:Ljava/lang/String;

    .line 74
    .line 75
    iget-object v2, p0, Lne/a;->f:Ljava/lang/String;

    .line 76
    .line 77
    iget-object p0, p0, Lne/a;->g:Lay0/a;

    .line 78
    .line 79
    invoke-direct {v0, v1, v2, p0}, Lak/k;-><init>(Ljava/lang/String;Ljava/lang/String;Lay0/a;)V

    .line 80
    .line 81
    .line 82
    new-instance p0, Lt2/b;

    .line 83
    .line 84
    const/4 v1, 0x1

    .line 85
    const v2, 0x49ca2b07

    .line 86
    .line 87
    .line 88
    invoke-direct {p0, v0, v1, v2}, Lt2/b;-><init>(Ljava/lang/Object;ZI)V

    .line 89
    .line 90
    .line 91
    const-string v0, "ENTER_COUNTRY_REGION"

    .line 92
    .line 93
    invoke-static {p1, v0, p0}, Ljp/jf;->a(Lz9/w;Ljava/lang/String;Lt2/b;)V

    .line 94
    .line 95
    .line 96
    :goto_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 97
    .line 98
    return-object p0

    .line 99
    :pswitch_1
    check-cast p1, Lz9/w;

    .line 100
    .line 101
    const-string v0, "<this>"

    .line 102
    .line 103
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 104
    .line 105
    .line 106
    new-instance v0, Lne/a;

    .line 107
    .line 108
    const/4 v1, 0x2

    .line 109
    iget-object v2, p0, Lne/a;->e:Ljava/lang/String;

    .line 110
    .line 111
    iget-object v3, p0, Lne/a;->f:Ljava/lang/String;

    .line 112
    .line 113
    iget-object p0, p0, Lne/a;->g:Lay0/a;

    .line 114
    .line 115
    invoke-direct {v0, v2, v3, p0, v1}, Lne/a;-><init>(Ljava/lang/String;Ljava/lang/String;Lay0/a;I)V

    .line 116
    .line 117
    .line 118
    const-string p0, "ENTER_COUNTRY_REGION"

    .line 119
    .line 120
    const-string v1, "DYNAMIC_RATE_GRAPH"

    .line 121
    .line 122
    invoke-static {p1, p0, v1, v0}, Ljp/r0;->e(Lz9/w;Ljava/lang/String;Ljava/lang/String;Lay0/k;)V

    .line 123
    .line 124
    .line 125
    goto :goto_0

    .line 126
    :pswitch_2
    check-cast p1, Lhi/a;

    .line 127
    .line 128
    const-string v0, "$this$sdkViewModel"

    .line 129
    .line 130
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 131
    .line 132
    .line 133
    const-class v0, Lke/f;

    .line 134
    .line 135
    sget-object v1, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 136
    .line 137
    invoke-virtual {v1, v0}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 138
    .line 139
    .line 140
    move-result-object v0

    .line 141
    check-cast p1, Lii/a;

    .line 142
    .line 143
    invoke-virtual {p1, v0}, Lii/a;->b(Lhy0/d;)Ljava/lang/Object;

    .line 144
    .line 145
    .line 146
    move-result-object p1

    .line 147
    move-object v2, p1

    .line 148
    check-cast v2, Lke/f;

    .line 149
    .line 150
    new-instance p1, Lne/k;

    .line 151
    .line 152
    new-instance v0, La30/b;

    .line 153
    .line 154
    const/16 v1, 0x1c

    .line 155
    .line 156
    iget-object v3, p0, Lne/a;->e:Ljava/lang/String;

    .line 157
    .line 158
    iget-object v4, p0, Lne/a;->f:Ljava/lang/String;

    .line 159
    .line 160
    const/4 v5, 0x0

    .line 161
    invoke-direct/range {v0 .. v5}, La30/b;-><init>(ILjava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 162
    .line 163
    .line 164
    new-instance v1, La90/s;

    .line 165
    .line 166
    const/16 v4, 0x13

    .line 167
    .line 168
    invoke-direct {v1, v2, v5, v4}, La90/s;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 169
    .line 170
    .line 171
    new-instance v4, Lne/b;

    .line 172
    .line 173
    const/4 v6, 0x0

    .line 174
    invoke-direct {v4, v2, v3, v5, v6}, Lne/b;-><init>(Lke/f;Ljava/lang/String;Lkotlin/coroutines/Continuation;I)V

    .line 175
    .line 176
    .line 177
    iget-object p0, p0, Lne/a;->g:Lay0/a;

    .line 178
    .line 179
    invoke-direct {p1, p0, v0, v1, v4}, Lne/k;-><init>(Lay0/a;La30/b;La90/s;Lne/b;)V

    .line 180
    .line 181
    .line 182
    return-object p1

    .line 183
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
